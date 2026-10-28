// `P10.20-b` — UNE LIGNE `cold_seal` ILLISIBLE N'EST JAMAIS UN FICHIER ABSENT ; LE VIEILLISSEMENT DIT CE QU'IL N'A
// PAS PU LIRE NI ÉCRIRE.
//
// Le défaut (VU sur 5100db29) :
//  * `file_seals` (`cold_store/seal.rs`) lisait par `if let Ok(prepare)` / `if let Ok(rows)` / `rows.flatten()` : une
//    ligne illisible faisait sauter son fichier sans un mot. Le lecteur (`hydrate_cold`) et le planificateur
//    (`select_files`, voies vectorisée, keyset et fusion) servaient la réponse SANS ce fichier, comme complète ; le
//    vieillissement reprenait un jour à seal illisible comme FRAIS (`age_one_day`) ou traversait la phase 2 sans rien
//    faire et comptait le jour « columnarisé » (`phase2_delete`) ;
//  * `detect_cold_seal_stuck` (`aging.rs`) rendait une lecture ratée sous la forme « aucun seal bloqué » (`.ok()`) ;
//  * `phase2_delete` comptait le fichier purgé AVANT l'`UPDATE cold_seal SET purged=1`, jeté par `let _` ;
//  * `emit_cold_aging_stall` / `emit_cold_seal_stuck` confondaient une écriture refusée et la dédup horaire
//    (`.unwrap_or(0) > 0`).
//
// LES TÉMOINS passent par les points d'entrée : `seals_du_jour` (direct, chaque issue), les quatre voies de lecture
// froide (`cold_union_query`, `cold_vectorized_try`, `cold_keyset_page`, `cold_vectorized_merge_try`), la passe
// `cold_age_run`, et `detect_cold_seal_stuck`. Les journaux sont jugés dans un SOUS-PROCESSUS, ligne ENTIÈRE ; les
// phrases sont comparées à des CONSTANTES du test.
//
// MUTANTS JOUÉS (sous la variable de mutation, retirés du source avant le commit), chacun vu ROUGE :
//  AV5_ABSENTE_AVOUEE (table absente rendue non lue), AV5_PREPARE_AVALEE (préparation ratée rendue « aucun fichier »),
//  AV5_ARRET_EN_ILLISIBLE (erreur du moteur en cours de parcours comptée comme ligne illisible), AV5_ILLISIBLE_AVALEE
//  (ligne illisible sautée), AV5_ILLISIBLES_UN (nombre de lignes illisibles rendu 1), AV5_READER_AVALE (lecteur :
//  index non lu rendu vide), AV5_PLANNER_AVALE (planificateur : idem), AV5_AGE_AVALE (vieillissement : jour à index
//  illisible repris comme frais), AV5_PHASE2_AVALEE (phase 2 : index illisible rendu vide), AV5_PURGE_COMPTE_AVANT
//  (fichier compté purgé quel que soit le marquage), AV5_ZERO_ACCEPTE (UPDATE qui ne marque aucune ligne compté
//  purgé), AV5_UPDATE_AVALE (UPDATE refusé jeté), AV5_STUCK_AVALE (détecteur non lu rendu « 0 bloqué », muet),
//  AV5_EMIT_STUCK_AVALE / AV5_EMIT_RETARD_AVALE (signal refusé rendu comme dédupliqué, muet), AV5_DEDUP_REFUS (la
//  dédup horaire du seal bloqué dite comme un refus), AV5_RETARD_DEDUP_REFUS (la dédup horaire du retard dite comme
//  un refus), AV5_VOIE_MOTEUR_FUSION (refus du moteur rendu par la voie froide comme une ligne illisible),
//  AV5_VOIE_SANS_NOTE (refus du moteur rendu sans la note de la base occupée), AW2_PRECEDENCE (erreur du moteur
//  survenue après des lignes illisibles rendue comme ces illisibles), AW2_QUERY_MAP_AVALEE (parcours refusé au liage
//  rendu « aucun fichier »), AW2C_A14 (retard rendu non mesuré quand son signal est refusé), AW2C_A15 / AW2C_A16
//  (vieillissement, phase 1 / phase 2 : refus du moteur sur l'index rendu « aucun fichier »), AW2C_A17 (le journal du
//  jour suspendu dit le message du moteur au lieu de sa nature), AW2C_A18 (le signal de seal bloqué ne nomme que la
//  cause VERIFY).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la route HTTP (`/api/query`) — la classe servie est jugée sur
// `en_classant_la_voie_froide`, que les routes appellent ; une base OCCUPÉE pendant la lecture des seals par la voie
// froide elle-même — la voie ouvre sa connexion en interne et ses énoncés antérieurs (horizon, liste des jours)
// rencontrent le verrou avant les seals : la note est jouée directement sur `pour_la_voie_froide` (2c). Le refus du
// moteur, lui, est joué sur les quatre voies (2b).
//
// RESTRICTIONS NOMMÉES, NON CORRIGÉES ICI : un marquage `purged=1` refusé sur le DERNIER fichier d'un jour laisse le seal
// à `purged=0` sans plus aucune ligne chaude ; la découverte partant des lignes chaudes, le jour n'est plus repris — le
// signal de seal bloqué le dit et nomme cette cause (6b). Le verdict rendu par `detect_cold_seal_stuck` n'est pas
// publié dans la série de la passe : « aucun verdict » n'est dit que par son journal (7).

use super::*;

const AV5_ENFANT: &str = "PLUME_TEST_AV5_SEALS_ENFANT";
const AV5_SEPARATEUR: &str = "@@av5-tour-suivant@@";
const AV5_PREFIXES: [&str; 3] = ["[cold] aging ", "[cold] détecteur de seal", "[cold] signal de santé"];

const AV5_REFUS_UNE_LIGNE: &str = "lecture froide refusée : index cold_seal illisible — un fichier scellé de la fenêtre ne se lit pas dans l'index, aucun fichier n'est tenu pour absent (1 ligne(s))";
const AV5_NATURE_LECTURE_FROIDE: &str = "lecture du tier froid non faite (ouverture, horizon de lecture, hydratation ou décodage d'un fichier), hors du cœur d'exécution";
const AV5_INTERROMPU: &str = "code SQLite 9 (OperationInterrupted)";
const AV5_TRIGGER: &str = "code SQLite 1811 (ConstraintViolation)";
const AW2_COLONNE_REFUSEE: &str = "code SQLite 1 (Unknown)";
const AW2_LECTURE_REFUSEE: &str = "code SQLite 23 (AuthorizationForStatementDenied)";

const AV5_JOUR: i64 = M - 10;

/// Relance le binaire de test sur UN test, en enfant, et rend ses lignes de journal (préfixes `AV5_PREFIXES`)
/// découpées par tour (séparateur écrit par l'enfant sur la même sortie d'erreur).
fn av5_lancer(mut enfant: std::process::Command, test: &str) -> Vec<Vec<String>> {
    let sortie = enfant.args(["--exact", "--nocapture", "--test-threads=1", test]).output().expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "contrôle : l'enfant a bien joué le test visé : {stdout}");
    let mut tours: Vec<Vec<String>> = vec![Vec::new()];
    for l in stderr.lines() {
        if l == AV5_SEPARATEUR {
            tours.push(Vec::new());
        } else if AV5_PREFIXES.iter().any(|p| l.starts_with(p)) {
            tours.last_mut().expect("au moins un tour").push(l.to_string());
        }
    }
    tours
}

fn av5_serie(db: &Arc<Mutex<Connection>>, nom: &str, cle: &str, valeur: &str) -> Option<f64> {
    serie(db, nom, Some(&format!("{{\"{cle}\":\"{valeur}\"}}")))
}

fn av5_jours(db: &Arc<Mutex<Connection>>, issue: &str) -> Option<f64> {
    av5_serie(db, crate::vieillissement_serie::NOM_JOURS, "issue", issue)
}

fn av5_purges(db: &Arc<Mutex<Connection>>) -> Option<f64> {
    av5_serie(db, crate::vieillissement_serie::NOM_FICHIERS, "etat", "purges")
}

fn av5_retirees(db: &Arc<Mutex<Connection>>) -> Option<f64> {
    av5_serie(db, crate::vieillissement_serie::NOM_LIGNES, "sens", "retirees_du_chaud")
}

/// Six lignes au jour `AV5_JOUR` (sources `src-0` à `src-5`) puis la ligne récente qui tient le compteur de rowid.
fn av5_six_lignes(db: &Arc<Mutex<Connection>>) {
    for i in 0..6 {
        insert_event(db, &rich_row(AV5_JOUR * SECS_PER_DAY + 100 + i, i));
    }
    insert_recent_tail_holder(db);
}

fn av5_conf(cold: &Path, plafond: Option<usize>) -> HashMap<String, String> {
    let mut c = conf_on(cold, HOT_WIN);
    if let Some(p) = plafond {
        c.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), p.to_string());
    }
    c
}

fn av5_purged(db: &Arc<Mutex<Connection>>, seq: i64) -> i64 {
    db.lock()
        .query_row("SELECT purged FROM cold_seal WHERE day=?1 AND seq=?2", params![AV5_JOUR, seq], |r| r.get(0))
        .unwrap()
}

fn av5_nature(r: Result<Vec<FileSeal>, SealsNonLus>) -> String {
    match r {
        Ok(v) => panic!("lecture rendue avec {} fichier(s), attendu un refus", v.len()),
        Err(e) => e.nature(),
    }
}

/// (1) `seals_du_jour`, CHAQUE ISSUE : table absente -> aucun fichier ; deux lignes lisibles -> les deux ; une ligne
/// illisible SEULE (`expected_rows` en texte) -> refus « 1 ligne » ; une seconde (`ts_min` en BLOB) -> « 2 lignes » ;
/// préparation refusée (colonne absente) -> nature du code ; moteur interrompu -> nature du code ; erreur du moteur
/// APRÈS une ligne illisible -> l'erreur du moteur, pas une illisible. La vue lit `av5_base` dont `seq` est la clé
/// du rowid : `ORDER BY seq` suit l'arbre sans trieur (contrôlé par le plan), donc le parcours rend seq 0 (lisible),
/// puis seq 1 (illisible, comptée), puis seq 2 où la fonction rend SQLITE_IOERR. Avec un `seq INTEGER` simple, un
/// trieur se remplissait d'abord et l'erreur survenait au premier pas, avant toute ligne illisible : la précédence
/// n'était pas jouée (mutant AW2_PRECEDENCE vert).
#[test]
fn av5_seals_du_jour_rend_chaque_issue() {
    let root = tmp_root("av5-issues");
    let db = mkdb(&root);
    let c = db.lock();
    let absente: i64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE name='cold_seal'", [], |r| r.get(0)).unwrap();
    assert_eq!(absente, 0, "contrôle : la table n'existe pas");
    assert_eq!(seals_du_jour(&c, "prod", AV5_JOUR).ok().map(|v| v.len()), Some(0), "table absente : aucun fichier, lecture faite");
    drop(c);

    let ts = AV5_JOUR * SECS_PER_DAY;
    seal_row(&db, "prod", AV5_JOUR, 0, 3, 0, 9, ts, ts + 2, i64::MIN, i64::MIN, 5, 0);
    seal_row(&db, "prod", AV5_JOUR, 1, 3, 0, 9, ts + 3, ts + 5, ts + 2, 5, 9, 1);
    let c = db.lock();
    let lus: Vec<(i64, i64, bool)> =
        seals_du_jour(&c, "prod", AV5_JOUR).unwrap_or_else(|e| panic!("contrôle : lecture faite ({})", e.nature())).iter().map(|s| (s.seq, s.expected, s.last_file)).collect();
    assert_eq!(lus, vec![(0, 3, false), (1, 3, true)], "deux lignes lisibles : les deux, dans l'ordre");

    c.execute("UPDATE cold_seal SET expected_rows='illisible' WHERE seq=0", []).unwrap();
    assert_eq!(av5_nature(seals_du_jour(&c, "prod", AV5_JOUR)), "1 ligne(s) illisible(s)", "une ligne illisible : refus, jamais un fichier absent");
    c.execute("UPDATE cold_seal SET ts_min=X'00' WHERE seq=1", []).unwrap();
    assert_eq!(av5_nature(seals_du_jour(&c, "prod", AV5_JOUR)), "2 ligne(s) illisible(s)", "deux lignes illisibles : le nombre exact");
    c.execute("UPDATE cold_seal SET expected_rows=3, ts_min=?1", params![ts]).unwrap();
    assert_eq!(seals_du_jour(&c, "prod", AV5_JOUR).ok().map(|v| v.len()), Some(2), "contrôle : réparées, les deux se lisent");

    c.progress_handler(1, Some(|| true));
    let interrompu = seals_du_jour(&c, "prod", AV5_JOUR);
    c.progress_handler(1, None::<fn() -> bool>);
    assert_eq!(av5_nature(interrompu), AV5_INTERROMPU, "moteur interrompu : la nature du code, jamais « aucun fichier »");
    drop(c);

    // PRÉPARATION REFUSÉE : une table `cold_seal` sans les colonnes de l'énoncé.
    let root_p = tmp_root("av5-preparation");
    let db_p = mkdb(&root_p);
    let c = db_p.lock();
    c.execute_batch("CREATE TABLE cold_seal(env_id TEXT, day INTEGER)").unwrap();
    match seals_du_jour(&c, "prod", AV5_JOUR) {
        Err(SealsNonLus::Moteur(_)) => {}
        Err(SealsNonLus::Illisibles(n)) => panic!("préparation refusée rendue comme {n} ligne(s) illisible(s)"),
        Ok(v) => panic!("préparation refusée rendue comme {} fichier(s)", v.len()),
    }
    drop(c);

    // ERREUR DU MOTEUR APRÈS UNE LIGNE ILLISIBLE : `cold_seal` est une vue sur `av5_base` (`seq` = clé du rowid, lue
    // dans l'ordre sans trieur) ; au seq 1 la ligne est illisible, au seq 2 une fonction rend le code de `av5_arme`
    // (0 = lisible, 10 = SQLITE_IOERR).
    let root_v = tmp_root("av5-vue");
    let db_v = mkdb(&root_v);
    let c = db_v.lock();
    c.create_scalar_function("av5_erreur", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
        match ctx.get::<i32>(0)? {
            0 => Ok(3),
            code => Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)),
        }
    })
    .unwrap();
    c.execute_batch(&format!(
        "CREATE TABLE av5_base(seq INTEGER PRIMARY KEY, expected_rows); \
         INSERT INTO av5_base VALUES(0, 3), (1, 'illisible'), (2, 3); \
         CREATE TABLE av5_arme(code INTEGER); INSERT INTO av5_arme VALUES(0); \
         CREATE VIEW cold_seal AS SELECT 'prod' AS env_id, {AV5_JOUR} AS day, seq, \
           CASE WHEN seq=2 THEN av5_erreur((SELECT code FROM av5_arme)) ELSE expected_rows END AS expected_rows, \
           0 AS purged, 9 AS max_id, \
           0 AS ts_min, 0 AS ts_max, 0 AS lo_ts, 0 AS lo_id, 0 AS hi_id, 0 AS last_file, NULL AS dim_stats FROM av5_base"
    ))
    .unwrap();
    let plan: Vec<String> = c
        .prepare(&format!("EXPLAIN QUERY PLAN {SQL_SEALS_DU_JOUR}"))
        .unwrap()
        .query_map(params!["prod", AV5_JOUR], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!plan.is_empty(), "contrôle : le plan est lu");
    assert!(
        plan.iter().all(|d| !d.contains("TEMP B-TREE")),
        "contrôle : aucun trieur, le parcours suit l'ordre de seq pas à pas : {plan:?}"
    );
    assert_eq!(
        av5_nature(seals_du_jour(&c, "prod", AV5_JOUR)),
        "1 ligne(s) illisible(s)",
        "contrôle : désarmée, la vue rend seq 2 lisible et seq 1 seule illisible — le parcours atteint seq 2"
    );
    c.execute("UPDATE av5_arme SET code=10", []).unwrap();
    assert_eq!(
        av5_nature(seals_du_jour(&c, "prod", AV5_JOUR)),
        "code SQLite 10 (SystemIoFailure)",
        "le moteur a refusé de continuer : la suite n'est pas lue, ce n'est pas une ligne illisible"
    );
}

const AW2_TROP_LONG: &str = "code SQLite 18 (TooBig)";
const AW2_LIMITE: i32 = 64;

fn aw2_lus(r: Result<Vec<FileSeal>, SealsNonLus>) -> usize {
    r.unwrap_or_else(|e| panic!("contrôle : lecture faite ({})", e.nature())).len()
}

/// (1b) `seals_du_jour`, PARCOURS REFUSÉ AU LIAGE : la préparation passe, `query_map` échoue en liant `?1`. La
/// longueur maximale d'une chaîne ou d'une valeur (SQLITE_LIMIT_LENGTH) est abaissée à 64 octets sur la connexion et
/// `env_id` en porte 65 : SQLITE_TOOBIG au liage. Le refus est celui du moteur, jamais « aucun fichier ». La limite
/// n'est pas abaissée davantage : sous la longueur d'un nom de colonne de l'énoncé, c'est la PRÉPARATION qui échoue,
/// et le liage n'est plus joué (contrôle : « prod » se lit encore sous la limite). En production ce liage n'échoue que
/// sur SQLITE_TOOBIG ou SQLITE_NOMEM (`sqlite_plafond::armer` n'abaisse pas cette limite) : branche rare, pas morte.
/// La limite passe par `sqlite3_limit` (rusqlite est construit sans sa fonction `limits`).
#[test]
fn av5_seals_du_jour_parcours_refuse_au_liage() {
    let root = tmp_root("aw2-liage");
    let db = mkdb(&root);
    let ts = AV5_JOUR * SECS_PER_DAY;
    seal_row(&db, "prod", AV5_JOUR, 0, 3, 0, 9, ts, ts + 2, i64::MIN, i64::MIN, 5, 1);
    let c = db.lock();
    assert_eq!(aw2_lus(seals_du_jour(&c, "prod", AV5_JOUR)), 1, "contrôle : le seal se lit");
    let trop_long = "p".repeat(AW2_LIMITE as usize + 1);
    // SAFETY : poignée de la connexion tenue sous son verrou ; sqlite3_limit ne fait que lire et poser une limite.
    let avant = unsafe { rusqlite::ffi::sqlite3_limit(c.handle(), rusqlite::ffi::SQLITE_LIMIT_LENGTH, AW2_LIMITE) };
    assert!(avant > AW2_LIMITE, "contrôle : la limite d'avant laissait passer {} octets ({avant})", trop_long.len());
    let sous_la_limite = seals_du_jour(&c, "prod", AV5_JOUR).map(|v| v.len());
    let refuse = seals_du_jour(&c, &trop_long, AV5_JOUR);
    // SAFETY : idem, la limite d'avant est remise.
    unsafe { rusqlite::ffi::sqlite3_limit(c.handle(), rusqlite::ffi::SQLITE_LIMIT_LENGTH, avant) };
    assert_eq!(
        sous_la_limite.map_err(|e| e.nature()),
        Ok(1),
        "contrôle : sous la limite, l'énoncé se prépare et se parcourt — seul le liage de la valeur trop longue échoue"
    );
    match refuse {
        Err(SealsNonLus::Moteur(e)) => assert_eq!(nature_de_l_echec_sur_l_index(&e), AW2_TROP_LONG, "la nature du code du liage"),
        Err(SealsNonLus::Illisibles(n)) => panic!("liage refusé rendu comme {n} ligne(s) illisible(s)"),
        Ok(v) => panic!("liage refusé rendu comme {} fichier(s), lecture tenue pour faite", v.len()),
    }
    assert_eq!(aw2_lus(seals_du_jour(&c, &trop_long, AV5_JOUR)), 0, "contrôle : la limite remise, la valeur se lie (aucun seal)");
    assert_eq!(aw2_lus(seals_du_jour(&c, "prod", AV5_JOUR)), 1, "contrôle : la limite remise, le seal se relit");
}

struct Av5Froid {
    _root: crate::tmp_possede::TmpPossede,
    db: Arc<Mutex<Connection>>,
    dbp: String,
    conf: HashMap<String, String>,
    b: i64,
}

/// Le jour `AV5_JOUR` vieilli en DEUX fichiers (plafond 3) ; la ligne récente reste chaude.
fn av5_froid(tag: &str) -> Av5Froid {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let mut conf = conf_union(HOT_WIN);
    conf.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), "3".to_string());
    av5_six_lignes(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 0, "contrôle : le jour est vieilli");
    let seqs: Vec<i64> = file_seals(&db.lock(), "prod", AV5_JOUR).iter().map(|s| s.seq).collect();
    assert_eq!(seqs, vec![0, 1], "contrôle : deux fichiers scellés");
    let b = union_boundary(&db, &conf);
    Av5Froid { _root: root, db, dbp, conf, b }
}

fn av5_froides(v: &Value) -> i64 {
    count_by_source(v).iter().filter(|(s, _)| s != "recent-tail").map(|(_, n)| n).sum()
}

/// (2) LES QUATRE VOIES DE LECTURE FROIDE : six lignes servies sur l'index lisible ; une ligne `cold_seal` illisible
/// (seq 0) -> chaque voie refuse, phrase entière, et la route la range au support (503 de la base illisible) — jamais
/// les trois lignes du seul seq 1 servies comme la réponse.
#[test]
fn av5_les_voies_froides_refusent_un_fichier_illisible() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let f = av5_froid("av5-voies");
    let from = (M - 20) * SECS_PER_DAY;
    let to = M * SECS_PER_DAY;
    let sql = compile_ev("search | stats count by source", from, to, FieldMaskSet::new());
    let union = || union_query_oracle(&f.dbp, &f.conf, None, from, to, f.b, &sql, None, 60_000, None, &[]).map(|(v, _, _)| v);
    let vectorisee = || cold_vectorized_try(&f.dbp, &f.conf, None, from, f.b - 1, f.b, "search | stats count by source", true, 60_000, &[]);
    let keyset = || cold_keyset_page(&f.dbp, &f.conf, None, from, f.b - 1, f.b, "search", true, None, 100, &[]);
    let fusion = || cold_vectorized_merge_try(&f.dbp, &f.conf, None, from, to, f.b, "search | stats count by source", true, 60_000, None, &[]);

    assert_eq!(av5_froides(&union().expect("contrôle : union")), 6, "contrôle : union, six lignes froides");
    assert_eq!(av5_froides(&vectorisee().expect("contrôle").expect("contrôle : routée")), 6, "contrôle : vectorisée");
    assert_eq!(keyset().expect("contrôle").expect("contrôle : routée").1.len(), 6, "contrôle : keyset");
    assert_eq!(av5_froides(&fusion().expect("contrôle").expect("contrôle : routée")), 6, "contrôle : fusion");

    f.db.lock().execute("UPDATE cold_seal SET expected_rows='illisible' WHERE day=?1 AND seq=0", params![AV5_JOUR]).unwrap();
    let refus = [
        ("union", union().err()),
        ("vectorisée", vectorisee().err()),
        ("keyset", keyset().err()),
        ("fusion", fusion().err()),
    ];
    for (voie, e) in refus {
        let e = e.unwrap_or_else(|| panic!("{voie} : servie sans le fichier illisible"));
        assert_eq!(e, AV5_REFUS_UNE_LIGNE, "{voie} : la phrase entière");
        assert_eq!(
            crate::query_exec::en_classant_la_voie_froide(|| Err::<(), String>(e.clone())),
            Err(crate::query_exec::EchecDeRequete::Support { nature: AV5_NATURE_LECTURE_FROIDE.to_string(), texte: e }),
            "{voie} : rangée au support (503 de la base illisible)"
        );
    }
}

/// (2b) LES QUATRE VOIES, REFUS DU MOTEUR À LA LECTURE DES SEALS : la colonne `expected_rows` de `cold_seal` est
/// renommée (seul l'énoncé des seals d'un jour la lit) ; chaque voie rend le texte du moteur — celui de la préparation
/// (avec la position du jeton) quand la connexion lit le schéma neuf, celui de la re-préparation au premier pas quand
/// elle tenait l'ancien — jamais la cause des lignes illisibles, et la route la range au support.
#[test]
fn av5_les_voies_froides_rendent_le_refus_du_moteur() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let f = av5_froid("av5-voies-moteur");
    let from = (M - 20) * SECS_PER_DAY;
    let to = M * SECS_PER_DAY;
    let sql = compile_ev("search | stats count by source", from, to, FieldMaskSet::new());
    let union = || union_query_oracle(&f.dbp, &f.conf, None, from, to, f.b, &sql, None, 60_000, None, &[]).map(|(v, _, _)| v);
    let vectorisee = || cold_vectorized_try(&f.dbp, &f.conf, None, from, f.b - 1, f.b, "search | stats count by source", true, 60_000, &[]);
    let keyset = || cold_keyset_page(&f.dbp, &f.conf, None, from, f.b - 1, f.b, "search", true, None, 100, &[]);
    let fusion = || cold_vectorized_merge_try(&f.dbp, &f.conf, None, from, to, f.b, "search | stats count by source", true, 60_000, None, &[]);

    assert_eq!(av5_froides(&union().expect("contrôle : union")), 6, "contrôle : union, six lignes froides");
    assert_eq!(av5_froides(&vectorisee().expect("contrôle").expect("contrôle : routée")), 6, "contrôle : vectorisée");
    assert_eq!(keyset().expect("contrôle").expect("contrôle : routée").1.len(), 6, "contrôle : keyset");
    assert_eq!(av5_froides(&fusion().expect("contrôle").expect("contrôle : routée")), 6, "contrôle : fusion");

    f.db.lock().execute_batch("ALTER TABLE cold_seal RENAME COLUMN expected_rows TO av5_renommee").unwrap();
    let a_la_preparation = {
        let c = f.db.lock();
        let texte = c.prepare(SQL_SEALS_DU_JOUR).err().map(|e| e.to_string());
        texte
    }
    .expect("contrôle : l'énoncé des seals ne se prépare plus");
    let au_premier_pas = "no such column: expected_rows";
    assert!(a_la_preparation.starts_with(au_premier_pas), "contrôle : le moteur refuse la colonne : {a_la_preparation}");
    for (voie, e) in [("union", union().err()), ("vectorisée", vectorisee().err()), ("keyset", keyset().err()), ("fusion", fusion().err())] {
        let e = e.unwrap_or_else(|| panic!("{voie} : servie sans l'index des seals"));
        assert!(e == a_la_preparation || e == au_premier_pas, "{voie} : le texte du moteur, rendu {e:?}");
        assert_eq!(
            crate::query_exec::en_classant_la_voie_froide(|| Err::<(), String>(e.clone())),
            Err(crate::query_exec::EchecDeRequete::Support { nature: AV5_NATURE_LECTURE_FROIDE.to_string(), texte: e }),
            "{voie} : rangée au support (503 de la base illisible)"
        );
    }
}

/// (2c) LA NOTE DE LA BASE OCCUPÉE sur un refus du moteur à la lecture des seals (`pour_la_voie_froide`, joué
/// directement — voir l'en-tête) : `SQLITE_BUSY` garde sa classe à travers le classeur froid ; un code du support
/// (`SQLITE_IOERR` au texte de l'occupation) reste au support, et les lignes illisibles aussi.
#[test]
fn av5_seals_non_lus_sur_base_occupee_restent_occupee() {
    use crate::query_exec::{en_classant_la_voie_froide, EchecDeRequete};
    let echec = |code: i32| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some("database is locked".to_string()));
    let classe = |s: SealsNonLus| en_classant_la_voie_froide(|| Err::<(), String>(s.pour_la_voie_froide()));
    assert_eq!(
        classe(SealsNonLus::Moteur(echec(rusqlite::ffi::SQLITE_BUSY))),
        Err(EchecDeRequete::Occupee { nature: "code SQLite 5 (DatabaseBusy)".to_string(), texte: "database is locked".to_string() }),
        "base occupée : servie occupée, jamais « illisible »"
    );
    assert_eq!(
        classe(SealsNonLus::Moteur(echec(rusqlite::ffi::SQLITE_IOERR))),
        Err(EchecDeRequete::Support { nature: AV5_NATURE_LECTURE_FROIDE.to_string(), texte: "database is locked".to_string() }),
        "code du support au texte de l'occupation : support, la classe ne se lit pas sur le texte"
    );
    assert_eq!(
        classe(SealsNonLus::Illisibles(1)),
        Err(EchecDeRequete::Support { nature: AV5_NATURE_LECTURE_FROIDE.to_string(), texte: AV5_REFUS_UNE_LIGNE.to_string() }),
        "ligne illisible : support"
    );
}

/// (3) VIEILLISSEMENT, JOUR À INDEX ILLISIBLE : la ligne `cold_seal` du seq 0 est illisible. Le jour est SUSPENDU
/// (compté `echoue`), le chaud intact, aucun fichier écrit par-dessus, la ligne gardée ; le journal le dit.
#[test]
fn av5_vieillissement_jour_a_index_illisible() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("jour_illisible") {
        let root = tmp_root("av5-jour-illisible");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        let ts = AV5_JOUR * SECS_PER_DAY;
        seal_row(&db, "prod", AV5_JOUR, 0, 6, 0, 6, ts, ts + 105, i64::MIN, i64::MIN, 6, 1);
        db.lock().execute("UPDATE cold_seal SET expected_rows='illisible'", []).unwrap();
        cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 6, "le chaud est intact");
        assert!(!file_path(&cold, "prod", AV5_JOUR, 0).exists(), "aucun fichier écrit par-dessus le seq scellé");
        let texte: i64 = db.lock().query_row("SELECT count(*) FROM cold_seal WHERE typeof(expected_rows)='text'", [], |r| r.get(0)).unwrap();
        assert_eq!(texte, 1, "la ligne illisible est gardée");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!(av5_jours(&db, "columnarise"), Some(0.0), "rien n'est dit columnarisé");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "jour_illisible");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_vieillissement_jour_a_index_illisible",
    );
    assert_eq!(
        tours,
        vec![vec![format!(
            "[cold] aging prod/{} échoué (lignes non retirées conservées hot): index cold_seal du jour non lu (1 ligne(s) illisible(s)) — jour SUSPENDU, aucun fichier tenu pour absent",
            ymd_from_day(AV5_JOUR)
        )]]
    );
}

/// (4) VIEILLISSEMENT, PHASE 2 SUR UN INDEX DEVENU ILLISIBLE : un déclencheur rend la ligne illisible au moment où la
/// phase 1 pose `last_file=1`. Le fichier est écrit, la phase 2 refuse : le chaud est intact, le jour compté `echoue`,
/// jamais « columnarisé ».
#[test]
fn av5_vieillissement_phase2_sur_index_illisible() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("phase2_illisible") {
        let root = tmp_root("av5-phase2");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        ensure_cold_seal_table(&db.lock());
        db.lock()
            .execute_batch(
                "CREATE TRIGGER av5_illisible AFTER UPDATE OF last_file ON cold_seal WHEN NEW.last_file=1 BEGIN \
                   UPDATE cold_seal SET expected_rows='illisible' WHERE env_id=NEW.env_id AND day=NEW.day AND seq=NEW.seq; END",
            )
            .unwrap();
        cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
        assert!(file_path(&cold, "prod", AV5_JOUR, 0).is_file(), "contrôle : la phase 1 a écrit le fichier");
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 6, "la phase 2 n'a rien retiré");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!(av5_jours(&db, "columnarise"), Some(0.0), "jamais « columnarisé »");
        assert_eq!(av5_purges(&db), Some(0.0), "aucun fichier purgé");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "phase2_illisible");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_vieillissement_phase2_sur_index_illisible",
    );
    assert_eq!(
        tours,
        vec![vec![format!(
            "[cold] aging prod/{} échoué (lignes non retirées conservées hot): index cold_seal du jour non lu (1 ligne(s) illisible(s)) — jour SUSPENDU, aucun fichier tenu pour absent",
            ymd_from_day(AV5_JOUR)
        )]]
    );
}

fn aw2_ligne_suspendue(nature: &str) -> Vec<Vec<String>> {
    vec![vec![format!(
        "[cold] aging prod/{} échoué (lignes non retirées conservées hot): index cold_seal du jour non lu ({nature}) — jour SUSPENDU, aucun fichier tenu pour absent",
        ymd_from_day(AV5_JOUR)
    )]]
}

/// (3b) VIEILLISSEMENT, REFUS DU MOTEUR SUR L'INDEX D'UN JOUR SCELLÉ : la colonne `expected_rows` est renommée (seul
/// l'énoncé des seals d'un jour la lit), la préparation est refusée. Le jour est SUSPENDU (compté `echoue`), le chaud
/// intact, aucun fichier écrit par-dessus le seq scellé ; le journal dit la NATURE du code, jamais le message.
#[test]
fn aw2_vieillissement_refus_du_moteur_sur_l_index() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("jour_moteur") {
        let root = tmp_root("aw2-jour-moteur");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        let ts = AV5_JOUR * SECS_PER_DAY;
        seal_row(&db, "prod", AV5_JOUR, 0, 6, 0, 6, ts, ts + 105, i64::MIN, i64::MIN, 6, 1);
        db.lock().execute_batch("ALTER TABLE cold_seal RENAME COLUMN expected_rows TO aw2_renommee").unwrap();
        let refus = db.lock().prepare(SQL_SEALS_DU_JOUR).err().map(|e| nature_de_l_echec_sur_l_index(&e));
        assert_eq!(refus.as_deref(), Some(AW2_COLONNE_REFUSEE), "contrôle : le moteur refuse l'énoncé des seals");
        cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 6, "le chaud est intact");
        assert!(!file_path(&cold, "prod", AV5_JOUR, 0).exists(), "aucun fichier écrit par-dessus le seq scellé");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!(av5_jours(&db, "columnarise"), Some(0.0), "rien n'est dit columnarisé");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "jour_moteur");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::aw2_vieillissement_refus_du_moteur_sur_l_index",
    );
    assert_eq!(tours, aw2_ligne_suspendue(AW2_COLONNE_REFUSEE));
}

/// (4b) VIEILLISSEMENT, REFUS DU MOTEUR EN PHASE 2 : un autorisateur refuse la lecture de `cold_seal.expected_rows`
/// dès que la phase 1 pose `last_file=1` (armé par un déclencheur). Le fichier est écrit, la relecture de la phase 2
/// est refusée par le moteur : le chaud est intact, le jour compté `echoue`, jamais « columnarisé », aucun fichier
/// purgé ; le journal dit la nature du code.
#[test]
fn aw2_vieillissement_phase2_refus_du_moteur() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, Ordering};
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("phase2_moteur") {
        let root = tmp_root("aw2-phase2-moteur");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        ensure_cold_seal_table(&db.lock());
        let arme = Arc::new(AtomicBool::new(false));
        {
            let c = db.lock();
            let a = arme.clone();
            c.create_scalar_function("aw2_armer", 0, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |_ctx| -> rusqlite::Result<i64> {
                a.store(true, Ordering::SeqCst);
                Ok(1)
            })
            .unwrap();
            let a = arme.clone();
            c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, column_name }
                    if table_name == "cold_seal" && column_name == "expected_rows" && a.load(Ordering::SeqCst) =>
                {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            c.execute_batch(
                "CREATE TRIGGER aw2_armer AFTER UPDATE OF last_file ON cold_seal WHEN NEW.last_file=1 BEGIN SELECT aw2_armer(); END",
            )
            .unwrap();
        }
        cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
        assert!(arme.load(Ordering::SeqCst), "contrôle : la phase 1 a posé last_file=1");
        assert!(file_path(&cold, "prod", AV5_JOUR, 0).is_file(), "contrôle : la phase 1 a écrit le fichier");
        let refus = db.lock().prepare(SQL_SEALS_DU_JOUR).err().map(|e| nature_de_l_echec_sur_l_index(&e));
        assert_eq!(refus.as_deref(), Some(AW2_LECTURE_REFUSEE), "contrôle : l'autorisateur refuse l'énoncé des seals");
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 6, "la phase 2 n'a rien retiré");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!(av5_jours(&db, "columnarise"), Some(0.0), "jamais « columnarisé »");
        assert_eq!(av5_purges(&db), Some(0.0), "aucun fichier purgé");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "phase2_moteur");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::aw2_vieillissement_phase2_refus_du_moteur",
    );
    assert_eq!(tours, aw2_ligne_suspendue(AW2_LECTURE_REFUSEE));
}

/// (5) MARQUAGE `purged=1` REFUSÉ (déclencheur `RAISE(ABORT)`) sur le PREMIER des deux fichiers : ses lignes sont
/// retirées (le fichier est vérifié), il n'est PAS compté purgé, le jour est compté `echoue` et le journal dit le code ;
/// le second fichier reste chaud. Au tour suivant (déclencheur retiré), le jour encore candidat marque les deux,
/// sans un mot.
#[test]
fn av5_marquage_purge_refuse() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("marquage_refuse") {
        let root = tmp_root("av5-marquage");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        ensure_cold_seal_table(&db.lock());
        db.lock()
            .execute_batch("CREATE TRIGGER av5_refus BEFORE UPDATE OF purged ON cold_seal BEGIN SELECT RAISE(ABORT, 'av5'); END")
            .unwrap();
        let conf = av5_conf(&cold, Some(3));
        cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 3, "le premier fichier est retiré du chaud, le second y reste");
        assert_eq!(av5_retirees(&db), Some(3.0), "les lignes retirées sont comptées");
        assert_eq!(av5_purges(&db), Some(0.0), "le fichier non marqué n'est pas compté purgé");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!((av5_purged(&db, 0), av5_purged(&db, 1)), (0, 0), "aucun seal marqué");

        db.lock().execute_batch("DROP TRIGGER av5_refus").unwrap();
        eprintln!("{AV5_SEPARATEUR}");
        cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
        assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 0, "au tour suivant, le second fichier est retiré");
        assert_eq!(av5_purges(&db), Some(2.0), "les deux fichiers sont marqués et comptés");
        assert_eq!(av5_jours(&db, "echoue"), Some(0.0), "aucun échec au tour suivant");
        assert_eq!((av5_purged(&db, 0), av5_purged(&db, 1)), (1, 1), "les deux seals marqués");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "marquage_refuse");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_marquage_purge_refuse",
    );
    assert_eq!(
        tours,
        vec![
            vec![format!(
                "[cold] aging prod/{} échoué (lignes non retirées conservées hot): fichier scellé seq 0 : lignes chaudes retirées mais marquage purged=1 refusé ({AV5_TRIGGER}) — non compté purgé, seal laissé purged=0 (repris au prochain tour où le jour est candidat, sinon signalé « seal BLOQUÉ » passé la grâce)",
                ymd_from_day(AV5_JOUR)
            )],
            vec![],
        ]
    );
}

/// (6) `UPDATE` QUI NE MARQUE AUCUNE LIGNE (déclencheur `RAISE(IGNORE)`) : même refus, avec le nombre de lignes
/// marquées.
#[test]
fn av5_marquage_purge_sans_ligne() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("marquage_ignore") {
        let root = tmp_root("av5-ignore");
        let cold = root.join("cold");
        let db = mkdb(&root);
        av5_six_lignes(&db);
        ensure_cold_seal_table(&db.lock());
        db.lock()
            .execute_batch("CREATE TRIGGER av5_ignore BEFORE UPDATE OF purged ON cold_seal BEGIN SELECT RAISE(IGNORE); END")
            .unwrap();
        cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
        assert_eq!(av5_purges(&db), Some(0.0), "aucune ligne marquée : non compté purgé");
        assert_eq!(av5_jours(&db, "echoue"), Some(1.0), "le jour est compté en échec");
        assert_eq!(av5_purged(&db, 0), 0, "contrôle : le seal n'est pas marqué");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "marquage_ignore");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_marquage_purge_sans_ligne",
    );
    assert_eq!(
        tours,
        vec![vec![format!(
            "[cold] aging prod/{} échoué (lignes non retirées conservées hot): fichier scellé seq 0 : lignes chaudes retirées mais seal non marqué purgé (0 ligne(s) marquée(s)) — non compté purgé, seal laissé purged=0 (repris au prochain tour où le jour est candidat, sinon signalé « seal BLOQUÉ » passé la grâce)",
            ymd_from_day(AV5_JOUR)
        )]]
    );
}

/// (6b) MARQUAGE REFUSÉ SUR LE SEUL FICHIER DU JOUR : toutes ses lignes chaudes sont retirées, le seal reste
/// `purged=0`. Passé la grâce, le détecteur de seal bloqué le signale, et le texte du signal nomme les DEUX causes
/// possibles (VERIFY en échec, marquage refusé après retrait) — plus seulement VERIFY, cause fausse ici.
#[test]
fn aw2_marquage_refuse_sur_le_dernier_fichier_signal_nomme_la_cause() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("aw2-dernier-fichier");
    let cold = root.join("cold");
    let db = mkdb(&root);
    av5_six_lignes(&db);
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute_batch("CREATE TRIGGER aw2_refus BEFORE UPDATE OF purged ON cold_seal BEGIN SELECT RAISE(ABORT, 'aw2'); END")
        .unwrap();
    cold_age_run(&db, "", &av5_conf(&cold, None), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", AV5_JOUR), 0, "contrôle : toutes les lignes chaudes du jour sont retirées");
    assert_eq!(av5_purged(&db, 0), 0, "contrôle : le seal reste purged=0");
    // `sealed_ts` est l'horloge du scellement, pas le `n` de la passe : la grâce se compte depuis lui.
    let sealed_ts: i64 = db.lock().query_row("SELECT sealed_ts FROM cold_seal WHERE seq=0", [], |r| r.get(0)).unwrap();
    let plus_tard = sealed_ts + COLD_SEAL_STUCK_GRACE_S + 60;
    assert_eq!(detect_cold_seal_stuck(&db, plus_tard - 120), SealBloque::Mesure(0), "contrôle : dans la grâce, rien de bloqué");
    assert_eq!(detect_cold_seal_stuck(&db, plus_tard), SealBloque::Mesure(1), "passé la grâce : un fichier bloqué");
    let message: String = db
        .lock()
        .query_row(
            "SELECT message FROM event WHERE source='plume-config' AND category='health' AND dedup LIKE '%plume-cold-seal-stuck-%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        message,
        "SEAL COLD BLOQUÉ : 1 fichier(s) scellé(s) sur 1 jour(s) restent NON PURGÉS (phase-2 bloquée). Deux causes possibles, \
         nommées par les journaux [cold] aging : VERIFY du fichier en échec à chaque tour (fichier illisible, ses lignes chaudes \
         ne sont jamais purgées), ou marquage purged=1 refusé après le retrait des lignes chaudes (fichier vérifié et lisible ; \
         s'il ne reste aucune ligne chaude au jour, la passe ne le reprend plus). Vérifier les journaux [cold] et l'intégrité disque."
    );
}

fn av5_signaux(db: &Arc<Mutex<Connection>>, cle: &str) -> i64 {
    db.lock()
        .query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND category='health' \
             AND dedup LIKE '%'||char(1)||?1||'-%'",
            params![cle],
            |r| r.get(0),
        )
        .unwrap()
}

fn av5_seal_bloque(db: &Arc<Mutex<Connection>>) {
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES('prod',?1,0,1,?2,0,0,0,0,0,0,0,1)",
            params![M - 50, n_now() - 2 * SECS_PER_DAY],
        )
        .unwrap();
}

/// (7) DÉTECTEUR DE SEAL BLOQUÉ : index non lu (moteur interrompu) -> aucun verdict, dit ; puis lu -> un bloqué, un
/// signal. Signal REFUSÉ (déclencheur sur l'écriture) -> dit, avec le compte ; déclencheur retiré, deux détections
/// dans la même heure -> un signal écrit, la seconde dédupliquée SANS un mot.
#[test]
fn av5_detecteur_de_seal_bloque_dit_ce_qu_il_n_a_pas_lu_ni_ecrit() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("detecteur") {
        let root = tmp_root("av5-detecteur");
        let db = mkdb(&root);
        db.lock().execute("CREATE UNIQUE INDEX idx_event_dedup ON event(dedup) WHERE dedup IS NOT NULL", []).unwrap();
        av5_seal_bloque(&db);
        db.lock().progress_handler(1, Some(|| true));
        assert_eq!(detect_cold_seal_stuck(&db, n_now()), SealBloque::NonMesure, "index non lu : aucun verdict");
        db.lock().progress_handler(1, None::<fn() -> bool>);
        eprintln!("{AV5_SEPARATEUR}");
        db.lock()
            .execute_batch(
                "CREATE TRIGGER av5_refus BEFORE INSERT ON event WHEN NEW.source='plume-config' BEGIN SELECT RAISE(ABORT, 'av5'); END",
            )
            .unwrap();
        assert_eq!(detect_cold_seal_stuck(&db, n_now()), SealBloque::Mesure(1), "lu : un fichier bloqué");
        assert_eq!(av5_signaux(&db, "plume-cold-seal-stuck"), 0, "contrôle : le signal est refusé");
        eprintln!("{AV5_SEPARATEUR}");
        db.lock().execute_batch("DROP TRIGGER av5_refus").unwrap();
        assert_eq!(detect_cold_seal_stuck(&db, n_now()), SealBloque::Mesure(1));
        assert_eq!(detect_cold_seal_stuck(&db, n_now() + 5), SealBloque::Mesure(1));
        assert_eq!(av5_signaux(&db, "plume-cold-seal-stuck"), 1, "un signal écrit, le second dédupliqué");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "detecteur");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_detecteur_de_seal_bloque_dit_ce_qu_il_n_a_pas_lu_ni_ecrit",
    );
    assert_eq!(
        tours,
        vec![
            vec![format!(
                "[cold] détecteur de seal BLOQUÉ inopérant ce tick — index cold_seal non lu ({AV5_INTERROMPU}) ; aucun verdict rendu (ni « bloqué », ni « sain »)"
            )],
            vec![format!(
                "[cold] signal de santé « seal cold BLOQUÉ » NON ÉCRIT ({AV5_TRIGGER}) — 1 fichier(s) bloqué(s) sur 1 jour(s), dits seulement par ce journal ce tick"
            )],
            vec![],
        ]
    );
}

/// (8) SIGNAL DE RETARD REFUSÉ PUIS DÉDUPLIQUÉ : le jour (vingt lignes, sans ligne récente) détient le compteur de
/// rowid, il est différé et le dead-man's-switch tire à chaque passe (rétention froide étendue, cadence désarmée) ;
/// son écriture est refusée -> dite, avec le nombre de lignes. Déclencheur retiré, une passe puis un second tir du
/// détecteur dans la même heure -> un signal écrit, le second dédupliqué SANS un mot (le second tir a bien mesuré).
/// Au tir refusé, le retard (20 lignes) est publié dans la série quand même.
#[test]
fn av5_signal_de_retard_refuse_est_dit() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    if std::env::var(AV5_ENFANT).as_deref() == Ok("retard") {
        let root = tmp_root("av5-retard");
        let cold = root.join("cold");
        let db = mkdb(&root);
        let day = M - 50;
        for i in 0..20 {
            insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
        }
        db.lock()
            .execute_batch(
                "CREATE TRIGGER av5_refus BEFORE INSERT ON event WHEN NEW.source='plume-config' BEGIN SELECT RAISE(ABORT, 'av5'); END",
            )
            .unwrap();
        let mut conf = conf_ext(&cold, 365);
        conf.insert("PLUME_COLD_STALL_CHECK_INTERVAL_S".to_string(), "0".to_string());
        cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
        assert_eq!(count_hot_day(&db, "prod", day), 20, "contrôle : le jour est différé");
        assert_eq!(av5_signaux(&db, "plume-cold-aging-stall"), 0, "contrôle : le signal est refusé");
        assert_eq!(
            serie(&db, crate::vieillissement_serie::NOM_RETARD_LIGNES, None),
            Some(20.0),
            "le retard mesuré part dans la série malgré le signal refusé"
        );
        eprintln!("{AV5_SEPARATEUR}");
        db.lock().execute_batch("DROP TRIGGER av5_refus").unwrap();
        db.lock().execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_event_dedup ON event(dedup) WHERE dedup IS NOT NULL", []).unwrap();
        cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
        assert_eq!(av5_signaux(&db, "plume-cold-aging-stall"), 1, "un signal écrit");
        assert_eq!(count_hot_day(&db, "prod", day), 20, "contrôle : le jour est encore en retard");
        // Le signal écrit détient désormais le compteur de rowid : une passe de plus vieillirait le jour. Le second
        // tir passe donc par le détecteur que la passe appelle, avec la même bande (cadence désarmée).
        let n2 = n_now() + 5;
        assert_eq!(
            detect_aging_stall(&db, &bande_sans_cadence(&db, &cold, 365, n2), n2),
            crate::vieillissement_serie::Retard::Mesure(20),
            "contrôle : le second tir a mesuré le retard"
        );
        assert_eq!(av5_signaux(&db, "plume-cold-aging-stall"), 1, "le second signal est dédupliqué");
        return;
    }
    let tours = av5_lancer(
        {
            let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            enfant.env(AV5_ENFANT, "retard");
            enfant
        },
        "cold_store::tests::seals_illisibles_jamais_absents::av5_signal_de_retard_refuse_est_dit",
    );
    assert_eq!(
        tours,
        vec![
            vec![format!(
                "[cold] signal de santé « aging cold en RETARD » NON ÉCRIT ({AV5_TRIGGER}) — 20 ligne(s) en retard, dites seulement par ce journal et la série ce tick"
            )],
            vec![],
        ]
    );
}
