// =====================================================================================
// `P10.29-w` (vague BB) — LE POINT DE SAUVEGARDE DE L'HORIZON EST LIBÉRÉ AUSSI QUAND LA LECTURE ÉCHOUE.
//
// LE DÉFAUT, RELEVÉ PAR LE VÉRIFICATEUR DE LA VAGUE BA (898cc1d6) ET RE-MESURÉ ICI : `HorizonDeLecture::lire`
// (`cold_store/reader.rs`) ouvre `SAVEPOINT horizon_de_lecture`, lit, puis libère dans tous les cas ; mais aucun témoin
// ne tenait la libération sur le chemin d'ERREUR. Un mutant qui rend l'erreur avant le `RELEASE` restait vert sur les
// témoins ciblés du tier froid alors qu'il laisse la connexion EN TRANSACTION : c'est le cas de la connexion du pool que lit la
// couverture (`panneau_avoue::horizon_de_la_voie_froide_lue` -> `ColdUnionMeta::premier_instant_servi`).
//
// LES TÉMOINS appellent le point d'entrée de la couverture, `ColdUnionMeta::premier_instant_servi`, et relisent l'état
// de la connexion après l'appel (`is_autocommit`, et l'existence du point de sauvegarde quand l'appelant tient déjà une
// transaction), pour chaque CLASSE d'échec de la lecture : réglage `retention_days` écrit et illisible (cause fixe
// `HORIZON_FROID_NON_LU`) et base occupée (la sonde échoue sous BUSY). Contrôle : la lecture qui réussit libère aussi.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)` dans `reader.rs`, retirés avant le commit), chacun vu ROUGE :
//  BB2_PAS_DE_RELEASE_SUR_ERREUR (l'erreur de la lecture est rendue avant le `RELEASE`) : (1), (2), (3) ;
//  BB2_PAS_DE_RELEASE_SUR_SUCCES (le succès est rendu avant le `RELEASE`) : (4).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'échec du `RELEASE` lui-même reste HORS D'ATTEINTE (dit au site) ; l'occupation
// est fabriquée par une connexion du même processus en journal de rollback.
// =====================================================================================
use super::*;

const BB2_RETENTION_ILLISIBLE: &str = "dix";
const BB2_FRONTIERE: i64 = 20_000 * SECS_PER_DAY;

/// Base de test (schéma miroir de `mkdb`, journal de rollback) avec `retention_days` écrit à `valeur`.
fn bb2_base(tag: &str, valeur: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>) {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    db.lock().execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days',?1)", params![valeur]).unwrap();
    (root, db)
}

/// (1) RÉGLAGE ILLISIBLE, CONNEXION EN AUTOCOMMIT : la lecture échoue sous la cause fixe, et la connexion n'est plus en
/// transaction après l'appel (le point de sauvegarde ouvert par `lire` a été libéré).
#[test]
fn bb2_horizon_illisible_libere_le_point_de_sauvegarde() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db) = bb2_base("bb2-illisible", BB2_RETENTION_ILLISIBLE);
    let c = db.lock();
    assert!(c.is_autocommit(), "contrôle : aucune transaction avant l'appel");
    let lu = ColdUnionMeta::premier_instant_servi(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    assert_eq!(lu, Err(HORIZON_FROID_NON_LU.to_string()), "réglage illisible : cause fixe");
    assert!(c.is_autocommit(), "le point de sauvegarde est libéré sur l'erreur : la connexion n'est plus en transaction");
}

/// (2) RÉGLAGE ILLISIBLE SOUS UNE TRANSACTION DE L'APPELANT : `lire` imbrique son point de sauvegarde ; sur l'erreur, il
/// le libère (un second `RELEASE` du même nom échoue : il n'existe plus) et laisse la transaction de l'appelant ouverte.
#[test]
fn bb2_horizon_illisible_libere_le_point_imbrique() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db) = bb2_base("bb2-imbrique", BB2_RETENTION_ILLISIBLE);
    let c = db.lock();
    c.execute_batch("BEGIN").unwrap();
    let lu = ColdUnionMeta::premier_instant_servi(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    assert_eq!(lu, Err(HORIZON_FROID_NON_LU.to_string()), "réglage illisible : cause fixe");
    assert!(!c.is_autocommit(), "la transaction de l'appelant reste ouverte");
    assert!(
        c.execute_batch("RELEASE horizon_de_lecture").is_err(),
        "le point de sauvegarde imbriqué est libéré sur l'erreur : il n'existe plus"
    );
    c.execute_batch("ROLLBACK").unwrap();
}

/// (3) BASE OCCUPÉE : une seconde connexion tient le verrou EXCLUSIF (journal de rollback), le lecteur attend zéro ; la
/// sonde échoue sous BUSY, et la connexion n'est plus en transaction après l'appel. Verrou rendu, la même connexion lit
/// (contrôle : rien n'est resté pris).
#[test]
fn bb2_horizon_sous_base_occupee_libere_le_point_de_sauvegarde() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (root, db) = bb2_base("bb2-occupee", "30");
    let c = db.lock();
    c.busy_timeout(std::time::Duration::ZERO).unwrap();
    let ecrivain = Connection::open(dbp(&root)).unwrap();
    ecrivain.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let lu = ColdUnionMeta::premier_instant_servi(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    match &lu {
        Err(e) => assert!(e.contains("database is locked") && e != HORIZON_FROID_NON_LU, "échec de la sonde, pas du réglage : {e}"),
        Ok(v) => panic!("contrôle : la base est prise, la lecture ne peut pas réussir ({v})"),
    }
    assert!(c.is_autocommit(), "le point de sauvegarde est libéré sur la base occupée : la connexion n'est plus en transaction");
    ecrivain.execute_batch("ROLLBACK").unwrap();
    assert!(ColdUnionMeta::premier_instant_servi(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None).is_ok(), "verrou rendu : la lecture sert");
}

/// (4) CONTRÔLE : la lecture qui RÉUSSIT libère aussi le point de sauvegarde.
#[test]
fn bb2_horizon_lu_libere_le_point_de_sauvegarde() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db) = bb2_base("bb2-lu", "30");
    let c = db.lock();
    assert!(ColdUnionMeta::premier_instant_servi(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None).is_ok(), "réglage lisible : la lecture sert");
    assert!(c.is_autocommit(), "le point de sauvegarde est libéré sur le succès");
}

// ---- La couverture (`panneau_avoue::plancher_de_l_horizon_froid`) range l'échec de l'horizon par sa classe. ----
// DÉFAUT RE-MESURÉ (vérificateur du lot) : `panneau_avoue.rs` rangeait tout échec de `premier_instant_servi` sous
// « retention_days » (`map_err(|_| "retention_days")`), et la notice disait un réglage de rétention écrit non lu sur une
// base seulement occupée. MUTANTS (VERIF_MUT sous `cfg!(test)` dans `panneau_avoue.rs`, retirés avant le commit) :
//  BB2C_TOUT_SOUS_RETENTION (la forme d'avant : tout échec rendu « retention_days ») : (5), (7) ;
//  BB2C_NON_PRIS_SOUS_RETENTION (l'échec hors occupation rendu « retention_days ») : (7).
// Ces témoins jugent la classe au point où elle se décide ; la couverture ENTIÈRE rendue par l'appelant réel
// (`panneau_avoue::horizon_de_la_voie_froide_lue`, base prise par le crochet `AvantLaPriseDeLHorizon`) est jugée par
// `tests/couverture_froide_sous_base_prise_bc2.rs`.

/// (5) BASE OCCUPÉE : la couverture dit l'occupation, pas un réglage non lu.
#[test]
fn bb2c_couverture_base_occupee_n_est_pas_un_reglage_non_lu() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (root, db) = bb2_base("bb2c-occupee", "30");
    let c = db.lock();
    c.busy_timeout(std::time::Duration::ZERO).unwrap();
    let ecrivain = Connection::open(dbp(&root)).unwrap();
    ecrivain.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let plancher = crate::panneau_avoue::plancher_de_l_horizon_froid(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    assert_eq!(plancher, Err(Err(crate::panneau_avoue::NOTICE_HORIZON_FROID_BASE_OCCUPEE)), "base occupée : dite occupée");
    ecrivain.execute_batch("ROLLBACK").unwrap();
    assert!(crate::panneau_avoue::plancher_de_l_horizon_froid(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None).is_ok(), "contrôle : verrou rendu, plancher lu");
}

/// (6) RÉGLAGE ILLISIBLE : la couverture nomme toujours « retention_days ».
#[test]
fn bb2c_couverture_reglage_illisible_reste_retention_days() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db) = bb2_base("bb2c-illisible", BB2_RETENTION_ILLISIBLE);
    let c = db.lock();
    let plancher = crate::panneau_avoue::plancher_de_l_horizon_froid(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    assert_eq!(plancher, Err(Ok("retention_days")), "réglage écrit illisible : nommé");
}

/// (7) LECTURE NON PRISE HORS OCCUPATION : un fichier qui n'est pas une base fait échouer la sonde (NOTADB) ; ni occupé,
/// ni réglage non lu.
#[test]
fn bb2c_couverture_lecture_non_prise_n_est_pas_un_reglage_non_lu() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let root = tmp_root("bb2c-pas-une-base");
    let chemin = root.join("pas-une-base.db");
    std::fs::write(&chemin, vec![0x5Au8; 8192]).unwrap();
    let c = Connection::open(&chemin).unwrap();
    let plancher = crate::panneau_avoue::plancher_de_l_horizon_froid(&c, &conf_union(HOT_WIN), BB2_FRONTIERE, None);
    assert_eq!(plancher, Err(Err(crate::panneau_avoue::NOTICE_HORIZON_FROID_NON_PRIS)), "lecture non prise : dite non prise");
}
