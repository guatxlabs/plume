// `P10.34-k` — LA COUVERTURE DÉCLARÉE DE LA BARRE DE RECHERCHE EST BORNÉE PAR LA RÉTENTION ; LE REFUS DE PURGE DU
// TIER FROID NE L'EST PAS, ET LE DIT.
//
// Le défaut (VU sur ac4ca5cd) : `search_cold_coverage` (`handlers/search.rs`) décidait « historique plus ancien NON
// cherché » sur `SELECT EXISTS(SELECT 1 FROM cold_seal WHERE day < ?1)`, sans borne de rétention. L'expiration
// (`expire_cold_days`) garde la ligne d'un fichier qu'elle n'a pas pu retirer : la note sortait alors que seuls des
// jours expirés restaient, jours qu'aucune voie ne sert (le lecteur froid les écarte). Et la lecture ratée de l'index
// servait le message du moteur dans la note. Côté purge, `cold_overlap` (`purge.rs`) n'est pas borné, à juste titre
// (le fichier est encore sur le disque), mais ni la phrase du refus ni la doc ne le disaient.
//
// LES TÉMOINS passent par le point d'entrée que le gestionnaire appelle (`search_cold_coverage`, instant injecté) et,
// pour la purge, par la simulation (`purge_plan`) puis la fabrique de la réponse servie (`purge_refusal_response`).
// Les notes et les phrases sont comparées à des CONSTANTES du test, corps ENTIER.
//  (1) jour expiré dont la ligne est gardée par un vrai refus d'unlink (vieillissement réel) : aucune note ; un jour
//      dans la rétention ajouté : la note « chaud seulement » ;
//  (2) bords : dernier jour expiré (aucune note), son lendemain (note) ;
//  (3) deux index, dont un sous une politique plus courte ;
//  (4) rétention illisible (« 365.0 », BLOB) : note maintenue et dite non bornée ; sans jour sous la frontière, rien ;
//  (5) index non lu (interruption) : `cold_coverage_unread`, la nature du code, jamais le message ;
//  (6) table absente : rien ;
//  (7) ligne d'index illisible seule : `cold_coverage_unread` ; avec un jour retenu : la note « chaud seulement » ;
//  (8) frontière : un jour à la frontière n'est pas de l'histoire froide, la veille l'est ;
//  (9) l'instant injecté décide (le même jour, quinze jours plus tard, est expiré) ;
//  (10) câblage du gestionnaire, lu sur le texte : même instant pour la frontière et la borne ;
//  (11) purge : un sceau d'un jour expiré refuse encore, et la phrase servie dit que le compte n'est pas borné ;
//  (12) rétention froide étendue (`PLUME_COLD_RETENTION_DAYS` > `retention_days`) : M-40 note, M-70 rien ;
//  (13) ligne illisible à côté d'un jour expiré : `cold_coverage_unread` ;
//  (14) deux lignes illisibles : le nombre exact dans la note.
//
// MUTANTS JOUÉS (variable de mutation, retirés du source avant le commit), chacun vu ROUGE :
//  AU2_SANS_BORNE (aucun jour écarté), AU2_BORD_MOINS (`>` devient `>=`), AU2_BORD_PLUS (lendemain écarté),
//  AU2_POLITIQUE_IGNOREE (rétention globale pour tout index), AU2_RETENTION_ZERO (rétention illisible traitée en
//  « 0 jour »), AU2_RETENTION_TUE (rétention illisible rendue comme lue), AU2_NOTE_RETENTION_TUE (la note ne le dit
//  pas), AU2_INDEX_AVALE (index non lu rendu « aucune »), AU2_ABSENTE_AVOUEE (table absente rendue non lue), AU2_ILLISIBLES_TUES, AU2_FRONTIERE_IGNOREE, AU2_FRONTIERE_INCLUSE
//  (`<` devient `<=`), AU2_HORLOGE (l'heure courante au lieu de l'instant injecté), AU2_PHRASE_ANCIENNE (phrase du
//  refus d'avant), AU2_PURGE_BORNEE (le refus de purge borné par la rétention), AU2_SANS_FROIDE_ETENDUE (conf passée à `Bande::calculer`
//  sans `PLUME_COLD_RETENTION_DAYS`), AU2_EXPIRE_AVALE (un jour sous la frontière mais expiré rend « aucune » avant les
//  lignes illisibles), AU2_ILLISIBLES_UN (le nombre de lignes illisibles rendu 1).
// Le câblage (10) est éprouvé dans le test lui-même (texte d'avant rejoué, le juge rougit).
// CE QUE CES TÉMOINS NE TIENNENT PAS : la route HTTP entière (`GET /api/search`) — les fabriques d'état de
// l'application vivent dans `crate::tests`, privées ; le gestionnaire est tenu par (10) ; les politiques par index
// illisibles (`load_index_policies`, même repli que le vieillissement et le plan d'escrow).

use super::*;

const AU2_NOTE_CHAUD_SEUL: &str = "recherche INCOMPLÈTE : la barre plein-texte n'interroge que l'index FTS5, qui n'existe que sur la fenêtre chaude — l'historique columnarisé plus ancien n'a PAS été cherché (ce n'est donc pas « aucun résultat »). Voie EXACTE sur tout l'historique : /api/query en GXQL, qui lit le tier froid (p. ex. `search message=~<motif>` ou `search <champ>=<valeur>`).";
const AU2_NOTE_RETENTION_NON_LUE: &str = "recherche INCOMPLÈTE : la barre plein-texte n'interroge que l'index FTS5, qui n'existe que sur la fenêtre chaude — l'historique columnarisé plus ancien n'a PAS été cherché (ce n'est donc pas « aucun résultat »). Voie EXACTE sur tout l'historique : /api/query en GXQL, qui lit le tier froid (p. ex. `search message=~<motif>` ou `search <champ>=<valeur>`). Le réglage de rétention (`retention_days`) n'a pas pu être lu : cette note n'est pas bornée par la rétention, et des jours au-delà de celle-ci, dont la ligne `cold_seal` est restée, peuvent suffire à la faire sortir — aucune borne n'est fabriquée.";
const AU2_NOTE_INDEX_INTERROMPU: &str = "couverture froide NON ÉTABLIE : l'index des jours scellés (`cold_seal`) ne se lit pas (code SQLite 9 (OperationInterrupted)) — la barre plein-texte n'a cherché que la fenêtre chaude et ne peut pas dire si un historique columnarisé plus ancien existe ; `/api/query` en GXQL lit le froid";
const AU2_NOTE_UNE_LIGNE_ILLISIBLE: &str = "couverture froide NON ÉTABLIE : l'index des jours scellés (`cold_seal`) ne se lit pas (1 ligne(s) illisible(s)) — la barre plein-texte n'a cherché que la fenêtre chaude et ne peut pas dire si un historique columnarisé plus ancien existe ; `/api/query` en GXQL lit le froid";
const AU2_PHRASE_COLD_TIER: &str = "REFUS — TIER FROID : 1 fichier(s) Parquet scellé(s) sur 1 jour(s) recouvrent cette fenêtre. Ces copies columnarisées resteraient INTERROGEABLES après le vidage de `event` : « purgé » serait faux. La purge ne sait pas réécrire un Parquet scellé — elle refuse au lieu de mentir. Contournement : attendre l'expiration cold (cold_retention_days) ou restreindre la fenêtre aux jours encore chauds. Ce compte n'est PAS borné par la rétention : un fichier d'un jour déjà expiré dont le retrait a été refusé reste sur le disque, il est compté et il refuse tant qu'il n'est pas retiré.";

fn au2_seal(db: &Arc<Mutex<Connection>>, env: &str, day: i64) {
    let ts = day * SECS_PER_DAY;
    seal_row(db, env, day, 0, 1, 1, 1, ts, ts, i64::MIN, i64::MIN, 1, 1);
}

/// La frontière à l'instant `M` : fenêtre chaude de deux jours, `(M-2)*SECS_PER_DAY`.
fn au2_frontiere() -> i64 {
    (M - HOT_WIN) * SECS_PER_DAY
}

fn au2_couverture(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>, n: i64) -> Option<Value> {
    crate::handlers::search::search_cold_coverage(&db.lock(), conf, au2_frontiere(), 0, n)
}

fn au2_note(notice: &str) -> Value {
    json!({ "searched_from": au2_frontiere(), "cold_boundary_ts": au2_frontiere(), "reason": "fts_hot_only", "notice": notice })
}

fn au2_non_etablie(notice: &str) -> Value {
    json!({ "searched_from": au2_frontiere(), "cold_boundary_ts": au2_frontiere(), "reason": "cold_coverage_unread", "notice": notice })
}

fn au2_base(tag: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, HashMap<String, String>) {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let conf = conf_on(&root.join("cold"), HOT_WIN);
    (root, db, conf)
}

/// (1) UN JOUR EXPIRÉ DONT LA LIGNE EST GARDÉE NE FAIT PAS SORTIR LA NOTE. État laissé par le VIEILLISSEMENT RÉEL :
/// l'entrée du fichier scellé est un répertoire, `unlink` est refusé, la ligne `cold_seal` reste. Rétention 30 j,
/// instant `M`. Puis un jour dans la rétention : la note sort, corps entier.
#[test]
fn au2_jour_expire_garde_par_le_vieillissement_ne_fait_pas_sortir_la_note() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (root, db, conf) = au2_base("au2-garde");
    let cold = root.join("cold");
    let expire = M - 40;
    let entree = file_path(&cold, "prod", expire, 0);
    std::fs::create_dir_all(&entree).unwrap(); // unlink -> EISDIR, même en root
    au2_seal(&db, "prod", expire);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    let gardees: i64 = db.lock().query_row("SELECT count(*) FROM cold_seal WHERE day=?1", params![expire], |r| r.get(0)).unwrap();
    assert_eq!(gardees, 1, "contrôle : le vieillissement a gardé la ligne du fichier non retiré");
    assert_eq!(au2_couverture(&db, &conf, n_now()), None, "seul un jour expiré reste : aucune histoire froide à déclarer");
    au2_seal(&db, "prod", M - 20);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "un jour dans la rétention : la note");
}

/// (2) LES BORDS : à rétention 30 et instant `M`, le dernier jour expiré est `M-31` (aucune note, même avec un jour
/// plus ancien), son lendemain `M-30` fait sortir la note.
#[test]
fn au2_bords_du_dernier_jour_expire() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-bord-expire");
    au2_seal(&db, "prod", M - 40);
    au2_seal(&db, "prod", M - 31);
    assert_eq!(au2_couverture(&db, &conf, n_now()), None, "M-31 est le dernier jour expiré");
    let (_root2, db2, conf2) = au2_base("au2-bord-servi");
    au2_seal(&db2, "prod", M - 30);
    assert_eq!(au2_couverture(&db2, &conf2, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "M-30 est dans la rétention");
}

/// (3) DEUX INDEX, UNE POLITIQUE PLUS COURTE : `stage` sous 10 j (dernier jour expiré `M-11`), `prod` sous la globale
/// (30 j). `prod` à `M-40` et `stage` à `M-11` : tous deux expirés, aucune note. `stage` à `M-10`, ou `prod` à `M-20`
/// (expiré pour `stage`, pas pour `prod`) : la note.
#[test]
fn au2_deux_index_dont_un_sous_politique_plus_courte() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_r1, db, conf) = au2_base("au2-politique-expire");
    mk_index_policy(&db, "stage", 10);
    au2_seal(&db, "prod", M - 40);
    au2_seal(&db, "stage", M - 11);
    assert_eq!(au2_couverture(&db, &conf, n_now()), None, "chaque jour au-delà de la rétention de SON index");
    let (_r2, db2, conf2) = au2_base("au2-politique-stage");
    mk_index_policy(&db2, "stage", 10);
    au2_seal(&db2, "stage", M - 10);
    assert_eq!(au2_couverture(&db2, &conf2, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "stage M-10 : dans ses 10 j");
    let (_r3, db3, conf3) = au2_base("au2-politique-prod");
    mk_index_policy(&db3, "stage", 10);
    au2_seal(&db3, "prod", M - 20);
    assert_eq!(au2_couverture(&db3, &conf3, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "prod M-20 : sous la globale");
}

/// (4) RÉTENTION ILLISIBLE (« 365.0 », puis BLOB), seul jour `M-40` (expiré sous le défaut de 30 j) : la note sort
/// (côté prudent) ET dit qu'elle n'est pas bornée. Sans jour sous la frontière (`M-1`), rien : la rétention n'est
/// alors pas en jeu.
#[test]
fn au2_retention_illisible_note_maintenue_et_dite() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    for valeur in ["'365.0'", "X'00'"] {
        let (_root, db, conf) = au2_base("au2-retention");
        db.lock()
            .execute_batch(&format!("INSERT INTO setting(scope,key,value) VALUES('global','retention_days',{valeur})"))
            .unwrap();
        au2_seal(&db, "prod", M - 40);
        assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_RETENTION_NON_LUE)), "{valeur}");
        let (_root2, db2, conf2) = au2_base("au2-retention-chaud");
        db2.lock()
            .execute_batch(&format!("INSERT INTO setting(scope,key,value) VALUES('global','retention_days',{valeur})"))
            .unwrap();
        au2_seal(&db2, "prod", M - 1);
        assert_eq!(au2_couverture(&db2, &conf2, n_now()), None, "{valeur} : aucun jour sous la frontière");
    }
}

/// (5) INDEX NON LU (le moteur interrompt chaque énoncé) : `cold_coverage_unread`, la nature du code SQLite, corps
/// entier. La sonde de schéma est interrompue elle aussi : une table dont on ne sait pas si elle existe n'est pas
/// absente. Contrôle : sans interruption, la note « chaud seulement ».
#[test]
fn au2_index_non_lu_declare_par_sa_nature() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-index");
    au2_seal(&db, "prod", M - 20);
    let c = db.lock();
    c.progress_handler(1, Some(|| true));
    let cov = crate::handlers::search::search_cold_coverage(&c, &conf, au2_frontiere(), 0, n_now());
    c.progress_handler(1, None::<fn() -> bool>);
    assert_eq!(cov, Some(au2_non_etablie(AU2_NOTE_INDEX_INTERROMPU)));
    let lu = crate::handlers::search::search_cold_coverage(&c, &conf, au2_frontiere(), 0, n_now());
    assert_eq!(lu, Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "contrôle : lecture faite");
}

/// (6) TABLE ABSENTE (tier froid jamais allumé sur cette base) : rien à déclarer.
#[test]
fn au2_table_absente_rien_a_declarer() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-absente");
    let presente: i64 = db.lock().query_row("SELECT count(*) FROM sqlite_master WHERE name='cold_seal'", [], |r| r.get(0)).unwrap();
    assert_eq!(presente, 0, "contrôle : la table n'existe pas");
    assert_eq!(au2_couverture(&db, &conf, n_now()), None);
}

/// (7) UNE LIGNE D'INDEX ILLISIBLE (`env_id` en BLOB), seule : son jour n'est pas établi, la couverture non plus.
/// Avec un jour retenu à côté : la note « chaud seulement » (l'histoire froide est établie par ce jour).
#[test]
fn au2_ligne_illisible_seule_couverture_non_etablie() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-illisible");
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES(X'00',?1,1,1,0,1,1,0,0,0,0,1,1)",
            params![M - 20],
        )
        .unwrap();
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_non_etablie(AU2_NOTE_UNE_LIGNE_ILLISIBLE)));
    au2_seal(&db, "prod", M - 20);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "un jour retenu à côté");
}

/// (8) LA FRONTIÈRE : un jour scellé au jour de la frontière (`M-2`) n'est pas sous elle (aucune note) ; la veille
/// (`M-3`) l'est.
#[test]
fn au2_frontiere_exclusive() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-frontiere");
    au2_seal(&db, "prod", M - 2);
    assert_eq!(au2_couverture(&db, &conf, n_now()), None, "le jour de la frontière est chaud");
    au2_seal(&db, "prod", M - 3);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "la veille est froide");
}

/// (9) L'INSTANT INJECTÉ DÉCIDE : `M-20` est dans la rétention à `M`, expiré à `M+15` (dernier jour expiré `M-16`).
#[test]
fn au2_l_instant_injecte_decide() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-instant");
    au2_seal(&db, "prod", M - 20);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)));
    assert_eq!(au2_couverture(&db, &conf, n_now() + 15 * SECS_PER_DAY), None, "quinze jours plus tard, M-20 est expiré");
}

/// Le gestionnaire passe-t-il à la couverture l'instant de SA frontière ? Une fois chacun, rien d'autre.
fn au2_cablage_tenu(src: &str) -> bool {
    src.matches("let instant_de_la_frontiere = now();").count() == 1
        && src.matches("crate::cold_store::cold_query_boundary(&c, &conf, instant_de_la_frontiere, rd)").count() == 1
        && src.matches("search_cold_coverage(conn, &load_config(), b, q_from, instant_de_la_frontiere)").count() == 1
        && src.matches("search_cold_coverage(").count() == 2
}

/// (10) CÂBLAGE DU GESTIONNAIRE, lu sur le texte : la frontière et la borne de rétention prennent le même instant. Le
/// juge est éprouvé sur le texte d'avant (heure courante relue au site de la couverture) : il rougit.
#[test]
fn au2_cablage_du_gestionnaire() {
    let src = include_str!("../../handlers/search.rs");
    assert!(au2_cablage_tenu(src), "le gestionnaire passe l'instant de sa frontière à la couverture");
    let avant = src.replace("q_from, instant_de_la_frontiere)", "q_from, now())");
    assert!(!au2_cablage_tenu(&avant), "épreuve : l'heure relue au site de la couverture est refusée");
    let frontiere_a_part = src.replace("(&c, &conf, instant_de_la_frontiere, rd)", "(&c, &conf, now(), rd)");
    assert!(!au2_cablage_tenu(&frontiere_a_part), "épreuve : une frontière à un autre instant est refusée");
}

/// (11) PURGE : un sceau d'un jour EXPIRÉ (jour 0) qui recouvre la fenêtre refuse encore la simulation — le fichier
/// est sur le disque tant que la ligne est là — et la réponse servie (409) dit que ce compte n'est pas borné par la
/// rétention. Corps entier.
#[tokio::test]
async fn au2_purge_un_sceau_expire_refuse_et_le_refus_le_dit() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(include_str!("../../../../db/schema.sql")).unwrap();
    assert!(crate::migrate(&c), "fixture : migrations complètes");
    for i in 0..6 {
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
             VALUES(?1,'flux','test',1,'preuve','h1','prod','','')",
            params![1_000 + i],
        )
        .unwrap();
    }
    ensure_cold_seal_table(&c);
    c.execute(
        "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
         VALUES('prod',0,0,6,0,1,99,1000,1005,1000,1,99,1)",
        [],
    )
    .unwrap();
    let scope = crate::purge_scope_from_args(&[("env".to_string(), "prod".to_string())], "0", "2000", crate::now()).expect("périmètre valide");
    let refus = match crate::purge_plan(&c, scope) {
        Err(e) => e,
        Ok(_) => panic!("un sceau d'un jour expiré recouvre la fenêtre : la simulation doit refuser"),
    };
    assert!(matches!(refus, crate::PurgeRefusal::ColdTier { files: 1, days: 1 }), "{refus}");
    let r = crate::purge_refusal_response(refus);
    assert_eq!(r.status().as_u16(), 409);
    let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    let corps: Value = serde_json::from_slice(&octets).expect("corps JSON");
    assert_eq!(corps, json!({ "ok": false, "refusal": "cold_tier", "message": AU2_PHRASE_COLD_TIER }));
}

const AU2_NOTE_DEUX_LIGNES_ILLISIBLES: &str = "couverture froide NON ÉTABLIE : l'index des jours scellés (`cold_seal`) ne se lit pas (2 ligne(s) illisible(s)) — la barre plein-texte n'a cherché que la fenêtre chaude et ne peut pas dire si un historique columnarisé plus ancien existe ; `/api/query` en GXQL lit le froid";

/// Une ligne d'index dont `env_id` est un BLOB (colonne qui ne se décode pas), au jour `day`, séquence `seq`.
fn au2_ligne_illisible(db: &Arc<Mutex<Connection>>, day: i64, seq: i64) {
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES(X'00',?1,?2,1,0,1,1,0,0,0,0,1,1)",
            params![day, seq],
        )
        .unwrap();
}

/// (12) RÉTENTION FROIDE ÉTENDUE (`PLUME_COLD_RETENTION_DAYS` = 60 > `retention_days` = 30) : la borne est celle du
/// vieillissement, rétention froide comprise. `M-40` (expiré sous 30 j, gardé sous 60) fait sortir la note ; `M-70`
/// (au-delà des 60) seul, rien. Contrôle : sans l'extension, `M-40` seul ne fait rien sortir.
#[test]
fn au2_retention_froide_etendue_borne_la_note() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_r0, db0, conf0) = au2_base("au2-froide-controle");
    au2_seal(&db0, "prod", M - 40);
    assert_eq!(au2_couverture(&db0, &conf0, n_now()), None, "contrôle : sans extension, M-40 est expiré");
    let (_r1, db, mut conf) = au2_base("au2-froide-etendue");
    conf.insert("PLUME_COLD_RETENTION_DAYS".to_string(), "60".to_string());
    au2_seal(&db, "prod", M - 40);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_note(AU2_NOTE_CHAUD_SEUL)), "M-40 sous la rétention froide de 60 j");
    let (_r2, db2, mut conf2) = au2_base("au2-froide-au-dela");
    conf2.insert("PLUME_COLD_RETENTION_DAYS".to_string(), "60".to_string());
    au2_seal(&db2, "prod", M - 70);
    assert_eq!(au2_couverture(&db2, &conf2, n_now()), None, "M-70 au-delà des 60 j : expiré");
}

/// (13) UNE LIGNE ILLISIBLE À CÔTÉ D'UN JOUR EXPIRÉ : le jour expiré (`M-40`, sous la frontière) n'établit aucune
/// histoire froide, la ligne illisible laisse donc la couverture non établie — un jour expiré ne l'avale pas.
#[test]
fn au2_ligne_illisible_a_cote_d_un_jour_expire_non_etablie() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-illisible-expire");
    au2_seal(&db, "prod", M - 40);
    assert_eq!(au2_couverture(&db, &conf, n_now()), None, "contrôle : le jour expiré seul ne déclare rien");
    au2_ligne_illisible(&db, M - 20, 1);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_non_etablie(AU2_NOTE_UNE_LIGNE_ILLISIBLE)));
}

/// (14) DEUX LIGNES ILLISIBLES : la note en dit le nombre exact.
#[test]
fn au2_deux_lignes_illisibles_comptees() {
    let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
    let (_root, db, conf) = au2_base("au2-deux-illisibles");
    au2_ligne_illisible(&db, M - 20, 1);
    au2_ligne_illisible(&db, M - 21, 2);
    assert_eq!(au2_couverture(&db, &conf, n_now()), Some(au2_non_etablie(AU2_NOTE_DEUX_LIGNES_ILLISIBLES)));
}
