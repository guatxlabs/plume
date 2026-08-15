//! Tests P1 du tier froid Parquet (#18) — writer round-trip, VERIFY, et AGING crash-safe/idempotent.
//! Tous derrière `#[cfg(feature = "cold_tier")]` (le module parent l'est) — jamais compilés en mode 0.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

// ---- helpers ---------------------------------------------------------------------------------------

/// L'ORACLE HISTORIQUE — `cold_union_query` rendu sous sa forme d'AVANT `exactness` : `(Value, total,
/// meta)`, la valeur DÉSÉQUESTRÉE, tronquée ou non.
///
/// Il n'est PAS un raccourci de confort. Deux usages, tous deux légitimes :
///   1. Les tests P3/P3.5/P4 portent sur le SQL RÉELLEMENT EXÉCUTÉ (union, masquage #45, authorizer,
///      élagage seal) — pas sur la correction des agrégats. Ils veulent la valeur, pas le verdict.
///   2. Le harnais de PARITÉ a besoin de la valeur FAUSSE pour PROUVER qu'elle est fausse : sans
///      accès à ce que le chemin d'union calcule, on ne peut pas mesurer le ×203 qu'on prétend fermer.
/// La production, elle, n'a AUCUN chemin vers cette valeur : `render` est sa seule sortie.
#[allow(clippy::too_many_arguments)]
fn union_query_oracle(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    page_sql: &str,
    count_sql: Option<&str>,
    budget_ms: u64,
    qid: Option<&str>,
    dim_preds: &[DimEq],
) -> Result<(Value, Option<i64>, ColdUnionMeta), String> {
    let (answer, meta) =
        cold_union_query(db_path, conf, env_filter, q_from, q_to, boundary, page_sql, count_sql, budget_ms, qid, dim_preds)?;
    let (v, total) = answer.into_value_even_if_wrong();
    Ok((v, total, meta))
}

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// Répertoire temporaire unique — chaque test s'isole. Il se POSSÈDE : sa destruction efface le
/// répertoire ENTIER, donc aussi les `-wal`/`-shm` que SQLite crée à côté sans que personne ne les
/// nomme (c'est là qu'était 90 % de la fuite mesurée). Rendre un `TmpPossede` au lieu d'un
/// `PathBuf` ne change RIEN aux appelants : il se déréférence en `&Path`.
fn tmp_root(tag: &str) -> crate::tmp_possede::TmpPossede {
    crate::tmp_possede::TmpPossede::neuf(&format!(
        "cold-{tag}-{}",
        UNIQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Table `event` MIROIR du schéma live (colonnes lues/supprimées par cold_store). In-file SQLite (pas
/// SQLCipher : les tests exercent la LOGIQUE d'aging, pas la crypto ; le SQL est identique).
fn mkdb(root: &Path) -> Arc<Mutex<Connection>> {
    let conn = rusqlite::Connection::open(root.join("plume.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE event(\
           id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, category TEXT, \
           severity INTEGER NOT NULL DEFAULT 0, host TEXT, message TEXT, fields TEXT, dedup TEXT, \
           env_id TEXT NOT NULL DEFAULT 'prod', origin TEXT NOT NULL DEFAULT '', \
           engagement_id TEXT NOT NULL DEFAULT '', src_ip TEXT, dst_ip TEXT, url TEXT, xff TEXT)",
    )
    .unwrap();
    // `P10.5-a` — la table où le vieillissement REND COMPTE de ce qu'il a fait (`vieillissement_serie`).
    // Colonnes MIROIR du schéma live (`db/schema.sql`) : c'est le même `INSERT` (le DTO d'ingestion) qui
    // écrit ici et en production. Sans elle, la publication échouerait silencieusement et les tests de
    // série ci-dessous ne prouveraient rien.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metric(ts INTEGER NOT NULL, name TEXT NOT NULL, labels TEXT, \
           value REAL NOT NULL, host TEXT, env_id TEXT NOT NULL DEFAULT 'prod')",
    )
    .unwrap();
    // `P10.13-a` levier ① — la table où le dead-man's-switch de retard mémorise SON DERNIER TIR (clé
    // `cold_aging_stall_last_ts`). Schéma MIROIR du live (`key TEXT PRIMARY KEY, value TEXT`, cf. la
    // chaîne de migrations). Sans elle, la lecture rendrait `None` à chaque passe et la CADENCE ne
    // serait jamais exercée : les tests passeraient tous, en ne prouvant rien de ce qui a changé.
    conn.execute_batch("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)").unwrap();
    Arc::new(Mutex::new(conn))
}

/// La valeur d'UN point de la série du vieillissement, relue depuis `metric` (le dernier écrit gagne :
/// les tests qui relancent une passe veulent la DERNIÈRE). `None` = série ABSENTE — ce qui est une
/// réponse à part entière ici (un trou n'est pas un zéro).
fn serie(db: &Arc<Mutex<Connection>>, nom: &str, labels: Option<&str>) -> Option<f64> {
    let conn = db.lock();
    match labels {
        Some(l) => conn
            .query_row(
                "SELECT value FROM metric WHERE name=?1 AND labels=?2 ORDER BY rowid DESC LIMIT 1",
                params![nom, l],
                |r| r.get(0),
            )
            .ok(),
        None => conn
            .query_row("SELECT value FROM metric WHERE name=?1 ORDER BY rowid DESC LIMIT 1", params![nom], |r| {
                r.get(0)
            })
            .ok(),
    }
}

fn insert_event(db: &Arc<Mutex<Connection>>, r: &ColdRow) {
    let conn = db.lock();
    conn.execute(
        "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            r.row.ts, r.row.severity, r.row.source, r.row.category, r.row.host, r.row.src_ip,
            r.row.dst_ip, r.row.url, r.xff, r.row.dedup, r.row.engagement_id, r.row.origin,
            r.row.env_id, r.row.message, r.row.fields
        ],
    )
    .unwrap();
}

fn count_hot(db: &Arc<Mutex<Connection>>) -> i64 {
    db.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap()
}

fn count_hot_day(db: &Arc<Mutex<Connection>>, env: &str, day: i64) -> i64 {
    db.lock()
        .query_row(
            "SELECT COUNT(*) FROM event WHERE env_id=?1 AND ts>=?2 AND ts<?3",
            params![env, day * SECS_PER_DAY, day * SECS_PER_DAY + SECS_PER_DAY],
            |r| r.get(0),
        )
        .unwrap()
}

/// Clé SQLCipher de TEST (source du matériel HKDF de la clé cold). Injectée dans la conf comme en prod
/// `PLUME_DB_KEY` ; `cold_base_secret` la résout (registre vide en test -> `db_key()` env absent -> conf).
const TEST_DB_KEY: &str = "plume-cold-test-key-do-not-use-in-prod-000000";

/// Passphrase age dérivée pour les lectures/écritures DIRECTES de fixtures (round-trip/verify/footer). IDENTIQUE
/// à celle qu'emploie `cold_age_run` avec une conf portant `TEST_DB_KEY` (même `cold_aead_passphrase`, même
/// source de base) -> les fichiers écrits par l'aging sont relisibles avec `tpass()`, et inversement.
fn tpass() -> String {
    let mut c = HashMap::new();
    c.insert("PLUME_DB_KEY".to_string(), TEST_DB_KEY.to_string());
    cold_aead_passphrase(&c, "").expect("dérivation de la passphrase cold de test")
}

// Wrappers de test injectant `tpass()` (la clé cold dérivée de TEST_DB_KEY) -> chaque écriture/lecture/verify
// direct de fixture passe par le format CHIFFRÉ at-rest (#18), identique au chemin de production. Les vraies
// fns sont ALIASÉES (`_wdp`...) pour que le corps des wrappers reste stable face aux renommages de call-sites.
use super::{footer_num_rows as _fnr, read_day_parquet as _rdp, verify_parquet_rows as _vpr, write_day_parquet as _wdp};
use super::write_day_parquet_rg as _wdp_rg;
fn t_write(path: &Path, rows: &[ColdRow]) -> Result<usize, String> { _wdp(path, rows, &tpass()) }
/// Écrit une fixture MULTI-ROW-GROUPS (#18 P3) : row-groups de `rg_rows` lignes (lignes triées par ts) -> plages
/// ts disjointes par groupe, pour exercer l'élagage row-group avec peu de lignes.
fn t_write_rg(path: &Path, rows: &[ColdRow], rg_rows: usize) -> Result<usize, String> { _wdp_rg(path, rows, &tpass(), rg_rows) }
fn t_read(path: &Path) -> Result<Vec<ColdRow>, String> { _rdp(path, &tpass()) }
fn t_verify(path: &Path, expected: usize) -> Result<(), String> { _vpr(path, expected, None, &tpass()) }
/// VERIFY LIÉ À UNE IDENTITÉ (FIX B / P2b) : fixture single-file -> `seq=0`, bornes ts = jour ENTIER (large mais
/// valide : un fichier d'un jour a tous ses ts dans le jour ; production passe la fenêtre serrée du fichier).
fn t_verify_id(path: &Path, expected: usize, env: &str, day: i64) -> Result<(), String> {
    let id = FileIdent { env_id: env, day, seq: 0, ts_min: day * SECS_PER_DAY, ts_max: day * SECS_PER_DAY + SECS_PER_DAY - 1 };
    _vpr(path, expected, Some(id), &tpass())
}
/// VERIFY LIÉ à une identité PAR-FICHIER explicite (env, day, seq, fenêtre ts) — exerce l'assertion `seq`.
fn t_verify_id_seq(path: &Path, expected: usize, env: &str, day: i64, seq: i64, ts_min: i64, ts_max: i64) -> Result<(), String> {
    _vpr(path, expected, Some(FileIdent { env_id: env, day, seq, ts_min, ts_max }), &tpass())
}
fn t_footer(path: &Path) -> Result<i64, String> { _fnr(path, &tpass()) }

/// Chemin d'un jour tenant en UN SEUL fichier (`seq=0`) — la plupart des fixtures/scénarios de test. Les tests
/// MULTI-FICHIERS utilisent `file_path(cold, env, day, seq)` directement.
fn day_path(cold: &Path, env: &str, day: i64) -> PathBuf { file_path(cold, env, day, 0) }

/// Insère UNE ligne de seal PAR-FICHIER (schéma #18 P2b) — contrôle total (seq, purged, keyset, last_file).
#[allow(clippy::too_many_arguments)]
fn seal_row(db: &Arc<Mutex<Connection>>, env: &str, day: i64, seq: i64, expected: i64, purged: i64, max_id: i64, ts_min: i64, ts_max: i64, lo_ts: i64, lo_id: i64, hi_id: i64, last_file: i64) {
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES(?1,?2,?3,?4,0,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![env, day, seq, expected, purged, max_id, ts_min, ts_max, lo_ts, lo_id, hi_id, last_file],
        )
        .unwrap();
}

/// Convenience : seal SINGLE-FILE (`seq=0`, `last_file=1`, lo=(MIN,MIN)) d'un jour de `k` lignes contiguës
/// `ts=day*SECS+0..k-1`, `hi_id=max_id`. Reproduit ce qu'écrirait la production pour un jour tenant en 1 fichier.
fn seal0_k(db: &Arc<Mutex<Connection>>, env: &str, day: i64, k: i64, purged: i64, max_id: i64) {
    let ts_min = day * SECS_PER_DAY;
    let ts_max = day * SECS_PER_DAY + (k - 1).max(0);
    seal_row(db, env, day, 0, k, purged, max_id, ts_min, ts_max, i64::MIN, i64::MIN, max_id, 1);
}

fn conf_on(cold_dir: &Path, hot_window: i64) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
    m.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), hot_window.to_string());
    m.insert("PLUME_COLD_DIR".to_string(), cold_dir.to_string_lossy().to_string());
    m.insert("PLUME_DB_KEY".to_string(), TEST_DB_KEY.to_string()); // clé source du chiffrement cold at-rest (#18)
    m
}

/// Une ligne "riche" (toutes colonnes peuplées + JSON fields) au timestamp `ts`, index `i`.
fn rich_row(ts: i64, i: i64) -> ColdRow {
    ColdRow {
        row: EventRow {
            ts,
            severity: (i % 5),
            source: format!("src-{i}"),
            category: "auth".to_string(),
            message: format!("msg-{i} lorem ipsum"),
            host: Some(format!("host-{i}")),
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: None,
            url: Some(format!("/p/{i}")),
            dedup: if i % 2 == 0 { Some(format!("d-{i}")) } else { None },
            fields: Some(format!("{{\"k\":{i},\"nested\":{{\"a\":\"b\"}}}}")),
            engagement_id: String::new(),
            origin: String::new(),
            env_id: Some("prod".to_string()),
        },
        xff: if i % 3 == 0 { Some(format!("xff-{i}")) } else { None },
    }
}

/// Insère une ligne « tail-holder » RÉCENTE (jour M-1, DANS la fenêtre chaude HOT_WIN=2) — appelée APRÈS les
/// lignes du jour à ager, elle porte donc l'id le PLUS HAUT de la table. En prod la fenêtre chaude est TOUJOURS
/// alimentée -> le compteur de rowid global est détenu par une donnée HOT et aucun jour éligible (plus ancien)
/// ne détient le tail : la garde H1 laisse alors ager normalement. Sans elle, un jour isolé détiendrait le tail
/// et son aging serait (correctement) DIFFÉRÉ par la garde. Le tail-holder n'est jamais agé (fenêtre chaude).
fn insert_recent_tail_holder(db: &Arc<Mutex<Connection>>) {
    let ts = (M - 1) * SECS_PER_DAY + 1; // hot (jamais agé) mais id le plus haut -> tient le tail du compteur.
    let mut r = rich_row(ts, 88_888);
    r.row.source = "recent-tail".to_string();
    insert_event(db, &r);
}

// ---- ROUND-TRIP ------------------------------------------------------------------------------------

#[test]
fn roundtrip_all_columns_and_fields_json_intact() {
    let root = tmp_root("rt");
    let p = root.join("day.parquet");
    let rows: Vec<ColdRow> = (0..50).map(|i| rich_row(1000 + i, i)).collect();
    let n = t_write(&p, &rows).unwrap();
    assert_eq!(n, 50);
    let back = t_read(&p).unwrap();
    assert_eq!(back.len(), 50);
    // déjà triés en entrée -> comparaison directe ; toutes colonnes + JSON fields identiques.
    assert_eq!(back, rows, "round-trip doit préserver toutes les colonnes (dont xff + fields JSON)");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn writer_sorts_rows_by_ts() {
    let root = tmp_root("sort");
    let p = root.join("day.parquet");
    // entrée DÉSORDONNÉE en ts.
    let unsorted: Vec<ColdRow> = [500, 100, 900, 300, 100, 700]
        .iter()
        .enumerate()
        .map(|(i, &ts)| rich_row(ts, i as i64))
        .collect();
    t_write(&p, &unsorted).unwrap();
    let back = t_read(&p).unwrap();
    let ts: Vec<i64> = back.iter().map(|r| r.row.ts).collect();
    assert_eq!(ts, vec![100, 100, 300, 500, 700, 900], "le writer DOIT trier par ts (stats serrées)");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verify_matches_count_and_rejects_mismatch_and_missing() {
    let root = tmp_root("verify");
    let p = root.join("day.parquet");
    let rows: Vec<ColdRow> = (0..12).map(|i| rich_row(2000 + i, i)).collect();
    t_write(&p, &rows).unwrap();
    assert!(t_verify(&p, 12).is_ok());
    assert!(t_verify(&p, 11).is_err(), "compte faux -> rejet");
    assert!(t_verify(&p, 13).is_err(), "compte faux -> rejet");
    assert!(t_verify(&root.join("absent.parquet"), 0).is_err(), "fichier absent -> Err");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- AGING (crash-safety / idempotence) ------------------------------------------------------------

// n aligné minuit (M jours). hot_window=2, rétention=30 -> jours éligibles [M-30, M-2).
const M: i64 = 20_000;
fn n_now() -> i64 {
    M * SECS_PER_DAY
}
const RET_DAYS: i64 = 30;
const HOT_WIN: i64 = 2;

#[test]
fn aging_converges_write_verify_delete() {
    let root = tmp_root("age");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10; // éligible
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..40).map(|i| rich_row(base + i, i)).collect();
    for r in &rows {
        insert_event(&db, r);
    }
    insert_recent_tail_holder(&db); // donnée hot récente -> le jour agé ne détient pas le tail (garde H1).
    assert_eq!(count_hot(&db), 41);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    // hot vidé pour ce jour ; Parquet écrit + scellé purgé ; contenu fidèle.
    assert_eq!(count_hot_day(&db, "prod", day), 0, "les lignes agées quittent le hot");
    let p = day_path(&cold, "prod", day);
    assert!(p.exists(), "jour-Parquet écrit");
    assert!(t_verify(&p, 40).is_ok());
    let back = t_read(&p).unwrap();
    assert_eq!(back.len(), 40);
    let (expected, purged, _) = { let c = db.lock(); seal_state(&c, "prod", day).unwrap() };
    assert_eq!(expected, 40);
    assert!(purged, "seal purgé après DELETE complet");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn aging_is_idempotent_second_run_noop() {
    let root = tmp_root("idem");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 5;
    let base = day * SECS_PER_DAY;
    for i in 0..25 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // garde H1 : le tail est tenu par une donnée hot, pas par le jour agé.
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0);
    let back1 = t_read(&day_path(&cold, "prod", day)).unwrap();

    // 2e passe : NO-OP (seal purgé) — aucune dup, aucun changement.
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0);
    let back2 = t_read(&day_path(&cold, "prod", day)).unwrap();
    assert_eq!(back1.len(), 25);
    assert_eq!(back2.len(), 25, "re-run ne duplique pas");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_write_before_seal_reruns_no_dup_no_loss() {
    // Simule un crash APRÈS rename (jour-Parquet présent) mais AVANT le seal : pas de ligne cold_seal,
    // lignes hot INTACTES. Re-run : aucun seal -> ré-écrit + scelle + supprime. Pas de dup, pas de perte.
    let root = tmp_root("cwbs");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 7;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..30).map(|i| rich_row(base + i, i)).collect();
    for r in &rows {
        insert_event(&db, r);
    }
    insert_recent_tail_holder(&db); // garde H1 : le jour agé ne détient pas le tail du compteur rowid.
    // pré-pose un jour-Parquet final SANS seal (état post-rename/pre-seal).
    let p = day_path(&cold, "prod", day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    t_write(&p, &rows).unwrap();
    assert!(seal_state(&db.lock(), "prod", day).is_none());

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 0, "pas de perte : les lignes hot sont bien parties en cold");
    assert!(t_verify(&p, 30).is_ok(), "pas de dup : le jour-Parquet est reconstruit à 30 lignes exactes");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(purged);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn crash_after_seal_before_delete_resumes_no_dup_no_loss() {
    // Simule un crash APRÈS seal (jour-Parquet durable + cold_seal purged=0) mais AVANT/pendant le DELETE :
    // lignes hot ENCORE présentes. Re-run : seal(purged=0) -> VERIFY -> REPREND le delete -> purged=1.
    let root = tmp_root("csbd");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..33).map(|i| rich_row(base + i, i)).collect();
    for r in &rows {
        insert_event(&db, r);
    }
    // état "scellé mais pas encore supprimé" : parquet durable (33) + seal purged=0 (last_file=1 -> write DONE
    // -> Phase 2 resume) + hot INTACT. max_id = borne d'identité de l'ensemble scellé (FIX #1), RELU au resume.
    let p = day_path(&cold, "prod", day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    t_write(&p, &rows).unwrap();
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prod", day, 33, 0, max_id);
    assert_eq!(count_hot_day(&db, "prod", day), 33);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 0, "delete repris -> hot vidé (pas de dup résiduel)");
    assert!(t_verify(&p, 33).is_ok(), "pas de perte : parquet scellé intact à 33");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(purged);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn resume_with_corrupt_sealed_parquet_does_not_delete_hot() {
    // seal purged=0 mais Parquet ABSENT/corrompu au re-run -> VERIFY échoue -> AUCUNE suppression du hot
    // (fail-safe : jamais de perte sur une preuve non prouvée durable).
    let root = tmp_root("corrupt");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 6;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    // seal prétend 20 lignes (+max_id), mais AUCUN fichier n'existe (verify-décode échouera -> pas de delete).
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prod", day, 20, 0, max_id);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 20, "verify échoué -> hot PRÉSERVÉ (pas de perte)");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(!purged, "seal reste non purgé (delete non exécuté)");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn control_events_never_aged() {
    // Un event de CONTRÔLE (origin='daemon' + source dans la liste) NE DOIT JAMAIS être agé/supprimé.
    let root = tmp_root("ctrl");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    let mut normal = rich_row(base + 1, 1);
    normal.row.source = "web".to_string();
    let mut ctrl = rich_row(base + 2, 2);
    ctrl.row.origin = "daemon".to_string();
    ctrl.row.source = "plume-config".to_string();
    insert_event(&db, &normal);
    insert_event(&db, &ctrl);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    // 1 seule ligne agée (la normale) ; l'event de contrôle reste hot.
    assert_eq!(count_hot_day(&db, "prod", day), 1, "l'event de contrôle reste hot");
    let p = day_path(&cold, "prod", day);
    let back = t_read(&p).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].row.source, "web");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn legal_hold_suspends_aging() {
    let root = tmp_root("hold");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 11;
    let base = day * SECS_PER_DAY;
    for i in 0..10 {
        insert_event(&db, &rich_row(base + i, i));
    }
    // table legal_hold avec un hold ACTIF -> enforcement != NoHolds -> aging suspendu.
    {
        let c = db.lock();
        c.execute_batch("CREATE TABLE legal_hold(id INTEGER PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0)")
            .unwrap();
        c.execute("INSERT INTO legal_hold(active) VALUES(1)", []).unwrap();
    }

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 10, "hold actif -> aucune ligne agée");
    assert!(!day_path(&cold, "prod", day).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn runtime_gate_off_is_inert() {
    // PLUME_COLD_TIER absent -> cold_age_run retourne IMMÉDIATEMENT : aucun fichier, hot inchangé, et
    // AUCUNE table cold_seal créée (base byte-identique côté cold).
    let root = tmp_root("gateoff");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..15 {
        insert_event(&db, &rich_row(base + i, i));
    }
    let mut conf = HashMap::new(); // PLUME_COLD_TIER NON posé
    conf.insert("PLUME_COLD_DIR".to_string(), cold.to_string_lossy().to_string());

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    assert_eq!(count_hot(&db), 15, "runtime OFF -> hot intact");
    assert!(!cold.exists(), "runtime OFF -> aucun fichier cold");
    let has_seal: i64 = db
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cold_seal'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has_seal, 0, "runtime OFF -> table cold_seal jamais créée (base inchangée)");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn day_outside_hot_and_retention_windows_untouched() {
    // Un jour DANS la fenêtre chaude (récent) et un jour AU-DELÀ de la rétention (trop vieux) ne sont PAS
    // agés par la fenêtre [M-30, M-2).
    let root = tmp_root("windows");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let hot_day = M - 1; // dans la fenêtre chaude (2j) -> reste hot
    let old_day = M - 40; // au-delà de la rétention (30j) -> pas agé (retention_run le hard-purge ailleurs)
    for (d, k) in [(hot_day, 5i64), (old_day, 5i64)] {
        let base = d * SECS_PER_DAY;
        for i in 0..k {
            insert_event(&db, &rich_row(base + i, i));
        }
    }

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", hot_day), 5, "jour chaud non agé");
    assert_eq!(count_hot_day(&db, "prod", old_day), 5, "jour hors rétention non agé (hard-purge = retention_run)");
    assert!(!day_path(&cold, "prod", hot_day).exists());
    assert!(!day_path(&cold, "prod", old_day).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn expired_day_parquet_and_seal_cleaned_up() {
    // Un jour scellé+purgé qui tombe AU-DELÀ de la rétention -> son fichier + son marqueur seal sont retirés.
    let root = tmp_root("expire");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let expired_day = M - 40; // day_end (M-39) <= retention_cutoff (M-30) -> expiré
    let p = day_path(&cold, "prod", expired_day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let rows: Vec<ColdRow> = (0..3).map(|i| rich_row(expired_day * SECS_PER_DAY + i, i)).collect();
    t_write(&p, &rows).unwrap();
    seal0_k(&db, "prod", expired_day, 3, 1, 3); // scellé+purgé (last_file=1)
    assert!(p.exists());

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert!(!p.exists(), "jour-Parquet expiré supprimé");
    assert!(seal_state(&db.lock(), "prod", expired_day).is_none(), "marqueur seal expiré supprimé");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn ymd_from_day_known_dates() {
    assert_eq!(ymd_from_day(0), "1970-01-01");
    assert_eq!(ymd_from_day(19_723), "2024-01-01"); // 2024-01-01 = 19723 jours après epoch
    assert_eq!(ymd_from_day(M), "2024-10-04"); // 20000 jours après epoch
}

// ---- NOUVEAUX TESTS (défauts CONFIRMÉS) ----------------------------------------------------------------

/// Crée/peuple la table `index_policy` (#49) avec une policy de rétention pour `name`.
fn mk_index_policy(db: &Arc<Mutex<Connection>>, name: &str, retention_days: i64) {
    let c = db.lock();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS index_policy(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, \
           retention_days INTEGER NOT NULL DEFAULT 0, max_rows INTEGER NOT NULL DEFAULT 0, \
           max_bytes INTEGER NOT NULL DEFAULT 0, description TEXT NOT NULL DEFAULT '', \
           enabled INTEGER NOT NULL DEFAULT 1, managed INTEGER NOT NULL DEFAULT 2, \
           created INTEGER, updated INTEGER, updated_by TEXT)",
    )
    .unwrap();
    c.execute("INSERT INTO index_policy(name,retention_days,enabled) VALUES(?1,?2,1)", params![name, retention_days])
        .unwrap();
}

// FIX #1 — BORNE D'IDENTITÉ. Une ligne backdatée ingérée APRÈS la capture de max_id (id > max_id) NE DOIT
// PAS être supprimée par le DELETE `id<=max_id`, même si son ts tombe dans la plage du jour.
#[test]
fn fix1_late_event_after_maxid_snapshot_is_not_deleted() {
    let root = tmp_root("fix1late");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i)); // ids 1..20
    }
    // SNAPSHOT (compte + borne d'identité) de l'ensemble à ager.
    let (n_snap, max_id) = { let c = db.lock(); count_and_max_id(&c, "prod", day).unwrap() };
    assert_eq!(n_snap, 20);
    assert_eq!(max_id, 20);
    // ARRIVÉE TARDIVE entre snapshot et delete : ts BACKDATÉ dans le jour, mais id=21 (> max_id).
    let mut late = rich_row(base + 5, 999);
    late.row.source = "late".to_string();
    insert_event(&db, &late);
    assert_eq!(count_hot_day(&db, "prod", day), 21);
    // DELETE BORNÉ à la fenêtre keyset du fichier single-file (lo=(MIN,MIN), hi=(base+19, id=20)) + id<=max_id :
    // ne touche QUE les 20 lignes scellées ; la tardive (id=21>max_id) est exclue.
    delete_file_rows(&db, "prod", day, max_id, i64::MIN, i64::MIN, base + 19, 20);
    assert_eq!(count_hot_day(&db, "prod", day), 1, "la ligne tardive (id>max_id) SURVIT (jamais supprimée sans archive)");
    let survivor: String = db
        .lock()
        .query_row(
            "SELECT source FROM event WHERE ts>=?1 AND ts<?2",
            params![base, base + SECS_PER_DAY],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(survivor, "late", "la survivante est bien l'event tardif non archivé");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #1 (bout-en-bout) — un straggler arrivant dans un jour DÉJÀ scellé+purgé reste HOT (pas de perte) et
// n'est jamais re-columnarisé (choix P1 documenté) ; le cold reste inchangé.
#[test]
fn fix1_straggler_in_sealed_day_stays_hot_no_loss() {
    let root = tmp_root("fix1strag");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // garde H1 : tail tenu par une donnée hot -> le jour agé s'âge normalement.
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0);
    let p = day_path(&cold, "prod", day);
    assert_eq!(t_read(&p).unwrap().len(), 20);
    // straggler backdaté APRÈS seal+purge (id > max_id du seal).
    let mut s = rich_row(base + 3, 777);
    s.row.source = "straggler".to_string();
    insert_event(&db, &s);
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS); // re-run : jour scellé+purgé -> NO-OP
    assert_eq!(count_hot_day(&db, "prod", day), 1, "straggler reste HOT (pas de perte)");
    assert_eq!(t_read(&p).unwrap().len(), 20, "cold inchangé (straggler jamais re-columnarisé en P1)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #2 — deux tenants distincts (MÊME env_id='prod', MÊME jour) écrivent des fichiers cold DISJOINTS ;
// aucun n'écrase l'autre ; chaque seal pointe SA propre donnée.
#[test]
fn fix2_two_tenants_same_env_disjoint_cold_files() {
    let root = tmp_root("fix2");
    let a_root = root.join("tenantA");
    let b_root = root.join("tenantB");
    std::fs::create_dir_all(&a_root).unwrap();
    std::fs::create_dir_all(&b_root).unwrap();
    let a_db = mkdb(&a_root);
    let b_db = mkdb(&b_root);
    let a_pstr = a_root.join("plume.db").to_string_lossy().to_string();
    let b_pstr = b_root.join("plume.db").to_string_lossy().to_string();
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..15 {
        insert_event(&a_db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&a_db); // garde H1 par-tenant : chaque base a sa donnée hot tenant le tail.
    for i in 0..25 {
        let mut r = rich_row(base + i, i);
        r.row.source = format!("b-{i}");
        insert_event(&b_db, &r);
    }
    insert_recent_tail_holder(&b_db);
    // conf SANS PLUME_COLD_DIR : la racine cold est dérivée du db_path PAR-TENANT (FIX #2).
    let mut conf = HashMap::new();
    conf.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
    conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), HOT_WIN.to_string());
    conf.insert("PLUME_DB_KEY".to_string(), TEST_DB_KEY.to_string()); // chiffrement cold at-rest (#18)

    cold_age_run(&a_db, &a_pstr, &conf, n_now(), RET_DAYS);
    cold_age_run(&b_db, &b_pstr, &conf, n_now(), RET_DAYS);

    let a_cold = cold_root(&conf, &a_pstr);
    let b_cold = cold_root(&conf, &b_pstr);
    assert_ne!(a_cold, b_cold, "racines cold par-tenant DISTINCTES");
    let a_file = day_path(&a_cold, "prod", day);
    let b_file = day_path(&b_cold, "prod", day);
    assert_ne!(a_file, b_file, "fichiers cold DISJOINTS (pas de collision)");
    assert!(a_file.exists() && b_file.exists(), "les deux fichiers existent");
    assert_eq!(t_read(&a_file).unwrap().len(), 15, "A conserve SES 15 lignes (non écrasé par B)");
    assert_eq!(t_read(&b_file).unwrap().len(), 25, "B conserve SES 25 lignes (non écrasé par A)");
    let (ea, _, _) = seal_state(&a_db.lock(), "prod", day).unwrap();
    let (eb, _, _) = seal_state(&b_db.lock(), "prod", day).unwrap();
    assert_eq!(ea, 15);
    assert_eq!(eb, 25);
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #2 (mode 0 inchangé) — tenant default : la racine cold reste HISTORIQUE (PLUME_COLD_DIR / <parent PLUME_DB>/cold).
#[test]
fn fix2_default_tenant_path_unchanged() {
    let root = tmp_root("fix2def");
    let cold = root.join("cold");
    // (a) PLUME_COLD_DIR posé (mode 0) -> racine == PLUME_COLD_DIR (db_path vide OU == PLUME_DB).
    let conf = conf_on(&cold, HOT_WIN);
    assert_eq!(cold_root(&conf, ""), cold, "db_path vide -> racine = PLUME_COLD_DIR (historique)");
    let mut conf_pdb = conf.clone();
    conf_pdb.insert("PLUME_DB".to_string(), "/var/lib/plume/db/plume.db".to_string());
    assert_eq!(cold_root(&conf_pdb, "/var/lib/plume/db/plume.db"), cold, "db_path==PLUME_DB -> racine historique");
    // (b) SANS PLUME_COLD_DIR -> <parent PLUME_DB>/cold.
    let mut conf2 = HashMap::new();
    conf2.insert("PLUME_DB".to_string(), "/data/x/plume.db".to_string());
    assert_eq!(cold_root(&conf2, ""), PathBuf::from("/data/x/cold"), "mode 0 sans override = <parent PLUME_DB>/cold");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #3 — writer STREAMÉ : un jour de N × (taille row-group) lignes produit PLUSIEURS row-groups (jamais
// tout le jour en RAM d'un coup). On le prouve via le nombre de row-groups du fichier de sortie.
#[test]
fn fix3_streaming_yields_multiple_row_groups() {
    let root = tmp_root("fix3");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let total: i64 = 35;
    for i in 0..total {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // garde H1 : le jour agé (M-10) ne détient pas le tail -> aging normal.
    let mut conf = conf_on(&cold, HOT_WIN);
    conf.insert("PLUME_COLD_ROWGROUP_ROWS".to_string(), "10".to_string()); // petit -> plusieurs groupes

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    let p = day_path(&cold, "prod", day);
    assert!(p.exists());
    let reader = open_cold_reader(&p, &tpass()).unwrap(); // déchiffre AVANT d'inspecter les métadonnées (row-groups)
    assert_eq!(reader.metadata().num_row_groups(), 4, "35 lignes / 10 par groupe -> 4 row-groups (borne mémoire)");
    assert_eq!(reader.metadata().file_metadata().num_rows(), 35);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "toutes agées");
    assert_eq!(t_read(&p).unwrap().len(), 35, "toutes les lignes présentes malgré le streaming");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #4 — l'EXPIRY du cold honore la rétention PAR-INDEX (#49) : un index à rétention LONGUE n'est pas
// expiré prématurément (pas de perte) ; un index à rétention COURTE est bien expiré (pas de sur-rétention) ;
// un index SANS policy retombe sur le cutoff GLOBAL (inchangé).
#[test]
fn fix4_per_index_retention_governs_cold_expiry() {
    let root = tmp_root("fix4");
    let cold = root.join("cold");
    let db = mkdb(&root);
    mk_index_policy(&db, "longkeep", 3650); // >> global (30)
    mk_index_policy(&db, "shortkeep", 7); // < global (30)
    ensure_cold_seal_table(&db.lock());
    // Pré-place des cold-files + seals SANS event hot (aging ne crée rien -> seule l'expiry agit).
    let place = |env: &str, day: i64, k: i64| -> PathBuf {
        let p = day_path(&cold, env, day);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let rows: Vec<ColdRow> = (0..k).map(|i| rich_row(day * SECS_PER_DAY + i, i)).collect();
        t_write(&p, &rows).unwrap();
        seal0_k(&db, env, day, k, 1, k); // scellé+purgé single-file
        p
    };
    let long_p = place("longkeep", M - 40, 3); // au-delà du global mais DANS 3650j -> survit
    let prod_p = place("prod", M - 40, 3); // pas de policy -> global 30 -> expiré
    let short_p = place("shortkeep", M - 10, 3); // dans global 30 mais au-delà de 7j -> expiré

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert!(long_p.exists(), "index rétention LONGUE (3650j) NON expiré prématurément (pas de perte)");
    assert!(seal_state(&db.lock(), "longkeep", M - 40).is_some(), "seal longkeep conservé");
    assert!(!prod_p.exists(), "index sans policy expiré au cutoff GLOBAL (comportement inchangé)");
    assert!(!short_p.exists(), "index rétention COURTE (7j) expiré -> pas de sur-rétention");
    assert!(seal_state(&db.lock(), "shortkeep", M - 10).is_none(), "seal shortkeep retiré à l'expiry");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #5 (adapté au format CHIFFRÉ at-rest #18) — sous AEAD (age STREAM), TOUTE corruption d'un octet du
// ciphertext est détectée par le tag Poly1305 du chunk concerné : le fichier devient ILLISIBLE (déchiffrement
// échoue). La faille « footer valide, page de données corrompue » de l'ancien format EN CLAIR n'est plus
// CONSTRUCTIBLE (on ne peut pas corrompre le Parquet interne sans casser le tag externe). VERIFY (qui
// DÉCHIFFRE puis décode) rejette donc ; l'accès footer seul échoue aussi (le footer est chiffré). Le décodage
// intégral FIX #5 subsiste comme défense EN PROFONDEUR (cf. `t_verify` sur le compte, plus haut).
#[test]
fn fix5_corrupt_ciphertext_rejected() {
    let root = tmp_root("fix5");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..50).map(|i| rich_row(base + i, i)).collect();
    let _ = &db; // (db seulement pour un layout homogène)
    let p = root.join("day.parquet");
    t_write(&p, &rows).unwrap();
    assert!(t_verify(&p, 50).is_ok(), "fichier chiffré intact -> verify OK (sanity)");
    // Corrompt un octet du CIPHERTEXT (milieu du fichier, bien après l'en-tête age -> dans le flux STREAM).
    let mut bytes = std::fs::read(&p).unwrap();
    assert!(bytes.len() > 200);
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&p, &bytes).unwrap();
    // AEAD : le tag Poly1305 du chunk corrompu échoue -> déchiffrement rejeté -> footer illisible ET verify rejette.
    assert!(t_footer(&p).is_err(), "ciphertext corrompu -> footer illisible (fichier non déchiffrable)");
    assert!(t_verify(&p, 50).is_err(), "ciphertext corrompu -> verify (déchiffre+décode) REJETTE");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #5 (bout-en-bout, format chiffré #18) — au RE-RUN, un jour-file scellé dont le CIPHERTEXT est corrompu
// -> déchiffrement/décodage échoue au VERIFY -> AUCUNE suppression du hot (fail-safe), seal reste non purgé.
#[test]
fn fix5_resume_corrupt_page_preserves_hot() {
    let root = tmp_root("fix5e2e");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..30).map(|i| rich_row(base + i, i)).collect();
    for r in &rows {
        insert_event(&db, r);
    }
    ensure_cold_seal_table(&db.lock());
    let p = day_path(&cold, "prod", day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    t_write(&p, &rows).unwrap();
    let mut bytes = std::fs::read(&p).unwrap();
    for b in bytes.iter_mut().take(64).skip(8) {
        *b ^= 0xFF;
    }
    std::fs::write(&p, &bytes).unwrap();
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prod", day, 30, 0, max_id);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 30, "page corrompue au resume -> hot PRÉSERVÉ (delete SKIPPÉ)");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(!purged, "seal reste non purgé (verify-décode a rejeté le fichier scellé)");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- H1 — TAIL GUARD (anti-réutilisation de rowid) -------------------------------------------------

// H1 (scénario du hazard) — un jour éligible qui DÉTIENT le tail du compteur de rowid global (aucune donnée
// plus récente) est DIFFÉRÉ (ni Parquet, ni suppression hot) ; dès qu'une donnée plus récente arrive et tient
// le tail (`table_max > day_max_id`), le tick suivant l'archive et le supprime correctement.
#[test]
fn h1_tail_holding_day_deferred_then_aged_after_newer_data() {
    let root = tmp_root("h1defer");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10; // éligible
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i)); // ids 1..20 ; CE jour détient MAX(id) global.
    }
    // Sanity : le jour détient bien le tail (day_max_id == table_max).
    let (_, day_max) = { let c = db.lock(); count_and_max_id(&c, "prod", day).unwrap() };
    let table_max = { let c = db.lock(); event_table_max_id(&c).unwrap() };
    assert_eq!(day_max, table_max, "précondition : le jour détient le tail du compteur");

    // TICK 1 : DIFFÉRÉ — aucune écriture cold, aucune suppression hot, aucun seal.
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 20, "jour tail-holder DIFFÉRÉ -> reste hot (sans perte)");
    assert!(!day_path(&cold, "prod", day).exists(), "aucun Parquet écrit pour un jour différé");
    assert!(seal_state(&db.lock(), "prod", day).is_none(), "aucun seal pour un jour différé");

    // Arrivée d'une donnée PLUS RÉCENTE (fenêtre chaude) -> id > 20 -> le tail passe hors du jour éligible.
    insert_recent_tail_holder(&db);
    let table_max2 = { let c = db.lock(); event_table_max_id(&c).unwrap() };
    assert!(table_max2 > day_max, "une donnée plus récente tient désormais le tail");

    // TICK 2 : le jour s'âge normalement (archive + suppression), le tail-holder récent reste hot.
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "tail passé ailleurs -> le jour s'âge enfin");
    let p = day_path(&cold, "prod", day);
    assert!(t_verify(&p, 20).is_ok(), "20 lignes archivées après levée du différé");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(purged, "seal purgé après aging complet");
    assert_eq!(count_hot_day(&db, "prod", M - 1), 1, "le tail-holder récent (hot) n'est jamais agé");
    let _ = std::fs::remove_dir_all(&root);
}

// H1 (cas normal) — un jour qui NE détient PAS le tail (donnée plus récente présente) s'âge IMMÉDIATEMENT :
// la garde ne bloque QUE le tail-holder, jamais les autres jours/envs sous le tail.
#[test]
fn h1_non_tail_day_ages_immediately() {
    let root = tmp_root("h1normal");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // le tail est tenu par une donnée hot -> le jour éligible ne l'est pas.

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour non-tail agé dès le 1er tick");
    assert!(t_verify(&day_path(&cold, "prod", day), 12).is_ok());
    assert!(seal_state(&db.lock(), "prod", day).unwrap().1, "seal purgé");
    let _ = std::fs::remove_dir_all(&root);
}

// H1 (garde par (env_id, day)) — deux jours éligibles ; SEUL celui qui détient le tail est différé, l'autre
// (sous le tail) s'âge. Prouve que la garde ne bloque pas accidentellement des jours dont max_id < table_max.
#[test]
fn h1_guard_defers_only_the_tail_holding_day() {
    let root = tmp_root("h1perday");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let early = M - 12; // inséré EN PREMIER -> ids bas -> sous le tail -> doit s'ager.
    let late = M - 8; // inséré EN DERNIER -> détient MAX(id) global -> doit être différé.
    for i in 0..10 {
        insert_event(&db, &rich_row(early * SECS_PER_DAY + i, i));
    }
    for i in 0..10 {
        insert_event(&db, &rich_row(late * SECS_PER_DAY + i, 100 + i));
    }
    // `late` détient le tail (dernier inséré) ; `early` non.
    let (_, early_max) = { let c = db.lock(); count_and_max_id(&c, "prod", early).unwrap() };
    let (_, late_max) = { let c = db.lock(); count_and_max_id(&c, "prod", late).unwrap() };
    let table_max = { let c = db.lock(); event_table_max_id(&c).unwrap() };
    assert!(early_max < table_max, "early sous le tail");
    assert_eq!(late_max, table_max, "late détient le tail");

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", early), 0, "le jour SOUS le tail s'âge");
    assert!(day_path(&cold, "prod", early).exists());
    assert_eq!(count_hot_day(&db, "prod", late), 10, "SEUL le jour tail-holder est différé (reste hot)");
    assert!(!day_path(&cold, "prod", late).exists());
    let _ = std::fs::remove_dir_all(&root);
}

// H1 (prédicat focalisé) — c'est bien `max_id >= table_max` (le jour détient le tail) qui déclenche le différé
// et le seul insert réutilisable <= max_id est CELUI que la garde évite. Un insert backdaté APRÈS suppression
// du tail-holder hypothétique porterait un id <= max_id : la garde (différé) est ce qui empêche cette réécriture.
#[test]
fn h1_guard_predicate_matches_tail_ownership() {
    let root = tmp_root("h1pred");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    // Lone-day : détient le tail -> prédicat de différé VRAI.
    let (_, day_max) = { let c = db.lock(); count_and_max_id(&c, "prod", day).unwrap() };
    let table_max = { let c = db.lock(); event_table_max_id(&c).unwrap() };
    assert!(day_max >= table_max, "jour isolé -> détient le tail -> DIFFÉRÉ");

    // Après arrivée d'une donnée plus récente (id supérieur AILLEURS), le prédicat de différé devient FAUX.
    insert_recent_tail_holder(&db);
    let table_max2 = { let c = db.lock(); event_table_max_id(&c).unwrap() };
    assert!(day_max < table_max2, "un id supérieur subsiste ailleurs -> plus de différé, aging autorisé");

    // Démonstration du danger que la garde évite : si l'on supprimait maintenant TOUT le jour (id<=day_max)
    // ALORS QUE le jour tenait le tail (avant l'arrivée récente), SQLite ré-allouerait un rowid <= day_max au
    // prochain insert -> un backdate dans le jour pendant un delete multi-lots serait supprimé sans archive.
    // On le prouve en re-créant l'état lone-day dans une base neuve et en observant la ré-allocation.
    let root2 = tmp_root("h1reuse");
    let db2 = mkdb(&root2);
    for i in 0..20 {
        insert_event(&db2, &rich_row(base + i, i)); // ids 1..20, day_max=20 == table_max
    }
    // Supprime la ligne tail (id=20) -> le compteur global retombe à 19.
    db2.lock().execute("DELETE FROM event WHERE id=20", []).unwrap();
    // Un nouvel insert réutilise un rowid <= day_max (20) : c'EST le hazard H1.
    insert_event(&db2, &rich_row(base + 3, 777));
    let reused: i64 = db2.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    assert!(reused <= 20, "rowid RÉUTILISÉ <= day_max après suppression du tail (hazard que la garde H1 évite)");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&root2);
}

// ---- H2 — REPARSE borné à la fenêtre chaude (immutabilité cold) ------------------------------------

// H2 (prédicat) — `reparse_lower_bound` : cold OFF -> borne inchangée (byte-identique) ; cold ON -> clampée à
// `max(requested, hot_cutoff)` (source unique partagée avec l'aging).
#[test]
fn h2_reparse_lower_bound_clamps_only_when_cold_on() {
    let root = tmp_root("h2pred");
    let db = mkdb(&root);
    let n = n_now();
    let requested_old = (M - 25) * SECS_PER_DAY; // bien avant la fenêtre chaude.
    let requested_hot = (M - 1) * SECS_PER_DAY; // déjà dans la fenêtre chaude.
    let cold_dir = root.join("cold");

    // Cold OFF -> renvoie la borne demandée telle quelle (comportement reparse historique).
    let mut off = HashMap::new();
    off.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), HOT_WIN.to_string());
    let c = db.lock();
    assert_eq!(reparse_lower_bound(&c, &off, n, requested_old), requested_old, "cold off -> inchangé");

    // Cold ON -> clamp à hot_cutoff (= n - HOT_WIN j) quand la demande est plus ancienne.
    let on = conf_on(&cold_dir, HOT_WIN);
    let hot_cutoff = n - HOT_WIN * SECS_PER_DAY;
    assert_eq!(
        reparse_lower_bound(&c, &on, n, requested_old),
        hot_cutoff,
        "cold on -> borne remontée à hot_cutoff (aucune ligne cold-éligible mutée)"
    );
    // Une demande DÉJÀ dans la fenêtre chaude est laissée intacte (max ne remonte pas).
    assert_eq!(
        reparse_lower_bound(&c, &on, n, requested_hot),
        requested_hot,
        "cold on + demande déjà hot -> inchangée"
    );
    // hot_cutoff partagé : identique à cold_hot_cutoff (source unique).
    assert_eq!(cold_hot_cutoff(&c, &on, n, RET_DAYS), hot_cutoff, "hot_cutoff = source unique de l'aging");
    drop(c);
    let _ = std::fs::remove_dir_all(&root);
}

// H2 (simulation reparse) — avec le clamp cold-ON, la mutation reparse (UPDATE ... WHERE ts>=cut) ne touche
// QUE les lignes hot ; une ligne d'un jour agé (ts < hot_cutoff) reste INTACTE. Cold OFF, la fenêtre entière
// est mutée (comportement inchangé).
#[test]
fn h2_reparse_update_spares_aged_rows_when_cold_on() {
    let root = tmp_root("h2sim");
    let db = mkdb(&root);
    let n = n_now();
    let aged_ts = (M - 10) * SECS_PER_DAY + 5; // cold-éligible (< hot_cutoff)
    let hot_ts = (M - 1) * SECS_PER_DAY + 5; // hot (>= hot_cutoff)
    let mut aged = rich_row(aged_ts, 1);
    aged.row.fields = Some("OLD".to_string());
    let mut hot = rich_row(hot_ts, 2);
    hot.row.fields = Some("OLD".to_string());
    insert_event(&db, &aged);
    insert_event(&db, &hot);

    let requested = (M - 30) * SECS_PER_DAY; // fenêtre large atteignant le jour agé.
    let on = conf_on(&root.join("cold"), HOT_WIN);

    // COLD ON : borne clampée -> l'UPDATE (mimant parser_reparse) épargne la ligne agée.
    {
        let c = db.lock();
        let cut = reparse_lower_bound(&c, &on, n, requested);
        c.execute("UPDATE event SET fields='NEW' WHERE ts>=?1", params![cut]).unwrap();
    }
    let aged_fields: String = db
        .lock()
        .query_row("SELECT fields FROM event WHERE ts=?1", params![aged_ts], |r| r.get(0))
        .unwrap();
    let hot_fields: String = db
        .lock()
        .query_row("SELECT fields FROM event WHERE ts=?1", params![hot_ts], |r| r.get(0))
        .unwrap();
    assert_eq!(aged_fields, "OLD", "cold on -> ligne agée (immuable) NON mutée par le reparse");
    assert_eq!(hot_fields, "NEW", "cold on -> ligne hot bien reparsée");

    // COLD OFF : même reparse -> la fenêtre entière (y compris la ligne agée) est mutée (inchangé vs historique).
    db.lock().execute("UPDATE event SET fields='OLD'", []).unwrap(); // reset
    let mut off = HashMap::new();
    off.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), HOT_WIN.to_string());
    {
        let c = db.lock();
        let cut = reparse_lower_bound(&c, &off, n, requested);
        c.execute("UPDATE event SET fields='NEW' WHERE ts>=?1", params![cut]).unwrap();
    }
    let aged_off: String = db
        .lock()
        .query_row("SELECT fields FROM event WHERE ts=?1", params![aged_ts], |r| r.get(0))
        .unwrap();
    assert_eq!(aged_off, "NEW", "cold off -> reparse historique mute toute la fenêtre demandée");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- #18 CHIFFREMENT AT-REST (confidentialité) -----------------------------------------------------

/// Passphrase VOLONTAIREMENT MAUVAISE : une chaîne littérale qui n'est PAS la clé cold dérivée (base64 HKDF).
/// Robuste face à l'env : c'est un « autre secret » quel que soit le résultat de `cold_base_secret`.
const WRONG_PASS: &str = "cle-completement-etrangere-au-tenant-cold-000";

// PREUVE DE CONFIDENTIALITÉ (le cœur du durcissement #18) : une chaîne d'event distinctive écrite via le VRAI
// chemin d'aging n'apparaît EN CLAIR nulle part dans les octets bruts du jour-file cold (chiffré at-rest).
#[test]
fn ciphertext_at_rest_no_plaintext_event_string_on_disk() {
    let root = tmp_root("cipher");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    const CANARY: &str = "PLUME_CANARY_c0nfidential_a1b2c3d4e5f6_SECRET";
    // Une ligne portant le canari en message (colonne FAT), src_ip (colonne fine) ET fields (JSON).
    let mut r = rich_row(base + 1, 1);
    r.row.message = format!("attacker exfiltration {CANARY} payload dump");
    r.row.src_ip = Some(CANARY.to_string());
    r.row.fields = Some(format!("{{\"marker\":\"{CANARY}\",\"k\":1}}"));
    insert_event(&db, &r);
    for i in 2..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // garde H1 : le jour agé ne détient pas le tail.

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    let p = day_path(&cold, "prod", day);
    assert!(p.exists(), "jour-file cold écrit");
    // Le canari NE DOIT PAS apparaître EN CLAIR dans les octets bruts sur disque (grep binaire du fichier).
    let raw = std::fs::read(&p).unwrap();
    let needle = CANARY.as_bytes();
    let found = raw.windows(needle.len()).any(|w| w == needle);
    assert!(!found, "la chaîne d'event ne doit PAS être en clair dans le jour-file cold (chiffré at-rest #18)");
    // Sanity : la donnée est bien LÀ et récupérable APRÈS déchiffrement avec la clé (round-trip fidèle).
    let back = t_read(&p).unwrap();
    assert!(
        back.iter().any(|c| c.row.src_ip.as_deref() == Some(CANARY)),
        "le canari est récupérable via la clé (déchiffrement -> décode)"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ROUND-TRIP explicite à travers le chiffrement : toutes colonnes + fields JSON + NULLs préservés (les NULLs
// sont portés par `rich_row` : `dst_ip=None`, `dedup=None` un rang sur deux, `xff=None` deux sur trois).
#[test]
fn encrypted_roundtrip_preserves_all_columns_and_nulls() {
    let root = tmp_root("encrt");
    let p = root.join("day.parquet");
    let rows: Vec<ColdRow> = (0..60).map(|i| rich_row(5000 + i, i)).collect();
    t_write(&p, &rows).unwrap();
    let back = t_read(&p).unwrap();
    assert_eq!(back, rows, "encrypt->decrypt->decode restitue EXACTEMENT les lignes (colonnes + JSON + NULLs)");
    // Contrôle explicite d'un NULL round-trippé (dst_ip est toujours None dans rich_row).
    assert!(back.iter().all(|c| c.row.dst_ip.is_none()), "les NULLs (dst_ip) sont préservés");
    let _ = std::fs::remove_dir_all(&root);
}

// MAUVAISE CLÉ -> échec fermé (jamais de décodage silencieux) : verify ET lecture échouent, la bonne clé passe.
#[test]
fn wrong_key_decrypt_and_verify_fail() {
    let root = tmp_root("wrongkey");
    let p = root.join("day.parquet");
    let rows: Vec<ColdRow> = (0..10).map(|i| rich_row(1000 + i, i)).collect();
    t_write(&p, &rows).unwrap(); // écrit avec la clé de test
    assert!(t_verify(&p, 10).is_ok(), "bonne clé -> verify OK (sanity)");
    // Une clé DIFFÉRENTE ne déchiffre pas -> verify ET lecture échouent (erreur remontée, jamais avalée).
    assert!(verify_parquet_rows(&p, 10, None, WRONG_PASS).is_err(), "mauvaise clé -> verify Err");
    assert!(read_day_parquet(&p, WRONG_PASS).is_err(), "mauvaise clé -> lecture Err");
    let _ = std::fs::remove_dir_all(&root);
}

// MAUVAISE CLÉ dans le chemin d'AGING (resume) : un jour-file scellé chiffré avec une clé ÉTRANGÈRE au tenant
// -> le VERIFY (déchiffre) échoue -> AUCUNE suppression du hot (fail-safe), seal non purgé.
#[test]
fn resume_wrong_key_sealed_file_preserves_hot() {
    let root = tmp_root("wrongkeyage");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..12).map(|i| rich_row(base + i, i)).collect();
    for r in &rows {
        insert_event(&db, r);
    }
    let p = day_path(&cold, "prod", day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    // Fichier scellé chiffré avec une clé DIFFÉRENTE de celle de la conf (conf_on = TEST_DB_KEY).
    write_day_parquet(&p, &rows, WRONG_PASS).unwrap();
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prod", day, 12, 0, max_id);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 12, "clé du fichier != clé du tenant -> verify échoue -> hot PRÉSERVÉ");
    let (_, purged, _) = seal_state(&db.lock(), "prod", day).unwrap();
    assert!(!purged, "seal reste non purgé (déchiffrement impossible)");
    let _ = std::fs::remove_dir_all(&root);
}

// FAIL-CLOSED sur clé INDISPONIBLE : cold ON mais aucune clé résolvable -> le tick ne fait RIEN (hot intact,
// aucun fichier écrit, aucune suppression). Déterministe via le REGISTRE par-tenant (`None` = tenant en clair
// -> pas de clé) : indépendant de l'env `PLUME_DB_KEY` du process de test.
#[test]
fn fail_closed_when_key_unavailable_no_file_no_delete() {
    let root = tmp_root("failclosed");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..15 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    // Tenant enregistré EN CLAIR (clé = None) -> `cold_base_secret` renvoie None -> chiffrement impossible.
    let dbp = root.join("tenant-plaintext.db");
    let dbp = dbp.to_string_lossy().into_owned();
    register_db_key(&dbp, None);
    let mut conf = HashMap::new();
    conf.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
    conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), HOT_WIN.to_string());

    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);

    assert_eq!(count_hot(&db), 16, "clé indisponible -> fail-closed : hot INTACT (rien agé/supprimé)");
    let cold_derived = cold_root(&conf, &dbp); // <dbp>.cold — ne doit pas exister
    assert!(!cold_derived.exists(), "fail-closed -> aucun fichier cold écrit");
    // Aucune table cold_seal peuplée (aucun seal produit).
    let seals: i64 = db
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cold_seal'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    // La table peut exister (créée paresseusement AVANT la dérivation de clé ? non : la clé est dérivée AVANT
    // ensure_cold_seal_table) -> 0 attendu. On tolère la présence de la table mais EXIGE 0 seal si présente.
    if seals == 1 {
        let n: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_seal", [], |r| r.get(0)).unwrap_or(0);
        assert_eq!(n, 0, "fail-closed -> aucun seal");
    }
    unregister_db_key(&dbp);
    let _ = std::fs::remove_dir_all(&root);
}

// ---- #18 FIX B — LIAISON D'IDENTITÉ (env_id, jour) anti-swap intra-tenant --------------------------

// FIX B (iii) — un fichier CORRECTEMENT PLACÉ vérifie sous SON identité liée ; (i) le MÊME fichier, exigé sous
// une AUTRE identité (jour), est REJETÉ. La liaison est DANS l'AEAD (footer chiffré) -> inforgeable sans la clé.
#[test]
fn fixb_bound_verify_accepts_correct_identity_rejects_wrong_day() {
    let root = tmp_root("fixbok");
    let p = root.join("day.parquet");
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..12).map(|i| rich_row(base + i, i)).collect(); // env "prod", jour = M-10
    t_write(&p, &rows).unwrap();
    // (iii) identité correcte -> OK (compte + env_id + jour + borne ts).
    assert!(t_verify_id(&p, 12, "prod", day).is_ok(), "identité liée correcte -> verify OK");
    // (i) exigé sous un AUTRE jour -> rejet (liaison KV + borne ts hors du jour attendu).
    assert!(t_verify_id(&p, 12, "prod", day + 1).is_err(), "jour attendu != jour lié -> REFUS (swap de jour)");
    assert!(t_verify_id(&p, 12, "prod", day - 30).is_err(), "jour très différent -> REFUS");
    // Le verify NON lié (fixtures génériques, None) reste tolérant sur l'identité (compte seul).
    assert!(t_verify(&p, 12).is_ok(), "verify non lié -> OK (aucune assertion d'identité)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX B (ii) — le MÊME fichier exigé sous un AUTRE env_id (même tenant/clé) est REJETÉ (liaison env_id).
#[test]
fn fixb_bound_verify_rejects_wrong_env_id() {
    let root = tmp_root("fixbenv");
    let p = root.join("day.parquet");
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // Fichier appartenant à l'env "prodA".
    let rows: Vec<ColdRow> = (0..9)
        .map(|i| { let mut r = rich_row(base + i, i); r.row.env_id = Some("prodA".to_string()); r })
        .collect();
    t_write(&p, &rows).unwrap();
    assert!(t_verify_id(&p, 9, "prodA", day).is_ok(), "env_id lié correct -> OK");
    assert!(t_verify_id(&p, 9, "prodB", day).is_err(), "env_id attendu != env_id lié -> REFUS (swap d'env)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX B (i, bout-en-bout RESUME) — un jour-file scellé dont le CONTENU (donc la liaison d'identité + les ts) est
// celui d'un AUTRE jour du MÊME tenant (attaquant qui substitue son fichier) est RÉCUSÉ au VERIFY de reprise
// -> AUCUNE suppression du hot mal-mappée (fail-safe), seal non purgé.
#[test]
fn fixb_day_swap_sealed_file_rejected_resume_preserves_hot() {
    let root = tmp_root("fixbdayswap");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let real_day = M - 9; // jour dont les 12 lignes hot DOIVENT survivre
    let other_day = M - 12; // AUTRE jour, contenu substitué par l'attaquant
    let base = real_day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i));
    }
    // Fichier posé au chemin du VRAI jour, mais stampé (et rempli de ts) pour un AUTRE jour -> swap intra-tenant.
    let p = day_path(&cold, "prod", real_day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let other_rows: Vec<ColdRow> = (0..12).map(|i| rich_row(other_day * SECS_PER_DAY + i, i)).collect();
    t_write(&p, &other_rows).unwrap(); // stampe ("prod", other_day, seq=0) DANS l'AEAD
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prod", real_day, 12, 0, max_id);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", real_day), 12, "swap de jour détecté au VERIFY -> hot PRÉSERVÉ (aucun delete mal-mappé)");
    let (_, purged, _) = seal_state(&db.lock(), "prod", real_day).unwrap();
    assert!(!purged, "seal reste non purgé (fichier d'identité étrangère refusé)");
    // Contrôle direct : REFUS sous le vrai jour, ACCEPTÉ sous sa vraie identité liée (other_day).
    assert!(t_verify_id(&p, 12, "prod", real_day).is_err(), "verify lié rejette un fichier stampé pour un autre jour");
    assert!(t_verify_id(&p, 12, "prod", other_day).is_ok(), "le même fichier vérifie SOUS sa vraie identité");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX B (ii, bout-en-bout RESUME) — même scénario pour un env_id substitué sous la MÊME clé de tenant.
#[test]
fn fixb_env_swap_sealed_file_rejected_resume_preserves_hot() {
    let root = tmp_root("fixbenvswap");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    // hot: 10 lignes de l'env "prodB" (celles à préserver).
    for i in 0..10 {
        let mut r = rich_row(base + i, i);
        r.row.env_id = Some("prodB".to_string());
        insert_event(&db, &r);
    }
    // Fichier posé au chemin de prodB mais stampé pour "prodA" (contenu d'un autre env, même clé).
    let p = day_path(&cold, "prodB", day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let other_rows: Vec<ColdRow> = (0..10)
        .map(|i| { let mut r = rich_row(base + i, i); r.row.env_id = Some("prodA".to_string()); r })
        .collect();
    t_write(&p, &other_rows).unwrap(); // stampe ("prodA", day, seq=0)
    let max_id: i64 = db.lock().query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
    seal0_k(&db, "prodB", day, 10, 0, max_id);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prodB", day), 10, "swap d'env détecté au VERIFY -> hot prodB PRÉSERVÉ");
    let (_, purged, _) = seal_state(&db.lock(), "prodB", day).unwrap();
    assert!(!purged, "seal prodB reste non purgé (fichier stampé prodA refusé)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX D — ISOLEMENT CRYPTO PAR-TENANT avec des CLÉS DISTINCTES (registre par-db_path). Deux tenants aux clés
// DIFFÉRENTES agent chacun un jour ; le fichier de A est INDÉCHIFFRABLE sous la clé dérivée de B (et vice-versa),
// tandis que chacun vérifie sous SA clé. Preuve end-to-end de l'indéchiffrabilité inter-tenant (là où l'ancien
// test partageait une clé et ne prouvait QUE la disjonction des chemins).
#[test]
fn fixd_distinct_per_tenant_keys_cross_undecryptable() {
    let root = tmp_root("fixd");
    let a_root = root.join("tenantA");
    let b_root = root.join("tenantB");
    std::fs::create_dir_all(&a_root).unwrap();
    std::fs::create_dir_all(&b_root).unwrap();
    let a_db = mkdb(&a_root);
    let b_db = mkdb(&b_root);
    let a_pstr = a_root.join("plume.db").to_string_lossy().into_owned();
    let b_pstr = b_root.join("plume.db").to_string_lossy().into_owned();
    // CLÉS DISTINCTES enregistrées dans le REGISTRE par-tenant (frontière crypto multi-tenant #2) : la conf ne
    // porte AUCUN PLUME_DB_KEY -> la clé vient EXCLUSIVEMENT du registre, propre à chaque db_path.
    register_db_key(&a_pstr, Some("tenantA-key-distinct-aaaaaaaaaaaaaaaaaaaa".to_string()));
    register_db_key(&b_pstr, Some("tenantB-key-distinct-bbbbbbbbbbbbbbbbbbbb".to_string()));

    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..10 {
        insert_event(&a_db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&a_db);
    for i in 0..10 {
        insert_event(&b_db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&b_db);

    let mut conf = HashMap::new();
    conf.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
    conf.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), HOT_WIN.to_string());

    cold_age_run(&a_db, &a_pstr, &conf, n_now(), RET_DAYS);
    cold_age_run(&b_db, &b_pstr, &conf, n_now(), RET_DAYS);

    let a_file = day_path(&cold_root(&conf, &a_pstr), "prod", day);
    let b_file = day_path(&cold_root(&conf, &b_pstr), "prod", day);
    assert!(a_file.exists() && b_file.exists(), "chaque tenant a agé son jour sous SA clé");

    // Passphrases cold DÉRIVÉES par-tenant (HKDF de la clé du registre) -> distinctes.
    let a_pass = cold_aead_passphrase(&conf, &a_pstr).unwrap();
    let b_pass = cold_aead_passphrase(&conf, &b_pstr).unwrap();
    assert_ne!(a_pass, b_pass, "clés de base distinctes -> passphrases cold distinctes");

    // Chacun vérifie SOUS SA clé (avec sa liaison d'identité seq=0)...
    let fid = || FileIdent { env_id: "prod", day, seq: 0, ts_min: day * SECS_PER_DAY, ts_max: day * SECS_PER_DAY + SECS_PER_DAY - 1 };
    assert!(verify_parquet_rows(&a_file, 10, Some(fid()), &a_pass).is_ok(), "A vérifie sous SA clé");
    assert!(verify_parquet_rows(&b_file, 10, Some(fid()), &b_pass).is_ok(), "B vérifie sous SA clé");
    // ...mais PAS sous celle de l'autre (déchiffrement impossible : clé étrangère).
    assert!(verify_parquet_rows(&a_file, 10, Some(fid()), &b_pass).is_err(), "fichier de A NON déchiffrable sous la clé de B");
    assert!(verify_parquet_rows(&b_file, 10, Some(fid()), &a_pass).is_err(), "fichier de B NON déchiffrable sous la clé de A");
    assert!(read_day_parquet(&a_file, &b_pass).is_err(), "lecture A sous clé B -> Err");
    assert!(read_day_parquet(&b_file, &a_pass).is_err(), "lecture B sous clé A -> Err");

    unregister_db_key(&a_pstr);
    unregister_db_key(&b_pstr);
    let _ = std::fs::remove_dir_all(&root);
}

// FIX A — le plafond scrypt de déchiffrement (`COLD_SCRYPT_MAX_LOG_N`) est SERRÉ : nos fichiers (log_n=12)
// passent toujours ; un fichier dont l'en-tête annonce log_n > plafond est rejeté DÈS l'en-tête (avant toute
// allocation scrypt). On ne peut pas fabriquer trivialement un tel en-tête ici, mais on prouve les deux
// invariants observables : (a) le plafond >= le facteur d'écriture (nos fichiers déchiffrent), (b) le plafond
// reste SERRÉ (<= 14) -> un log_n=22 (N≈4 Gio) serait au-dessus et donc rejeté par age (ExcessiveWork).
#[test]
fn fixa_scrypt_cap_is_tight_and_admits_own_files() {
    assert!(COLD_SCRYPT_MAX_LOG_N >= COLD_SCRYPT_LOG_N, "le plafond doit admettre nos propres fichiers (log_n=12)");
    assert!(COLD_SCRYPT_MAX_LOG_N <= 14, "le plafond doit rester SERRÉ (<=14 ~16 Mio, TRÈS sous le budget 2 Gio)");
    assert!(COLD_SCRYPT_MAX_LOG_N < 22, "un fichier hostile à log_n=22 (N~4 Gio) est AU-DESSUS du plafond -> rejeté");
    // Sanity fonctionnel : un fichier écrit à log_n=12 déchiffre/vérifie bien sous le plafond serré.
    let root = tmp_root("fixa");
    let p = root.join("day.parquet");
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let rows: Vec<ColdRow> = (0..8).map(|i| rich_row(base + i, i)).collect();
    t_write(&p, &rows).unwrap();
    assert!(t_verify_id(&p, 8, "prod", day).is_ok(), "nos fichiers (log_n=12) déchiffrent sous le plafond=14");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P1.5 — EXTENSION DE RÉTENTION TOTALE (`PLUME_COLD_RETENTION_DAYS`). Tous ADDITIFS : ils n'exercent
// l'extension QUE quand le knob est posé. Knob NON posé -> cold_ret==retention_days -> comportement d'avant
// P1.5 (backward-compat), déjà couvert par les tests P1 ci-dessus (aucun ne pose le knob).
// ====================================================================================================

/// conf cold-ON avec le knob d'extension posé à `cold_ret` jours.
fn conf_ext(cold_dir: &Path, cold_ret: i64) -> HashMap<String, String> {
    let mut c = conf_on(cold_dir, HOT_WIN);
    c.insert("PLUME_COLD_RETENTION_DAYS".to_string(), cold_ret.to_string());
    c
}

/// `P10.13-a` levier ① — LA BANDE QU'UN TICK VERRAIT avec cette conf. Depuis le levier ①,
/// `detect_aging_stall` ne prend plus ses bornes en vrac : il prend la `Bande`, qui porte À LA FOIS la
/// fenêtre, le gate d'armement (`cold_ret > retention_days`) et la CADENCE. Les tests qui appellent le
/// détecteur directement passent donc par le MÊME objet que la passe — ils ne peuvent plus exercer une
/// combinaison que la production ne produit pas.
fn bande_de(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>, n: i64) -> Bande {
    let conn = db.lock();
    Bande::calculer(&conn, conf, n, RET_DAYS)
}

/// La MÊME chose, mais CADENCE DÉSARMÉE (`PLUME_COLD_STALL_CHECK_INTERVAL_S=0` -> tir à chaque appel).
/// Les tests qui prouvent ce que le détecteur COMPTE ne doivent pas rester verts parce qu'il n'a pas
/// tiré : sans ce désarmement, un second appel silencieux passerait pour un « régime drainé » et
/// l'assertion ne garderait plus rien. La cadence, elle, a ses propres tests.
fn bande_sans_cadence(db: &Arc<Mutex<Connection>>, cold_dir: &Path, cold_ret: i64, n: i64) -> Bande {
    let mut c = conf_ext(cold_dir, cold_ret);
    c.insert("PLUME_COLD_STALL_CHECK_INTERVAL_S".to_string(), "0".to_string());
    bande_de(db, &c, n)
}

/// Pré-place un cold-file scellé+purgé (k lignes) SANS event hot -> seule l'expiry agira dessus.
fn place_sealed_cold(db: &Arc<Mutex<Connection>>, cold: &Path, env: &str, day: i64, k: i64) -> PathBuf {
    let p = day_path(cold, env, day);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let rows: Vec<ColdRow> = (0..k).map(|i| rich_row(day * SECS_PER_DAY + i, i)).collect();
    t_write(&p, &rows).unwrap();
    seal0_k(db, env, day, k, 1, k); // scellé+purgé single-file
    p
}

/// Insère UNE ligne hot d'un env donné au jour `day`.
fn ins_env_day(db: &Arc<Mutex<Connection>>, env: &str, day: i64, tag: i64) {
    let mut r = rich_row(day * SECS_PER_DAY + 5, tag);
    r.row.env_id = Some(env.to_string());
    insert_event(db, &r);
}

// P1.5 (knob) — sémantique + clamp NO-LOSS de `cold_retention_days`. NON POSÉ -> retention_days (byte-identique).
#[test]
fn p15_cold_retention_days_semantics_and_clamp() {
    let base = conf_on(std::path::Path::new("/x"), HOT_WIN); // PAS de PLUME_COLD_RETENTION_DAYS
    assert_eq!(cold_retention_days(&base, 30), 30, "NON POSÉ -> retention_days (byte-identique/backward-compat)");
    let mut c = base.clone();
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "365".into());
    assert_eq!(cold_retention_days(&c, 30), 365, "posé > retention_days -> honoré (extension)");
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "10".into());
    assert_eq!(cold_retention_days(&c, 30), 30, "posé < retention_days -> REMONTÉ à retention_days (NO-LOSS)");
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "30".into());
    assert_eq!(cold_retention_days(&c, 30), 30, "posé == retention_days -> retention_days");
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "99999".into());
    assert_eq!(cold_retention_days(&c, 30), 3650, "au-dessus du plafond -> clampé à 3650 (borne dure event)");
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "pas-un-nombre".into());
    assert_eq!(cold_retention_days(&c, 30), 30, "non parsable -> retention_days (fail-safe)");
    c.insert("PLUME_COLD_RETENTION_DAYS".into(), "   ".into());
    assert_eq!(cold_retention_days(&c, 30), 30, "vide -> retention_days (byte-identique)");
}

// P1.5 (test 1) — l'extension GARDE un cold-file au-delà de retention_days JUSQU'À cold_ret (puis l'expire).
#[test]
fn p15_extension_keeps_cold_file_past_retention_until_cold_ret() {
    let root = tmp_root("p15ext");
    let cold = root.join("cold");
    let db = mkdb(&root);
    ensure_cold_seal_table(&db.lock());
    let within = place_sealed_cold(&db, &cold, "prod", M - 90, 3); // 90j : > retention_days(30) mais < cold_ret(365)
    let beyond = place_sealed_cold(&db, &cold, "prod", M - 400, 3); // 400j : > cold_ret(365)

    cold_age_run(&db, "", &conf_ext(&cold, 365), n_now(), RET_DAYS);

    assert!(within.exists(), "cold-file à 90j SURVIT au-delà de retention_days (30j), retenu jusqu'à cold_ret (365j)");
    assert!(seal_state(&db.lock(), "prod", M - 90).is_some(), "seal du jour à 90j conservé");
    assert!(!beyond.exists(), "cold-file à 400j EXPIRÉ (au-delà de cold_ret 365j)");
    assert!(seal_state(&db.lock(), "prod", M - 400).is_none(), "seal du jour à 400j retiré à l'expiry");
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 4, backward-compat) — knob NON posé -> l'horizon d'expiry == retention_days, EXACTEMENT comme
// avant P1.5 (un cold-file à 90j est expiré à 30j, pas retenu). Prouve le défaut byte-identique.
#[test]
fn p15_backward_compat_knob_unset_horizon_is_retention_days() {
    let root = tmp_root("p15bc");
    let cold = root.join("cold");
    let db = mkdb(&root);
    ensure_cold_seal_table(&db.lock());
    let p = place_sealed_cold(&db, &cold, "prod", M - 90, 3); // 90j > retention_days(30)

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS); // knob NON posé

    assert!(!p.exists(), "knob unset -> cold-file à 90j EXPIRÉ à retention_days (30j), comme avant P1.5");
    assert!(seal_state(&db.lock(), "prod", M - 90).is_none());
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 2) — LE CAS DE PERTE : une ligne hot PAS ENCORE AGÉE, plus vieille que retention_days mais DANS
// cold_ret, NE DOIT PAS être hard-purgée (sinon perte prématurée). ET une fois AGÉE elle vit en cold jusqu'à
// cold_ret. Exerce le HARD-PURGE HOT RÉEL (rollups::retention_prune_table) avec l'horizon étendu.
#[test]
fn p15_no_premature_hot_purge_then_aged_row_lives_in_cold() {
    let root = tmp_root("p15hotloss");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let conf = conf_ext(&cold, 365);
    let cold_ret = cold_retention_days(&conf, RET_DAYS);
    assert_eq!(cold_ret, 365);
    let n = n_now();

    // (A) une ligne à 90j : > retention_days(30) mais < cold_ret(365) — le cas de perte.
    let day90 = M - 90;
    insert_event(&db, &rich_row(day90 * SECS_PER_DAY + 5, 1));
    // PREUVE du cas de perte : la ligne EST sous l'ANCIEN horizon (now - retention_days) -> l'ancien code
    // l'aurait hard-purgée ; elle est >= l'horizon ÉTENDU (now - cold_ret) -> le nouveau la préserve.
    let old_horizon = n - RET_DAYS * SECS_PER_DAY;
    let event_global_cutoff = n - cold_ret * SECS_PER_DAY;
    assert!(day90 * SECS_PER_DAY + 5 < old_horizon, "à 90j la ligne EST sous l'ancien horizon 30j (l'ancien code l'aurait perdue)");
    assert!(day90 * SECS_PER_DAY + 5 >= event_global_cutoff, "mais >= l'horizon étendu (cold_ret) -> préservée");
    let policies = { let c = db.lock(); crate::rollups::load_index_policies(&c) };
    crate::rollups::retention_prune_table(&db, "event", "ts", RETENTION_NONPURGE, event_global_cutoff, n, &policies);
    assert_eq!(count_hot_day(&db, "prod", day90), 1, "ligne à 90j (< cold_ret) NON hard-purgée (pas de perte prématurée)");

    // (B) ONCE AGED : la même ligne est columnarisée (bande [hot_window, cold_ret]) puis vit en cold jusqu'à
    // cold_ret. On alimente la fenêtre chaude (garde H1) pour ne pas différer l'aging.
    insert_recent_tail_holder(&db);
    cold_age_run(&db, "", &conf, n, RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day90), 0, "ligne à 90j AGÉE -> quitte le hot");
    let p = day_path(&cold, "prod", day90);
    assert!(p.exists(), "ligne à 90j vit désormais en COLD");
    assert!(seal_state(&db.lock(), "prod", day90).is_some(), "cold-file à 90j retenu (< cold_ret) : pas d'expiry");
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 3, cold-expiry) — un index à policy per-index SHORTER que cold_ret expire à SA policy ; un LONGER
// est honoré (jamais expiré prématurément par le global étendu). L'env SANS policy suit cold_ret.
#[test]
fn p15_per_index_cold_expiry_vs_extension() {
    let root = tmp_root("p15pix");
    let cold = root.join("cold");
    let db = mkdb(&root);
    mk_index_policy(&db, "shortkeep", 30); // < cold_ret 365
    mk_index_policy(&db, "longkeep", 1000); // > cold_ret 365
    ensure_cold_seal_table(&db.lock());
    let short_expired = place_sealed_cold(&db, &cold, "shortkeep", M - 60, 3); // 60 > 30 -> expiré à SA policy
    let short_kept = place_sealed_cold(&db, &cold, "shortkeep", M - 20, 3); // 20 < 30 -> gardé
    let long_kept = place_sealed_cold(&db, &cold, "longkeep", M - 400, 3); // 400 < 1000 -> gardé (LONGER honoré)
    let prod_kept = place_sealed_cold(&db, &cold, "prod", M - 90, 3); // 90 < cold_ret 365 -> gardé (extension)
    let prod_expired = place_sealed_cold(&db, &cold, "prod", M - 400, 3); // 400 > cold_ret 365 -> expiré

    cold_age_run(&db, "", &conf_ext(&cold, 365), n_now(), RET_DAYS);

    assert!(!short_expired.exists(), "shortkeep 60j expiré à SA policy (30j), jamais sur-retenu par cold_ret");
    assert!(short_kept.exists(), "shortkeep 20j gardé (< sa policy 30j)");
    assert!(long_kept.exists(), "longkeep 400j gardé (< sa policy 1000j) — LONGER honoré, PAS expiré au global 365");
    assert!(prod_kept.exists(), "prod 90j gardé (< cold_ret 365 : extension globale)");
    assert!(!prod_expired.exists(), "prod 400j expiré (> cold_ret 365)");
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 3, hot-purge) — MÊME matrice per-index côté HARD-PURGE HOT : chaque index à policy est purgé à SA
// fenêtre ; l'env sans policy à cold_ret. Jamais de purge prématurée d'un index à rétention plus LONGUE.
#[test]
fn p15_per_index_hot_purge_vs_extension() {
    let root = tmp_root("p15pixh");
    let db = mkdb(&root);
    mk_index_policy(&db, "shortkeep", 30);
    mk_index_policy(&db, "longkeep", 1000);
    let conf = conf_ext(std::path::Path::new("/x"), 365);
    let cold_ret = cold_retention_days(&conf, RET_DAYS);
    let n = n_now();
    ins_env_day(&db, "shortkeep", M - 60, 1); // > policy 30 -> purgé
    ins_env_day(&db, "shortkeep", M - 20, 2); // < policy 30 -> gardé
    ins_env_day(&db, "longkeep", M - 400, 3); // < policy 1000 -> gardé (LONGER honoré)
    ins_env_day(&db, "prod", M - 90, 4); // < cold_ret 365 -> gardé (extension)
    ins_env_day(&db, "prod", M - 400, 5); // > cold_ret 365 -> purgé (filet global étendu)

    let event_global_cutoff = n - cold_ret * SECS_PER_DAY;
    let policies = { let c = db.lock(); crate::rollups::load_index_policies(&c) };
    crate::rollups::retention_prune_table(&db, "event", "ts", RETENTION_NONPURGE, event_global_cutoff, n, &policies);

    assert_eq!(count_hot_day(&db, "shortkeep", M - 60), 0, "shortkeep 60j hard-purgé à SA policy (30j)");
    assert_eq!(count_hot_day(&db, "shortkeep", M - 20), 1, "shortkeep 20j gardé (< policy 30j)");
    assert_eq!(count_hot_day(&db, "longkeep", M - 400), 1, "longkeep 400j gardé (< policy 1000j) — jamais purge prématurée");
    assert_eq!(count_hot_day(&db, "prod", M - 90), 1, "prod 90j gardé (< cold_ret 365 : extension)");
    assert_eq!(count_hot_day(&db, "prod", M - 400), 0, "prod 400j hard-purgé (> cold_ret 365 : filet global)");
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 5) — DEAD-MAN'S-SWITCH : le signal de retard TIRE quand des lignes non-NONPURGE stagnent en hot
// bien au-delà de la fenêtre chaude ; il RESTE MUET en régime drainé normal (zéro faux positif).
#[test]
fn p15_aging_stall_signal_fires_on_stall_and_quiet_when_drained() {
    // `event.dedup` est CLOISONNÉ PAR HÔTE à l'écriture (`ingest::store::dedup_scoped_by_host`) : la clé
    // STOCKÉE d'un signal daemon est `<len>\u{1}plume-daemon\u{1}plume-cold-…`. Le `LIKE` porte donc sur
    // la clé ÉMETTEUR à l'intérieur de la clé cloisonnée (`…||char(1)||'plume-cold-…-%'`) — ce qui est
    // EXACTEMENT la propriété testée (1 signal par heure sur CE daemon), sans dépendre de l'encodage du préfixe.
    let health_stall = |db: &Arc<Mutex<Connection>>| -> i64 {
        db.lock()
            .query_row(
                "SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND category='health' \
                 AND dedup LIKE '%'||char(1)||'plume-cold-aging-stall-%'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let day = M - 50; // 50j : bien au-delà de hot_window(2)+grâce, DANS cold_ret(365)
    let base = day * SECS_PER_DAY;

    // (a) STALL — 20 lignes à 50j, AUCUNE donnée récente -> le jour DÉTIENT le tail -> H1 DIFFÈRE -> jamais agé,
    // aucun seal -> lignes non drainées -> le dead-man's-switch DOIT tirer (extension active).
    let root_a = tmp_root("p15stall");
    let cold_a = root_a.join("cold");
    let db_a = mkdb(&root_a);
    for i in 0..20 {
        insert_event(&db_a, &rich_row(base + i, i));
    }
    cold_age_run(&db_a, "", &conf_ext(&cold_a, 365), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db_a, "prod", day), 20, "jour différé (tail) reste hot -> bloat vers cold_ret");
    assert_eq!(health_stall(&db_a), 1, "aging en RETARD -> signal de santé émis (dead-man's-switch)");

    // (b) DRAINÉ — même volume mais AVEC donnée récente (fenêtre chaude alimentée) -> le jour s'âge (sealed+purged)
    // -> hot drainé -> AUCUN signal (pas de faux positif en régime normal).
    let root_b = tmp_root("p15drained");
    let cold_b = root_b.join("cold");
    let db_b = mkdb(&root_b);
    for i in 0..20 {
        insert_event(&db_b, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db_b);
    cold_age_run(&db_b, "", &conf_ext(&cold_b, 365), n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db_b, "prod", day), 0, "jour agé -> hot drainé");
    assert_eq!(health_stall(&db_b), 0, "régime drainé -> AUCUN signal (zéro faux positif)");

    // (c) MUET SANS EXTENSION — même stall mais knob NON posé (cold_ret==retention_days) -> aucun bloat NOUVEAU
    // (hot toujours plafonné à retention_days) -> signal NON émis (byte-identique : les tests P1 ne l'atteignent jamais).
    let root_c = tmp_root("p15noext");
    let cold_c = root_c.join("cold");
    let db_c = mkdb(&root_c);
    let day_c = M - 10; // dans retention_days(30), au-delà de hot_window+grâce
    for i in 0..20 {
        insert_event(&db_c, &rich_row(day_c * SECS_PER_DAY + i, i));
    }
    cold_age_run(&db_c, "", &conf_on(&cold_c, HOT_WIN), n_now(), RET_DAYS); // knob NON posé
    assert_eq!(count_hot_day(&db_c, "prod", day_c), 20, "jour différé reste hot (H1)");
    assert_eq!(health_stall(&db_c), 0, "sans extension -> pas de signal (pas de bloat nouveau)");

    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
    let _ = std::fs::remove_dir_all(&root_c);
}

// ---- FIX #18 : SIGNAL « seal cold BLOQUÉ » (delete-side stall) --------------------------------------

/// Insère un seal PAR-FICHIER avec un `sealed_ts` EXPLICITE (le helper `seal_row` le fige à 0) — nécessaire
/// pour exercer la fenêtre de grâce de detect_cold_seal_stuck. Les colonnes non lues par le détecteur sont à 0.
fn seal_at(db: &Arc<Mutex<Connection>>, env: &str, day: i64, seq: i64, purged: i64, sealed_ts: i64) {
    ensure_cold_seal_table(&db.lock());
    db.lock()
        .execute(
            "INSERT INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file) \
             VALUES(?1,?2,?3,1,?4,?5,0,0,0,0,0,0,1)",
            params![env, day, seq, sealed_ts, purged],
        )
        .unwrap();
}

/// Compte les signaux de santé « seal cold bloqué » (source/origin/category/severity 4 + dedup dédié).
fn health_seal_stuck(db: &Arc<Mutex<Connection>>) -> i64 {
    db.lock()
        .query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-config' AND origin='daemon' AND category='health' \
             AND severity=4 AND dedup LIKE '%'||char(1)||'plume-cold-seal-stuck-%'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

const STUCK_GRACE: i64 = COLD_SEAL_STUCK_GRACE_S;

// FIX #18 (test a) — RUNTIME OFF : un seal bloqué présent mais PLUME_COLD_TIER non posé -> cold_age_run
// retourne AVANT d'atteindre detect_cold_seal_stuck -> AUCUN signal (byte-identique côté runtime-off). Le cas
// feature-OFF est couvert par la compilation : sans `cold_tier` ce module n'existe pas.
#[test]
fn fix18_seal_stuck_quiet_when_runtime_off() {
    let root = tmp_root("seal-stuck-off");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let n = n_now();
    seal_at(&db, "prod", M - 30, 0, 0, n - 2 * SECS_PER_DAY); // bloqué depuis 2 j -> bien au-delà de la grâce
    let mut off = conf_ext(&cold, 365);
    off.remove("PLUME_COLD_TIER"); // runtime OFF -> cold_age_run early-return
    cold_age_run(&db, "", &off, n, RET_DAYS);
    assert_eq!(health_seal_stuck(&db), 0, "runtime off -> detect_cold_seal_stuck jamais atteint -> aucun signal");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #18 (test b) — TOUS PURGÉS : des seals purged=1 (jour drainé normalement) -> phase2 OK -> aucun signal.
#[test]
fn fix18_seal_stuck_quiet_when_all_purged() {
    let root = tmp_root("seal-stuck-purged");
    let db = mkdb(&root);
    let n = n_now();
    seal_at(&db, "prod", M - 40, 0, 1, n - 3 * SECS_PER_DAY); // purged=1 (drainé), ancien
    seal_at(&db, "prod", M - 41, 0, 1, n - 3 * SECS_PER_DAY);
    detect_cold_seal_stuck(&db, n);
    assert_eq!(health_seal_stuck(&db), 0, "tous purged=1 -> aucun seal bloqué -> aucun signal");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #18 (test c) — FRAÎCHEMENT SCELLÉ : purged=0 mais sealed_ts=n (DANS la grâce) -> un tick sain scelle puis
// purge dans le même tick horaire -> ne PAS crier au blocage tant que la grâce n'est pas dépassée.
#[test]
fn fix18_seal_stuck_within_grace_no_signal() {
    let root = tmp_root("seal-stuck-grace");
    let db = mkdb(&root);
    let n = n_now();
    seal_at(&db, "prod", M - 5, 0, 0, n); // fraîchement scellé, non purgé -> normal ce tick
    seal_at(&db, "prod", M - 5, 1, 0, n - STUCK_GRACE + 60); // encore dans la grâce (60 s de marge)
    detect_cold_seal_stuck(&db, n);
    assert_eq!(health_seal_stuck(&db), 0, "purged=0 dans la grâce -> aucun signal (zéro faux positif)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #18 (test d) — BLOQUÉ : purged=0 avec sealed_ts < n-grâce -> EXACTEMENT un signal de santé sévérité 4,
// NON-PURGEABLE (survit à la garde de rétention RETENTION_NONPURGE que retention_run applique).
#[test]
fn fix18_seal_stuck_fires_and_is_nonpurgeable() {
    let root = tmp_root("seal-stuck-fire");
    let db = mkdb(&root);
    let n = n_now();
    seal_at(&db, "prod", M - 50, 0, 0, n - 2 * SECS_PER_DAY); // bloqué depuis 2 j
    detect_cold_seal_stuck(&db, n);
    assert_eq!(health_seal_stuck(&db), 1, "seal bloqué au-delà de la grâce -> exactement 1 signal");
    // Champs canoniques du canal de santé.
    let (src, org, cat, sev): (String, String, String, i64) = db
        .lock()
        .query_row(
            "SELECT source, origin, category, severity FROM event WHERE dedup LIKE '%'||char(1)||'plume-cold-seal-stuck-%'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((src.as_str(), org.as_str(), cat.as_str(), sev), ("plume-config", "daemon", "health", 4));
    // Champs JSON exigés.
    let fields: String = db
        .lock()
        .query_row("SELECT fields FROM event WHERE dedup LIKE '%'||char(1)||'plume-cold-seal-stuck-%'", [], |r| r.get(0))
        .unwrap();
    assert!(fields.contains("\"subsystem\":\"cold-tier\"") && fields.contains("\"signal\":\"seal-stuck\""), "fields={fields}");
    assert!(fields.contains("\"stuck_files\":1") && fields.contains("\"stuck_days\":1"), "compteurs seal-stuck : {fields}");
    // NON-PURGEABLE : une purge de rétention (même garde RETENTION_NONPURGE, cutoff englobant) ne l'efface PAS,
    // alors qu'un event ordinaire du même ts EST purgé.
    insert_event(&db, &rich_row(n, 7)); // event ordinaire (origin='' -> purgeable)
    let del = format!("DELETE FROM event WHERE ts <= ?1 AND {RETENTION_NONPURGE}");
    db.lock().execute(&del, params![n]).unwrap();
    assert_eq!(health_seal_stuck(&db), 1, "signal seal-stuck NON-PURGEABLE -> survit à la purge de rétention");
    let ordinary: i64 = db
        .lock()
        .query_row("SELECT COUNT(*) FROM event WHERE source LIKE 'src-%'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ordinary, 0, "un event ordinaire du même ts EST purgé (contrôle de la garde)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #18 (test e) — DÉDUP HORAIRE : deux détections dans la MÊME heure -> une SEULE ligne (INSERT OR IGNORE
// sur dedup UNIQUE `plume-cold-seal-stuck-<n/3600>`).
#[test]
fn fix18_seal_stuck_hourly_dedup() {
    let root = tmp_root("seal-stuck-dedup");
    let db = mkdb(&root);
    // Index UNIQUE partiel sur `dedup` (comme la base de prod) -> l'INSERT OR IGNORE dédupe réellement.
    db.lock()
        .execute("CREATE UNIQUE INDEX idx_event_dedup ON event(dedup) WHERE dedup IS NOT NULL", [])
        .unwrap();
    let n = n_now();
    seal_at(&db, "prod", M - 60, 0, 0, n - 2 * SECS_PER_DAY);
    detect_cold_seal_stuck(&db, n);
    detect_cold_seal_stuck(&db, n + 5); // même bucket horaire (n/3600 inchangé)
    assert_eq!(health_seal_stuck(&db), 1, "deux détections même heure -> une seule ligne (dédup horaire)");
    let _ = std::fs::remove_dir_all(&root);
}

// FIX #18 (test f) — COMPLÉMENTARITÉ : un jour SCELLÉ-mais-bloqué déclenche detect_cold_seal_stuck SEUL (il a un
// seal -> exclu de detect_aging_stall), un jour JAMAIS-SCELLÉ déclenche detect_aging_stall SEUL (aucun seal ->
// invisible à detect_cold_seal_stuck qui ne lit QUE cold_seal). Aucun double-signal.
#[test]
fn fix18_seal_stuck_complementary_to_aging_stall() {
    let root = tmp_root("seal-stuck-complement");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let n = n_now();
    let base_stuck = (M - 100) * SECS_PER_DAY; // jour scellé-bloqué (avec events hot POUR prouver l'exclusion)
    let base_hot = (M - 50) * SECS_PER_DAY; // jour jamais scellé (lignes stagnantes)
    for i in 0..10 {
        insert_event(&db, &rich_row(base_stuck + i, i));
        insert_event(&db, &rich_row(base_hot + i, i));
    }
    seal_at(&db, "prod", M - 100, 0, 0, n - 2 * SECS_PER_DAY); // le jour bloqué A un seal (purged=0)
    let health_aging = |db: &Arc<Mutex<Connection>>| -> i64 {
        db.lock()
            .query_row(
                "SELECT COUNT(*) FROM event WHERE dedup LIKE '%'||char(1)||'plume-cold-aging-stall-%'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    detect_cold_seal_stuck(&db, n);
    detect_aging_stall(&db, &bande_sans_cadence(&db, &cold, 365, n), n);
    // seal-stuck : compte UNIQUEMENT le jour scellé-bloqué (1 fichier, 1 jour) ; le jour hot jamais-scellé n'a
    // pas de ligne cold_seal -> ignoré.
    assert_eq!(health_seal_stuck(&db), 1, "seal-stuck tire sur le jour scellé-bloqué");
    let stuck_days: String = db
        .lock()
        .query_row("SELECT fields FROM event WHERE dedup LIKE '%'||char(1)||'plume-cold-seal-stuck-%'", [], |r| r.get(0))
        .unwrap();
    assert!(stuck_days.contains("\"stuck_days\":1"), "un seul jour bloqué : {stuck_days}");
    // aging-stall : tire sur le jour hot jamais-scellé ; le jour scellé-bloqué est EXCLU (il a un seal) -> pas de
    // double comptage.
    assert_eq!(health_aging(&db), 1, "aging-stall tire sur le jour jamais-scellé (et lui seul)");
    let _ = std::fs::remove_dir_all(&root);
}

// `P10.13-a` — CE QUE LE DEAD-MAN'S-SWITCH COMPTE, ET SUR QUELLE CLÉ. Le test ci-dessus n'assertait que la
// PRÉSENCE du signal (`health_aging == 1`) : MESURÉ, il reste VERT si l'énoncé oublie la corrélation sur
// `env_id` (faux négatif multi-env) ET s'il oublie l'anti-jointure (faux positif permanent) — dans les deux
// cas un signal part quand même, et la dédup horaire écrase la différence. Deux angles morts, donc, sur le
// seul énoncé qui garde le tier cold d'un bloat silencieux. Celui-ci ferme les deux en assertant la VALEUR
// (`lingering_rows`) sur un jeu MULTI-ENV, plus les trois exclusions que l'en-tête de `detect_aging_stall`
// promet : jour à seal EN COURS (purged=0), events de CONTRÔLE, et jour hors bande.
#[test]
fn le_retard_compte_les_lignes_par_couple_env_et_jour() {
    let root = tmp_root("retard-par-env");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let n = n_now(); // bande du retard = [n-365 j, n-(HOT_WIN+2) j) = jours [M-365 .. M-5]
    let pose = |ts: i64, i: i64, env: &str, controle: bool| {
        let mut r = rich_row(ts, i);
        r.row.env_id = Some(env.to_string());
        if controle {
            r.row.origin = "daemon".to_string(); // + source de contrôle -> RETENTION_NONPURGE
            r.row.source = "plume-config".to_string();
        }
        insert_event(&db, &r);
    };
    // (a) jour M-50 : 'prod' NON scellé (6) + 'staging' SCELLÉ (4). Le seal de staging ne doit PAS masquer
    //     prod -> +6. (b) jour M-40 : la situation SYMÉTRIQUE -> +3. Les deux sens, parce qu'une corrélation
    //     qui aurait perdu `env_id` passerait encore l'un des deux.
    for i in 0..6 { pose((M - 50) * SECS_PER_DAY + i, i, "prod", false); }
    for i in 0..4 { pose((M - 50) * SECS_PER_DAY + 100 + i, 100 + i, "staging", false); }
    seal_at(&db, "staging", M - 50, 0, 1, n);
    for i in 0..5 { pose((M - 40) * SECS_PER_DAY + i, 200 + i, "prod", false); }
    for i in 0..3 { pose((M - 40) * SECS_PER_DAY + 100 + i, 300 + i, "staging", false); }
    seal_at(&db, "prod", M - 40, 0, 1, n);
    // (c) jour M-30 : seal EN COURS (purged=0) -> phase 2 non terminée, PAS un retard -> +0.
    for i in 0..7 { pose((M - 30) * SECS_PER_DAY + i, 400 + i, "prod", false); }
    seal_at(&db, "prod", M - 30, 0, 0, n);
    // (d) jour M-20 : events de CONTRÔLE seulement (jamais agés) -> +0.
    for i in 0..5 { pose((M - 20) * SECS_PER_DAY + i, 500 + i, "prod", true); }
    // (e) jour M-10 : TROIS seals pour le même jour. L'anti-jointure produit 3 lignes appariées par event :
    //     si la multiplicité fuyait dans le compte, ce jour l'y ferait exploser -> +0.
    for i in 0..9 { pose((M - 10) * SECS_PER_DAY + i, 600 + i, "prod", false); }
    for seq in 0..3 { seal_at(&db, "prod", M - 10, seq, 1, n); }
    // (f) jour M-3 : DANS la fenêtre chaude + grâce -> hors bande -> +0.
    for i in 0..8 { pose((M - 3) * SECS_PER_DAY + i, 700 + i, "prod", false); }

    let signaux = |db: &Arc<Mutex<Connection>>| -> Vec<String> {
        db.lock()
            .prepare("SELECT fields FROM event WHERE dedup LIKE '%'||char(1)||'plume-cold-aging-stall-%' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    // CADENCE DÉSARMÉE ICI : ce test prouve ce que le détecteur COMPTE, pas quand il tire. Avec la
    // cadence par défaut, le SECOND appel ci-dessous serait silencieux et l'assertion « régime drainé »
    // resterait verte même si l'énoncé rendait n'importe quoi — le test ne garderait plus rien.
    detect_aging_stall(&db, &bande_sans_cadence(&db, &cold, 365, n), n);
    let s = signaux(&db);
    assert_eq!(s.len(), 1, "un signal et un seul : {s:?}");
    // 6 (prod du jour M-50) + 3 (staging du jour M-40) et RIEN d'autre. C'est la valeur qui prouve la clé de
    // corrélation : oublier `env_id` rendrait 0, oublier l'anti-jointure rendrait 34.
    assert!(
        s[0].contains("\"lingering_rows\":9"),
        "le retard doit valoir EXACTEMENT 9 lignes (6 prod/M-50 + 3 staging/M-40) : {}",
        s[0]
    );

    // RÉGIME DRAINÉ : on scelle les deux couples restants. Une heure plus tard (la dédup est HORAIRE, sinon
    // le silence ne prouverait rien), le détecteur doit rester MUET — « zéro faux positif en régime drainé »
    // est une propriété écrite, on la mesure.
    seal_at(&db, "prod", M - 50, 0, 1, n);
    seal_at(&db, "staging", M - 40, 0, 1, n);
    let n2 = n + 3600;
    detect_aging_stall(&db, &bande_sans_cadence(&db, &cold, 365, n2), n2);
    assert_eq!(signaux(&db).len(), 1, "régime drainé : aucun signal NOUVEAU ne doit être émis");
    let _ = std::fs::remove_dir_all(&root);
}

// =====================================================================================================
// `P10.13-a` LEVIER ① — LE DÉTECTEUR DE RETARD TIRE UNE FOIS PAR JOUR, PAS À CHAQUE PASSE.
//
// LE CHIFFRE QUI L'A DÉCIDÉ, relevé en production le 2026-08-13 sur 44 h et 45 passes : **2 passes
// utiles, 43 sans le moindre travail** — 95,6 % de gaspillage, soit **20,0 min de `db.lock()` pour rien
// sur 20,9 min au total**. La columnarisation n'a lieu qu'UNE FOIS PAR JOUR (un jour franchit la fenêtre
// chaude) ; les 23 autres passes horaires ne peuvent rien faire PAR CONSTRUCTION. Et cet énoncé porte la
// TOTALITÉ du coût de chaque passe (`SCAN e`, 27,9 s, 1,78 M lignes balayées).
//
// CE LEVIER NE SUPPRIME AUCUN TRAVAIL : il supprime des passes qui n'en avaient aucun.
// =====================================================================================================

/// LA DÉCISION DE TIR EST PURE, ET TOUT CE QUI N'EST PAS « TROP RÉCENT » TIRE. C'est la propriété qui
/// protège le dead-man's-switch : jamais tiré, cadence désarmée, horodatage dans le FUTUR (horloge
/// revenue en arrière, base restaurée, valeur corrompue) — chacun de ces cas doit TIRER, pas se taire.
/// Un `unwrap_or` qui aurait rendu « trop tôt » sur une valeur illisible aurait muselé la garde EN
/// SILENCE, ce qui est littéralement le mode de panne qu'elle existe pour fermer.
///
/// MUTATION : dans `tir_du_retard`, remplacer `n.saturating_sub(t) < periode` par
/// `n.saturating_sub(t) <= periode` ⇒ le cas « exactement à l'échéance » rougit (il faut TIRER à
/// l'échéance, pas au tick d'après). Remplacer le bras `_ => TirDuRetard::Du { lo, hi }` par
/// `_ => TirDuRetard::Ajourne(RETARD_CADENCE)` ⇒ les quatre cas dégradés rougissent d'un coup.
#[test]
fn la_decision_de_tir_du_retard_est_pure_et_faillit_vers_le_tir() {
    const HW: i64 = 2;
    const RET: i64 = 30;
    const EXT: i64 = 365; // rétention cold ÉTENDUE -> détecteur ARMÉ
    let n = n_now();
    let du = |periode: i64, dernier: Option<i64>| {
        matches!(tir_du_retard(HW, EXT, RET, periode, n, dernier), TirDuRetard::Du { .. })
    };
    let cause = |cold_ret: i64, periode: i64, dernier: Option<i64>| -> Option<&'static str> {
        match tir_du_retard(HW, cold_ret, RET, periode, n, dernier) {
            TirDuRetard::Ajourne(c) => Some(c),
            TirDuRetard::Du { .. } => None,
        }
    };

    // ---- LES TROIS REFUS, chacun avec sa cause (= l'étiquette que la série publiera). ----
    assert_eq!(cause(RET, 86_400, None), Some(RETARD_NON_ARME), "cold_ret == retention_days -> pas armé");
    assert_eq!(
        cause(RET - 1, 86_400, None),
        Some(RETARD_NON_ARME),
        "cold_ret < retention_days (défensif) -> pas armé non plus"
    );
    // Fenêtre VIDE : hot_window + grâce couvre déjà toute la rétention cold.
    assert_eq!(
        match tir_du_retard(400, EXT, RET, 86_400, n, None) {
            TirDuRetard::Ajourne(c) => Some(c),
            TirDuRetard::Du { .. } => None,
        },
        Some(RETARD_FENETRE_VIDE)
    );
    assert_eq!(cause(EXT, 86_400, Some(n - 3600)), Some(RETARD_CADENCE), "1 h après le dernier tir -> trop tôt");

    // ---- ET TOUT LE RESTE TIRE. ----
    assert!(du(86_400, None), "jamais tiré (base neuve/démarrage) -> il DOIT tirer");
    assert!(du(0, Some(n - 1)), "cadence désarmée (0) -> comportement historique : tir à chaque passe");
    assert!(du(-5, Some(n - 1)), "période négative (défensif) -> tir, jamais silence");
    assert!(du(86_400, Some(n + 50_000)), "horodatage dans le FUTUR (horloge/restauration) -> tir");
    assert!(du(86_400, Some(n - 86_400)), "EXACTEMENT à l'échéance -> tir (pas au tick d'après)");
    assert!(du(86_400, Some(n - 90_000)), "au-delà de l'échéance -> tir");

    // ---- LA FENÊTRE RENDUE EST CELLE DE `bornes_du_retard`, jamais une variante. ----
    let TirDuRetard::Du { lo, hi } = tir_du_retard(HW, EXT, RET, 86_400, n, None) else {
        panic!("précondition : ce cas doit tirer");
    };
    assert_eq!(
        (lo, hi),
        bornes_du_retard(HW, EXT, n).expect("fenêtre non vide"),
        "la porte a rendu d'AUTRES bornes que la source unique -> la sonde mesurerait une autre fenêtre"
    );
}

/// LA PÉRIODE EST PLAFONNÉE PAR LA GRÂCE, ET CE PLAFOND EST DÉRIVÉ. Un knob capable de rendre la cadence
/// PLUS LONGUE que la grâce que le détecteur s'accorde déjà annulerait la garde qu'il est censé régler.
/// Le plafond suit `COLD_STALL_GRACE_DAYS` : le relever demain relève le plafond, sans que personne n'y
/// pense. Et une valeur ILLISIBLE retombe sur le DÉFAUT — ni sur `0` (on reprendrait les 20 min/jour),
/// ni sur une valeur hors plafond.
///
/// MUTATION : remplacer le `.clamp(0, COLD_STALL_GRACE_DAYS * SECS_PER_DAY)` par `.max(0)` ⇒ l'assertion
/// du plafond rougit en nommant la valeur acceptée.
#[test]
fn la_periode_de_tir_est_plafonnee_par_la_grace_du_detecteur() {
    let avec = |v: &str| {
        let mut c: HashMap<String, String> = HashMap::new();
        if !v.is_empty() {
            c.insert("PLUME_COLD_STALL_CHECK_INTERVAL_S".to_string(), v.to_string());
        }
        periode_de_tir(&c)
    };
    let plafond = COLD_STALL_GRACE_DAYS * SECS_PER_DAY;
    assert_eq!(avec(""), PERIODE_TIR_RETARD_DEFAUT_S, "knob non posé -> 24 h");
    assert_eq!(avec("   "), PERIODE_TIR_RETARD_DEFAUT_S, "knob vide -> 24 h");
    assert_eq!(avec("pas-un-nombre"), PERIODE_TIR_RETARD_DEFAUT_S, "illisible -> DÉFAUT, jamais 0");
    assert_eq!(avec("3600"), 3600, "un exploitant peut racheter la latence d'origine, à chaud");
    assert_eq!(avec("0"), 0, "0 = cadence DÉSARMÉE (comportement d'avant P10.13-a)");
    assert_eq!(avec("-1"), 0, "négatif -> désarmé (tir à chaque passe), jamais un silence");
    assert_eq!(
        avec(&(plafond * 10).to_string()),
        plafond,
        "une configuration ne doit PAS pouvoir rendre la cadence plus longue que la grâce de {COLD_STALL_GRACE_DAYS} j"
    );
    assert!(
        PERIODE_TIR_RETARD_DEFAUT_S < plafond,
        "le défaut ({PERIODE_TIR_RETARD_DEFAUT_S} s) doit rester STRICTEMENT sous le plafond ({plafond} s) : \
         sinon il n'y a plus de marge entre la cadence et la grâce"
    );
}

/// Compte les LIGNES d'une série dans `metric` — pas sa dernière valeur. C'est ce qu'il faut pour
/// prouver un TROU : `serie()` rendrait la valeur de la passe PRÉCÉDENTE et on ne verrait pas que la
/// passe courante n'a rien publié.
fn compte_serie(db: &Arc<Mutex<Connection>>, nom: &str) -> i64 {
    db.lock()
        .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", params![nom], |r| r.get(0))
        .unwrap()
}

/// LE LEVIER, DE BOUT EN BOUT, SUR LA VRAIE PASSE (site de FIN DE PASSE) — et l'état SURVIT AU
/// REDÉMARRAGE.
///
/// Quatre passes : la première tire (aucun horodatage), les deux suivantes NON (dont une APRÈS
/// réouverture du FICHIER de base — c'est ce qui prouve que l'état n'est pas dans le handle), la
/// quatrième à +24 h tire de nouveau. La SÉRIE doit distinguer les deux situations : un compte de
/// retard n'est publié QUE lorsqu'un verdict a été rendu ; sinon la cause NOMME le trou.
///
/// LES ASSERTIONS PORTENT SUR LE NOMBRE DE LIGNES DE SÉRIE, PAS SUR LEUR VALEUR — et ce n'est pas une
/// précaution, c'est une CORRECTION. Première rédaction : j'assertais « 20 lignes en retard » à la
/// passe 4 aussi. FAUX, et le mécanisme vaut d'être écrit : le signal de santé émis à la passe 1 est un
/// `event` de plus, donc un `MAX(id)` PLUS HAUT que celui du jour bloqué — la garde H1, qui ne différait
/// ce jour QUE parce qu'il détenait le tail du compteur de rowid, le laisse passer dès la passe 2 et le
/// jour se columnarise. **Le dead-man's-switch DÉBLOQUE lui-même le defer H1 qu'il signale.** Le compte
/// de lignes, lui, dit exactement ce qu'on veut savoir : combien de fois le détecteur a rendu un verdict.
///
/// MUTATION : faire rendre `None` à `dernier_tir_du_retard` (état de cadence illisible) ⇒ les trois
/// assertions « 1 seule mesure » rougissent d'un coup — la cadence n'a plus d'état à consulter, donc le
/// détecteur retire à chaque passe, ce qui est exactement le comportement d'avant ce lot.
#[test]
fn le_detecteur_de_retard_ne_tire_quune_fois_par_jour_et_son_etat_survit_au_redemarrage() {
    let root = tmp_root("retard-cadence");
    let cold = root.join("cold");
    let chemin = root.join("plume.db");
    let db = mkdb(&root);
    let conf = conf_ext(&cold, 365); // extension -> détecteur ARMÉ ; cadence au DÉFAUT (24 h)
    let day = M - 50;
    // 20 lignes anciennes et AUCUNE donnée récente -> le jour détient le tail -> H1 DIFFÈRE à la passe 1
    // -> aucun seal -> le dead-man's-switch a de quoi tirer.
    for i in 0..20 {
        insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
    }
    let n = n_now();

    // ---- PASSE 1 (aucun horodatage) : LE DÉTECTEUR TIRE. ----
    cold_age_run(&db, "", &conf, n, RET_DAYS);
    assert_eq!(serie(&db, NOM_RETARD_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0), "passe 1 : verdict rendu");
    assert_eq!(serie(&db, NOM_RETARD_LIGNES, None), Some(20.0), "passe 1 : 20 lignes en retard, MESURÉES");
    assert_eq!(compte_serie(&db, NOM_RETARD_LIGNES), 1);
    assert_eq!(
        { let c = db.lock(); dernier_tir_du_retard(&c) },
        Some(n),
        "le tir doit être HORODATÉ dans `meta` — sinon la cadence n'a aucun état à consulter"
    );

    // ---- PASSE 2, une heure plus tard : PAS DUE. Un TROU NOMMÉ, jamais un zéro. ----
    cold_age_run(&db, "", &conf, n + 3600, RET_DAYS);
    assert_eq!(
        serie(&db, NOM_RETARD_OK, Some(&format!("{{\"cause\":\"{RETARD_CADENCE}\"}}"))),
        Some(0.0),
        "la passe qui saute le détecteur doit le DIRE, avec sa cause"
    );
    assert_eq!(
        compte_serie(&db, NOM_RETARD_LIGNES),
        1,
        "un SECOND compte de retard a été publié alors que le détecteur n'a pas tiré -> la série \
         affirmerait un verdict qui n'a pas été rendu"
    );

    // ---- PASSE 3, APRÈS REDÉMARRAGE : toujours pas due. C'EST LE POINT DE LA PERSISTANCE. ----
    // On rouvre le FICHIER (nouvelle connexion, nouveau handle) : c'est tout ce qu'un redémarrage de pod
    // change pour ce module. Un état rangé dans la connexion — ou reconstruit au démarrage — retirerait ici.
    drop(db);
    let db = Arc::new(Mutex::new(rusqlite::Connection::open(&chemin).unwrap()));
    cold_age_run(&db, "", &conf, n + 7200, RET_DAYS);
    assert_eq!(
        compte_serie(&db, NOM_RETARD_LIGNES),
        1,
        "le détecteur a RETIRÉ après un redémarrage -> l'état de cadence n'a pas survécu, et un pod qui \
         redémarre souvent paierait les 27,9 s PLUS souvent qu'avant le levier"
    );

    // ---- PASSE 4, à +24 h EXACTEMENT : le détecteur retire. ----
    cold_age_run(&db, "", &conf, n + SECS_PER_DAY, RET_DAYS);
    assert_eq!(
        compte_serie(&db, NOM_RETARD_LIGNES),
        2,
        "à l'échéance le détecteur DOIT retirer : une cadence qui ne se rouvre jamais serait un \
         dead-man's-switch mort"
    );
    assert_eq!(
        { let c = db.lock(); dernier_tir_du_retard(&c) },
        Some(n + SECS_PER_DAY),
        "l'horodatage doit AVANCER au tir, sinon la cadence se déclencherait à chaque passe ensuite"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// LA PORTE COUVRE AUSSI L'AUTRE SITE D'APPEL — celui de la CLÉ ABSENTE (`aging.rs`, fail-closed), qui
/// portait sa PROPRE copie du gate d'armement avant ce lot. C'est le site le plus important à couvrir :
/// c'est celui où la passe est SUSPENDUE et où le détecteur tire quand même, parce que « plus de clé »
/// veut dire « plus aucun drainage ».
///
/// Et il donne un stall PERMANENT et déterministe : sans clé, rien n'est jamais columnarisé, donc le
/// compte reste à 20 d'une passe à l'autre — ce que le site de fin de passe ne permet pas (cf. le
/// déblocage H1 décrit au-dessus).
///
/// MUTATION : remettre un `if bande.cold_ret > bande.retention_days` autour de CE site seulement, et
/// retirer la cadence de `detect_aging_stall` ⇒ la seconde passe retire et l'assertion « 1 seule
/// mesure » rougit. C'est la démonstration que la porte est bien UNE, et pas deux qui se ressemblent.
#[test]
fn la_cadence_couvre_aussi_le_site_de_la_cle_absente() {
    let root = tmp_root("retard-cadence-clef");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let mut conf = conf_ext(&cold, 365);
    conf.remove("PLUME_DB_KEY"); // fail-closed : la passe se suspend AVANT d'ager quoi que ce soit
    let day = M - 50;
    for i in 0..20 {
        insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
    }
    let n = n_now();

    // PASSE 1 : passe SUSPENDUE (`cle_absente`) et détecteur TIRÉ — les deux à la fois.
    cold_age_run(&db, "", &conf, n, RET_DAYS);
    assert_eq!(
        serie(&db, NOM_OK, Some(&format!("{{\"cause\":\"{CAUSE_CLE_ABSENTE}\"}}"))),
        Some(0.0),
        "précondition : la passe doit bien être suspendue par l'absence de clé"
    );
    assert_eq!(
        serie(&db, NOM_RETARD_LIGNES, None),
        Some(20.0),
        "le détecteur DOIT tirer sur ce chemin : c'est précisément la panne qu'il surveille"
    );
    assert_eq!(compte_serie(&db, NOM_RETARD_LIGNES), 1);

    // PASSE 2, une heure plus tard : la CADENCE s'applique ICI AUSSI (rien n'a été columnarisé
    // entre-temps -> le retard est toujours là, et pourtant le détecteur ne le recompte pas).
    cold_age_run(&db, "", &conf, n + 3600, RET_DAYS);
    assert_eq!(
        compte_serie(&db, NOM_RETARD_LIGNES),
        1,
        "le site `cle_absente` a échappé à la cadence -> la porte est en DEUX exemplaires, et le \
         troisième site ajouté demain en oubliera un"
    );
    assert_eq!(
        serie(&db, NOM_RETARD_OK, Some(&format!("{{\"cause\":\"{RETARD_CADENCE}\"}}"))),
        Some(0.0)
    );

    // PASSE 3, à +24 h : il retire, et le retard n'a pas bougé (rien n'a jamais pu être drainé).
    cold_age_run(&db, "", &conf, n + SECS_PER_DAY, RET_DAYS);
    assert_eq!(compte_serie(&db, NOM_RETARD_LIGNES), 2);
    assert_eq!(serie(&db, NOM_RETARD_LIGNES, None), Some(20.0), "sans clé, rien n'a pu être columnarisé");
    let _ = std::fs::remove_dir_all(&root);
}

/// UNE REQUÊTE EN ÉCHEC NE CONSOMME PAS LE TIR — et c'est CE LOT qui rend la propriété critique.
///
/// AVANT la cadence, un échec de la requête du dead-man's-switch coûtait au pire UNE HEURE : le tick
/// suivant réessayait. DEPUIS la cadence, si l'échec consommait le tir, ce serait **24 H DE SILENCE** sur
/// un dead-man's-switch inopérant — le lot AGGRAVE la portée du trou qu'il n'a pas créé. Le
/// `unwrap_or(0)` retiré en `P10.13-a` était déjà exactement ce mode de panne : une garde qui répond
/// « tout va bien » parce qu'elle n'a rien pu lire.
///
/// LE TROU ÉTAIT RÉEL ET IL A ÉTÉ MESURÉ (2026-08-14) : déplacer l'écriture de l'horodatage AVANT le
/// `return Retard::NonMesure(RETARD_REQUETE)` laissait la suite **VERTE (6 passed, 0 failed)**. Le
/// commentaire de `detect_aging_stall` promettait pourtant « marqué APRÈS le verdict, donc jamais sur un
/// échec » : une promesse en prose, que rien n'opposait. Ce test l'oppose.
///
/// COMMENT L'ÉCHEC EST PROVOQUÉ, ET POURQUOI AINSI. La table `cold_seal` est ABSENTE de la fixture
/// (`mkdb` ne la crée pas) : l'anti-jointure de l'énoncé n° 5 la référence, donc `query_row` échoue à la
/// PRÉPARATION (« no such table: cold_seal »). C'est le moyen le plus propre disponible — il n'exige ni
/// corruption de fichier, ni verrou concurrent, ni monkey-patch, et il exerce le chemin d'erreur RÉEL de
/// `conn.query_row`. On appelle `detect_aging_stall` DIRECTEMENT plutôt que `cold_age_run` parce que la
/// passe complète appelle `ensure_cold_seal_table` en tête et recréerait la table qu'on veut absente.
///
/// TROIS FAITS, ET LE TROISIÈME EST SON PROPRE TÉMOIN POSITIF : (1) la cause publiée est
/// `requete_echouee` ; (2) `meta` n'a PAS été écrite ; (3) le tick suivant, UNE HEURE plus tard,
/// RÉESSAIE — et comme il réussit cette fois, il écrit l'horodatage. Sans (3), « meta non écrite »
/// pourrait être vrai parce que l'écriture n'a jamais lieu du tout.
///
/// MUTATION (exécutée le 2026-08-14) : déplacer l'`INSERT … ON CONFLICT` sur `META_DERNIER_TIR_DU_RETARD`
/// AVANT le `return Retard::NonMesure(...)` du bras `Err` ⇒ 2 assertions rougissent dans ce test —
/// « l'échec a CONSOMMÉ le tir » (`left: Some(...)`, `right: None`) puis, si on la laisse passer, le
/// retir devient `NonMesure("cadence")` au lieu de `Mesure(20)`. Aucun autre test ne bouge : c'est bien
/// celui-ci, et lui seul, qui garde cet axe.
#[test]
fn une_requete_de_retard_en_echec_ne_consomme_pas_le_tir() {
    let root = tmp_root("retard-requete-ko");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let conf = conf_ext(&cold, 365); // détecteur ARMÉ, cadence au DÉFAUT (24 h)
    let day = M - 50;
    for i in 0..20 {
        insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
    }
    let n = n_now();

    // PRÉCONDITION, VÉRIFIÉE : `cold_seal` est bien ABSENTE. Sans cette assertion, une fixture qui la
    // créerait un jour ferait passer ce test pour une preuve alors qu'il n'exercerait plus l'échec.
    let table_existe = |db: &Arc<Mutex<Connection>>| -> bool {
        db.lock()
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cold_seal'", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
            > 0
    };
    assert!(!table_existe(&db), "précondition : `cold_seal` doit être ABSENTE pour que l'énoncé échoue");

    // ---- (1) LA CAUSE. Aucun verdict n'est rendu, et le trou est NOMMÉ. ----
    let bande = bande_de(&db, &conf, n);
    assert_eq!(
        detect_aging_stall(&db, &bande, n),
        Retard::NonMesure(RETARD_REQUETE),
        "une requête en échec doit rendre un TROU NOMMÉ — ni « en retard », ni « à jour »"
    );

    // ---- (2) LE CŒUR : `meta` N'A PAS ÉTÉ ÉCRITE. Le tir n'est pas consommé par un échec. ----
    assert_eq!(
        { let c = db.lock(); dernier_tir_du_retard(&c) },
        None,
        "l'échec a CONSOMMÉ le tir : le dead-man's-switch, déjà inopérant, se tairait maintenant 24 H \
         au lieu de réessayer dans l'heure. C'est le lot de cadence qui transforme ce trou d'une heure \
         perdue en une journée de silence"
    );

    // ---- (3) LE TICK SUIVANT RÉESSAIE — une heure plus tard, PAS vingt-quatre. ----
    // On rend la requête exécutable (la table revient, comme un `ensure_cold_seal_table` de la passe
    // réelle l'aurait fait) : le détecteur doit rendre un VERDICT, pas `NonMesure("cadence")`.
    ensure_cold_seal_table(&db.lock());
    assert!(table_existe(&db), "validation de l'instrument : la table doit être revenue");
    let n2 = n + 3600;
    let bande2 = bande_de(&db, &conf, n2);
    assert_eq!(
        detect_aging_stall(&db, &bande2, n2),
        Retard::Mesure(20),
        "le tick suivant est BLOQUÉ par la cadence alors que le précédent n'avait rendu AUCUN verdict"
    );
    // TÉMOIN POSITIF de (2) : le tir RÉUSSI, lui, écrit bien l'horodatage. Sans lui, « meta non écrite »
    // ci-dessus pourrait être vrai simplement parce que l'écriture n'existe pas.
    assert_eq!(
        { let c = db.lock(); dernier_tir_du_retard(&c) },
        Some(n2),
        "un tir RÉUSSI doit horodater — sinon l'assertion (2) ne prouverait rien"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `P10.14-a` — UNE PASSE SUSPENDUE DIT AUSSI CE QUE LE DÉTECTEUR DE RETARD A FAIT, ET SUR SES DEUX
/// CHEMINS. La prose de `RETARD_PASSE_SUSPENDUE` promet que la série DISE la suspension « plutôt que
/// laisser un trou anonyme » ; rien ne l'opposait. Le test voisin `le_retard_se_publie_meme_sur_une_passe_
/// suspendue` couvre le cas INVERSE (passe suspendue ET détecteur qui TIRE, sur `cle_absente`), et
/// `legal_hold_suspends_aging` n'assertait NI la ligne de retard NI même la série — seulement que le
/// chaud reste plein et qu'aucun fichier n'est écrit (relevé le 2026-08-14 : AUCUN test de ce module ne
/// citait `legal_hold` en étiquette). Déplacer ou supprimer le second membre du tuple rendu par `balayer` était donc
/// invisible : la paire `retard_ok`/`retard_lignes` aurait disparu SANS QU'UN TEST NE BOUGE, et un
/// `timechart` aurait lu le trou comme « pas de retard » — l'ambiguïté exacte que `P10.13-a` a fermée.
///
/// LES DEUX ÉMETTEURS SONT COUVERTS, parce qu'ils sont deux retours DISTINCTS de `balayer` :
/// `aging.rs` sur `retention_days <= 1`, et `aging.rs` sur legal-hold actif. Un seul des deux laisserait
/// l'autre libre de redevenir muet.
///
/// TROIS FAITS PAR CHEMIN, ET LE PREMIER EST LE TÉMOIN POSITIF DU TROISIÈME : (1) la passe est bien
/// SUSPENDUE et le dit (`plume_cold_aging_ok{cause}`) — sans quoi le reste porterait sur une passe qui
/// n'a pas eu lieu ; (2) `plume_cold_aging_retard_ok{cause="passe_suspendue"}` = 0, le trou est NOMMÉ ;
/// (3) `plume_cold_aging_retard_lignes` est ABSENTE — un zéro s'y lirait « mesuré, et il n'y a pas de
/// retard », alors que le détecteur n'a jamais regardé. (2) prouve que la publication a bien eu lieu,
/// donc l'absence de (3) n'est pas celle d'une série qui n'écrit rien.
///
/// TROIS MUTATIONS, exécutées le 2026-08-14, parce que Rust s'arrête au PREMIER panic : supposer que
/// les assertions suivantes mordent aussi serait exactement la promesse en prose que ce lot remplace.
///   1. chemin `retention_days <= 1` -> `Retard::Mesure(0)` ⇒ rouge sur l'ÉMETTEUR 1,
///      `left: None / right: Some(0.0)` (la cause n'est plus publiée) ; l'émetteur 2 reste vert.
///   2. chemin legal-hold -> `Retard::Mesure(0)` ⇒ rouge sur l'ÉMETTEUR 2, `left: None`, et lui seul.
///      Les deux émetteurs sont donc gardés INDÉPENDAMMENT.
///   3. `points()` publiant `NOM_RETARD_LIGNES` à `0.0` dans la branche `NonMesure` ⇒ rouge sur la
///      TROISIÈME assertion, `left: Some(0.0) / right: None` — le trou devenu zéro. Sans cette
///      mutation-là, rien ne prouverait que l'assertion d'ABSENCE mord.
#[test]
fn une_passe_suspendue_nomme_le_trou_du_detecteur_de_retard() {
    let etiquette_du_trou = format!("{{\"cause\":\"{RETARD_PASSE_SUSPENDUE}\"}}");

    // ---- ÉMETTEUR 1 : RÉTENTION GLOBALE TROP COURTE (`retention_days <= 1`) ----
    {
        let root = tmp_root("retard-susp-retention");
        let cold = root.join("cold");
        let db = mkdb(&root);
        cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), 1);

        assert_eq!(
            serie(&db, NOM_OK, Some("{\"cause\":\"retention_courte\"}")),
            Some(0.0),
            "précondition : la passe doit être SUSPENDUE pour rétention courte, sinon ce test regarde \
             autre chose que le chemin visé"
        );
        assert_eq!(
            serie(&db, NOM_RETARD_OK, Some(&etiquette_du_trou)),
            Some(0.0),
            "le trou du dead-man's-switch doit être NOMMÉ `{RETARD_PASSE_SUSPENDUE}` — sinon la série ne \
             distingue plus « le détecteur n'a pas tourné » de « il n'a pas tourné DEPUIS QUAND »"
        );
        assert_eq!(
            serie(&db, NOM_RETARD_LIGNES, None),
            None,
            "un compte de retard publié sur une passe qui n'a jamais atteint le détecteur se lirait \
             « à jour » — c'est précisément le mensonge que `P10.13-a` a fermé"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- ÉMETTEUR 2 : LEGAL-HOLD ACTIF (abstention DÉLIBÉRÉE, mais qui doit rester DITE) ----
    {
        let root = tmp_root("retard-susp-hold");
        let cold = root.join("cold");
        let db = mkdb(&root);
        let day = M - 11;
        let base = day * SECS_PER_DAY;
        for i in 0..10 {
            insert_event(&db, &rich_row(base + i, i));
        }
        {
            let c = db.lock();
            c.execute_batch("CREATE TABLE legal_hold(id INTEGER PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0)")
                .unwrap();
            c.execute("INSERT INTO legal_hold(active) VALUES(1)", []).unwrap();
        }

        cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

        assert_eq!(
            serie(&db, NOM_OK, Some("{\"cause\":\"legal_hold\"}")),
            Some(0.0),
            "précondition : le hold doit bien avoir suspendu la passe"
        );
        assert_eq!(count_hot_day(&db, "prod", day), 10, "précondition : le hold conserve les preuves chaudes");
        assert_eq!(
            serie(&db, NOM_RETARD_OK, Some(&etiquette_du_trou)),
            Some(0.0),
            "un hold est une abstention VISIBLE et auditée, pas un stall — mais la série doit le DIRE, \
             sinon son trou est indiscernable d'un démon arrêté"
        );
        assert_eq!(serie(&db, NOM_RETARD_LIGNES, None), None, "aucun verdict rendu -> aucun compte publié");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// SANS EXTENSION (le DÉFAUT de tous les déploiements), LE DÉTECTEUR N'EST PAS ARMÉ — ET LA SÉRIE LE
/// DIT. Avant `P10.13-a`, ce cas laissait un SILENCE : rien dans la série ne distinguait « le détecteur
/// n'a pas lieu d'être » de « il n'a rien trouvé ». Et il n'écrit RIEN dans `meta` : le chemin par
/// défaut reste sans effet de bord, comme il l'a toujours été.
///
/// MUTATION : rendre `Retard::Mesure(0)` au lieu de `NonMesure(RETARD_NON_ARME)` quand le gate est
/// fermé ⇒ la série publie un « 0 ligne de retard » pour un détecteur qui n'a jamais regardé.
#[test]
fn sans_extension_le_detecteur_nest_pas_arme_et_la_serie_le_nomme() {
    let root = tmp_root("retard-non-arme");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    for i in 0..20 {
        insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
    }
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS); // knob d'extension NON posé
    assert_eq!(
        serie(&db, NOM_RETARD_OK, Some(&format!("{{\"cause\":\"{RETARD_NON_ARME}\"}}"))),
        Some(0.0),
        "sans extension, la série doit NOMMER le trou au lieu de le laisser muet"
    );
    assert_eq!(
        compte_serie(&db, NOM_RETARD_LIGNES),
        0,
        "un compte de retard publié par un détecteur NON ARMÉ serait un chiffre que personne n'a mesuré"
    );
    assert_eq!(
        { let c = db.lock(); dernier_tir_du_retard(&c) },
        None,
        "le chemin par défaut (sans extension) ne doit RIEN écrire dans `meta`"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// P1.5 (test 6) — BANDES DISJOINTES sous extension : aucun jour n'est À LA FOIS agé ET hard-purgé, et aucun
// trou. On sème 1 ligne/jour à travers les frontières (hot | cold [hot_window..cold_ret] | purge > cold_ret),
// on lance l'aging PUIS le hard-purge hot étendu, et on vérifie que chaque jour atterrit dans EXACTEMENT une
// destination. Frontière : env_lo_day(aging)=ceil(n-cold_ret)=M-365 et cutoff(purge)=n-cold_ret*SECS -> le jour
// M-365 est agé (>=env_lo_day) et NON purgé (ts>=cutoff) ; M-366 est purgé (ts<cutoff) et NON agé -> disjoint, sans trou.
#[test]
fn p15_disjoint_bands_under_extension() {
    let root = tmp_root("p15disjoint");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let conf = conf_ext(&cold, 365);
    let cold_ret = cold_retention_days(&conf, RET_DAYS);
    let n = n_now();

    // Sème du plus ANCIEN au plus RÉCENT -> le plus récent (M-1, hot) détient le tail (garde H1 : rien différé).
    let purge_far = M - 400; // > cold_ret -> hard-purgé, jamais agé
    let purge_edge = M - 366; // juste au-delà de cold_ret(365) -> hard-purgé, jamais agé
    let cold_edge = M - 365; // FRONTIÈRE : agé (>= env_lo_day) et NON purgé
    let cold_mid = M - 100; // pleine bande cold -> agé
    let hot_recent = M - 1; // fenêtre chaude -> reste hot, tient le tail
    for d in [purge_far, purge_edge, cold_edge, cold_mid, hot_recent] {
        insert_event(&db, &rich_row(d * SECS_PER_DAY + 5, d));
    }

    // 1) AGING : columnarise la bande [hot_window, cold_ret]. 2) HARD-PURGE HOT à l'horizon ÉTENDU (cold_ret).
    cold_age_run(&db, "", &conf, n, RET_DAYS);
    let event_global_cutoff = n - cold_ret * SECS_PER_DAY;
    let policies = { let c = db.lock(); crate::rollups::load_index_policies(&c) };
    crate::rollups::retention_prune_table(&db, "event", "ts", RETENTION_NONPURGE, event_global_cutoff, n, &policies);

    // HOT : seul le jour récent subsiste.
    assert_eq!(count_hot_day(&db, "prod", hot_recent), 1, "jour récent reste HOT");
    // COLD (agés) : présents en cold ET absents du hot -> agés SEULEMENT (jamais aussi hard-purgés).
    for d in [cold_mid, cold_edge] {
        assert!(day_path(&cold, "prod", d).exists(), "jour {d} de la bande cold est COLD (agé)");
        assert_eq!(count_hot_day(&db, "prod", d), 0, "jour {d} agé -> hors du hot");
    }
    // FRONTIÈRE cold_edge (M-365) : agé et NON expiré (day > max_expire_day = M-366) -> seal présent.
    assert!(seal_state(&db.lock(), "prod", cold_edge).is_some(), "frontière M-365 agée et retenue (pas d'expiry)");
    // PURGE ( > cold_ret) : hard-purgés du hot ET JAMAIS columnarisés (aucun cold-file) -> purgés SEULEMENT.
    for d in [purge_far, purge_edge] {
        assert_eq!(count_hot_day(&db, "prod", d), 0, "jour {d} (> cold_ret) hard-purgé du hot");
        assert!(!day_path(&cold, "prod", d).exists(), "jour {d} (> cold_ret) JAMAIS agé (pas de cold-file) -> disjoint");
    }
    // NO GAP : chaque ligne semée est comptabilisée exactement une fois (hot + cold + purgée = 5, aucune perdue
    // silencieuse). cold = 2 fichiers (cold_mid, cold_edge) ; hot = 1 ; purgées = 2.
    assert_eq!(t_read(&day_path(&cold, "prod", cold_mid)).unwrap().len(), 1, "cold_mid : 1 ligne en cold");
    assert_eq!(t_read(&day_path(&cold, "prod", cold_edge)).unwrap().len(), 1, "cold_edge : 1 ligne en cold");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P2b — SPLIT MULTI-FICHIERS BORNÉS EN TAILLE (writer size-bounded, index par-fichier, crash-safety N fichiers).
// ====================================================================================================

/// conf cold-ON avec un PLAFOND DE FICHIER réduit (`file_cap`) pour forcer le split sur de petits volumes.
fn conf_split(cold_dir: &Path, file_cap: usize) -> HashMap<String, String> {
    let mut c = conf_on(cold_dir, HOT_WIN);
    c.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), file_cap.to_string());
    c
}

/// Nombre de fichiers cold scellés d'un (env, day) + leur Σ lignes (lu du seal PAR-FICHIER, sans déchiffrer).
fn file_seal_rows(db: &Arc<Mutex<Connection>>, env: &str, day: i64) -> Vec<FileSeal> {
    let c = db.lock();
    file_seals(&c, env, day)
}

/// Collecte TOUTES les lignes cold d'un jour à travers SES fichiers séquencés (déchiffre chaque fichier).
fn read_all_day_files(cold: &Path, env: &str, day: i64) -> Vec<ColdRow> {
    let mut out = Vec::new();
    let mut seq = 0i64;
    loop {
        let p = file_path(cold, env, day, seq);
        if !p.exists() {
            break;
        }
        out.extend(t_read(&p).unwrap());
        seq += 1;
    }
    out
}

/// Écrit+scelle un PRÉFIXE de `n_files` fichiers (seq 0..n_files) EXACTEMENT comme la production (write_one_file
/// -> fsync -> rename -> seal purged=0), mais SANS poser `last_file` -> état d'un crash EN PLEINE PHASE 1. Le hot
/// reste INTACT (aucun delete). Renvoie le curseur keyset (lo_ts, lo_id) du dernier fichier scellé (info seulement).
fn seal_prefix_no_last(db: &Arc<Mutex<Connection>>, cold: &Path, env: &str, day: i64, max_id: i64, file_cap: usize, rg_rows: usize, n_files: i64) {
    std::fs::create_dir_all(day_dir(cold, env)).unwrap();
    let (mut lo_ts, mut lo_id) = (i64::MIN, i64::MIN);
    for seq in 0..n_files {
        let final_path = file_path(cold, env, day, seq);
        let tmp = final_path.with_extension("parquet.tmp");
        let meta = write_one_file(&tmp, db, env, day, seq, max_id, lo_ts, lo_id, file_cap, rg_rows, &tpass())
            .unwrap()
            .expect("préfixe : fichier non vide attendu");
        fsync_file(&tmp).unwrap();
        std::fs::rename(&tmp, &final_path).unwrap();
        // seal purged=0, last_file=0 (Phase 1 NON commitée) — même contenu que le seal de production.
        seal_row(db, env, day, seq, meta.row_count as i64, 0, max_id, meta.ts_min, meta.ts_max, lo_ts, lo_id, meta.hi_id, 0);
        lo_ts = meta.ts_max;
        lo_id = meta.hi_id;
    }
}

// P2b (test 1) — un jour EXCÉDANT le plafond de fichier produit PLUSIEURS fichiers séquencés, chacun
// INDÉPENDAMMENT déchiffrable+vérifiable sous SA propre identité (env,day,seq), et l'UNION couvre EXACTEMENT les
// lignes du jour (aucun trou, aucun doublon).
#[test]
fn p2b_day_over_cap_splits_into_verifiable_sequenced_files() {
    let root = tmp_root("p2bsplit");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let total: i64 = 35;
    for i in 0..total {
        insert_event(&db, &rich_row(base + i, i)); // ts distincts base..base+34
    }
    insert_recent_tail_holder(&db); // garde H1 : le jour agé ne détient pas le tail.

    cold_age_run(&db, "", &conf_split(&cold, 10), n_now(), RET_DAYS); // cap=10 -> 4 fichiers (10,10,10,5)

    assert_eq!(count_hot_day(&db, "prod", day), 0, "toutes les lignes du jour agées");
    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 4, "35 lignes / cap 10 -> 4 fichiers séquencés");
    // seq contigus 0..3, exactement un last_file, tous purgés.
    for (i, s) in seals.iter().enumerate() {
        assert_eq!(s.seq, i as i64, "seq contigu");
        assert!(s.purged, "fichier {} purgé après Phase 2", s.seq);
    }
    assert_eq!(seals.iter().filter(|s| s.last_file).count(), 1, "UN seul marqueur last_file (dernier seq)");
    assert!(seals.last().unwrap().last_file, "last_file sur le PLUS HAUT seq");
    // Chaque fichier existe, est INDÉPENDAMMENT déchiffrable ET vérifiable sous SON identité (env,day,seq,ts).
    for s in &seals {
        let p = file_path(&cold, "prod", day, s.seq);
        assert!(p.exists(), "fichier seq {} présent", s.seq);
        assert!(t_verify_id_seq(&p, s.expected as usize, "prod", day, s.seq, s.ts_min, s.ts_max).is_ok(), "fichier seq {} vérifiable seul", s.seq);
        assert!(s.expected <= 10, "fichier seq {} <= cap", s.seq);
    }
    // UNION == exactement les 35 lignes du jour, sans trou ni doublon (ts distincts base..base+34).
    let mut ts: Vec<i64> = read_all_day_files(&cold, "prod", day).iter().map(|c| c.row.ts).collect();
    ts.sort_unstable();
    let expected_ts: Vec<i64> = (0..total).map(|i| base + i).collect();
    assert_eq!(ts, expected_ts, "union des fichiers = exactement les lignes du jour (no gap/dup)");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b (test 2) — l'index PAR-FICHIER `ts_min`/`ts_max` du seal est CORRECT et permet d'ÉLAGUER (sélectionner)
// les fichiers chevauchant une fenêtre sous-journalière SANS déchiffrer aucun fichier (métadonnées seal seules).
#[test]
fn p2b_per_file_ts_bounds_prune_without_decrypt() {
    let root = tmp_root("p2bprune");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..30 {
        insert_event(&db, &rich_row(base + i, i)); // ts = base+0..base+29
    }
    insert_recent_tail_holder(&db);

    cold_age_run(&db, "", &conf_split(&cold, 10), n_now(), RET_DAYS); // 3 fichiers : [base..+9],[+10..+19],[+20..+29]

    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 3);
    assert_eq!((seals[0].ts_min, seals[0].ts_max), (base, base + 9), "fichier 0 borné [base, base+9]");
    assert_eq!((seals[1].ts_min, seals[1].ts_max), (base + 10, base + 19), "fichier 1 borné [base+10, base+19]");
    assert_eq!((seals[2].ts_min, seals[2].ts_max), (base + 20, base + 29), "fichier 2 borné [base+20, base+29]");
    // ÉLAGAGE d'une fenêtre sous-journalière [base+12, base+15] : décision UNIQUEMENT sur (ts_min, ts_max) du
    // seal — AUCUN open_cold_reader/déchiffrement. Seul le fichier 1 chevauche.
    let (win_lo, win_hi) = (base + 12, base + 15);
    let selected: Vec<i64> = seals
        .iter()
        .filter(|s| s.ts_min <= win_hi && s.ts_max >= win_lo) // overlap [ts_min,ts_max] ∩ [win_lo,win_hi]
        .map(|s| s.seq)
        .collect();
    assert_eq!(selected, vec![1], "seul le fichier 1 chevauche la fenêtre -> les fichiers 0 et 2 sont élagués SANS déchiffrer");
    // Contrôle : une fenêtre à cheval sur deux fichiers en sélectionne DEUX (frontière).
    let spanning: Vec<i64> = seals.iter().filter(|s| s.ts_min <= base + 20 && s.ts_max >= base + 9).map(|s| s.seq).collect();
    assert_eq!(spanning, vec![0, 1, 2], "fenêtre [base+9, base+20] chevauche les trois fichiers");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b (test 3) — CRASH EN PHASE 1 (préfixe de fichiers scellés, AUCUN last_file, hot INTACT) : le re-run COMPLÈTE
// le jour (écrit les fichiers manquants depuis le hot intact, pose last_file, supprime) SANS perte ni doublon.
// Pilote le VRAI chemin de reprise (seals présents + pas de last_file -> resume-écriture puis Phase 2).
#[test]
fn p2b_crash_mid_phase1_resume_completes_no_loss_no_dup() {
    let root = tmp_root("p2bcrash");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let total: i64 = 25;
    for i in 0..total {
        insert_event(&db, &rich_row(base + i, i)); // ts distincts base..base+24, ids 1..25
    }
    insert_recent_tail_holder(&db); // le jour ne détient pas le tail (réaliste : H1 passé au 1er tick)
    // max_id = borne d'identité de l'ensemble du jour (comme la production le capturerait au snapshot).
    let (_, max_id) = { let c = db.lock(); count_and_max_id(&c, "prod", day).unwrap() };

    // CRASH SIMULÉ : seuls seq 0 et 1 sont scellés (purged=0), pas de last_file -> Phase 2 JAMAIS démarrée -> hot intact.
    seal_prefix_no_last(&db, &cold, "prod", day, max_id, 10, 10, 2);
    assert!(file_path(&cold, "prod", day, 0).exists() && file_path(&cold, "prod", day, 1).exists(), "seq 0,1 scellés");
    assert!(!file_path(&cold, "prod", day, 2).exists(), "seq 2 PAS encore écrit (crash)");
    assert_eq!(count_hot_day(&db, "prod", day), 25, "hot INTACT en Phase 1 (aucun delete avant last_file)");
    assert!(file_seal_rows(&db, "prod", day).iter().all(|s| !s.last_file), "aucun last_file (Phase 1 non commitée)");

    // RE-RUN : reprise réelle. Complète seq 2, pose last_file, Phase 2 -> hot drainé.
    cold_age_run(&db, "", &conf_split(&cold, 10), n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 0, "reprise : jour entièrement drainé (pas de dup résiduel)");
    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 3, "3 fichiers au total (2 repris du préfixe + 1 complété)");
    assert!(seals.iter().all(|s| s.purged), "tous les fichiers purgés");
    assert_eq!(seals.iter().filter(|s| s.last_file).count(), 1, "exactement un last_file après reprise");
    // NO LOSS / NO DUP : union == exactement les 25 lignes (ts distincts).
    let mut ts: Vec<i64> = read_all_day_files(&cold, "prod", day).iter().map(|c| c.row.ts).collect();
    ts.sort_unstable();
    assert_eq!(ts, (0..total).map(|i| base + i).collect::<Vec<_>>(), "reprise : toutes les lignes présentes une seule fois");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b (test 4) — la LIAISON (env, day, seq) récuse un fichier PLACÉ AU MAUVAIS seq (swap intra-jour de séquence),
// même parfaitement déchiffrable/décodable (le seq stampé DANS l'AEAD ne correspond pas).
#[test]
fn p2b_seq_binding_rejects_file_at_wrong_seq() {
    let root = tmp_root("p2bseq");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..25 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, "", &conf_split(&cold, 10), n_now(), RET_DAYS); // 3 fichiers seq 0,1,2

    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 3);
    let (s0, s1) = (&seals[0], &seals[1]);
    let p0 = file_path(&cold, "prod", day, 0);
    // (a) fichier 0 vérifie SOUS son vrai seq=0, mais est REJETÉ exigé sous seq=1 (KV seq lié = 0).
    assert!(t_verify_id_seq(&p0, s0.expected as usize, "prod", day, 0, s0.ts_min, s0.ts_max).is_ok(), "fichier 0 OK sous seq=0");
    assert!(t_verify_id_seq(&p0, s0.expected as usize, "prod", day, 1, s0.ts_min, s0.ts_max).is_err(), "fichier 0 exigé sous seq=1 -> REFUS (swap de séquence)");
    // (b) ATTAQUANT : place le contenu du fichier 1 au chemin du fichier 0. Vérifié sous seq=0 -> REJET (stampé seq=1).
    std::fs::copy(file_path(&cold, "prod", day, 1), &p0).unwrap();
    assert!(t_verify_id_seq(&p0, s1.expected as usize, "prod", day, 0, s1.ts_min, s1.ts_max).is_err(), "fichier de seq=1 posé au chemin seq=0 -> REFUS (seq lié != attendu)");
    // ... mais le MÊME contenu vérifie sous sa VRAIE séquence (seq=1).
    assert!(t_verify_id_seq(&p0, s1.expected as usize, "prod", day, 1, s1.ts_min, s1.ts_max).is_ok(), "le même contenu vérifie sous SA vraie séquence seq=1");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b (test 5) — BORNE DE TAILLE PAR FICHIER : un GROS jour produit BEAUCOUP de fichiers plafonnés, AUCUN
// n'excédant le plafond (RAM de déchiffrement bornée à VOLUME QUELCONQUE : plus de fichiers, pas de fichiers plus gros).
#[test]
fn p2b_per_file_size_cap_holds_on_huge_day() {
    let root = tmp_root("p2bcap");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let total: i64 = 95;
    for i in 0..total {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let cap = 10usize;

    cold_age_run(&db, "", &conf_split(&cold, cap), n_now(), RET_DAYS);

    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 10, "95 lignes / cap 10 -> 10 fichiers (9x10 + 1x5)");
    let mut sum = 0i64;
    for s in &seals {
        assert!(s.expected as usize <= cap, "AUCUN fichier n'excède le plafond ({} <= {cap})", s.expected);
        // Contrôle indépendant : le footer Parquet du fichier confirme <= cap lignes.
        let p = file_path(&cold, "prod", day, s.seq);
        assert!(t_footer(&p).unwrap() as usize <= cap, "footer seq {} <= cap", s.seq);
        sum += s.expected;
    }
    assert_eq!(sum, total, "Σ des fichiers = total du jour (aucune ligne perdue par le plafonnement)");
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour entièrement drainé");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P2b — READER / HYDRATE (primitive INTERNE, table cold_event éphémère). Masquage/DENY = P3 (jamais ici).
// ====================================================================================================

/// Toutes les colonnes cold PROJETABLES (= PARQUET_COLS sans "ts", que hydrate_cold force toujours) — projection
/// « tout » pour les tests de fidélité.
const ALL_HYDRATE_COLS: [&str; 14] = [
    "severity", "source", "category", "host", "src_ip", "dst_ip", "url", "xff", "dedup",
    "engagement_id", "origin", "env_id", "message", "fields",
];

/// Hydrate une fenêtre pour le tenant DÉFAUT (db_path ""), verrou db pris le temps de la prune (les workers ne
/// touchent JAMAIS la connexion tenant -> pas de deadlock). Renvoie la table cold_event éphémère + métadonnées.
fn hydrate_win(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>, env: &str, lo: i64, hi: i64, cols: &[&str]) -> Result<ColdHydrate, String> {
    let g = db.lock();
    hydrate_cold(&g, conf, "", env, lo, hi, cols, &[])
}

/// #28 PHASE B — hydrate AVEC prédicats sur une base PAR-TENANT (`dbp`) -> `cold_root = {dbp}.cold` (JAMAIS
/// `PLUME_COLD_DIR`) -> IMMUNISÉ à la course inter-tests sur l'env process-global `PLUME_COLD_DIR` (les tests
/// cold-caps de tests/ingest mutent cet env ; `cfg` fait env > conf). Exerce l'élagage min/max + bloom sans déchiffrer.
fn hydrate_dbp_pred(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>, dbp: &str, env: &str, lo: i64, hi: i64, cols: &[&str], preds: &[DimEq]) -> Result<ColdHydrate, String> {
    let g = db.lock();
    hydrate_cold(&g, conf, dbp, env, lo, hi, cols, preds)
}
/// conf cold PAR-TENANT (SANS `PLUME_COLD_DIR` -> `cold_root` dérivé du db_path, race-immune). `cap` = plafond
/// lignes/fichier (split) optionnel.
fn pb_conf(cap: Option<usize>) -> HashMap<String, String> {
    let mut m = conf_union(HOT_WIN);
    if let Some(c) = cap {
        m.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), c.to_string());
    }
    m
}

/// Dump DÉTERMINISTE de cold_event (ORDER BY id -> ordre d'insertion canonique) pour comparaison bit-à-bit.
fn dump_cold(h: &ColdHydrate) -> Vec<(i64, i64, String, Option<String>, Option<String>, Option<String>, i64)> {
    let mut st = h
        .conn
        .prepare("SELECT id, ts, source, host, xff, fields, severity FROM cold_event ORDER BY id")
        .unwrap();
    st.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, i64>(6)?,
        ))
    })
    .unwrap()
    .map(|x| x.unwrap())
    .collect()
}

// P2b READER (test 1) — ÉLAGAGE SANS DÉCHIFFREMENT : la prune sélectionne EXACTEMENT les fichiers dont
// [ts_min,ts_max] chevauche la fenêtre ; les fichiers NON chevauchants ne sont JAMAIS ouverts. Prouvé en
// CORROMPANT les fichiers hors fenêtre : si la prune les ouvrait, l'hydratation échouerait — elle réussit.
#[test]
fn p2b_hydrate_prune_selects_only_overlapping_files_non_overlap_not_opened() {
    let root = tmp_root("hydprune");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..30 {
        insert_event(&db, &rich_row(base + i, i)); // ts base+0..base+29
    }
    insert_recent_tail_holder(&db);
    let conf = conf_split(&cold, 10); // 3 fichiers : [base..+9],[+10..+19],[+20..+29]
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 3);

    // CORROMPT les fichiers 0 et 2 (hors de la fenêtre [base+12, base+15]) : s'ils étaient ouverts par la prune
    // ou lus, l'AEAD échouerait. La fenêtre ne chevauche QUE le fichier 1.
    for seq in [0i64, 2] {
        let p = file_path(&cold, "prod", day, seq);
        let mut b = std::fs::read(&p).unwrap();
        let mid = b.len() / 2;
        b[mid] ^= 0xFF;
        std::fs::write(&p, &b).unwrap();
    }

    let h = hydrate_win(&db, &conf, "prod", base + 12, base + 15, &ALL_HYDRATE_COLS).expect("prune -> seul fichier 1, sain");
    assert_eq!(h.files_read, 1, "un seul fichier sélectionné (chevauche la fenêtre)");
    assert_eq!(h.files_pruned, 2, "deux fichiers élagués (hors fenêtre) — jamais ouverts (sinon corruption -> Err)");
    assert_eq!(h.rows_hydrated, 4, "exactement ts base+12..base+15");
    assert!(!h.truncated);
    let mut ts: Vec<i64> = h.conn.prepare("SELECT ts FROM cold_event ORDER BY ts").unwrap().query_map([], |r| r.get::<_, i64>(0)).unwrap().map(|x| x.unwrap()).collect();
    ts.sort_unstable();
    assert_eq!(ts, vec![base + 12, base + 13, base + 14, base + 15]);
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 2) — ROUND-TRIP d'hydratation : toutes les colonnes demandées correctes, `fields` JSON +
// NULLs intacts, et les lignes HORS fenêtre exclues.
#[test]
fn p2b_hydrate_roundtrip_cols_json_nulls_and_window() {
    let root = tmp_root("hydrt");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i)); // ts base+0..base+19
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN); // 1 fichier (cap défaut)
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    // Fenêtre SOUS-journalière [base+5, base+14] -> 10 lignes ; hors-fenêtre (0..4, 15..19) exclues.
    let h = hydrate_win(&db, &conf, "prod", base + 5, base + 14, &ALL_HYDRATE_COLS).unwrap();
    assert_eq!(h.rows_hydrated, 10, "seule la fenêtre [+5,+14]");
    assert!(!h.truncated);
    // Aucune ligne hors fenêtre.
    let out_of_win: i64 = h.conn.query_row("SELECT COUNT(*) FROM cold_event WHERE ts<?1 OR ts>?2", params![base + 5, base + 14], |r| r.get(0)).unwrap();
    assert_eq!(out_of_win, 0, "lignes hors fenêtre exclues");

    // Fidélité colonne-à-colonne + NULLs + JSON. i=6 : dedup=Some(d-6) (pair), xff=Some(xff-6) (6%3==0),
    // dst_ip=None, fields=JSON. i=7 : dedup=None (impair), xff=None (7%3!=0).
    let (src6, host6, dst6, ded6, xff6, fld6): (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) = h
        .conn
        .query_row("SELECT source,host,dst_ip,dedup,xff,fields FROM cold_event WHERE ts=?1", params![base + 6], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })
        .unwrap();
    assert_eq!(src6, "src-6");
    assert_eq!(host6.as_deref(), Some("host-6"));
    assert_eq!(dst6, None, "dst_ip NULL préservé");
    assert_eq!(ded6.as_deref(), Some("d-6"), "dedup non-NULL (pair)");
    assert_eq!(xff6.as_deref(), Some("xff-6"), "xff non-NULL (6%3==0)");
    assert_eq!(fld6.as_deref(), Some("{\"k\":6,\"nested\":{\"a\":\"b\"}}"), "fields JSON intact bit-à-bit");
    let (ded7, xff7): (Option<String>, Option<String>) =
        h.conn.query_row("SELECT dedup,xff FROM cold_event WHERE ts=?1", params![base + 7], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(ded7, None, "dedup NULL (impair) préservé");
    assert_eq!(xff7, None, "xff NULL (7%3!=0) préservé");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 2b) — PROJECTION : une colonne NON demandée reste NULL dans cold_event (on ne matérialise que
// les colonnes projetées), la colonne demandée est peuplée. Le schéma reste complet (union P3), seule la donnée
// des colonnes non-projetées est absente.
#[test]
fn p2b_hydrate_projection_leaves_unrequested_columns_null() {
    let root = tmp_root("hydproj");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    for i in 0..6 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    // On ne demande QUE `source` (+ ts forcé). `message`/`fields`/`host` NON projetés -> NULL.
    let h = hydrate_win(&db, &conf, "prod", base, base + 5, &["source"]).unwrap();
    assert_eq!(h.rows_hydrated, 6);
    let non_null_src: i64 = h.conn.query_row("SELECT COUNT(*) FROM cold_event WHERE source IS NOT NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(non_null_src, 6, "colonne demandée peuplée");
    let non_null_msg: i64 = h.conn.query_row("SELECT COUNT(*) FROM cold_event WHERE message IS NOT NULL OR fields IS NOT NULL OR host IS NOT NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(non_null_msg, 0, "colonnes non demandées laissées NULL (projection)");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 3) — FAIL-SAFE PLAFOND : au-delà du row-cap interactif (défaut PLUME_QUERY_MAX=5000), on
// TRONQUE et on SIGNALE (jamais une réponse incomplète silencieuse). Utilise le défaut 5000 (pas de mutation
// d'env, sûr en tests parallèles) : 5001 lignes -> 5000 hydratées + truncated=true.
#[test]
fn p2b_hydrate_row_cap_truncates_and_signals() {
    let root = tmp_root("hydcap");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    let total: i64 = 5001; // > cap défaut (5000)
    {
        // insertion en un lot (transaction) pour la vitesse.
        let c = db.lock();
        let tx = c.unchecked_transaction().unwrap();
        for i in 0..total {
            let r = rich_row(base + i, i);
            tx.execute(
                "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![r.row.ts, r.row.severity, r.row.source, r.row.category, r.row.host, r.row.src_ip, r.row.dst_ip, r.row.url, r.xff, r.row.dedup, r.row.engagement_id, r.row.origin, r.row.env_id, r.row.message, r.row.fields],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    let h = hydrate_win(&db, &conf, "prod", base, base + total, &["source"]).unwrap();
    assert_eq!(h.rows_hydrated, 5000, "tronqué au plafond interactif (PLUME_QUERY_MAX défaut)");
    assert!(h.truncated, "troncature SIGNALÉE (jamais une réponse incomplète silencieuse)");
    let n: i64 = h.conn.query_row("SELECT COUNT(*) FROM cold_event", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 5000, "cold_event borné au plafond");
    // Déterminisme du préfixe tronqué : les 5000 premières lignes CANONIQUES (ts base+0..base+4999).
    let max_ts: i64 = h.conn.query_row("SELECT MAX(ts) FROM cold_event", [], |r| r.get(0)).unwrap();
    assert_eq!(max_ts, base + 4999, "préfixe canonique déterministe (les 5000 plus anciennes)");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 4) — DÉTERMINISME PARALLÈLE : le contenu de cold_event est IDENTIQUE à degré 1 et à degré 4
// (rowid inclus) -> aucun ordre d'achèvement de worker ni horloge ne fuit dans le résultat.
#[test]
fn p2b_hydrate_parallel_determinism_degree1_vs_4() {
    let _el = par_env_lock();
    let root = tmp_root("hyddet");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..45 {
        insert_event(&db, &rich_row(base + i, i)); // 45 lignes
    }
    insert_recent_tail_holder(&db);
    let conf = conf_split(&cold, 10); // cap 10 -> 5 fichiers (assez pour occuper 4 workers)
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 5);

    // Degré 1 (séquentiel) vs 4 (parallèle). PLUME_COLD_READ_PARALLELISM ne change QUE la performance/le degré,
    // jamais la correction/déterminisme d'AUTRES tests -> sûr en parallèle. On restaure à la fin.
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "1");
    let h1 = hydrate_win(&db, &conf, "prod", base, base + 44, &ALL_HYDRATE_COLS).unwrap();
    let dump1 = dump_cold(&h1);
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "4");
    let h4 = hydrate_win(&db, &conf, "prod", base, base + 44, &ALL_HYDRATE_COLS).unwrap();
    let dump4 = dump_cold(&h4);
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");

    assert_eq!(h1.rows_hydrated, 45);
    assert_eq!(h4.rows_hydrated, 45);
    assert_eq!(dump1, dump4, "cold_event IDENTIQUE (rowid inclus) quel que soit le degré de parallélisme");
    // Ordre canonique = (day, seq, position) == ts croissant ici (ts distincts, triés) -> rowid monotone sur ts.
    let ts: Vec<i64> = dump1.iter().map(|r| r.1).collect();
    let mut sorted = ts.clone();
    sorted.sort_unstable();
    assert_eq!(ts, sorted, "insertion en ordre canonique déterministe");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 5a) — POLITIQUE CORRUPTION : un fichier SÉLECTIONNÉ corrompu -> hydrate_cold ÉCHOUE
// (fail-closed), JAMAIS de résultat cold partiel silencieux.
#[test]
fn p2b_hydrate_corrupt_selected_file_fails_closed_no_partial() {
    let root = tmp_root("hydcorrupt");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..25 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_split(&cold, 10); // 3 fichiers
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 3);

    // Corrompt le CIPHERTEXT du fichier 1 (SÉLECTIONNÉ par une fenêtre couvrant tout le jour).
    let p1 = file_path(&cold, "prod", day, 1);
    let mut b = std::fs::read(&p1).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xFF;
    std::fs::write(&p1, &b).unwrap();

    let res = hydrate_win(&db, &conf, "prod", base, base + 24, &ALL_HYDRATE_COLS);
    let err = res.err().expect("un fichier sélectionné corrompu -> hydrate_cold ÉCHOUE (jamais de cold partiel)");
    assert!(err.contains("ÉCHOUÉE"), "erreur explicite fail-closed: {err}");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 5b) — POLITIQUE MAUVAISE CLÉ / IDENTITÉ : une clé tenant ÉTRANGÈRE (ou une identité liée
// != attendue) -> verify échoue sur les fichiers sélectionnés -> hydrate_cold ÉCHOUE (fail-closed).
#[test]
fn p2b_hydrate_wrong_key_fails_closed() {
    let root = tmp_root("hydwrongkey");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS); // écrit avec TEST_DB_KEY

    // Conf avec une clé PLUME_DB_KEY ÉTRANGÈRE : cold_aead_passphrase dérive une passphrase FAUSSE -> déchiffrement
    // rejeté sur chaque fichier sélectionné -> Err (jamais de partiel). Même racine cold (fichiers présents).
    let mut wrong = conf.clone();
    wrong.insert("PLUME_DB_KEY".to_string(), "cle-completement-etrangere-au-tenant-cold-000".to_string());
    let res = hydrate_win(&db, &wrong, "prod", base, base + 11, &ALL_HYDRATE_COLS);
    assert!(res.is_err(), "mauvaise clé tenant -> hydrate_cold ÉCHOUE (fail-closed)");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 6) — SÉCURITÉ (structurel) : hydrate_cold est une primitive INTERNE. AUCUN chemin de requête
// utilisateur (query_exec) ni handler ne la référence (sinon = fuite de lignes cold BRUTES non masquées, le
// masquage/DENY étant P3). On balaie tout src/ SAUF cold_store.rs / cold_store/ et on prouve zéro référence.
#[test]
fn p2b_hydrate_is_internal_no_query_or_handler_reference() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fn walk(dir: &Path, hits: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, hits);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                // EXCLUT le module cold_store lui-même (définition + tests) — la seule surface légitime.
                let s = p.to_string_lossy();
                if s.contains("cold_store") {
                    continue;
                }
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    if txt.contains("hydrate_cold") {
                        hits.push(s.to_string());
                    }
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(&src, &mut hits);
    assert!(
        hits.is_empty(),
        "hydrate_cold NE DOIT être référencée par AUCUN chemin de requête/handler (fuite cold non masqué) — trouvé dans: {hits:?}"
    );
}

// P2b READER (test 7) — BORNES DE L'ÉLAGAGE (égalités INCLUSIVES). Le prédicat de chevauchement
// `ts_min <= q_end && ts_max >= q_start` ET la dérivation `[lo_day, hi_day]` (via `div_euclid`) DOIVENT inclure les
// ÉGALITÉS EXACTES. On prouve quatre bornes et on vérifie que la ligne-borne apparaît bien dans cold_event (jamais
// élaguée par erreur) : (a) fichier dont `ts_max == q_start` ; (b) fichier dont `ts_min == q_end` ; (c) fenêtre de
// LARGEUR NULLE (`q_start == q_end`) tombant DANS un fichier ; (d) fin de fenêtre = multiple EXACT de 86400 (la
// ligne à `ts == q_end`, 1re seconde du jour, vit dans `hi_day` -> le jour du fichier DOIT être balayé).
#[test]
fn p2b_hydrate_prune_boundary_inclusive_equalities() {
    let root = tmp_root("hydbound");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY; // MULTIPLE EXACT de 86400 (début du jour) -> sert la borne (d).
    for i in 0..30 {
        insert_event(&db, &rich_row(base + i, i)); // ts base+0..base+29, UN SEUL fichier (cap défaut 262144)
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 1, "un seul fichier -> ts_min=base, ts_max=base+29");

    // (a) ts_max == q_start : la fenêtre COMMENCE exactement au ts max du fichier -> sélectionné (>= inclusif) ;
    //     ligne borne (ts=base+29) hydratée ; aucun ts > base+29 -> exactement 1 ligne.
    let ha = hydrate_win(&db, &conf, "prod", base + 29, base + 40, &ALL_HYDRATE_COLS).unwrap();
    assert_eq!(ha.files_read, 1, "ts_max==q_start -> chevauchement inclusif (fichier sélectionné)");
    assert_eq!(ha.rows_hydrated, 1);
    assert_eq!(ha.conn.query_row("SELECT ts FROM cold_event", [], |r| r.get::<_, i64>(0)).unwrap(), base + 29, "ligne à ts_max==q_start présente");

    // (b) ts_min == q_end : la fenêtre FINIT exactement au ts min du fichier -> sélectionné (<= inclusif) ; ligne
    //     borne (ts=base) hydratée ; aucun ts < base -> exactement 1 ligne. (q_start dans le jour PRÉCÉDENT.)
    let hb = hydrate_win(&db, &conf, "prod", base - 6, base, &ALL_HYDRATE_COLS).unwrap();
    assert_eq!(hb.files_read, 1, "ts_min==q_end -> chevauchement inclusif (fichier sélectionné)");
    assert_eq!(hb.rows_hydrated, 1);
    assert_eq!(hb.conn.query_row("SELECT ts FROM cold_event", [], |r| r.get::<_, i64>(0)).unwrap(), base, "ligne à ts_min==q_end présente");

    // (c) fenêtre de LARGEUR NULLE (q_start == q_end) tombant DANS le fichier -> exactement la ligne à ce ts.
    let hc = hydrate_win(&db, &conf, "prod", base + 15, base + 15, &ALL_HYDRATE_COLS).unwrap();
    assert_eq!(hc.files_read, 1, "fenêtre point -> fichier contenant le point sélectionné");
    assert_eq!(hc.rows_hydrated, 1);
    assert_eq!(hc.conn.query_row("SELECT ts FROM cold_event", [], |r| r.get::<_, i64>(0)).unwrap(), base + 15, "unique ligne au point de la fenêtre");

    // (d) fin de fenêtre = MULTIPLE EXACT de 86400 : q_end == base == day*86400 -> hi_day = q_end.div_euclid(86400)
    //     == day. q_start dans le jour PRÉCÉDENT -> lo_day == day-1 < hi_day : PREUVE que hi_day inclut bien le jour
    //     du fichier même quand q_end est la TOUTE 1re seconde du jour. La ligne à ts==q_end DOIT être hydratée.
    assert_eq!(base % SECS_PER_DAY, 0, "précondition : q_end est un multiple exact de 86400");
    let hd = hydrate_win(&db, &conf, "prod", base - 100, base, &ALL_HYDRATE_COLS).unwrap();
    assert_eq!(hd.files_read, 1, "q_end multiple de 86400 -> hi_day==day -> fichier du jour balayé");
    assert_eq!(hd.rows_hydrated, 1, "seule la ligne à ts==q_end (1re seconde du jour) est dans la fenêtre");
    assert_eq!(hd.conn.query_row("SELECT ts FROM cold_event", [], |r| r.get::<_, i64>(0)).unwrap(), base, "ligne à ts==q_end (multiple) hydratée depuis hi_day");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 8) — TRONCATURE MULTI-FICHIERS DÉTERMINISTE. Une requête couvrant PLUSIEURS fichiers cold dont
// le Σ lignes DÉPASSE le plafond (`cold_hydrate_row_cap`, défaut 5000) -> `truncated=true` ET le préfixe tronqué est
// le préfixe CANONIQUE (day,seq,position) déterministe, IDENTIQUE à degré 1 et 4. On utilise le plafond DÉFAUT 5000
// (5001 lignes réparties en 3 fichiers) -> AUCUNE mutation de PLUME_QUERY_MAX -> sûr en tests parallèles.
#[test]
fn p2b_hydrate_multifile_truncation_deterministic() {
    let _el = par_env_lock();
    let root = tmp_root("hydmftrunc");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    let total: i64 = 5001; // > cap défaut 5000
    {
        // insertion en un lot (transaction) pour la vitesse.
        let c = db.lock();
        let tx = c.unchecked_transaction().unwrap();
        for i in 0..total {
            let r = rich_row(base + i, i);
            tx.execute(
                "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![r.row.ts, r.row.severity, r.row.source, r.row.category, r.row.host, r.row.src_ip, r.row.dst_ip, r.row.url, r.xff, r.row.dedup, r.row.engagement_id, r.row.origin, r.row.env_id, r.row.message, r.row.fields],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    insert_recent_tail_holder(&db);
    let conf = conf_split(&cold, 2000); // 5001 lignes -> 3 fichiers bornés (2000,2000,1001)
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 3, "requête MULTI-fichiers (3 fichiers scellés)");

    // Degré 1 (séquentiel) vs 4 (parallèle) -> MÊME préfixe tronqué. PLUME_COLD_READ_PARALLELISM ne change QUE le
    // degré ; toutes les assertions (dump, compte, troncature) sont INVARIANTES au degré -> sûres même sous course
    // d'env (le même knob est basculé par p2b_hydrate_parallel_determinism_degree1_vs_4, sans conséquence).
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "1");
    let h1 = hydrate_win(&db, &conf, "prod", base, base + total, &ALL_HYDRATE_COLS).unwrap();
    let dump1 = dump_cold(&h1);
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "4");
    let h4 = hydrate_win(&db, &conf, "prod", base, base + total, &ALL_HYDRATE_COLS).unwrap();
    let dump4 = dump_cold(&h4);
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");

    assert!(h1.truncated && h4.truncated, "Σ lignes (5001) > plafond (5000) -> troncature SIGNALÉE aux deux degrés");
    assert_eq!(h1.rows_hydrated, 5000, "borné au plafond défaut 5000 (séquentiel)");
    assert_eq!(h4.rows_hydrated, 5000, "borné au plafond défaut 5000 (parallèle)");
    assert_eq!(h1.files_read, 3);
    assert_eq!(h4.files_read, 3);
    assert_eq!(dump1, dump4, "préfixe tronqué IDENTIQUE degré 1 vs 4 (canonique, rowid inclus)");
    assert_eq!(dump1.len(), 5000, "dump du préfixe tronqué");
    // Préfixe CANONIQUE = les 5000 lignes les plus ANCIENNES (ts base+0..base+4999) ; la 5001e (base+5000, dernière
    // ligne du 3e fichier) est JETÉE de façon déterministe.
    let max_ts: i64 = h1.conn.query_row("SELECT MAX(ts) FROM cold_event", [], |r| r.get(0)).unwrap();
    assert_eq!(max_ts, base + 4999, "préfixe canonique déterministe : 5000 plus anciennes, dernière ligne jetée");
    let _ = std::fs::remove_dir_all(&root);
}

// P2b READER (test 9 — INVARIANT DRAIN-ON-ERROR, DOCUMENTÉ). Le correctif MED de l'inséreur (deadlock latent) :
// une défaillance CÔTÉ INSÉREUR (`mem.prepare` / `stmt.execute` en mémoire, ex. SQLITE_NOMEM) NE ?-retourne PLUS
// mid-drain — elle enregistre `first_err` + `abort` puis DRAINE `rx` jusqu'à fermeture, de sorte qu'aucun worker
// bloqué sur `tx.send` (canal `sync_channel(degree)` plein) ne reste bloqué -> `thread::scope` joint proprement,
// puis `hydrate_cold` renvoie Err (fail-closed, jamais de cold_event partiel). Cette défaillance N'EST PAS
// injectable proprement : le schéma de `cold_event` est SANS contrainte (relâché à dessein pour la projection),
// donc un INSERT n'échoue que sur épuisement mémoire réel (SQLITE_NOMEM) — non déclenchable sans un drapeau de
// faute `#[cfg(test)]` DANS la boucle d'insertion de production (machinerie test-only prohibée). CONFORMÉMENT à la
// consigne, on DOCUMENTE donc l'invariant (ce test + les commentaires aux deux sites corrigés dans cold_store.rs)
// plutôt que d'injecter une faute artificielle. Les chemins d'erreur RÉELLEMENT atteignables (fichier corrompu /
// mauvaise clé -> erreur CÔTÉ WORKER) sont couverts par 5a/5b et empruntent le MÊME chemin de drain (déjà sûr).
#[test]
fn p2b_hydrate_inserter_error_drain_invariant_documented() {
    let _el = par_env_lock();
    // Sanity de non-régression du chemin d'erreur ATTEIGNABLE le plus proche (erreur worker, même drain que
    // l'inséreur) : un fichier sélectionné corrompu -> Err sans blocage, aucun cold partiel. (Backstop léger ;
    // l'assertion anti-deadlock forte vit dans le raisonnement + les commentaires du site corrigé.)
    let root = tmp_root("hyddrain");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_split(&cold, 8); // 5 fichiers -> canal sync_channel(degree) réellement mis sous pression
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 5);
    // Corrompt un fichier sélectionné -> erreur worker -> abort + drain -> Err propre (le join ne pend jamais).
    let p = file_path(&cold, "prod", day, 2);
    let mut b = std::fs::read(&p).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xFF;
    std::fs::write(&p, &b).unwrap();
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "4");
    let res = hydrate_win(&db, &conf, "prod", base, base + 39, &ALL_HYDRATE_COLS);
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
    assert!(res.is_err(), "erreur worker -> hydrate_cold Err (drain propre, pas de deadlock/join pendu)");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P3 — UNION hot∪cold MASQUÉE (CRUX SÉCURITÉ) : le masquage (#45) + l'authorizer DENY s'appliquent aux
// lignes COLD EXACTEMENT comme au hot, via le MÊME SQL compilé + le MÊME authorizer. Anti-double-comptage à la
// frontière, complétude rollup-gap, agrégats corrects, truncated surfacé, chemin hot-only inchangé, per-tenant.
// ====================================================================================================

use guatx_core::soql::{FieldMaskSet, MaskAction, Schema};

/// db_path (chemin RÉEL, unique par test) : `cold_root` dérive `{db_path}.cold` -> l'aging (db_path=dbp) et
/// l'union (open_cold_union sur dbp) partagent la MÊME racine cold, comme en production (mode 0 : req_db_path).
fn dbp(root: &Path) -> String {
    root.join("plume.db").to_string_lossy().to_string()
}

/// conf union : cold ON + fenêtre chaude + clé. SANS PLUME_COLD_DIR -> `cold_root` dérive du db_path PAR-TENANT.
fn conf_union(hw: i64) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("PLUME_COLD_TIER".to_string(), "1".to_string());
    m.insert("PLUME_COLD_HOT_WINDOW_DAYS".to_string(), hw.to_string());
    m.insert("PLUME_DB_KEY".to_string(), TEST_DB_KEY.to_string());
    // GATE 0 posé EXPLICITEMENT (il vaut son défaut : ARMÉ). Le laisser écrit rend les fixtures
    // indépendantes du défaut, de sorte qu'un futur changement de défaut ne déplace pas silencieusement
    // ce que ces tests mesurent. Le défaut lui-même est prouvé par `gate0_vectorized_router_is_armed_by_default…`.
    m.insert("PLUME_COLD_VECTORIZED".to_string(), "1".to_string());
    m
}

/// Frontière jour de requête (= aging), calculée sur une connexion locale (n_now aligné minuit -> B==(M-hw)*S).
fn union_boundary(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>) -> i64 {
    let c = db.lock();
    cold_query_boundary(&c, conf, n_now(), RET_DAYS)
}

/// Compile un pipeline GXQL event (dialect SQLite, masques éventuels) -> SQL référençant `event`.
fn compile_ev(soql: &str, from: i64, to: i64, masks: FieldMaskSet) -> String {
    guatx_core::soql::to_sql(soql, from, to, &Schema::events().with_masks(masks)).expect("compile GXQL")
}

/// Colonne (par nom) d'un résultat {columns,rows} en Vec<Value>.
fn col_vals(v: &Value, col: &str) -> Vec<Value> {
    let cols = v["columns"].as_array().expect("columns");
    let idx = cols.iter().position(|c| c.as_str() == Some(col)).unwrap_or_else(|| panic!("colonne {col} absente de {cols:?}"));
    v["rows"].as_array().expect("rows").iter().map(|r| r.as_array().expect("row")[idx].clone()).collect()
}

/// `stats count by source` d'un résultat -> map triée (source -> count) pour comparaison ordre-insensible.
fn count_by_source(v: &Value) -> Vec<(String, i64)> {
    let srcs = col_vals(v, "source");
    let cnts = col_vals(v, "count");
    let mut out: Vec<(String, i64)> = srcs
        .iter()
        .zip(cnts.iter())
        .map(|(s, c)| (s.as_str().unwrap_or("").to_string(), c.as_i64().unwrap_or(0)))
        .collect();
    out.sort();
    out
}

const UWIN_FROM: i64 = (M - 30) * SECS_PER_DAY; // fenêtre large : couvre le jour cold ET la donnée hot récente
const UWIN_TO: i64 = M * SECS_PER_DAY;

// P3 (test 1, HEADLINE) — MASQUAGE APPLIQUÉ AU COLD : un masque MASK sur `src_ip` caviarde les lignes COLD
// IDENTIQUEMENT au hot. Preuve directe : sans masque le src_ip cold est brut ('10.0.0.1'), avec masque il vaut
// '***' — le masquage est dans le SQL compilé, l'union le fait passer aux lignes cold automatiquement.
#[test]
fn p3_masking_applies_to_cold_rows() {
    let root = tmp_root("p3mask");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10; // cold (ts < B)
    let base = day * SECS_PER_DAY;
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i)); // src_ip='10.0.0.1', source='src-{i}'
    }
    insert_recent_tail_holder(&db); // hot (day M-1, source='recent-tail', src_ip='10.0.0.1')
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour cold purgé du hot");
    let b = union_boundary(&db, &conf);

    // (a) SANS masque : le src_ip COLD revient BRUT ('10.0.0.1') -> l'union sert bien les lignes cold.
    let raw_sql = compile_ev("search | table source, src_ip", UWIN_FROM, UWIN_TO, FieldMaskSet::new());
    let (raw, _t, _m) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &raw_sql, None, 60_000, None, &[]).unwrap();
    let raw_srcs = col_vals(&raw, "source");
    let cold_present = raw_srcs.iter().any(|s| s.as_str().map(|x| x.starts_with("src-")).unwrap_or(false));
    let hot_present = raw_srcs.iter().any(|s| s.as_str() == Some("recent-tail"));
    assert!(cold_present && hot_present, "l'union sert hot ET cold (source cold + tail hot)");
    assert!(col_vals(&raw, "src_ip").iter().all(|v| v.as_str() == Some("10.0.0.1")), "sans masque : src_ip brut");

    // (b) AVEC masque MASK sur src_ip : TOUTES les lignes (cold incluses) reviennent '***' — jamais le brut.
    let mut masks = FieldMaskSet::new();
    masks.insert("src_ip".to_string(), MaskAction::Mask);
    let masked_sql = compile_ev("search | table source, src_ip", UWIN_FROM, UWIN_TO, masks);
    let (masked, _t2, _m2) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &masked_sql, None, 60_000, None, &[]).unwrap();
    let m_srcs = col_vals(&masked, "source");
    let m_ips = col_vals(&masked, "src_ip");
    // Au moins une ligne cold présente ET masquée (preuve que le COLD passe par le masque, pas seulement le hot).
    let mut cold_masked = false;
    for (s, ip) in m_srcs.iter().zip(m_ips.iter()) {
        assert_eq!(ip.as_str(), Some("***"), "src_ip MASQUÉ ('***', jamais le brut) pour TOUTE ligne (hot ET cold)");
        if s.as_str().map(|x| x.starts_with("src-")).unwrap_or(false) {
            cold_masked = true;
        }
    }
    assert!(cold_masked, "au moins une ligne COLD, masquée à '***' — masquage appliqué au cold");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 2, CRUX SÉCU) — AUTHORIZER DENY APPLIQUÉ AU COLD : une colonne réelle sous DENY (#45) est refusée à
// la LECTURE sur `cold_event` (miroir) EXACTEMENT comme sur `main.event` — le cold ne contourne PAS l'authorizer.
#[test]
fn p3_deny_authorizer_applies_to_cold() {
    let root = tmp_root("p3deny");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);

    // Règle DENY sur la colonne réelle src_ip pour CE db_path (comme field_filters_reload l'alimenterait).
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("src_ip".to_string());
        w.insert(dbp.clone(), s);
    }
    let u = open_cold_union(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &[]).expect("union construite");
    // L'authorizer DENY refuse la LECTURE au prepare() -> Err (« access to … is prohibited » / « not authorized »).
    let denied = |r: &Result<Value, String>| -> bool {
        let s = format!("{r:?}");
        r.is_err() && (s.contains("prohibited") || s.contains("not authorized"))
    };
    // Déni de la colonne src_ip sur le MIROIR cold_event (sinon exfil cold de la colonne déniée).
    let cold_denied = run_on_conn(&u.conn, &dbp, "SELECT src_ip FROM cold_event", 60_000, None);
    assert!(denied(&cold_denied), "src_ip DÉNIÉ sur cold_event (miroir) : {cold_denied:?}");
    // Parité : déni AUSSI sur main.event (hot).
    let hot_denied = run_on_conn(&u.conn, &dbp, "SELECT src_ip FROM main.event", 60_000, None);
    assert!(denied(&hot_denied), "src_ip DÉNIÉ sur main.event (hot) — parité : {hot_denied:?}");
    // Une colonne NON déniée reste lisible sur cold_event (le déni est scopé à la colonne).
    let ok = run_on_conn(&u.conn, &dbp, "SELECT source FROM cold_event", 60_000, None);
    assert!(ok.is_ok(), "colonne non déniée lisible sur cold_event : {ok:?}");
    crate::field_deny_cols_cell().write().remove(&dbp); // hygiène (db_path unique, mais on nettoie)
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 3) — PAS DE DOUBLE-COMPTAGE à l'overlap : une ligne présente en HOT (scellée-non-purgée, ts<B) ET en
// COLD n'est comptée QU'UNE FOIS. La partition (hot ts>=B ∪ cold ts<B) dédoublonne : count == N (pas 2N).
#[test]
fn p3_no_double_count_at_overlap() {
    let root = tmp_root("p3dup");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let n_rows = 40i64;
    for i in 0..n_rows {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS); // hot du jour purgé ; cold a n_rows
    assert_eq!(count_hot_day(&db, "prod", day), 0);
    // Ré-insère les MÊMES lignes (mêmes ts<B) dans le HOT -> overlap scellé-non-purgé (présent dans les DEUX).
    for i in 0..n_rows {
        insert_event(&db, &rich_row(base + i, i));
    }
    assert_eq!(count_hot_day(&db, "prod", day), n_rows, "overlap : n_rows en hot ET en cold (ts<B)");
    let b = union_boundary(&db, &conf);
    // count sur la fenêtre du jour : la partition exclut le hot ts<B, garde le cold ts<B -> compté UNE fois.
    let sql = compile_ev("search | stats count", base, base + n_rows, FieldMaskSet::new());
    let (v, _t, _m) = union_query_oracle(&dbp, &conf, None, base, base + n_rows, b, &sql, None, 60_000, None, &[]).unwrap();
    let cnt = col_vals(&v, "count")[0].as_i64().unwrap();
    assert_eq!(cnt, n_rows, "compté UNE fois (partition hot ts>=B / cold ts<B) — pas 2N={}", 2 * n_rows);
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 4) — COMPLÉTUDE ROLLUP-GAP : un agrégat sur une fenêtre ENTIÈREMENT COLD calcule sur le BRUT cold
// (cold_event), pas un rollup tronqué. count == compte brut réel des lignes cold de la fenêtre.
#[test]
fn p3_rollup_gap_aggregate_complete_from_cold_raw() {
    let root = tmp_root("p3gap");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10; // cold
    let base = day * SECS_PER_DAY;
    for i in 0..37 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    // Fenêtre ENTIÈREMENT sous B (cold-only) : hot side vide, complétude = brut cold. from/to < B.
    let (from, to) = (base, base + 36);
    assert!(to < b, "fenêtre entièrement cold");
    let sql = compile_ev("search | stats count", from, to, FieldMaskSet::new());
    let (v, _t, meta) = union_query_oracle(&dbp, &conf, None, from, to, b, &sql, None, 60_000, None, &[]).unwrap();
    assert_eq!(col_vals(&v, "count")[0].as_i64().unwrap(), 37, "agrégat COMPLET depuis le brut cold (pas de rollup tronqué)");
    assert_eq!(meta.rows_hydrated, 37, "37 lignes cold brutes scannées");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 5) — AGRÉGATS CORRECTS SUR L'UNION : `stats count by source` / `dc(host)` / `avg(severity)` sur
// hot∪cold == le MÊME pipeline sur une table hot ÉQUIVALENTE contenant TOUTES les lignes (union-de-lignes-
// puis-agrégat-une-fois, jamais une fusion d'agrégats partiels).
#[test]
fn p3_aggregate_correctness_union_equals_single_table() {
    let root = tmp_root("p3agg");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let cold_day = M - 10;
    let cbase = cold_day * SECS_PER_DAY;
    let hot_day = M - 1; // dans la fenêtre chaude (hot)
    let hbase = hot_day * SECS_PER_DAY;
    // Lignes cold (source alterné A/B) + lignes hot (source A/C) -> group-by/dc/avg non triviaux.
    for i in 0..30 {
        let mut r = rich_row(cbase + i, i);
        r.row.source = if i % 2 == 0 { "A".into() } else { "B".into() };
        r.row.host = Some(format!("h{}", i % 5));
        r.row.severity = i % 4;
        insert_event(&db, &r);
    }
    for i in 0..10 {
        let mut r = rich_row(hbase + i, 1000 + i);
        r.row.source = if i % 2 == 0 { "A".into() } else { "C".into() };
        r.row.host = Some(format!("h{}", i % 3));
        r.row.severity = i % 4;
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    // RÉFÉRENCE : AVANT aging, `event` (hot) contient TOUTES les lignes -> agrégat de référence.
    let by_sql = compile_ev("search | stats count by source", UWIN_FROM, UWIN_TO, FieldMaskSet::new());
    let dc_sql = compile_ev("search | stats dc(host)", UWIN_FROM, UWIN_TO, FieldMaskSet::new());
    let avg_sql = compile_ev("search | stats avg(severity)", UWIN_FROM, UWIN_TO, FieldMaskSet::new());
    let ref_by = { let g = db.lock(); run_on_conn(&g, &dbp, &by_sql, 60_000, None).unwrap() };
    let ref_dc = { let g = db.lock(); run_on_conn(&g, &dbp, &dc_sql, 60_000, None).unwrap() };
    let ref_avg = { let g = db.lock(); run_on_conn(&g, &dbp, &avg_sql, 60_000, None).unwrap() };

    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS); // columnarise le jour cold
    assert_eq!(count_hot_day(&db, "prod", cold_day), 0);
    let b = union_boundary(&db, &conf);
    let (u_by, _t1, _m1) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &by_sql, None, 60_000, None, &[]).unwrap();
    let (u_dc, _t2, _m2) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &dc_sql, None, 60_000, None, &[]).unwrap();
    let (u_avg, _t3, _m3) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &avg_sql, None, 60_000, None, &[]).unwrap();

    assert_eq!(count_by_source(&u_by), count_by_source(&ref_by), "count by source : union == table unique");
    let dc_col = u_dc["columns"][0].as_str().unwrap().to_string();
    assert_eq!(col_vals(&u_dc, &dc_col)[0], col_vals(&ref_dc, &dc_col)[0], "dc(host) : union == table unique");
    let avg_col = u_avg["columns"][0].as_str().unwrap().to_string();
    assert_eq!(col_vals(&u_avg, &avg_col)[0], col_vals(&ref_avg, &avg_col)[0], "avg(severity) : union == table unique");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 6) — TRUNCATED SURFACÉ : au-delà du plafond cold (PLUME_QUERY_MAX défaut 5000), l'union TRONQUE et
// SIGNALE (meta.truncated), jamais un cold∪hot incomplet présenté comme complet.
#[test]
fn p3_truncated_surfaced() {
    let root = tmp_root("p3trunc");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    let total = 5001i64; // > cap défaut (5000)
    {
        let c = db.lock();
        let tx = c.unchecked_transaction().unwrap();
        for i in 0..total {
            let r = rich_row(base + i, i);
            tx.execute(
                "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![r.row.ts, r.row.severity, r.row.source, r.row.category, r.row.host, r.row.src_ip, r.row.dst_ip, r.row.url, r.xff, r.row.dedup, r.row.engagement_id, r.row.origin, r.row.env_id, r.row.message, r.row.fields],
            ).unwrap();
        }
        tx.commit().unwrap();
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    let sql = compile_ev("search | table source", base, base + total, FieldMaskSet::new());
    let (_v, _t, meta) = union_query_oracle(&dbp, &conf, None, base, base + total, b, &sql, None, 60_000, None, &[]).unwrap();
    assert!(meta.truncated, "cap cold dépassé -> truncated SIGNALÉ (incomplétude jamais silencieuse)");
    assert_eq!(meta.rows_hydrated, 5000, "borné au plafond interactif");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 7) — FENÊTRE HOT-ONLY INCHANGÉE : le déclencheur (from < B) NE s'arme PAS pour une fenêtre
// entièrement dans la fenêtre chaude (from >= B) ; et invoquée à tort sur une telle fenêtre, l'union n'hydrate
// AUCUNE ligne cold (hi = min(to,B-1) < B <= from -> sous-fenêtre cold vide).
#[test]
fn p3_hot_only_window_no_hydration() {
    let root = tmp_root("p3hot");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    // DÉCLENCHEUR : from==B -> hot-only (from < B faux) ; from==B-1 -> atteint le cold (from < B vrai).
    assert!(!(b < b), "from==B -> hot-only -> déclencheur OFF (from < B faux)");
    assert!((b - 1) < b, "from==B-1 -> atteint le cold -> déclencheur ON");
    // Invoquée à tort sur [B, B+jour] : hi < lo -> aucune hydratation cold.
    let u = open_cold_union(&dbp, &conf, None, b, b + SECS_PER_DAY, b, &[]).expect("union");
    assert_eq!(u.meta.rows_hydrated, 0, "fenêtre hot-only -> aucune ligne cold hydratée");
    assert_eq!(u.meta.files_read, 0, "fenêtre hot-only -> aucun fichier cold ouvert");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 8) — PER-TENANT : l'union du tenant A n'utilise QUE le hot+cold de A (clé/racine de A). Aucune ligne
// de B (base/racine/clé disjointes). Prouvé : l'union A ne sert AUCUNE source 'b-*'.
#[test]
fn p3_per_tenant_isolation() {
    let root = tmp_root("p3tenant");
    let a_root = root.join("a");
    let b_root = root.join("b");
    std::fs::create_dir_all(&a_root).unwrap();
    std::fs::create_dir_all(&b_root).unwrap();
    let a_db = mkdb(&a_root);
    let b_db = mkdb(&b_root);
    let a_dbp = dbp(&a_root);
    let b_dbp = dbp(&b_root);
    let conf = conf_union(HOT_WIN); // SANS PLUME_COLD_DIR -> racine cold par-tenant `{db_path}.cold`
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..15 {
        let mut r = rich_row(base + i, i);
        r.row.source = format!("a-{i}");
        insert_event(&a_db, &r);
    }
    insert_recent_tail_holder(&a_db);
    for i in 0..25 {
        let mut r = rich_row(base + i, i);
        r.row.source = format!("b-{i}");
        insert_event(&b_db, &r);
    }
    insert_recent_tail_holder(&b_db);
    cold_age_run(&a_db, &a_dbp, &conf, n_now(), RET_DAYS);
    cold_age_run(&b_db, &b_dbp, &conf, n_now(), RET_DAYS);
    assert_ne!(cold_root(&conf, &a_dbp), cold_root(&conf, &b_dbp), "racines cold DISJOINTES");
    let b = union_boundary(&a_db, &conf);
    let sql = compile_ev("search | table source", UWIN_FROM, UWIN_TO, FieldMaskSet::new());
    let (v, _t, _m) = union_query_oracle(&a_dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &sql, None, 60_000, None, &[]).unwrap();
    let srcs = col_vals(&v, "source");
    assert!(srcs.iter().any(|s| s.as_str().map(|x| x.starts_with("a-")).unwrap_or(false)), "union A sert le cold de A");
    assert!(!srcs.iter().any(|s| s.as_str().map(|x| x.starts_with("b-")).unwrap_or(false)), "union A ne sert JAMAIS le cold de B (isolation)");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P3 — VERROUS DE RÉGRESSION du masquage-sur-cold (revue sécu P4 : masquage JUGÉ SOUND mais les chemins de
// masquage à PLUS HAUT ENJEU n'étaient pas DIRECTEMENT testés). Ces 4 tests ciblent chacun un chemin de masque
// précis appliqué aux lignes COLD via l'UNION hot∪cold (même SQL compilé + même wiring sécu que le hot).
// ====================================================================================================

// P3 (test 9, HASH-SUR-COLD — HEADLINE) — l'action HASH (#45) s'applique aux lignes COLD **et CORRÈLE** avec le
// hot : même valeur -> même hash, car le SEL (`meta.field_mask_salt`) est lu sur la connexion d'UNION qui a le
// HOT en `main`. Preuve DIRECTE (pas un raccourci) : le src_ip d'une ligne cold == le src_ip d'une ligne hot ==
// `fmask_hash(sel, '10.0.0.1')` (hash recalculé indépendamment côté Rust), et JAMAIS le brut. Si l'union lisait
// un sel différent (ou brut), cold≠hot ou cold≠expected -> le test casse.
#[test]
fn p3_hash_masking_over_cold_matches_hot() {
    let root = tmp_root("p3hash");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    // SEL de masque RÉEL posé sur main.meta (migrate_v86 le pose immuable en prod) -> la connexion d'union le
    // lit sur `main` (= hot) via install_fmask_udf ; le HASH cold devient byte-identique au HASH hot pour la
    // même entrée. (Sans ce sel, install_fmask_udf tomberait sur un sel vide par défaut — ici on prouve
    // que le sel de main.meta est BIEN celui utilisé.)
    //
    // `P10.13-a` — LA TABLE N'EST PLUS CRÉÉE ICI : `mkdb` la pose, comme la chaîne de migrations la pose sur
    // TOUS les déploiements. Ce test la créait lui-même parce que la fixture ne l'avait pas ; garder ce
    // `CREATE TABLE` nu le faisait échouer sur « table meta already exists » — MESURÉ, deux tests rouges.
    const SALT: &str = "p3-hash-salt-2f9c";
    db.lock()
        .execute_batch(&format!(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('field_mask_salt','{SALT}');"
        ))
        .unwrap();
    let day = M - 10; // cold (ts < B)
    let base = day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i)); // src_ip='10.0.0.1'
    }
    insert_recent_tail_holder(&db); // hot (day M-1), src_ip='10.0.0.1'
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour cold purgé du hot");
    let b = union_boundary(&db, &conf);

    let mut masks = FieldMaskSet::new();
    masks.insert("src_ip".to_string(), MaskAction::Hash);
    let sql = compile_ev("search | table source, src_ip", UWIN_FROM, UWIN_TO, masks);
    assert!(sql.contains("plume_fmask_hash"), "le compilo émet le HASH dans la projection : {sql}");
    let (v, _t, _m) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &sql, None, 60_000, None, &[]).unwrap();

    // Hash de RÉFÉRENCE recalculé indépendamment (même fonction que l'UDF SQL) -> preuve non circulaire.
    let expected = crate::fmask_hash(SALT, "10.0.0.1");
    assert_ne!(expected, "10.0.0.1", "le hash n'est pas la valeur brute");
    let srcs = col_vals(&v, "source");
    let ips = col_vals(&v, "src_ip");
    let mut cold_ip: Option<String> = None;
    let mut hot_ip: Option<String> = None;
    for (s, ip) in srcs.iter().zip(ips.iter()) {
        let ipv = ip.as_str().unwrap_or("").to_string();
        assert_ne!(ipv, "10.0.0.1", "aucune ligne (hot NI cold) ne renvoie le src_ip BRUT sous HASH");
        assert_eq!(ipv, expected, "src_ip = HASH salé (sel lu depuis main.meta sur la connexion d'union)");
        if s.as_str().map(|x| x.starts_with("src-")).unwrap_or(false) {
            cold_ip = Some(ipv.clone());
        }
        if s.as_str() == Some("recent-tail") {
            hot_ip = Some(ipv);
        }
    }
    let cold_ip = cold_ip.expect("au moins une ligne COLD servie");
    let hot_ip = hot_ip.expect("au moins une ligne HOT servie");
    assert_eq!(cold_ip, hot_ip, "HASH cold == HASH hot pour la même entrée (corrélation préservée à la frontière)");
    assert_eq!(cold_ip, expected, "HASH cold == fmask_hash(sel_de_main.meta, '10.0.0.1')");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 10, CLÉ-JSON-SUR-COLD — ENJEU MAXIMAL) — une clé du SAC `fields` masquée (`password`) est RETIRÉE du
// blob JSON des lignes COLD (`json_remove`) EXACTEMENT comme du hot : le secret n'est PAS récupérable depuis la
// ligne cold. Preuve DIRECTE : la valeur secrète n'apparaît dans AUCUN `fields` renvoyé (cold NI hot), et la clé
// `password` est absente du blob. (Sans le caviardage du sac sur le cold, le secret ressortirait EN CLAIR dans le
// blob brut cold — c'est précisément le chemin le plus exfiltrant.)
#[test]
fn p3_fields_json_key_masking_over_cold() {
    let root = tmp_root("p3jkey");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // Lignes COLD portant un secret dans le sac fields sous la clé `password`.
    for i in 0..12 {
        let mut r = rich_row(base + i, i);
        r.row.fields = Some(format!("{{\"k\":{i},\"password\":\"COLD-SECRET-{i}\"}}"));
        insert_event(&db, &r);
    }
    // Ligne HOT (dans la fenêtre chaude) portant AUSSI le secret -> parité hot/cold démontrable.
    {
        let mut h = rich_row((M - 1) * SECS_PER_DAY + 5, 77_777);
        h.row.source = "hot-secret".to_string();
        h.row.fields = Some("{\"k\":1,\"password\":\"HOT-SECRET\"}".to_string());
        insert_event(&db, &h);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour cold purgé du hot");
    let b = union_boundary(&db, &conf);

    let mut masks = FieldMaskSet::new();
    masks.insert("password".to_string(), MaskAction::Deny); // clé JSON (pas une colonne réelle) -> retirée du sac
    let sql = compile_ev("search | table source, fields", UWIN_FROM, UWIN_TO, masks);
    assert!(sql.contains("json_remove"), "le compilo RETIRE la clé masquée du blob (json_remove) : {sql}");
    let (v, _t, _m) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &sql, None, 60_000, None, &[]).unwrap();

    let srcs = col_vals(&v, "source");
    let fields = col_vals(&v, "fields");
    let mut cold_seen = false;
    let mut hot_seen = false;
    for (s, f) in srcs.iter().zip(fields.iter()) {
        let fs = f.as_str().unwrap_or("");
        assert!(!fs.contains("SECRET"), "secret JAMAIS présent dans le blob fields renvoyé (cold NI hot) : {fs}");
        assert!(!fs.contains("password"), "clé password RETIRÉE du blob (json_remove) : {fs}");
        if s.as_str().map(|x| x.starts_with("src-")).unwrap_or(false) {
            cold_seen = true;
        }
        if s.as_str() == Some("hot-secret") {
            hot_seen = true;
        }
    }
    assert!(cold_seen, "au moins une ligne COLD servie (secret retiré de SON blob)");
    assert!(hot_seen, "au moins une ligne HOT servie (parité : secret retiré identiquement)");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 11, MASQUE-AVANT-AGRÉGAT-SUR-COLD) — un HASH sur src_ip combiné à `stats count by src_ip` sur l'union
// hot∪cold : la CLÉ DE GROUPE est le HASH (jamais le brut), donc le masque s'applique AVANT l'agrégation SUR les
// lignes cold. Toutes les lignes (cold+hot) partagent le même src_ip -> UN seul groupe (le hash), count == total :
// les lignes cold sont bien AGRÉGÉES sous la clé masquée (aucun groupe brut cold séparé ne fuit).
#[test]
fn p3_masked_aggregate_over_cold() {
    let root = tmp_root("p3magg");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    const SALT: &str = "p3-agg-salt-71bd";
    db.lock()
        .execute_batch(&format!(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('field_mask_salt','{SALT}');"
        ))
        .unwrap();
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let n_cold = 20i64;
    for i in 0..n_cold {
        insert_event(&db, &rich_row(base + i, i)); // src_ip='10.0.0.1'
    }
    insert_recent_tail_holder(&db); // hot, src_ip='10.0.0.1'
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0);
    let b = union_boundary(&db, &conf);

    let mut masks = FieldMaskSet::new();
    masks.insert("src_ip".to_string(), MaskAction::Hash);
    let sql = compile_ev("search | stats count by src_ip", UWIN_FROM, UWIN_TO, masks);
    assert!(sql.contains("plume_fmask_hash"), "group-by sur la valeur HACHÉE, jamais brute : {sql}");
    let (v, _t, _m) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &sql, None, 60_000, None, &[]).unwrap();

    let expected = crate::fmask_hash(SALT, "10.0.0.1");
    let keys = col_vals(&v, "src_ip");
    assert!(!keys.is_empty(), "au moins un groupe");
    for k in &keys {
        assert_ne!(k.as_str(), Some("10.0.0.1"), "aucune clé de groupe = src_ip BRUT (masque AVANT agrégat, cold inclus)");
        assert_eq!(k.as_str(), Some(expected.as_str()), "clé de groupe = HASH salé");
    }
    // Toutes les lignes (cold + hot tail) collapsent sur le même hash -> un groupe, count == n_cold+1.
    let total: i64 = col_vals(&v, "count").iter().map(|c| c.as_i64().unwrap_or(0)).sum();
    assert_eq!(total, n_cold + 1, "count total = cold ({n_cold}) + hot tail (1) — lignes cold AGRÉGÉES sous la clé masquée");
    assert_eq!(keys.len(), 1, "une seule clé de groupe (le hash) — pas de groupe brut cold séparé qui fuirait");
    let _ = std::fs::remove_dir_all(&root);
}

// P3 (test 12, GARDE-FOU HANDLER — le SQL BRUT ne route JAMAIS par l'union cold) — l'union cold n'est ARMÉE que
// dans la branche GXQL du handler ; la branche `sql` BRUT (réservée admin) laisse `cold_boundary=None` -> chemin
// HOT byte-identique, jamais de ligne cold. On VERROUILLE ça par DEUX assertions :
//   (a) INVARIANT DE SOURCE sur handlers/query.rs : chaque branche raw-sql (les deux handlers query+export la
//       partagent) ne référence AUCUN jeton de routage cold (`cold_boundary`/`cold_union`/`open_cold_union`), et
//       `cold_boundary = Some(` n'apparaît QUE dans la branche GXQL, gardé par le déclencheur fenêtre `if from<b`.
//       -> un refactor futur qui armerait le cold pour le SQL brut CASSE ce test.
//   (b) BACKSTOP COMPORTEMENTAL : `cold_event` est une table TEMP LOCALE à la connexion d'union ; une connexion
//       HOT ordinaire (celle qu'emprunte le SQL brut, via le pool de lecture) ne la voit pas -> le SQL brut est
//       STRUCTURELLEMENT incapable de lire une ligne cold, même si des données cold existent sur disque.
#[test]
fn p3_raw_sql_never_touches_cold() {
    // (a) INVARIANT DE SOURCE.
    let src = include_str!("../handlers/query.rs");
    let anchors: Vec<usize> = src.match_indices("raw_sql_allowed(false").map(|(i, _)| i).collect();
    assert_eq!(anchors.len(), 2, "deux branches raw-sql (query + export) attendues — sinon le handler a changé de forme, revérifier l'invariant");
    for start in anchors {
        // La branche raw-sql court de l'ancre jusqu'au `};` qui clôt le `let (sql, …) = if … else { … };`.
        let rest = &src[start..];
        let end = rest.find("};").expect("branche raw-sql close par `};`");
        let branch = &rest[..end];
        assert!(!branch.contains("cold_boundary"), "la branche raw-sql n'ARME PAS cold_boundary");
        assert!(!branch.contains("cold_union"), "la branche raw-sql n'appelle PAS cold_union_query");
        assert!(!branch.contains("open_cold_union"), "la branche raw-sql n'ouvre PAS l'union cold");
    }
    // Positif : chaque armement `cold_boundary = Some(` est DANS la branche GXQL, sous le gate fenêtre `if from < b`.
    let arms: Vec<usize> = src.match_indices("cold_boundary = Some(").map(|(i, _)| i).collect();
    assert_eq!(arms.len(), 2, "cold_boundary armé exactement 2 fois (query + export)");
    for i in arms {
        let pre = &src[..i];
        let last_gate = pre.rfind("if from < b {").expect("armement gardé par le déclencheur fenêtre `if from < b`");
        let last_soql = pre.rfind("body.get(\"soql\")").expect("armement DANS la branche GXQL");
        assert!(last_soql < last_gate, "gate fenêtre imbriqué SOUS la branche GXQL (donc jamais dans la branche raw-sql)");
    }

    // (b) BACKSTOP COMPORTEMENTAL : cold_event est local à la connexion d'union.
    let root = tmp_root("p3rawsql");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..10 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    // Connexion HOT ordinaire (RO), PAS l'union : cold_event n'existe pas -> un SELECT brut sur cold_event échoue.
    let hot = Connection::open_with_flags(&dbp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let r = hot.query_row("SELECT COUNT(*) FROM cold_event", [], |row| row.get::<_, i64>(0));
    assert!(r.is_err(), "cold_event ABSENTE d'une connexion hot ordinaire -> le SQL brut ne peut atteindre le cold");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// TIER FROID 2-TIER BACKUP (#18) — plan d'escrow incrémental (`cold_backup_plan` / `all_sealed_files`).
// ====================================================================================================

use std::collections::HashSet;

/// Crée le FICHIER local d'un (env, day, seq) sous `cold` (contenu factice — `cold_backup_plan` ne teste QUE
/// l'existence, jamais la décodabilité). Crée le répertoire parent. Symétrique au layout de production.
fn touch_cold_file(cold: &Path, env: &str, day: i64, seq: i64) {
    let p = file_path(cold, env, day, seq);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"x").unwrap();
}

fn keyset(items: &[String]) -> HashSet<String> {
    items.iter().cloned().collect()
}

/// La clé objet ATTENDUE (préfixe "default") pour (env, day, seq) — reflète le schéma de `cold_backup_plan`.
fn exp_key(env: &str, day: i64, seq: i64) -> String {
    format!("cold/default/{env}/{}-{:04}.parquet", ymd_from_day(day), seq)
}

/// (1) DELTA — les fichiers scellés ABSENTS de `remote_keys` sont émis ; ceux DÉJÀ présents sont SKIP.
#[test]
fn cold_backup_plan_emits_unbacked_skips_present() {
    let root = tmp_root("cbp-delta");
    let cold = root.join("cold");
    let db = mkdb(&root);
    // 3 fichiers scellés : (prod,100,0), (prod,100,1), (prod,101,0). Tous ont leur fichier local.
    seal0_k(&db, "prod", 100, 5, 1, 5);
    seal_row(&db, "prod", 100, 1, 3, 1, 8, 0, 0, 0, 0, 8, 1);
    seal0_k(&db, "prod", 101, 4, 1, 4);
    touch_cold_file(&cold, "prod", 100, 0);
    touch_cold_file(&cold, "prod", 100, 1);
    touch_cold_file(&cold, "prod", 101, 0);
    // Le remote a DÉJÀ (prod,100,0).
    let present = exp_key("prod", 100, 0);
    let remote = keyset(&[present.clone()]);
    let plan = { let c = db.lock(); cold_backup_plan(&c, &cold, "default", &remote) };
    let keys: Vec<String> = plan.iter().map(|i| i.key.clone()).collect();
    assert!(!keys.contains(&present), "la clé DÉJÀ au remote doit être SKIP");
    assert_eq!(keys.len(), 2, "seuls les 2 fichiers non-escrowés sont émis");
    assert!(keys.contains(&exp_key("prod", 100, 1)));
    assert!(keys.contains(&exp_key("prod", 101, 0)));
    // Chaque chemin local émis EXISTE et correspond exactement à file_path.
    for it in &plan {
        assert!(it.local.exists(), "chemin local émis doit exister");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// (2) IDEMPOTENCE (invariant GFS) — rejouer le plan avec les clés qu'il vient d'émettre ajoutées à
/// `remote_keys` -> plan VIDE (miroir de l'invariant idempotent de `backup_prune_plan`).
#[test]
fn cold_backup_plan_idempotent_after_backup() {
    let root = tmp_root("cbp-idem");
    let cold = root.join("cold");
    let db = mkdb(&root);
    seal0_k(&db, "prod", 100, 5, 1, 5);
    seal0_k(&db, "prod", 101, 4, 1, 4);
    seal0_k(&db, "staging", 100, 2, 1, 2);
    touch_cold_file(&cold, "prod", 100, 0);
    touch_cold_file(&cold, "prod", 101, 0);
    touch_cold_file(&cold, "staging", 100, 0);
    // Run 1 : remote vide -> tout émis.
    let plan1 = { let c = db.lock(); cold_backup_plan(&c, &cold, "default", &HashSet::new()) };
    assert_eq!(plan1.len(), 3, "run initial émet les 3 fichiers scellés");
    // Simule le `mc cp` du sidecar : ajoute les clés émises au remote.
    let mut remote2 = HashSet::new();
    for it in &plan1 { remote2.insert(it.key.clone()); }
    // Run 2 : plan VIDE (rien de neuf à escrower).
    let plan2 = { let c = db.lock(); cold_backup_plan(&c, &cold, "default", &remote2) };
    assert!(plan2.is_empty(), "rejouer avec les clés copiées -> plan VIDE (idempotence GFS)");
    let _ = std::fs::remove_dir_all(&root);
}

/// (3) FICHIER LOCAL MANQUANT — un seal présent mais DONT LE FICHIER a (déjà) été supprimé (course
/// expire/backup) N'EST PAS émis -> jamais d'émission FANTÔME d'un chemin inexistant.
#[test]
fn cold_backup_plan_skips_missing_local() {
    let root = tmp_root("cbp-missing");
    let cold = root.join("cold");
    let db = mkdb(&root);
    seal0_k(&db, "prod", 100, 5, 1, 5);   // seal présent...
    seal0_k(&db, "prod", 101, 4, 1, 4);
    touch_cold_file(&cold, "prod", 101, 0); // ...mais SEUL (prod,101,0) a son fichier local (100 « vient d'expirer »).
    let plan = { let c = db.lock(); cold_backup_plan(&c, &cold, "default", &HashSet::new()) };
    let keys: Vec<String> = plan.iter().map(|i| i.key.clone()).collect();
    assert_eq!(keys, vec![exp_key("prod", 101, 0)], "seul le fichier local PRÉSENT est émis (pas de fantôme)");
    let _ = std::fs::remove_dir_all(&root);
}

/// (4) ORDRE DÉTERMINISTE — insertion des seals dans un ordre BROUILLÉ ; sortie triée `(env_id, day, seq)`,
/// STABLE entre deux exécutions.
#[test]
fn cold_backup_plan_deterministic_order() {
    let root = tmp_root("cbp-order");
    let cold = root.join("cold");
    let db = mkdb(&root);
    // Insertion volontairement DÉSORDONNÉE.
    seal0_k(&db, "prod", 101, 1, 1, 1);
    seal_row(&db, "prod", 100, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1);
    seal0_k(&db, "prod", 100, 1, 1, 1);
    seal0_k(&db, "alpha", 200, 1, 1, 1);
    touch_cold_file(&cold, "prod", 101, 0);
    touch_cold_file(&cold, "prod", 100, 1);
    touch_cold_file(&cold, "prod", 100, 0);
    touch_cold_file(&cold, "alpha", 200, 0);
    let run = || -> Vec<String> {
        let c = db.lock();
        cold_backup_plan(&c, &cold, "default", &HashSet::new()).iter().map(|i| i.key.clone()).collect()
    };
    let expected = vec![
        exp_key("alpha", 200, 0),
        exp_key("prod", 100, 0),
        exp_key("prod", 100, 1),
        exp_key("prod", 101, 0),
    ];
    assert_eq!(run(), expected, "ordre trié (env_id, day, seq)");
    assert_eq!(run(), expected, "ordre STABLE entre deux exécutions");
    let _ = std::fs::remove_dir_all(&root);
}

/// (5) FORMAT DE CLÉ == NOMMAGE ON-DISK — la clé objet se termine EXACTEMENT par le basename de `file_path`
/// (segment `<YYYY-MM-DD>-<NNNN>.parquet`, `seq` zéro-paddé sur 4) ; le chemin local == `file_path`.
#[test]
fn cold_backup_plan_key_matches_on_disk_naming() {
    let root = tmp_root("cbp-key");
    let cold = root.join("cold");
    let db = mkdb(&root);
    // seq=7 -> exerce le zéro-padding %04 (0007), identique à file_path.
    seal_row(&db, "prod", 100, 7, 3, 1, 9, 0, 0, 0, 0, 9, 1);
    touch_cold_file(&cold, "prod", 100, 7);
    let plan = { let c = db.lock(); cold_backup_plan(&c, &cold, "default", &HashSet::new()) };
    assert_eq!(plan.len(), 1);
    let item = &plan[0];
    // Chemin local == file_path EXACT.
    assert_eq!(item.local, file_path(&cold, "prod", 100, 7));
    // La clé se termine par le basename on-disk EXACT (day-seq portion).
    let on_disk = file_path(&cold, "prod", 100, 7);
    let basename = on_disk.file_name().unwrap().to_string_lossy();
    assert_eq!(&*basename, format!("{}-0007.parquet", ymd_from_day(100)));
    assert!(item.key.ends_with(&*basename), "la clé se termine par le basename on-disk (day-seq %04)");
    assert_eq!(item.key, format!("cold/default/prod/{}-0007.parquet", ymd_from_day(100)));
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #28 PHASE A — SIDECAR ROLLUP COLD : le rollup par-jour est calculé AU SCELLEMENT (crash-atomique avec
// last_file=1), stocké EN BASE tenant (cold_rollup / cold_dim_rollup), et servi par la route COLD+HOT
// (event_rollup ∪ cold_rollup) SANS ouvrir un seul Parquet. Tests : (a) calcul au seal ; (b) route ==
// scan brut ; (c) zéro Parquet ; (d) union hot∪cold sans double-comptage à B ; (e) dc/timechart fallback ;
// (f) DENY authorizer sur le miroir cold_rollup ; (g) masquage ; (h) généricité source inconnue ;
// (i) re-seal idempotent (pas de double NI d'effacement). Tous derrière `#[cfg(feature="cold_tier")]`.
// ====================================================================================================

/// Crée les tables de rollup HOT (event_rollup / event_dim_rollup) — en prod posées par les migrations ;
/// ici mkdb ne crée que `event`. Nécessaire dès que la route COLD+HOT (qui unionne event_rollup) est exécutée.
fn ensure_hot_rollups(db: &Arc<Mutex<Connection>>) {
    db.lock()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS event_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
               severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
               host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
               env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(bucket,source,severity,action,src_ip,host,env_id)); \
             CREATE TABLE IF NOT EXISTS event_dim_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
               dim TEXT NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
               env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(bucket,source,dim,val,env_id));",
        )
        .unwrap();
}

fn cold_rollup_sum(db: &Arc<Mutex<Connection>>, where_sql: &str) -> i64 {
    db.lock()
        .query_row(&format!("SELECT COALESCE(SUM(n),0) FROM cold_rollup WHERE {where_sql}"), [], |r| r.get(0))
        .unwrap()
}

// (a) — Le rollup cold est CALCULÉ au scellement : après aging, cold_rollup compte EXACTEMENT les lignes
// columnarisées (== le compte brut du jour), par source. Preuve directe que seal_cold_rollup a tourné.
#[test]
fn phase_a_seal_computes_cold_rollup() {
    let root = tmp_root("carollup-seal");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i)); // source='src-{i}'
    }
    for i in 0..3 {
        let mut r = rich_row(base + 100 + i, 500 + i);
        r.row.source = "dup-src".into();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour cold purgé du hot");
    assert_eq!(cold_rollup_sum(&db, "1"), 43, "cold_rollup total == lignes columnarisées (43)");
    assert_eq!(cold_rollup_sum(&db, "source='dup-src'"), 3, "count par source EXACT dans cold_rollup");
    let _ = std::fs::remove_dir_all(&root);
}

// (b)+(c) — `stats count by source` sur une fenêtre COLD via la ROUTE == scan brut cold (correctness), et la
// route N'OUVRE AUCUN Parquet (elle interroge event_rollup ∪ cold_rollup EN BASE ; run_query_ex = pool
// read-only, jamais l'hydratation cold). Fenêtre purement cold (to < B) -> côté hot vide des DEUX côtés.
#[test]
fn phase_a_cold_route_count_by_source_equals_raw_zero_parquet() {
    let root = tmp_root("carollup-eqraw");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    ensure_hot_rollups(&db);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i));
    }
    for i in 0..5 {
        let mut r = rich_row(base + 200 + i, 700 + i);
        r.row.source = "shared".into();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + SECS_PER_DAY - 1; // jour M-10 entier, tout < B
    let rr = crate::try_cold_rollup_route("search | stats count by source", from, to, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test())
        .expect("route cold `count by source`");
    // (c) ZÉRO Parquet : la route ne cite QUE les tables rollup EN BASE, jamais cold_event/Parquet.
    let low = rr.sql.to_lowercase();
    assert!(rr.sql.contains("cold_rollup") && rr.sql.contains("event_rollup"), "route = union des rollups EN BASE: {}", rr.sql);
    assert!(!low.contains("cold_event") && !low.contains("parquet"), "route N'OUVRE PAS de Parquet: {}", rr.sql);
    let routed = crate::run_query_ex(&dbp, &rr.sql, 60_000, None).expect("exec route cold (pool read-only, aucun Parquet)");
    // (b) ground truth : scan brut hot∪cold (cold_union_query) sur le MÊME `stats count by source`.
    let gt_sql = compile_ev("search | stats count by source", from, to, FieldMaskSet::new());
    let (gt, _t, _m) = union_query_oracle(&dbp, &conf, None, from, to, b, &gt_sql, None, 60_000, None, &[]).unwrap();
    assert_eq!(count_by_source(&routed), count_by_source(&gt), "route cold == scan brut cold (correctness)");
    assert!(count_by_source(&routed).iter().any(|(s, c)| s == "shared" && *c == 5), "count exact dim rollée");
    let _ = std::fs::remove_dir_all(&root);
}

// (b2) — B2 MULTI-DIM COLD : `stats count by source,severity` (grain EXACT routable = dims NOT NULL sans
// COALESCE) sur une fenêtre COLD via la ROUTE A-multi == scan brut cold, ZÉRO Parquet. Généralise (b) au
// group-by multi-dim (event_rollup ∪ cold_rollup, GROUP BY dims). `host`/`action` sont EXCLUS du grain
// routable (COALESCE '' à la matérialisation -> divergence NULL/'') -> non testés en route ici.
#[test]
fn phase_a_cold_route_multidim_by_dims_equals_raw_b2() {
    let root = tmp_root("carollup-multidim-b2");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    ensure_hot_rollups(&db);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // combos RÉPÉTÉS sur (source,severity,host) — tous peuplés -> groupes non triviaux + parité stricte.
    let combos: &[(&str, i64, &str)] = &[("web", 4, "web1"), ("web", 2, "web1"), ("web", 4, "web2"), ("sshd", 3, "bastion"), ("sshd", 3, "bastion")];
    let mut k = 0i64;
    for (src, sev, host) in combos {
        for _ in 0..4 {
            let mut r = rich_row(base + k, k);
            r.row.source = (*src).into();
            r.row.severity = *sev;
            r.row.host = Some((*host).into());
            insert_event(&db, &r);
            k += 1;
        }
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + SECS_PER_DAY - 1; // jour M-10 entier, tout < B
    let soql = "search | stats count by source,severity";
    let rr = crate::try_cold_rollup_route(soql, from, to, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).expect("route cold multi-dim (B2)");
    let low = rr.sql.to_lowercase();
    assert!(rr.sql.contains("cold_rollup") && rr.sql.contains("event_rollup"), "union des rollups EN BASE: {}", rr.sql);
    assert!(!low.contains("cold_event") && !low.contains("parquet"), "route N'OUVRE PAS de Parquet: {}", rr.sql);
    let routed = crate::run_query_ex(&dbp, &rr.sql, 60_000, None).expect("exec route cold multi-dim");
    let gt_sql = compile_ev(soql, from, to, FieldMaskSet::new());
    let (gt, _t, _m) = union_query_oracle(&dbp, &conf, None, from, to, b, &gt_sql, None, 60_000, None, &[]).unwrap();
    // map (source|severity -> count), ordre-insensible.
    let dims_map = |v: &Value| -> Vec<(String, i64)> {
        let s = col_vals(v, "source");
        let sev = col_vals(v, "severity");
        let c = col_vals(v, "count");
        let mut out: Vec<(String, i64)> = (0..c.len())
            .map(|i| {
                let key = format!("{}|{}", s[i].as_str().unwrap_or(""), sev[i].as_i64().unwrap_or(-1));
                (key, c[i].as_i64().unwrap_or(0))
            })
            .collect();
        out.sort();
        out
    };
    assert_eq!(dims_map(&routed), dims_map(&gt), "route cold MULTI-DIM == scan brut cold (B2 parité)");
    let tot: i64 = dims_map(&routed).iter().map(|(_, n)| n).sum();
    assert_eq!(tot, 20, "total conservé (5 combos * 4) sur le multi-dim");
    let _ = std::fs::remove_dir_all(&root);
}

// (d) — UNION hot∪cold SANS DOUBLE-COMPTAGE à la frontière B : une source présente EN COLD (bucket<B) ET en
// HOT (bucket>=B) est sommée UNE FOIS chaque côté ; une ligne event_rollup STALE à bucket<B (rollup pré-aging
// non purgé) est EXCLUE par le côté hot (bucket>=B) -> jamais sur-comptée.
#[test]
fn phase_a_hot_cold_union_no_double_count_at_boundary() {
    let root = tmp_root("carollup-boundary");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    ensure_hot_rollups(&db);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..10 {
        let mut r = rich_row(base + i, i);
        r.row.source = "shared".into();
        insert_event(&db, &r);
    }
    for i in 0..5 {
        let mut r = rich_row(base + 50 + i, 300 + i);
        r.row.source = "cold-only".into();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    {
        let c = db.lock();
        // HOT (bucket>=B) : shared=7, hot-only=3.
        c.execute("INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'shared',0,'','','',7,?1,'prod')", params![b]).unwrap();
        c.execute("INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'hot-only',0,'','','',3,?1,'prod')", params![b]).unwrap();
        // PIÈGE : event_rollup STALE à bucket<B (999) -> la route DOIT l'exclure (côté hot = bucket>=B).
        c.execute("INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'shared',0,'','','',999,?1,'prod')", params![base]).unwrap();
    }
    let rr = crate::try_cold_rollup_route("search | stats count by source", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
    let res = crate::run_query_ex(&dbp, &rr.sql, 60_000, None).unwrap();
    let m: std::collections::HashMap<String, i64> = count_by_source(&res).into_iter().collect();
    assert_eq!(m.get("shared").copied().unwrap_or(0), 17, "shared = cold(10)+hot(7) ; STALE <B (999) EXCLU -> pas de double-comptage à B");
    assert_eq!(m.get("cold-only").copied().unwrap_or(0), 5, "cold-only = cold(5)");
    assert_eq!(m.get("hot-only").copied().unwrap_or(0), 3, "hot-only = hot(3)");
    let _ = std::fs::remove_dir_all(&root);
}

// (e) — dc()/distinct + timechart + 2e-filtre NE SONT PAS des motifs `count by` -> parse_stats_by_shape None
// -> pas de route cold -> l'appelant retombe sur le chemin brut cold_union_query (dc EXACT prouvé par
// p3_aggregate_correctness_union_equals_single_table). Fallback documenté (correct, plus lent).
#[test]
fn phase_a_dc_timechart_secondfilter_fall_back_no_cold_route() {
    let b = 12_345 * SECS_PER_DAY;
    assert!(crate::try_cold_rollup_route("search | stats dc(host) by source", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "dc() by -> pas de route cold");
    assert!(crate::try_cold_rollup_route("search | stats dc(host)", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "dc() -> pas de route cold");
    assert!(crate::try_cold_rollup_route("search | timechart count", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "timechart -> pas de route cold");
    assert!(crate::try_cold_rollup_route("search source=web status=500 | stats count by path", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "2e filtre non exprimable -> pas de route cold (angle mort évité)");
    assert!(crate::try_cold_rollup_route("search | stats avg(severity) by source", 0, 0, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).is_none(), "avg() -> pas de route cold");
}

// (f) — DENY (#45) sur une colonne réelle est REFUSÉ sur le MIROIR cold_rollup / cold_dim_rollup EXACTEMENT
// comme sur event : le sidecar cold (dims EN CLAIR) ne devient PAS un canal d'exfiltration d'une dim déniée en
// SQL brut. Réutilise l'authorizer partagé (install_field_authorizer) — la route cold est de toute façon
// désactivée dès qu'un masque/deny existe (comme le hot), ce miroir ferme AUSSI le chemin SQL brut.
#[test]
fn phase_a_deny_authorizer_covers_cold_rollup_mirrors() {
    let root = tmp_root("carollup-deny");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..12 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    // DENY src_ip pour ce db_path (comme field_filters_reload l'alimenterait).
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("src_ip".to_string());
        w.insert(dbp.clone(), s);
    }
    let denied = |r: &Result<Value, String>| -> bool {
        let s = format!("{r:?}");
        r.is_err() && (s.contains("prohibited") || s.contains("not authorized"))
    };
    // src_ip DÉNIÉ sur cold_rollup (miroir exact d'event_rollup) — sinon exfil de la dim déniée.
    let cr = crate::run_query_ex(&dbp, "SELECT src_ip FROM cold_rollup", 60_000, None);
    assert!(denied(&cr), "src_ip DÉNIÉ sur cold_rollup (miroir) : {cr:?}");
    // val DÉNIÉ sur cold_dim_rollup (déni CONSERVATEUR dès qu'un champ physique est dénié — parité event_dim_rollup).
    let cdr = crate::run_query_ex(&dbp, "SELECT val FROM cold_dim_rollup", 60_000, None);
    assert!(denied(&cdr), "val DÉNIÉ sur cold_dim_rollup (miroir conservateur) : {cdr:?}");
    // Parité : même déni sur event (hot).
    let hot = crate::run_query_ex(&dbp, "SELECT src_ip FROM event", 60_000, None);
    assert!(denied(&hot), "src_ip DÉNIÉ sur event (parité) : {hot:?}");
    // Déni SCOPÉ : une colonne non déniée reste lisible sur le miroir cold_rollup.
    let ok = crate::run_query_ex(&dbp, "SELECT source FROM cold_rollup", 60_000, None);
    assert!(ok.is_ok(), "source lisible sur cold_rollup (déni scopé src_ip) : {ok:?}");
    crate::field_deny_cols_cell().write().remove(&dbp);
    let _ = std::fs::remove_dir_all(&root);
}

// (g) — MASQUAGE : cold_rollup stocke les dims EN CLAIR (donc le servir SOUS masque fuiterait -> la route est
// GATÉE sur masque VIDE, comme le hot). Quand un masque est actif, query.rs prend le chemin brut
// cold_union_query, qui applique le MÊME masque (émis dans le SQL compilé) aux lignes COLD -> jamais le brut.
#[test]
fn phase_a_masking_cold_rollup_raw_but_union_masks_cold() {
    let root = tmp_root("carollup-mask");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i)); // source='src-{i}'
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    // 1) cold_rollup stocke `source` EN CLAIR -> justifie le GATE (le servir sous masque exfiltrerait).
    let raw_in_rollup: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_rollup WHERE source LIKE 'src-%'", [], |r| r.get(0)).unwrap();
    assert!(raw_in_rollup > 0, "cold_rollup stocke la dim EN CLAIR (gate sur masque VIDE obligatoire)");
    // 2) chemin brut cold_union_query avec masque MASK sur source -> lignes COLD masquées '***', jamais brut.
    let mut masks = FieldMaskSet::new();
    masks.insert("source".to_string(), MaskAction::Mask);
    let msql = compile_ev("search | table source", UWIN_FROM, UWIN_TO, masks);
    let (mres, _t, _m) = union_query_oracle(&dbp, &conf, None, UWIN_FROM, UWIN_TO, b, &msql, None, 60_000, None, &[]).unwrap();
    let msrc = col_vals(&mres, "source");
    assert!(msrc.iter().any(|v| v.as_str() == Some("***")), "source COLD masquée '***' via l'union sous masque");
    assert!(!msrc.iter().any(|v| v.as_str().map(|s| s.starts_with("src-")).unwrap_or(false)), "source brute 'src-*' JAMAIS servie sous masque");
    let _ = std::fs::remove_dir_all(&root);
}

// (h) — GÉNÉRICITÉ : une source JAMAIS vue (hors dim_rollup_specs, zéro config) est rollée dans cold_rollup
// (event_rollup GROUP BY source, aucun code par-source) ET servie vite par la route COLD. Preuve du levier
// « un nouveau vendeur auto-rollé ».
#[test]
fn phase_a_generic_unknown_source_rolls_up_zero_config() {
    let root = tmp_root("carollup-generic");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    ensure_hot_rollups(&db);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..9 {
        let mut r = rich_row(base + i, i);
        r.row.source = "totally-unknown-vendor-xyz".into();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    assert_eq!(cold_rollup_sum(&db, "source='totally-unknown-vendor-xyz'"), 9, "source INCONNUE rollée SANS config");
    let from = base;
    let to = base + SECS_PER_DAY - 1;
    let rr = crate::try_cold_rollup_route("search | stats count by source", from, to, None, b, RollupCoverage::asserted_by_the_test(i64::MAX, i64::MAX), DimRollupCoverage::all_asserted_by_the_test()).unwrap();
    let res = crate::run_query_ex(&dbp, &rr.sql, 60_000, None).unwrap();
    assert!(count_by_source(&res).iter().any(|(s, c)| s == "totally-unknown-vendor-xyz" && *c == 9), "route sert la source inconnue vite (aucun Parquet)");
    let _ = std::fs::remove_dir_all(&root);
}

// (i) — RE-SEAL IDEMPOTENT : re-jouer l'aging (jour déjà scellé+purgé) laisse cold_rollup STABLE — ni double
// (le hot ne re-tourne pas la Phase 1) ni effacement (pas de recompute sur un hot vidé). Verrouille le contrat
// crash-safety : une fois last_file=1 durable, seal_cold_rollup n'est PLUS jamais appelée pour ce jour.
#[test]
fn phase_a_reseal_idempotent_no_double_no_wipe() {
    let root = tmp_root("carollup-idem");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(cold_rollup_sum(&db, "1"), 20, "1er seal : cold_rollup = 20");
    // 2e run : jour scellé+purgé -> age_one_day court-circuite la Phase 1 -> cold_rollup INCHANGÉ.
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(cold_rollup_sum(&db, "1"), 20, "re-run aging : cold_rollup STABLE (ni double ni effacement)");
    let _ = std::fs::remove_dir_all(&root);
}

/// MAX(id) de l'ensemble agéable d'un jour (env prod) — snapshot du `max_id` FROZEN (comme `count_and_max_id`).
#[cfg(feature = "cold_tier")]
fn day_max_id(db: &Arc<Mutex<Connection>>, day: i64) -> i64 {
    db.lock()
        .query_row(
            "SELECT COALESCE(MAX(id),0) FROM event WHERE env_id='prod' AND ts>=?1 AND ts<?2",
            params![day * SECS_PER_DAY, day * SECS_PER_DAY + SECS_PER_DAY],
            |r| r.get(0),
        )
        .unwrap()
}

/// Somme cold_dim_rollup (miroir de cold_rollup_sum côté dim-grain) pour vérifier la stabilité au re-calcul.
#[cfg(feature = "cold_tier")]
fn cold_dim_rollup_sum(db: &Arc<Mutex<Connection>>, where_sql: &str) -> i64 {
    db.lock()
        .query_row(&format!("SELECT COALESCE(SUM(n),0) FROM cold_dim_rollup WHERE {where_sql}"), [], |r| r.get(0))
        .unwrap()
}

// (j) — RESUME-RECOMPUTE IDEMPOTENT (scan lock-free + apply) : le chemin PERF (#28 Phase A) matérialise le
// rollup HORS verrou (`compute_cold_rollup`) puis l'INSÈRE court (`apply_cold_rollup`). Rejouer compute+apply
// DEUX FOIS (== ce que fait un resume de Phase 1 : per-file seals présents, `last_file` absent, hot INTACT ->
// write_day_files ré-entre et RECALCULE depuis le hot intact) laisse cold_rollup / cold_dim_rollup STRICTEMENT
// IDENTIQUES : ni double (delete-jour avant insert), ni effacement (recompute complet). Parité : la somme ==
// le compte brut columnarisé du jour.
#[test]
#[cfg(feature = "cold_tier")]
fn phase_a_lockfree_recompute_idempotent_no_double_no_wipe() {
    let root = tmp_root("carollup-recompute");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // 18 lignes génériques + 6 lignes 'web' avec un champ `status` (dim rollup web/status -> cold_dim_rollup).
    for i in 0..18 {
        insert_event(&db, &rich_row(base + i, i));
    }
    for i in 0..6 {
        let mut r = rich_row(base + 100 + i, 900 + i);
        r.row.source = "web".into();
        r.row.fields = Some(format!("{{\"status\":\"{}\"}}", 200 + (i % 2) * 204)); // 200 / 404
        insert_event(&db, &r);
    }
    let total = 24i64;
    let max_id = day_max_id(&db, day);

    // 1er calcul (hors verrou) + application (court, sous verrou).
    let mat1 = crate::rollups::compute_cold_rollup(&db, &dbp, "prod", day, max_id).expect("scan lock-free 1");
    { let c = db.lock(); crate::rollups::apply_cold_rollup(&c, "prod", day, &mat1).expect("apply 1"); }
    let ev1 = cold_rollup_sum(&db, "1");
    let rows1: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_rollup", [], |r| r.get(0)).unwrap();
    let dim1 = cold_dim_rollup_sum(&db, "1");
    let dimrows1: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_dim_rollup", [], |r| r.get(0)).unwrap();
    assert_eq!(ev1, total, "parité : cold_rollup somme == lignes columnarisées du jour ({total})");
    assert_eq!(cold_dim_rollup_sum(&db, "source='web' AND dim='status'"), 6, "dim web/status rollé (6)");

    // 2e calcul + application (== resume : recompute depuis le hot INTACT).
    let mat2 = crate::rollups::compute_cold_rollup(&db, &dbp, "prod", day, max_id).expect("scan lock-free 2");
    { let c = db.lock(); crate::rollups::apply_cold_rollup(&c, "prod", day, &mat2).expect("apply 2"); }
    let ev2 = cold_rollup_sum(&db, "1");
    let rows2: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_rollup", [], |r| r.get(0)).unwrap();
    let dim2 = cold_dim_rollup_sum(&db, "1");
    let dimrows2: i64 = db.lock().query_row("SELECT COUNT(*) FROM cold_dim_rollup", [], |r| r.get(0)).unwrap();

    assert_eq!(ev1, ev2, "re-compute : cold_rollup somme STABLE (ni double ni wipe)");
    assert_eq!(rows1, rows2, "re-compute : cold_rollup nb de lignes STABLE");
    assert_eq!(dim1, dim2, "re-compute : cold_dim_rollup somme STABLE");
    assert_eq!(dimrows1, dimrows2, "re-compute : cold_dim_rollup nb de lignes STABLE");
    let _ = std::fs::remove_dir_all(&root);
}

// (k) — FROZEN SET sous scan LOCK-FREE : une ligne insérée APRÈS la capture de `max_id` (donc `id>max_id`) —
// exactement ce que fait l'ingest concurrent pendant le scan sans verrou — est EXCLUE du rollup matérialisé.
// Preuve que le prédicat `id<=max_id` gèle l'ensemble agé indépendamment de l'ingest concurrent (pas de skew).
#[test]
#[cfg(feature = "cold_tier")]
fn phase_a_lockfree_scan_excludes_id_gt_maxid() {
    let root = tmp_root("carollup-frozen");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // 15 lignes de l'ensemble FROZEN.
    for i in 0..15 {
        insert_event(&db, &rich_row(base + i, i));
    }
    let max_id = day_max_id(&db, day); // capture du tail FROZEN.
    // 10 lignes CONCURRENTES du MÊME jour/env, insérées APRÈS la capture -> id>max_id (== ingest pendant le scan).
    for i in 0..10 {
        insert_event(&db, &rich_row(base + 500 + i, 5_000 + i));
    }
    // Scan lock-free borné au max_id FROZEN, puis application.
    let mat = crate::rollups::compute_cold_rollup(&db, &dbp, "prod", day, max_id).expect("scan lock-free");
    { let c = db.lock(); crate::rollups::apply_cold_rollup(&c, "prod", day, &mat).expect("apply"); }
    assert_eq!(cold_rollup_sum(&db, "1"), 15, "id>max_id EXCLUS : rollup == ensemble frozen (15), pas 25");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #28 PHASE B — ÉLAGAGE DIMENSIONNEL SEAL-RÉSIDENT (tests). min/max + bloom scellés à l'écriture, élagage
// SANS déchiffrement au lecteur, INVARIANT prune==full-scan, rétro-compat (seal sans stats), fail-safe
// masqué/dénié, et extracteur de prédicats CONSERVATEUR. Tous gatés cold_tier (module parent).
// ====================================================================================================

/// Ligne aux dims EXPLICITES (les autres colonnes remplies de valeurs inertes) — contrôle total des dims
/// universelles élaguables pour les tests Phase B.
fn ev_full(ts: i64, source: &str, category: &str, host: Option<&str>, src_ip: Option<&str>, severity: i64) -> ColdRow {
    ColdRow {
        row: EventRow {
            ts,
            severity,
            source: source.to_string(),
            category: category.to_string(),
            message: "m".to_string(),
            host: host.map(|s| s.to_string()),
            src_ip: src_ip.map(|s| s.to_string()),
            dst_ip: None,
            url: None,
            dedup: None,
            fields: None,
            engagement_id: String::new(),
            origin: String::new(),
            env_id: Some("prod".to_string()),
        },
        xff: None,
    }
}

fn pb_corrupt(p: &Path) {
    let mut b = std::fs::read(p).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xFF;
    std::fs::write(p, &b).unwrap();
}

type PbRow = (i64, String, String, Option<String>, Option<String>, i64);
/// Dump DÉTERMINISTE des dims d'une hydratation (ts,source,category,host,src_ip,severity), trié par (ts,source).
fn pb_dump(h: &ColdHydrate) -> Vec<PbRow> {
    let mut st = h
        .conn
        .prepare("SELECT ts, source, category, host, src_ip, severity FROM cold_event ORDER BY ts, source")
        .unwrap();
    st.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, i64>(5)?))
    })
    .unwrap()
    .map(|x| x.unwrap())
    .collect()
}

// (a) STATS CALCULÉES À L'ÉCRITURE : min/max (sev/source/category/host) + bloom (présence jamais faux-négative).
#[test]
fn phaseb_dim_stats_computed_at_write() {
    let root = tmp_root("pb-write");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = pb_conf(None);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    insert_event(&db, &ev_full(base, "apache", "web", Some("web1"), Some("10.0.0.1"), 1));
    insert_event(&db, &ev_full(base + 1, "nginx", "auth", Some("web2"), Some("10.0.0.9"), 5));
    insert_event(&db, &ev_full(base + 2, "zeek", "network", None, None, 3)); // host/src_ip NULL ici
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let seals = file_seal_rows(&db, "prod", day);
    assert_eq!(seals.len(), 1, "un seul fichier");
    let st = seals[0].dim_stats.clone().expect("dim_stats scellées (Phase B)");
    assert_eq!((st.sev_min, st.sev_max), (1, 5), "severity min/max");
    assert_eq!((st.src_min.as_str(), st.src_max.as_str()), ("apache", "zeek"), "source min/max lexicographiques");
    assert_eq!((st.cat_min.as_str(), st.cat_max.as_str()), ("auth", "web"), "category min/max");
    assert_eq!((st.host_min.as_deref(), st.host_max.as_deref()), (Some("web1"), Some("web2")), "host min/max (NULL ignoré)");
    // BLOOM : une valeur INSÉRÉE n'est JAMAIS exclue (jamais de faux négatif) -> excluded_by == false.
    assert!(!st.excluded_by(&[DimEq { dim: ColdDim::Source, value: "apache".into() }]));
    assert!(!st.excluded_by(&[DimEq { dim: ColdDim::SrcIp, value: "10.0.0.1".into() }]));
    assert!(!st.excluded_by(&[DimEq { dim: ColdDim::Host, value: "web2".into() }]));
    // ABSENCE PROUVÉE -> exclu (severity hors range ; source > max).
    assert!(st.excluded_by(&[DimEq { dim: ColdDim::Severity, value: "9".into() }]));
    assert!(st.excluded_by(&[DimEq { dim: ColdDim::Source, value: "zzz-after-zeek".into() }]));
    // ENCODE/DECODE round-trip (le blob scellé redonne les MÊMES stats).
    assert_eq!(DimStats::decode(&st.encode()).unwrap(), st, "encode/decode round-trip");
    let _ = std::fs::remove_dir_all(&root);
}

// (b) L'ÉLAGAGE SAUTE LES FICHIERS NON-MATCHANTS SANS DÉCHIFFRER : fichiers hors-match CORROMPUS ; s'ils
// étaient ouverts, l'AEAD échouerait -> hydrate Err. Prouvé pour source=X, host=Y, src_ip=Z.
#[test]
fn phaseb_prune_skips_nonmatching_files_without_decrypt() {
    let root = tmp_root("pb-skip");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 11;
    let base = day * SECS_PER_DAY;
    insert_event(&db, &ev_full(base, "apache", "web", Some("web1"), Some("10.0.0.1"), 1));
    insert_event(&db, &ev_full(base + 1, "nginx", "web", Some("web2"), Some("10.20.30.40"), 2));
    insert_event(&db, &ev_full(base + 2, "zeek", "web", Some("web3"), Some("172.16.9.9"), 3));
    insert_recent_tail_holder(&db);
    let conf = pb_conf(Some(1)); // 1 ligne/fichier -> mapping fichier<->ligne déterministe
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 3);
    let cold = cold_root(&conf, &dbp); // racine cold PAR-TENANT (race-immune)
    // Corrompt les fichiers 0 et 2 (la valeur cherchée vit dans le fichier 1). Ouverts -> Err.
    for seq in [0i64, 2] {
        pb_corrupt(&file_path(&cold, "prod", day, seq));
    }
    for preds in [
        vec![DimEq { dim: ColdDim::Source, value: "nginx".into() }],
        vec![DimEq { dim: ColdDim::Host, value: "web2".into() }],
        vec![DimEq { dim: ColdDim::SrcIp, value: "10.20.30.40".into() }],
    ] {
        let h = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base + 2, &ALL_HYDRATE_COLS, &preds)
            .expect("élagage -> seul le fichier 1 (sain) lu (les corrompus jamais ouverts)");
        assert_eq!(h.files_read, 1, "un seul fichier matchant lu");
        assert_eq!(h.files_pruned, 2, "deux fichiers non-matchants élagués SANS déchiffrer");
        assert_eq!(h.rows_hydrated, 1);
    }
    let _ = std::fs::remove_dir_all(&root);
}

// (c)+(d) INVARIANT DE CORRECTION : prune == full-scan. Pour une BATTERIE de requêtes sélectives, l'ensemble
// des lignes qui MATCHENT le prédicat est IDENTIQUE que les fichiers soient élagués ou intégralement scannés
// (un faux positif de bloom ne fait qu'ajouter un déchiffrement ; min/max ne saute que le prouvé-hors-borne).
#[test]
fn phaseb_prune_equals_full_scan_battery() {
    let root = tmp_root("pb-eq");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 12;
    let base = day * SECS_PER_DAY;
    // 64 lignes, dims LOCALISÉES par blocs (localité temporelle) : bloc A [0..32) apache/web1/10.0.0.1/web sev{0,1} ;
    // bloc B [32..64) zeek/db1/192.168.1.5/auth sev{3,4}. cap=8 -> 8 fichiers (0..3 = A, 4..7 = B).
    for i in 0..64i64 {
        let r = if i < 32 {
            ev_full(base + i, "apache", "web", Some("web1"), Some("10.0.0.1"), i % 2)
        } else {
            ev_full(base + i, "zeek", "auth", Some("db1"), Some("192.168.1.5"), 3 + i % 2)
        };
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    let conf = pb_conf(Some(8));
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let nfiles = file_seal_rows(&db, "prod", day).len();
    assert_eq!(nfiles, 8, "8 fichiers");
    let (lo, hi) = (base, base + 63);

    // La référence : full-scan (aucun prédicat) -> TOUTES les lignes (ts-filtrées), une seule fois.
    let full = pb_dump(&hydrate_dbp_pred(&db, &conf, &dbp, "prod", lo, hi, &ALL_HYDRATE_COLS, &[]).unwrap());
    assert_eq!(full.len(), 64);

    // Chaque cas : (préds, filtre Rust de l'ÉGALITÉ, doit-il élaguer au moins 1 fichier ?).
    struct Case {
        preds: Vec<DimEq>,
        f: Box<dyn Fn(&PbRow) -> bool>,
        expect_prune: bool,
    }
    let cases = vec![
        Case { preds: vec![DimEq { dim: ColdDim::Source, value: "zeek".into() }], f: Box::new(|r: &PbRow| r.1 == "zeek"), expect_prune: true },
        Case { preds: vec![DimEq { dim: ColdDim::Source, value: "apache".into() }], f: Box::new(|r: &PbRow| r.1 == "apache"), expect_prune: true },
        Case { preds: vec![DimEq { dim: ColdDim::Host, value: "web1".into() }], f: Box::new(|r: &PbRow| r.3.as_deref() == Some("web1")), expect_prune: true },
        Case { preds: vec![DimEq { dim: ColdDim::SrcIp, value: "192.168.1.5".into() }], f: Box::new(|r: &PbRow| r.4.as_deref() == Some("192.168.1.5")), expect_prune: true },
        Case { preds: vec![DimEq { dim: ColdDim::Category, value: "auth".into() }], f: Box::new(|r: &PbRow| r.2 == "auth"), expect_prune: true },
        Case { preds: vec![DimEq { dim: ColdDim::Severity, value: "4".into() }], f: Box::new(|r: &PbRow| r.5 == 4), expect_prune: true },
        // Valeur ABSENTE partout -> tout élagué -> 0 ligne des DEUX côtés (jamais une ligne rendue à tort).
        Case { preds: vec![DimEq { dim: ColdDim::Source, value: "absent-xyz".into() }], f: Box::new(|r: &PbRow| r.1 == "absent-xyz"), expect_prune: true },
        // MULTI-PRÉD (AND contradictoire entre blocs) -> tout élagué -> 0 ligne des deux côtés.
        Case {
            preds: vec![DimEq { dim: ColdDim::Source, value: "apache".into() }, DimEq { dim: ColdDim::Host, value: "db1".into() }],
            f: Box::new(|r: &PbRow| r.1 == "apache" && r.3.as_deref() == Some("db1")),
            expect_prune: true,
        },
    ];
    for c in &cases {
        let pruned = hydrate_dbp_pred(&db, &conf, &dbp, "prod", lo, hi, &ALL_HYDRATE_COLS, &c.preds).unwrap();
        let pdump = pb_dump(&pruned);
        let ff: Vec<PbRow> = full.iter().filter(|r| (c.f)(r)).cloned().collect();
        let pf: Vec<PbRow> = pdump.iter().filter(|r| (c.f)(r)).cloned().collect();
        assert_eq!(ff, pf, "INVARIANT prune==full-scan violé (lignes matchantes divergentes)");
        if c.expect_prune {
            assert!(pruned.files_pruned >= 1, "requête sélective localisée -> au moins 1 fichier élagué (files_pruned={})", pruned.files_pruned);
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

// (e) RÉTRO-COMPAT : un seal SANS stats (colonne NULL, pré-Phase-B) OU au blob illisible -> None -> le fichier
// est TOUJOURS GARDÉ (jamais élagué), même pour un prédicat qui l'exclurait avec des stats -> zéro perte.
#[test]
fn phaseb_pre_phaseb_seal_without_stats_always_kept() {
    let root = tmp_root("pb-compat");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 13;
    let base = day * SECS_PER_DAY;
    insert_event(&db, &ev_full(base, "apache", "web", Some("web1"), Some("10.0.0.1"), 1));
    insert_recent_tail_holder(&db);
    let conf = pb_conf(None);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let absent = vec![DimEq { dim: ColdDim::Source, value: "zzz-absent".into() }];
    // Avec stats : source > max -> fichier élagué.
    let with_stats = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base, &ALL_HYDRATE_COLS, &absent).unwrap();
    assert_eq!(with_stats.files_pruned, 1);
    assert_eq!(with_stats.files_read, 0);
    // Simule PRÉ-Phase-B : NULL la colonne dim_stats -> None -> jamais d'élagage.
    db.lock().execute("UPDATE cold_seal SET dim_stats=NULL", []).unwrap();
    assert!(file_seal_rows(&db, "prod", day)[0].dim_stats.is_none(), "seal NULL -> None");
    let kept = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base, &ALL_HYDRATE_COLS, &absent).unwrap();
    assert_eq!(kept.files_read, 1, "seal sans stats -> GARDÉ (fallback correct)");
    assert_eq!(kept.files_pruned, 0);
    // Blob ILLISIBLE (mauvaise version) -> None aussi -> gardé.
    db.lock().execute("UPDATE cold_seal SET dim_stats=X'00DEADBEEF'", []).unwrap();
    assert!(file_seal_rows(&db, "prod", day)[0].dim_stats.is_none(), "blob illisible -> None");
    let kept2 = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base, &ALL_HYDRATE_COLS, &absent).unwrap();
    assert_eq!(kept2.files_read, 1, "blob illisible -> GARDÉ");
    let _ = std::fs::remove_dir_all(&root);
}

// (f) GÉNÉRIQUE : une source JAMAIS configurée (vendeur inconnu) élague à l'identique, ZÉRO config — le
// mécanisme est clé sur la VALEUR BRUTE de la colonne, pas sur un vocabulaire.
#[test]
fn phaseb_generic_unknown_source_prunes_zero_config() {
    let root = tmp_root("pb-generic");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 14;
    let base = day * SECS_PER_DAY;
    insert_event(&db, &ev_full(base, "mystery-siem-v9000", "web", Some("h1"), Some("10.0.0.1"), 1)); // fichier 0
    insert_event(&db, &ev_full(base + 1, "apache", "web", Some("h2"), Some("10.0.0.2"), 2)); // fichier 1
    insert_recent_tail_holder(&db);
    let conf = pb_conf(Some(1));
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    let cold = cold_root(&conf, &dbp);
    // Corrompt le fichier 1 (apache) : une requête sur le vendeur inconnu doit l'élaguer (source apache < mystery? non
    // -> "apache" < "mystery..." -> pred "mystery" > max "apache" -> exclu par max). Fichier 0 (le vendeur) gardé.
    pb_corrupt(&file_path(&cold, "prod", day, 1));
    let preds = vec![DimEq { dim: ColdDim::Source, value: "mystery-siem-v9000".into() }];
    let h = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base + 1, &ALL_HYDRATE_COLS, &preds).expect("vendeur inconnu élague pareil");
    assert_eq!(h.files_read, 1);
    assert_eq!(h.files_pruned, 1);
    assert_eq!(h.rows_hydrated, 1);
    let _ = std::fs::remove_dir_all(&root);
}

// (g) SÉCURITÉ — FAIL-SAFE MASQUÉ/DÉNIÉ : un filtre sur une dim MASQUÉE/DÉNIÉE est REJETÉ à la COMPILATION
// (garde oracle-de-filtre #45) -> la requête échoue AVANT tout chemin cold -> l'élagage ne s'exécute JAMAIS
// sur une dim masquée. L'élagage n'ajoute donc AUCUNE capacité : il n'optimise que des filtres qui compilent,
// et un filtre de dim masquée/déniée ne compile pas. (Décision documentée : prune-fail-safe par construction.)
#[test]
fn phaseb_masked_or_denied_dim_filter_rejected_before_cold_prune() {
    use guatx_core::soql::{FieldMaskSet, MaskAction};
    let mut deny = FieldMaskSet::new();
    deny.insert("src_ip", MaskAction::Deny);
    assert!(
        crate::soql_to_sql_masked_x("search src_ip=9.9.9.9", 0, 0, None, &deny).is_err(),
        "filtre sur dim DÉNIÉE rejeté à la compilation -> jamais de prune cold sur elle"
    );
    let mut mask = FieldMaskSet::new();
    mask.insert("host", MaskAction::Mask);
    assert!(
        crate::soql_to_sql_masked_x("search host=web1", 0, 0, None, &mask).is_err(),
        "filtre sur dim MASQUÉE rejeté à la compilation"
    );
    // Contrôle : sans masque, la MÊME requête compile (le fail-safe est BIEN dû au masque, pas à la forme).
    assert!(crate::soql_to_sql_masked_x("search host=web1", 0, 0, None, &FieldMaskSet::new()).is_ok());
}

/// #28 PHASE B — EXTRAIT les préds cold en lisant le SQL que le CŒUR compile RÉELLEMENT (nouvelle source de
/// vérité : `extract_cold_dim_preds` prend le SQL COMPILÉ, plus le GXQL brut). from/to=0 -> pas d'atome `ts`
/// parasite (sans effet sur l'extraction, mais WHERE plus lisible).
fn xpreds(soql: &str) -> Vec<DimEq> {
    extract_cold_dim_preds(&compile_ev(soql, 0, 0, FieldMaskSet::new()))
}

// EXTRACTEUR (via SQL COMPILÉ) — extrait les égalités SÛRES de dims de la FEUILLE de base, et N'EXTRAIT RIEN
// d'ambigu (négation/regex/joker/in/numérique-string/étage-aval/append/non-dim). Parité PAR CONSTRUCTION : on
// lit la sortie du compilateur -> la valeur ne peut diverger de ce que la requête filtre.
#[test]
fn phaseb_extract_preds_conservative_and_safe() {
    let g = xpreds;
    let has = |v: &[DimEq], d: ColdDim, val: &str| v.iter().any(|p| p.dim == d && p.value == val);

    let p = g("search source=apache host=web1 severity=3 src_ip=10.0.0.1 dst_ip=10.0.0.2 category=web");
    assert!(has(&p, ColdDim::Source, "apache"));
    assert!(has(&p, ColdDim::Host, "web1"));
    assert!(has(&p, ColdDim::Severity, "3"));
    assert!(has(&p, ColdDim::SrcIp, "10.0.0.1"));
    assert!(has(&p, ColdDim::DstIp, "10.0.0.2"));
    assert!(has(&p, ColdDim::Category, "web"));
    // base NUE (pas de mot-clé `search`) + alias `:` de l'égalité.
    assert!(has(&g("source=nginx"), ColdDim::Source, "nginx"));
    assert!(has(&g("search source:zeek"), ColdDim::Source, "zeek"));
    // Valeur QUOTÉE : le cœur strippe les guillemets -> `"source" = 'a b'` -> on extrait DÉSORMAIS 'a b' (lossless :
    // c'est exactement l'octet filtré ; l'ancien ré-parse GXQL s'en abstenait faute de tokeniser comme le cœur).
    assert!(has(&g("search source=\"a b\""), ColdDim::Source, "a b"), "valeur quotée -> extraite du SQL compilé");

    // NÉGATIVES — ne DOIVENT rien extraire (repli ts-only, jamais de sur-élagage) :
    assert!(g("search source!=apache").is_empty(), "négation -> <>");
    assert!(g("search source=~apa").is_empty(), "regex =~ -> REGEXP");
    assert!(g("search source:~apa").is_empty(), "regex :~ -> REGEXP");
    assert!(g("search source=web*").is_empty(), "joker * -> LIKE");
    assert!(g("search source in (a,b)").is_empty(), "in (...) -> IN, pas une égalité");
    assert!(g("search url=http://x").is_empty(), "url non élaguable");
    assert!(g("search fieldx=1").is_empty(), "champ JSON non universel");
    assert!(g("search source=500").is_empty(), "numérique sur dim string -> branche cast, pas extrait");
    assert!(g("severity>=3").is_empty(), "borne, pas égalité");
    assert!(g("metric cpu source=x").is_empty(), "base metric -> aucun FROM event -> rien");
    // ÉTAGE AVAL / APPEND : un prédicat HORS de la feuille de base ne contraint pas le scan -> jamais extrait.
    let pipe = g("search host=web1 | where source=evil");
    assert!(has(&pipe, ColdDim::Host, "web1"), "host de la FEUILLE de base extrait");
    assert!(!pipe.iter().any(|p| p.dim == ColdDim::Source), "source d'un `where` AVAL (WHERE englobant) PAS extrait");
    let sub = g("search host=web1 | append [search source=evil]");
    assert!(sub.is_empty(), "append = 2 feuilles FROM event -> bail TOTAL (même host n'est pas extrait)");
    let ft = g("error | stats count by source");
    assert!(ft.is_empty(), "terme libre + agrégat -> aucune égalité de dim de base");
}

// PARITÉ PAR CONSTRUCTION — l'extracteur LIT le SQL compilé, donc TOUT pred émis y apparaît forcément à la
// VALEUR EXACTE. Ce test verrouille (a) l'invariant `pred ⊆ SQL compilé` sur une batterie, et (b) la
// RESTAURATION des formes que l'ancien ré-parse GXQL abandonnait : F1 « colle op-char » (`source=foo! bar` ->
// cœur `source='foo!bar'`) est désormais extraite à la valeur COLLÉE exacte (lossless), tandis que les formes où
// le cœur ne compile AUCUNE égalité de dim (op-char en tête -> freetext json) ne produisent toujours rien.
#[test]
fn phaseb_extractor_matches_core_compile_parity() {
    // Fragment WHERE EXACT que le cœur émet pour une égalité de dim (colonne quotée `"x"`, valeur simple-quotée ;
    // severity = entier nu). Le `'` de FERMETURE rend le `contains` PRÉCIS : `"source" = 'foo!'` n'est PAS une
    // sous-chaîne de `"source" = 'foo!bar'` -> un pred à valeur TRONQUÉE serait détecté comme absent.
    let frag = |dim: ColdDim, val: &str| -> String {
        let col = match dim {
            ColdDim::Source => "source",
            ColdDim::Category => "category",
            ColdDim::Host => "host",
            ColdDim::SrcIp => "src_ip",
            ColdDim::DstIp => "dst_ip",
            ColdDim::Severity => "severity",
        };
        match dim {
            ColdDim::Severity => format!("\"{col}\" = {val}"),
            _ => format!("\"{col}\" = '{}'", val.replace('\'', "''")),
        }
    };

    // Batterie : F1 (colle op-char), cas propres, variantes casse/espace/quotée/in/parens. INVARIANT : chaque
    // pred émis est une sous-chaîne du SQL compilé (donc la valeur filtrée EXACTE) -> jamais de sur-élagage.
    let battery = [
        "search source=foo! bar",             // F1 : cœur -> source='foo!bar' -> extrait 'foo!bar' (valeur EXACTE)
        "search foo> source=bar",             // op-char en tête -> freetext json (aucune égalité source) -> rien
        "source=a=b",                         // op-char INTERNE : cœur ET extracteur -> source='a=b'
        "host=x!",                            // op-char final sans suivant : pas de colle -> host='x!'
        "search src_ip=10.0.0.1! nope",       // F1 : cœur colle -> src_ip='10.0.0.1!nope' -> extrait la valeur collée
        "search source=apache host=web1",
        "search severity=3",
        "search source=apache host=web1 severity=3 src_ip=10.0.0.1 dst_ip=10.0.0.2 category=web",
        "source=nginx",
        "search source:zeek",                 // alias `:` de l'égalité
        "search Source=apache",               // CASSE : `Source` != colonne réelle -> rien
        "search source = apache",             // ESPACES autour de `=` : le cœur colle -> source='apache' (RESTAURÉ)
        "search source=\"a b\"",              // valeur quotée : cœur strippe -> source='a b' (RESTAURÉ)
        "search host=web1 source in (a,b)",   // host=web1 EXTRAIT (IN non-élaguable) — RESTAURÉ
        "search source=a (b)",                // `(b)` freetext -> source='a' extrait
    ];

    // SECONDE BATTERIE — LES ENTRÉES QUE LE CŒUR REFUSE DE COMPILER (donc qui n'atteignent JAMAIS le cold).
    //
    // Ces deux formes compilaient jusqu'à guatx-core v0.2.0 : dans `champ [not] in (…)` le nom de champ était
    // TRONQUÉ au séparateur, si bien que `src_ip=10.0.0.1 not in (x)` partait sur une vraie colonne que
    // l'utilisateur n'avait jamais nommée. C'est précisément le défaut « entrée non fiable » fermé par le lot
    // B.1 (core v0.2.1, pin bumpé en 1a67014) : le cœur REJETTE désormais le nom malformé.
    // On les garde ICI, assertées comme REJETÉES, plutôt que de les supprimer : le contrat de sûreté du tier
    // cold pour ces formes est « le cœur ne compile rien -> rien n'est extrait -> aucun fichier Parquet élagué »,
    // et il doit rester OPPOSABLE. Si un cœur futur ré-acceptait ces noms, cette assertion rougirait — au lieu de
    // laisser revenir en silence une divergence extracteur/compilateur, c'est-à-dire une PERTE DE LIGNES muette
    // sur l'historique froid.
    //
    // L'ASSERTION PORTE SUR L'IDENTITÉ DE L'ERREUR, PAS SUR SA PRÉSENCE. Un `is_err()` nu resterait VERT si un
    // cœur futur rejetait ces requêtes pour une raison SANS RAPPORT (grammaire cassée, commande inconnue, schéma
    // vide, panique convertie en Err…) : le contrat « c'est la VALIDATION DU NOM DE CHAMP qui refuse » ne serait
    // plus vérifié, seulement le fait qu'un refus quelconque a lieu. On exige donc les DEUX marqueurs du refus
    // attendu : le motif de validation (`champ invalide dans le filtre`) ET le NOM MALFORMÉ EXACT que le cœur
    // cite (`source=x` / `src_ip=10.0.0.1`) — ce second marqueur prouve que le refus vise bien CE token-là.
    let battery_core_rejects = [
        // (requête, nom de champ malformé que le cœur DOIT citer dans son refus)
        ("search source=x in (a,b)", "source=x"),          // nom de champ invalide devant `in (…)`
        ("search src_ip=10.0.0.1 not in (x)", "src_ip=10.0.0.1"), // idem devant `not in (…)`
    ];
    const CORE_INVALID_FIELD_MARKER: &str = "champ invalide dans le filtre";
    for (q, bad_field) in battery_core_rejects {
        let r = guatx_core::soql::to_sql(q, 0, 0, &Schema::events());
        let e = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        assert!(r.is_err(),
            "`{q}` doit être REJETÉ par le cœur (nom de champ malformé devant `[not] in`, durci en core v0.2.1) ; \
             compilé = {r:?}. S'il compile de nouveau, RE-VÉRIFIER la parité de l'extracteur AVANT de le \
             réintégrer à la batterie ci-dessus.");
        assert!(e.contains(CORE_INVALID_FIELD_MARKER) && e.contains(bad_field),
            "`{q}` est bien refusé, mais PAS pour la raison verrouillée ici : le refus attendu est la VALIDATION \
             DU NOM DE CHAMP (`{CORE_INVALID_FIELD_MARKER}` + le nom malformé `{bad_field}`), or le cœur répond \
             «{e}». Un refus pour une AUTRE cause (grammaire, commande inconnue, schéma…) ne prouve RIEN sur la \
             garde B.1 et masquerait son retrait.");
    }

    for q in battery {
        let sql = compile_ev(q, 0, 0, FieldMaskSet::new());
        let preds = extract_cold_dim_preds(&sql);
        for p in &preds {
            let f = frag(p.dim, &p.value);
            assert!(
                sql.contains(&f),
                "PARITÉ VIOLÉE : pour `{q}` l'extracteur émet {:?}=`{}` mais le SQL compilé `{sql}` ne contient \
                 pas `{f}` -> élaguer là-dessus DROPPERAIT une ligne que la requête rend",
                p.dim, p.value
            );
        }
    }

    // RESTAURÉ — F1 « colle op-char » : la valeur COLLÉE exacte est désormais extraite (l'ancien code bailait) :
    assert!(xpreds("search source=foo! bar").iter().any(|p| p.dim == ColdDim::Source && p.value == "foo!bar"),
        "F1 restauré : `source=foo! bar` -> cœur source='foo!bar' -> extrait 'foo!bar'");
    assert!(xpreds("search src_ip=10.0.0.1! nope").iter().any(|p| p.dim == ColdDim::SrcIp && p.value == "10.0.0.1!nope"),
        "F1 restauré : src_ip collé -> valeur exacte extraite");
    // ...et le cœur ne compile AUCUN filtre source pour `foo> source=bar` (op-char en tête -> freetext json) :
    assert!(!xpreds("search foo> source=bar").iter().any(|p| p.dim == ColdDim::Source),
        "`foo> source=bar` : le cœur ne compile aucune égalité source -> rien extrait");
    // cas SÛRS toujours émis :
    assert!(xpreds("source=a=b").iter().any(|p| p.dim == ColdDim::Source && p.value == "a=b"));
    assert!(xpreds("host=x!").iter().any(|p| p.dim == ColdDim::Host && p.value == "x!"));
}

// `in (...)` / PARENTHÈSES — l'ÉGALITÉ QUI ACCOMPAGNE un `IN` est RESTAURÉE. AVANT (ré-parse GXQL) : toute base
// portant `(`/`in` -> BAIL TOTAL (perte de l'élagage sur host, alors même que `"host" = 'web1'` contraint bien
// toutes les lignes). MAINTENANT (lecture du SQL compilé) : la clause `IN (...)` n'est pas une égalité (jamais
// mal-extraite comme telle), MAIS l'égalité `"host" = 'web1'` qui l'accompagne EST extraite -> élagage sur host
// restauré, sans risque (lossless par construction : la valeur est celle que le cœur filtre).
#[test]
fn phaseb_extractor_in_clause_extracts_the_equality_not_the_in() {
    // (1) LE CAS MOTIVANT — `host=web1 source in (a,b)` : host=web1 EXTRAIT, la clause IN NON.
    let p = xpreds("search host=web1 source in (a,b)");
    assert!(p.iter().any(|x| x.dim == ColdDim::Host && x.value == "web1"), "host=web1 EXTRAIT (RESTAURÉ)");
    assert!(!p.iter().any(|x| x.dim == ColdDim::Source), "la clause `source in (a,b)` n'est PAS extraite comme égalité");

    // (2) `in (...)` sur la dim elle-même -> aucune égalité (mais pas de bail catastrophique) :
    assert!(xpreds("search source in (a,b)").is_empty(), "`source in (a,b)` seul -> aucune égalité");
    // `source=x in (a,b)` — F2, MAINTENANT FERMÉ PLUS HAUT, DANS LE CŒUR. Jusqu'à guatx-core v0.2.0 le cœur
    // ACCEPTAIT ce nom de champ malformé (`source=x`), le tronquait au séparateur et compilait `source=''`
    // (+ un IN sur `fields.x`) ; le test vérifiait ici que l'extracteur n'en tirait pas `source='x'`.
    // guatx-core v0.2.1 (lot B.1 « entrée non fiable », pin bumpé en 1a67014) REJETTE désormais la requête à la
    // COMPILATION : « champ invalide dans le filtre : source=x ». La garde est donc devenue STRICTEMENT plus
    // forte — une requête que le cœur refuse de compiler n'atteint JAMAIS le tier cold, donc aucun pred ne peut
    // en être extrait ni aucun fichier Parquet élagué à tort. On verrouille ce contrat-là (et non l'ancien SQL
    // permissif) : si un cœur futur ré-acceptait ce nom, ce test rougirait au lieu de laisser F2 revenir en
    // silence. NB : c'est CE test qui a rougi quand le pin est passé en v0.2.1, et rien en CI ne l'exécutait.
    // (La liste complète des formes que le cœur rejette vit dans `battery_core_rejects`, plus bas.)
    let rejected = guatx_core::soql::to_sql("search source=x in (a,b)", 0, 0, &Schema::events());
    assert!(rejected.is_err(),
        "le cœur doit REJETER le nom de champ malformé `source=x` (v0.2.1+) ; compilé = {rejected:?}");

    // (3) NON-RÉGRESSION — bases propres, à parité avec le cœur :
    let clean = xpreds("search source=apache host=web1 severity=3");
    assert!(clean.iter().any(|p| p.dim == ColdDim::Source && p.value == "apache"), "clean : source émis");
    assert!(clean.iter().any(|p| p.dim == ColdDim::Host && p.value == "web1"), "clean : host émis");
    assert!(clean.iter().any(|p| p.dim == ColdDim::Severity && p.value == "3"), "clean : severity émis");
    // un `source=intel` (valeur contenant `in`) émet toujours — aucune confusion avec le mot-clé `in` :
    assert!(xpreds("search source=intel").iter().any(|p| p.dim == ColdDim::Source && p.value == "intel"),
        "`source=intel` (valeur contenant `in`) émet bien");
}

// F1 (BOUT-EN-BOUT) — VALEUR À OP-CHAR EXTRAITE À LA VALEUR EXACTE, FICHIER GARDÉ. Le cœur compile
// `search source=foo! bar` en `"source" = 'foo!bar'` (colle op-char). L'extracteur, LISANT ce SQL, émet
// DÉSORMAIS source='foo!bar' (la valeur collée EXACTE) -> le fichier dont la ligne est source='foo!bar' est dans
// le bloom -> NON élagué -> ligne rendue (lossless, ET l'élagage est restauré au lieu d'être abandonné). On PROUVE
// aussi que la valeur TRONQUÉE `source='foo!'` (l'ancienne divergence F1) aurait élagué à tort -> perte évitée.
#[test]
fn phaseb_operator_char_value_extracted_exact_and_kept() {
    let root = tmp_root("pb-opchar");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 16;
    let base = day * SECS_PER_DAY;
    insert_event(&db, &ev_full(base, "foo!bar", "web", Some("web1"), Some("10.0.0.1"), 1));
    insert_recent_tail_holder(&db);
    let conf = pb_conf(Some(1));
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 1, "1 fichier cold");

    // L'extracteur lit le SQL compilé (`"source" = 'foo!bar'`) -> émet source='foo!bar' (valeur collée EXACTE).
    let preds = xpreds("search source=foo! bar");
    assert!(preds.iter().any(|p| p.dim == ColdDim::Source && p.value == "foo!bar"),
        "F1 : valeur collée EXACTE 'foo!bar' extraite (RESTAURÉ)");
    let kept = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base, &ALL_HYDRATE_COLS, &preds).unwrap();
    assert_eq!(kept.files_pruned, 0, "fichier NON élagué (source='foo!bar' est dans le bloom)");
    assert_eq!(kept.files_read, 1);
    let dump = pb_dump(&kept);
    assert!(dump.iter().any(|r| r.1 == "foo!bar"), "la ligne source='foo!bar' (le vrai match) EST rendue");

    // PREUVE DU DANGER ÉVITÉ : la valeur TRONQUÉE (ancienne divergence) aurait élagué CE fichier -> ligne perdue.
    let truncated = vec![DimEq { dim: ColdDim::Source, value: "foo!".into() }];
    let dropped = hydrate_dbp_pred(&db, &conf, &dbp, "prod", base, base, &ALL_HYDRATE_COLS, &truncated).unwrap();
    assert_eq!(dropped.files_pruned, 1, "la valeur tronquée `source=foo!` élague le fichier (démontre la perte évitée)");
    assert_eq!(dropped.rows_hydrated, 0, "-> la ligne matchante aurait été DROPPÉE (silent data loss)");

    let _ = std::fs::remove_dir_all(&root);
}

// PARSER DU SQL COMPILÉ — ROBUSTESSE (SQL forgé à la main, sans passer par le cœur). Verrouille les gardes du
// nouvel extracteur : feuille UNIQUE, split AND top-level conscient des littéraux/parenthèses, rejet OR/</>/LIKE/
// IN/json_extract, borne du WHERE au `)` englobant, dé-échappement `''`/`""`, bail sur feuilles multiples.
#[test]
fn phaseb_extract_from_compiled_sql_parser_robustness() {
    let g = extract_cold_dim_preds; // prend le SQL COMPILÉ directement
    let has = |v: &[DimEq], d: ColdDim, val: &str| v.iter().any(|p| p.dim == d && p.value == val);

    // Feuille unique, deux égalités top-level AND -> les deux extraites.
    let p = g("SELECT ts FROM event WHERE \"source\" = 'apache' AND \"host\" = 'web1'");
    assert!(has(&p, ColdDim::Source, "apache") && has(&p, ColdDim::Host, "web1"), "deux égalités top-level extraites");

    // Severity numérique nu (signe optionnel) ; borne -> pas extraite.
    assert!(has(&g("SELECT ts FROM event WHERE \"severity\" = 7"), ColdDim::Severity, "7"));
    assert!(has(&g("SELECT ts FROM event WHERE \"severity\" = -1"), ColdDim::Severity, "-1"));
    assert!(g("SELECT ts FROM event WHERE \"severity\" >= 3").is_empty(), "borne severity -> pas extraite");
    assert!(g("SELECT ts FROM event WHERE \"severity\" = '7'").is_empty(), "severity quotée (non-numérique) -> pas extraite");

    // Échappement `''` dans la valeur -> round-trip byte-exact.
    assert!(has(&g("SELECT ts FROM event WHERE \"source\" = 'a''b'"), ColdDim::Source, "a'b"), "unescape '' -> ' (round-trip)");
    // Identifiant échappé `""` (défensif).
    assert!(has(&g("SELECT ts FROM event WHERE \"host\" = 'h'"), ColdDim::Host, "h"));

    // OR parenthésé (eventtype/tag) -> segment `(...)` rejeté ; OR de premier niveau (défensif) -> résidu rejeté.
    assert!(g("SELECT ts FROM event WHERE (\"source\" = 'a' OR \"host\" = 'b')").is_empty(), "OR parenthésé -> rien");
    assert!(g("SELECT ts FROM event WHERE \"source\" = 'a' OR \"host\" = 'b'").is_empty(), "OR top-level (résidu) -> rien");

    // <> / LIKE / IN / json_extract / RHS numérique nu sur dim string -> jamais extraits.
    assert!(g("SELECT ts FROM event WHERE \"source\" <> 'a'").is_empty(), "<> -> rien");
    assert!(g("SELECT ts FROM event WHERE \"source\" LIKE '%a%'").is_empty(), "LIKE -> rien");
    assert!(g("SELECT ts FROM event WHERE \"source\" COLLATE NOCASE IN ('a','b')").is_empty(), "IN -> rien");
    assert!(g("SELECT ts FROM event WHERE json_extract(fields,'$.x') = 'a'").is_empty(), "json_extract -> rien");
    assert!(g("SELECT ts FROM event WHERE \"source\" = 500").is_empty(), "RHS numérique nu sur dim string -> rien");

    // PLUSIEURS feuilles FROM event (union/append/join) -> bail TOTAL (un pred global n'est pas sûr).
    assert!(
        g("SELECT c FROM (SELECT ts FROM event WHERE \"host\" = 'a') UNION ALL SELECT ts FROM event WHERE \"source\" = 'b'").is_empty(),
        "2 feuilles FROM event -> bail total"
    );

    // `FROM event` et ` AND ` À L'INTÉRIEUR d'un littéral -> ne comptent pas / ne coupent pas (scan conscient des quotes).
    let lit = g("SELECT ts FROM event WHERE \"source\" = 'FROM event' AND \"host\" = 'web1'");
    assert!(has(&lit, ColdDim::Source, "FROM event") && has(&lit, ColdDim::Host, "web1"), "`FROM event` en littéral -> une seule feuille");
    assert!(has(&g("SELECT ts FROM event WHERE \"source\" = 'a AND b' AND \"host\" = 'web1'"), ColdDim::Source, "a AND b"),
        "` AND ` en littéral ne coupe pas le segment");

    // WHERE borné par le `)` de la sous-requête englobante : une égalité du WHERE AVAL n'est PAS lue.
    let wrapped = g("SELECT * FROM (SELECT ts FROM event WHERE \"host\" = 'web1') WHERE \"source\" = 'evil'");
    assert!(has(&wrapped, ColdDim::Host, "web1"), "égalité de la feuille extraite");
    assert!(!wrapped.iter().any(|p| p.dim == ColdDim::Source), "égalité du WHERE AVAL (hors feuille) PAS extraite");

    // WHERE borné par un mot-clé de clause (GROUP BY) — cas non-parenthésé défensif.
    let grp = g("SELECT \"host\" FROM event WHERE \"source\" = 'a' GROUP BY \"host\"");
    assert!(has(&grp, ColdDim::Source, "a"), "égalité avant GROUP BY extraite");

    // base metric / aucun FROM event -> rien.
    assert!(g("SELECT ts FROM metric WHERE name='cpu'").is_empty(), "aucun FROM event -> rien");
}

// BOUT-EN-BOUT (RESTAURÉ) — `host=web1 source in (a,b)` élague DÉSORMAIS sur host, à parité avec le full-scan.
// AVANT : la base portait `(`/`in` -> BAIL total -> AUCUN élagage. MAINTENANT : host='web1' est extrait du SQL
// compilé -> les fichiers sans web1 sont sautés, et l'ensemble des lignes rendues reste IDENTIQUE au full-scan.
#[test]
fn phaseb_now_prunes_host_when_in_clause_present_equals_full_scan() {
    let root = tmp_root("pb-hostin");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let day = M - 17;
    let base = day * SECS_PER_DAY;
    // bloc A [0..32) host=web1 (source alterne a/b) ; bloc B [32..64) host=web9 (source c/d). cap=8 -> 8 fichiers.
    for i in 0..64i64 {
        let r = if i < 32 {
            ev_full(base + i, if i % 2 == 0 { "a" } else { "b" }, "web", Some("web1"), Some("10.0.0.1"), i % 2)
        } else {
            ev_full(base + i, if i % 2 == 0 { "c" } else { "d" }, "web", Some("web9"), Some("10.0.0.9"), i % 2)
        };
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    let conf = pb_conf(Some(8));
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(file_seal_rows(&db, "prod", day).len(), 8, "8 fichiers");
    let (lo, hi) = (base, base + 63);

    // Le cœur compile `"source" COLLATE NOCASE IN ('a','b') AND "host" = 'web1'` -> l'extracteur en tire host='web1'.
    let preds = xpreds("search host=web1 source in (a,b)");
    assert!(preds.iter().any(|p| p.dim == ColdDim::Host && p.value == "web1"), "host=web1 extrait");
    assert!(!preds.iter().any(|p| p.dim == ColdDim::Source), "la clause IN n'est pas extraite comme égalité");

    // INVARIANT LOSSLESS : prune == full-scan pour le PRÉDICAT RÉEL de la requête (host=web1 AND source∈{a,b}).
    let full = pb_dump(&hydrate_dbp_pred(&db, &conf, &dbp, "prod", lo, hi, &ALL_HYDRATE_COLS, &[]).unwrap());
    let pruned = hydrate_dbp_pred(&db, &conf, &dbp, "prod", lo, hi, &ALL_HYDRATE_COLS, &preds).unwrap();
    let q = |r: &PbRow| r.3.as_deref() == Some("web1") && (r.1 == "a" || r.1 == "b");
    let ff: Vec<PbRow> = full.iter().filter(|r| q(r)).cloned().collect();
    let pf: Vec<PbRow> = pb_dump(&pruned).iter().filter(|r| q(r)).cloned().collect();
    assert_eq!(ff, pf, "prune==full-scan (lignes matchantes identiques)");
    assert!(pruned.files_pruned >= 1, "élagage RESTAURÉ sur host malgré la clause IN (files_pruned={})", pruned.files_pruned);
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P1 — HARNAIS DE PARITÉ + BENCH du DÉCODE COLONNAIRE (oracle Row-API `read_day_parquet` vs décode
// colonnaire bas-niveau `read_day_parquet_columnar`, sur le MÊME fichier chiffré). Gatés cold_tier.
// ====================================================================================================

/// Ligne aux Option NULL PARSEMÉS DÉLIBÉRÉMENT (host/src_ip/dst_ip/url/xff/dedup/env_id/fields tantôt None,
/// tantôt Some) -> EXERCE les def-levels des colonnes OPTIONAL (une absence != chaîne vide). Message UTF-8
/// multi-octets pour éprouver la conversion ByteArray->String. `ts` monotone (le writer trie de toute façon).
fn sparse_row(ts: i64, i: i64) -> ColdRow {
    ColdRow {
        row: EventRow {
            ts,
            severity: i % 6,
            source: format!("src-{i}"),
            category: if i % 4 == 0 { "auth".into() } else { "web".into() },
            message: format!("msg {i} — accentué é€ 日本"),
            host: if i % 3 == 0 { None } else { Some(format!("h-{i}")) },
            src_ip: if i % 5 == 0 { None } else { Some(format!("10.0.{}.{}", i % 256, (i / 256) % 256)) },
            dst_ip: if i % 7 == 0 { Some("8.8.8.8".into()) } else { None },
            url: if i % 2 == 0 { Some(format!("/p/{i}")) } else { None },
            dedup: if i % 11 == 0 { Some(format!("d-{i}")) } else { None },
            fields: if i % 9 == 0 { None } else { Some(format!("{{\"k\":{i},\"n\":{{\"a\":\"b\"}}}}")) },
            engagement_id: String::new(),
            origin: String::new(),
            env_id: if i % 13 == 0 { None } else { Some("prod".into()) },
        },
        xff: if i % 3 == 0 { Some(format!("xff-{i}")) } else { None },
    }
}

// PARITÉ (garde-fou NON négociable) : 300k lignes -> DEUX row-groups (writer chunke à ROW_GROUP_ROWS=262144)
// -> éprouve AUSSI la reconstruction À LA FRONTIÈRE de groupe. NULL parsemés -> def-levels. On décode des DEUX
// façons (oracle Row-API vs colonnaire P1) et on ASSERTE l'égalité champ-à-champ, ligne à ligne (ordre inclus).
#[test]
#[cfg(feature = "cold_tier")]
fn columnar_decode_parity() {
    let root = tmp_root("colparity");
    let p = root.join("day.parquet");
    let n: i64 = 300_000; // > ROW_GROUP_ROWS -> multi row-groups (frontière testée)
    let rows: Vec<ColdRow> = (0..n).map(|i| sparse_row(1_000 + i, i)).collect();
    let written = t_write(&p, &rows).unwrap();
    assert_eq!(written as i64, n);
    // Sanity : le fichier a bien PLUSIEURS row-groups (sinon la frontière n'est pas exercée).
    let ngroups = open_cold_reader(&p, &tpass()).unwrap().metadata().num_row_groups();
    assert!(ngroups >= 2, "attendu >=2 row-groups (frontière), obtenu {ngroups}");

    let oracle = t_read(&p).expect("oracle Row-API");
    let colr = read_day_parquet_columnar(&p, &tpass()).expect("décode colonnaire");

    assert_eq!(colr.len() as i64, n, "colonnaire : nb de lignes");
    assert_eq!(oracle.len(), colr.len(), "même nombre de lignes que l'oracle");
    // ColdRow::eq compare TOUS les champs (ts, severity, source, category, host, src_ip, dst_ip, url, dedup,
    // fields, engagement_id, origin, env_id, xff). Échoue si UN SEUL champ diverge sur UNE SEULE ligne.
    for (idx, (a, b)) in oracle.iter().zip(colr.iter()).enumerate() {
        assert_eq!(a, b, "DIVERGENCE ligne {idx}:\n  oracle     ={a:?}\n  colonnaire ={b:?}");
    }
    // Preuve EXPLICITE que des NULL ont été produits (def-levels réellement exercés, pas des chaînes vides),
    // et que l'oracle voit EXACTEMENT les mêmes (aucune divergence None/Some sur les colonnes OPTIONAL).
    let host_null = colr.iter().filter(|r| r.row.host.is_none()).count();
    let xff_null = colr.iter().filter(|r| r.xff.is_none()).count();
    let env_null = colr.iter().filter(|r| r.row.env_id.is_none()).count();
    let dst_some = colr.iter().filter(|r| r.row.dst_ip.is_some()).count();
    assert!(host_null > 0 && xff_null > 0 && env_null > 0 && dst_some > 0, "def-levels : NULL ET non-NULL doivent coexister");
    assert_eq!(host_null, oracle.iter().filter(|r| r.row.host.is_none()).count(), "host: mêmes NULL que l'oracle");
    assert_eq!(xff_null, oracle.iter().filter(|r| r.xff.is_none()).count(), "xff: mêmes NULL que l'oracle");
    assert_eq!(env_null, oracle.iter().filter(|r| r.row.env_id.is_none()).count(), "env_id: mêmes NULL que l'oracle");
    let _ = std::fs::remove_dir_all(&root);
}

// BENCH : 800k lignes, MÊME fichier chiffré, Row-API (baseline ~11s au POC) vs colonnaire P1. Imprime les
// timings + le facteur de gain (eprintln, visible avec --nocapture). Asserte AUSSI la parité sur 800k.
#[test]
#[cfg(feature = "cold_tier")]
fn columnar_decode_bench() {
    let root = tmp_root("colbench");
    let p = root.join("day.parquet");
    let n: i64 = 800_000;
    let rows: Vec<ColdRow> = (0..n).map(|i| sparse_row(1_000 + i, i)).collect();
    let written = t_write(&p, &rows).unwrap();
    assert_eq!(written as i64, n);
    let pass = tpass();

    // (0) DÉCHIFFREMENT SEUL (age STREAM -> Bytes) — coût PARTAGÉ par les deux chemins (isole le décode pur).
    let td = std::time::Instant::now();
    let _r = open_cold_reader(&p, &pass).unwrap();
    let decrypt = td.elapsed();
    drop(_r);

    // (a) Row API (baseline).
    let t0 = std::time::Instant::now();
    let a = t_read(&p).unwrap();
    let row_api = t0.elapsed();
    assert_eq!(a.len() as i64, n);

    // (b) Décode colonnaire P1.
    let t1 = std::time::Instant::now();
    let b = read_day_parquet_columnar(&p, &pass).unwrap();
    let columnar = t1.elapsed();
    assert_eq!(b.len() as i64, n);

    // (c) SONDE : décode PARQUET pur (buffers typés, sans String/rows) -> plancher du décode que P1 attaque.
    let t2 = std::time::Instant::now();
    let (ni, nba) = decode_columnar_raw_counts(&p, &pass).unwrap();
    let raw = t2.elapsed();
    assert!(ni > 0 && nba > 0);

    // Le bench prouve AUSSI l'identité (pas seulement la vitesse) sur 800k lignes.
    assert_eq!(a, b, "bench : Row-API et colonnaire DOIVENT produire des lignes identiques");

    let factor = row_api.as_secs_f64() / columnar.as_secs_f64().max(1e-9);
    // Coût de DÉCODE seul (hors déchiffrement partagé) -> facteur sur la partie que P1 attaque réellement.
    let dec = decrypt.as_secs_f64();
    let row_dec = (row_api.as_secs_f64() - dec).max(1e-9);
    let col_dec = (columnar.as_secs_f64() - dec).max(1e-9);
    let raw_dec = (raw.as_secs_f64() - dec).max(1e-9);
    eprintln!(
        "[columnar_decode_bench] {n} lignes  déchiffrement(partagé)={decrypt:?}\n  \
         TOTAL   Row-API={row_api:?}  colonnaire={columnar:?}  gain=×{factor:.2}\n  \
         DÉCODE-seul  Row-API={row_dec:.2}s  colonnaire(rows+String)={col_dec:.2}s  parquet-brut(sans String/rows)={raw_dec:.2}s  gain-décode=×{:.2}",
        row_dec / col_dec
    );
    let _ = (ni, nba);
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// TESTS HOSTILES (#18 P1) — tentent de FAIRE DIVERGER le décode colonnaire de la
// Row-API sur les 8 vecteurs à risque (multi-pages, dict, ""/NULL, required/optional, transpose, UTF-8,
// bords). NE MODIFIENT AUCUN code de prod (reader/writer/schema). Tous gatés `cold_tier`.
// ====================================================================================================

/// Décrypte le fichier cold et renvoie le nombre de DATA-PAGES de la colonne `col_idx` dans le row-group `rg`
/// (via l'offset index, écrit par défaut par le writer). Prouve qu'un chunk de colonne est bien MULTI-PAGES.
#[cfg(feature = "cold_tier")]
fn adv_data_pages(path: &Path, rg: usize, col_idx: usize) -> usize {
    use parquet::file::serialized_reader::{ReadOptionsBuilder, SerializedFileReader};
    let bytes = cold_decrypt_to_bytes(path, &tpass()).unwrap();
    let opts = ReadOptionsBuilder::new().with_page_index().build();
    let rdr = SerializedFileReader::new_with_options(bytes, opts).unwrap();
    let oi = rdr.metadata().offset_index().expect("offset index présent (writer par défaut)");
    oi[rg][col_idx].page_locations().len()
}

/// ATTAQUE #1 (truncature multi-pages) + #5 (append) + #6 (transpose) : UN SEUL row-group dont les colonnes
/// FAT (`message` REQ, `fields` OPT parsemé de NULL) sont réparties sur PLUSIEURS data-pages (limite octets
/// 1 Mio ET limite 20000 lignes/page du writer). Si `read_records` s'arrêtait à la 1re page sans boucler, ou
/// si l'arithmétique `remaining`/def-levels dérapait, le compte OU l'alignement divergerait. On PROUVE d'abord
/// le multi-pages (offset index), puis la parité ligne-à-ligne, y compris NULL sur colonne grasse.
#[test]
#[cfg(feature = "cold_tier")]
fn adv_multipage_fat_variable_parity() {
    let root = tmp_root("adv-multipage");
    let p = root.join("day.parquet");
    let n: i64 = 30_000; // > 20000 (limite lignes/page) MAIS < ROW_GROUP_ROWS -> UN row-group multi-pages
    let rows: Vec<ColdRow> = (0..n)
        .map(|i| {
            let mlen = 200 + (i as usize * 37) % 1400; // longueur TRÈS variable -> pages octet-splitées irrégulières
            let mut msg = format!("m{i}:");
            msg.push_str(&"é€ ".repeat(mlen / 6)); // multi-octets (UTF-8) -> éprouve ByteArray->String (#7)
            ColdRow {
                row: EventRow {
                    ts: 1_000 + i,
                    severity: i % 6,
                    source: format!("s{}", i % 97),
                    category: if i % 3 == 0 { "auth".into() } else { "web".into() },
                    message: msg,
                    host: if i % 4 == 0 { None } else { Some(format!("h{i}")) },
                    src_ip: None,
                    dst_ip: if i % 5 == 0 { Some("8.8.8.8".into()) } else { None },
                    url: None,
                    dedup: None,
                    fields: if i % 8 == 0 { None } else { Some(format!("{{\"k\":{i},\"b\":\"{}\"}}", "x".repeat((i as usize * 13) % 900))) },
                    engagement_id: String::new(),
                    origin: String::new(),
                    env_id: if i % 11 == 0 { None } else { Some("prod".into()) },
                },
                xff: None,
            }
        })
        .collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);

    let ngroups = open_cold_reader(&p, &tpass()).unwrap().metadata().num_row_groups();
    assert_eq!(ngroups, 1, "un seul row-group attendu (n<ROW_GROUP_ROWS)");
    let msg_pages = adv_data_pages(&p, 0, 13); // message (REQ, FAT)
    let fields_pages = adv_data_pages(&p, 0, 14); // fields (OPT, FAT)
    assert!(msg_pages >= 2, "message DOIT être multi-pages (obtenu {msg_pages}) — sinon le vecteur n'est pas exercé");
    assert!(fields_pages >= 2, "fields (OPT) DOIT être multi-pages (obtenu {fields_pages})");

    let oracle = t_read(&p).expect("oracle Row-API");
    let colr = read_day_parquet_columnar(&p, &tpass()).expect("décode colonnaire");
    assert_eq!(colr.len() as i64, n, "colonnaire : ZÉRO perte de ligne sur multi-pages");
    assert_eq!(oracle.len(), colr.len());
    for (idx, (a, b)) in oracle.iter().zip(colr.iter()).enumerate() {
        assert_eq!(a, b, "DIVERGENCE multi-pages ligne {idx}:\n oracle={a:?}\n colonnaire={b:?}");
    }
    let f_null = colr.iter().filter(|r| r.row.fields.is_none()).count();
    assert!(f_null > 0, "def-levels sur colonne FAT réellement exercés");
    assert_eq!(f_null, oracle.iter().filter(|r| r.row.fields.is_none()).count(), "fields: mêmes NULL que l'oracle");
    let _ = std::fs::remove_dir_all(&root);
}

/// ATTAQUE #3 : `Some("")` (def=1 + ByteArray vide) vs `None` (def=0) sur colonnes OPTIONAL — le décode DOIT
/// distinguer chaîne VIDE de ABSENCE. Éprouve aussi les colonnes REQUIRED à valeur vide (`source`/`message`/
/// `category`/`engagement_id`). Trois régimes par colonne opt : None / Some("") / Some("v..").
#[test]
#[cfg(feature = "cold_tier")]
fn adv_empty_string_vs_null_parity() {
    let root = tmp_root("adv-empty");
    let p = root.join("day.parquet");
    let mk = |i: i64, v: i64| -> Option<String> {
        match v.rem_euclid(3) { 0 => None, 1 => Some(String::new()), _ => Some(format!("v{i}")) }
    };
    let n: i64 = 300;
    let rows: Vec<ColdRow> = (0..n)
        .map(|i| ColdRow {
            row: EventRow {
                ts: 1_000 + i,
                severity: i % 4,
                source: if i % 3 == 0 { String::new() } else { format!("s{i}") }, // REQ vide
                category: if i % 3 == 1 { String::new() } else { "web".into() },   // REQ vide
                message: if i % 5 == 0 { String::new() } else { format!("m{i}") }, // REQ vide
                host: mk(i, i),
                src_ip: mk(i, i + 1),
                dst_ip: mk(i, i + 2),
                url: mk(i, i),
                dedup: mk(i, i + 1),
                fields: mk(i, i + 2),
                engagement_id: if i % 4 == 0 { String::new() } else { format!("e{i}") },
                origin: String::new(),
                env_id: mk(i, i),
            },
            xff: mk(i, i + 2),
        })
        .collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);

    let oracle = t_read(&p).expect("oracle");
    let colr = read_day_parquet_columnar(&p, &tpass()).expect("colonnaire");
    assert_eq!(oracle, colr, "parité chaine-vide vs NULL");

    // PREUVE EXPLICITE que les deux régimes coexistent ET que colonnaire==oracle sur chacun.
    let host_empty = |v: &[ColdRow]| v.iter().filter(|r| r.row.host.as_deref() == Some("")).count();
    let host_none = |v: &[ColdRow]| v.iter().filter(|r| r.row.host.is_none()).count();
    assert!(host_empty(&colr) > 0 && host_none(&colr) > 0, "host: Some(\"\") ET None doivent coexister");
    assert_eq!(host_empty(&colr), host_empty(&oracle), "host Some(\"\") : colonnaire == oracle");
    assert_eq!(host_none(&colr), host_none(&oracle), "host None : colonnaire == oracle");
    let xff_empty = colr.iter().filter(|r| r.xff.as_deref() == Some("")).count();
    assert!(xff_empty > 0, "xff Some(\"\") produit");
    assert_eq!(xff_empty, oracle.iter().filter(|r| r.xff.as_deref() == Some("")).count());
    let _ = std::fs::remove_dir_all(&root);
}

/// ATTAQUE #2 : encodage DICTIONNAIRE (faible cardinalité). `read_records` DOIT résoudre le dictionnaire
/// (valeurs, pas indices). On PROUVE que `category` est bien dict-encodée puis on asserte la parité.
#[test]
#[cfg(feature = "cold_tier")]
fn adv_dictionary_encoded_parity() {
    use parquet::basic::Encoding;
    use parquet::file::serialized_reader::SerializedFileReader;
    let root = tmp_root("adv-dict");
    let p = root.join("day.parquet");
    let n: i64 = 50_000;
    let rows: Vec<ColdRow> = (0..n)
        .map(|i| ColdRow {
            row: EventRow {
                ts: 1_000 + i,
                severity: i % 3,
                source: "const-source".into(), // 1 valeur -> dict
                category: if i % 2 == 0 { "auth".into() } else { "web".into() }, // 2 valeurs -> dict
                message: format!("m{}", i % 5), // faible card -> dict
                host: Some("h".into()),
                src_ip: None,
                dst_ip: None,
                url: None,
                dedup: None,
                fields: Some("{}".into()),
                engagement_id: String::new(),
                origin: String::new(),
                env_id: Some("prod".into()),
            },
            xff: None,
        })
        .collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);

    let bytes = cold_decrypt_to_bytes(&p, &tpass()).unwrap();
    let rdr = SerializedFileReader::new(bytes).unwrap();
    let enc: Vec<Encoding> = rdr.metadata().row_group(0).column(3).encodings().collect(); // col 3 == category
    assert!(
        enc.iter().any(|e| matches!(e, Encoding::RLE_DICTIONARY | Encoding::PLAIN_DICTIONARY)),
        "category DOIT être dict-encodée pour exercer le vecteur, encodings={enc:?}"
    );

    let oracle = t_read(&p).unwrap();
    let colr = read_day_parquet_columnar(&p, &tpass()).unwrap();
    assert_eq!(oracle, colr, "parité sur colonnes dict-encodées");
    let _ = std::fs::remove_dir_all(&root);
}

/// ATTAQUE #8 : comptes de lignes DÉGÉNÉRÉS — 1 ligne, 2 lignes, et dernier row-group PARTIEL (n = kG+1 ->
/// 2e groupe d'UNE ligne). (Un groupe de 0 ligne n'est jamais émis par le writer.)
#[test]
#[cfg(feature = "cold_tier")]
fn adv_edge_row_counts_parity() {
    for n in [1i64, 2, ROW_GROUP_ROWS as i64 + 1] {
        let root = tmp_root("adv-edge");
        let p = root.join("day.parquet");
        let rows: Vec<ColdRow> = (0..n).map(|i| sparse_row(1_000 + i, i)).collect();
        assert_eq!(t_write(&p, &rows).unwrap() as i64, n, "n={n}: écriture");
        let oracle = t_read(&p).unwrap();
        let colr = read_day_parquet_columnar(&p, &tpass()).unwrap();
        assert_eq!(colr.len() as i64, n, "n={n}: compte colonnaire");
        assert_eq!(oracle, colr, "n={n}: parité");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// ATTAQUE #4 : optionalité du SCHÉMA writer == ensemble REQUIRED du décodeur. `cold_col_required` est privé
/// (non appelable), mais son littéral est {ts,severity,source,category,engagement_id,origin,message} ; on
/// vérifie que le SCHÉMA writer déclare REQUIRED EXACTEMENT ce set (et OPTIONAL le complément). La PARITÉ
/// (tests ci-dessus) prouve ensuite que le décodeur s'accorde au schéma à l'exécution. Toute désynchro
/// schéma/décodeur casserait soit ce test, soit la parité.
#[test]
#[cfg(feature = "cold_tier")]
fn adv_schema_required_set_matches_decoder_doc() {
    use parquet::basic::Repetition;
    let expected_required: std::collections::HashSet<&str> =
        ["ts", "severity", "source", "category", "engagement_id", "origin", "message"].into_iter().collect();
    let schema = cold_schema();
    let mut seen = std::collections::HashSet::new();
    for f in schema.get_fields() {
        let name = f.name().to_string();
        let is_req = f.get_basic_info().repetition() == Repetition::REQUIRED;
        assert_eq!(
            is_req,
            expected_required.contains(name.as_str()),
            "col '{name}': schéma REQUIRED={is_req} != ensemble required du décodeur ({})",
            expected_required.contains(name.as_str())
        );
        seen.insert(name);
    }
    for c in PARQUET_COLS {
        assert!(seen.contains(c), "colonne PARQUET_COLS '{c}' absente du schéma writer");
    }
    assert_eq!(seen.len(), PARQUET_COLS.len(), "schéma writer et PARQUET_COLS de tailles différentes");
}

// ====================================================================================================
// #18 P2 — MOTEUR VECTORISÉ : HARNAIS DE PARITÉ (vectorisé == chemin hydrate-SQLite) + BENCH. Gatés cold_tier.
// ----------------------------------------------------------------------------------------------------
// PRINCIPE : sur le MÊME dataset (mêmes ColdRow -> écrites en cold parquet chiffré ET insérées dans un SQLite
// éphémère), on exécute chaque forme GXQL représentative des DEUX façons et on ASSERTE l'égalité EXACTE
// (comptes/groupes/valeurs, masquage #45 inclus). L'oracle SQLite APPLIQUE le masquage via `union_proj` (la MÊME
// fonction que `open_cold_union`) -> parité de masquage par CONSTRUCTION. Regex : l'oracle installe l'UDF `regexp`
// VERBATIM (`install_query_udfs`) -> mêmes semantics `regex::Regex` que le kernel. Le test échoue si UN agrégat/
// valeur diverge. NULL (host/src_ip/fields parsemés) ET masquage (deny-set) sont dans les données de test.
// ====================================================================================================

/// Ligne P2 : dims BASSE cardinalité (group-by significatif) + NULL parsemés (host/src_ip/fields) + message
/// ASCII portant des tokens `action=…`/`code=NN` (regex/like/contains). `ts` monotone unique.
fn vrow(i: i64) -> ColdRow {
    let action = ["login", "logout", "block", "alert"][(i % 4) as usize];
    // Dims DÉCORRÉLÉES (source×severity×category couvre les 8×6×4=192 combos) -> group-by multi-dim à forte
    // cardinalité (bench représentatif + parité sur de nombreux groupes).
    ColdRow {
        row: EventRow {
            ts: 1_000 + i,
            severity: (i / 8) % 6,
            source: format!("s{}", i % 8),
            category: ["auth", "web", "net", "dns"][((i / 48) % 4) as usize].to_string(),
            message: format!("evt {i} action={action} code={:02}", i % 100),
            host: if i % 7 == 0 { None } else { Some(format!("h{}", i % 5)) },
            src_ip: if i % 5 == 0 { None } else { Some(format!("10.0.{}.{}", i % 256, (i / 256) % 256)) },
            dst_ip: None,
            url: None,
            dedup: None,
            fields: if i % 9 == 0 { None } else { Some(format!("{{\"a\":{},\"act\":\"{action}\"}}", i % 50)) },
            engagement_id: String::new(),
            origin: String::new(),
            env_id: Some("prod".to_string()),
        },
        xff: None,
    }
}

/// Construit l'oracle SQLite ÉPHÉMÈRE : table `ev` (schéma UNION_COLS) alimentée par `rows`, VUE `mev` masquée
/// par `union_proj(deny)` (la MÊME fonction que le chemin cold live) + UDF `regexp` VERBATIM. Toute requête de
/// parité s'exécute sur `mev` -> masquage #45 identique au chemin hydraté, par construction.
fn build_oracle(rows: &[ColdRow], deny: &std::collections::HashSet<String>) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE ev(id INTEGER PRIMARY KEY, ts INTEGER, source TEXT, category TEXT, severity INTEGER, \
         host TEXT, message TEXT, fields TEXT, dedup TEXT, env_id TEXT, origin TEXT, engagement_id TEXT, \
         src_ip TEXT, dst_ip TEXT, url TEXT, xff TEXT)",
    )
    .unwrap();
    {
        let mut ins = c
            .prepare(
                "INSERT INTO ev(ts,source,category,severity,host,message,fields,dedup,env_id,origin,engagement_id,src_ip,dst_ip,url,xff) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            )
            .unwrap();
        for r in rows {
            ins.execute(params![
                r.row.ts, r.row.source, r.row.category, r.row.severity, r.row.host, r.row.message,
                r.row.fields, r.row.dedup, r.row.env_id, r.row.origin, r.row.engagement_id,
                r.row.src_ip, r.row.dst_ip, r.row.url, r.xff
            ])
            .unwrap();
        }
    }
    // VUE masquée par la MÊME `union_proj` que `open_cold_union` (#45) -> `NULL AS c` pour toute colonne déniée.
    let proj = union_proj(deny);
    c.execute_batch(&format!("CREATE TEMP VIEW mev AS SELECT {proj} FROM ev")).unwrap();
    install_query_udfs(&c); // UDF `regexp` (regex::Regex) VERBATIM -> mêmes semantics que le kernel Regex.
    c
}

/// group-by oracle mono-string -> `HashMap<GroupKey, i64>`.
fn oracle_gb1(c: &Connection, sql_where: &str, dim: &str) -> HashMap<GroupKey, i64> {
    let sql = format!("SELECT {dim}, COUNT(*) FROM mev {sql_where} GROUP BY {dim}");
    let mut st = c.prepare(&sql).unwrap();
    st.query_map([], |r| Ok((vec![r.get::<_, Option<String>>(0)?], r.get::<_, i64>(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect()
}

/// COUNT(*) oracle sur `mev` avec un WHERE arbitraire.
fn oracle_count(c: &Connection, sql_where: &str) -> i64 {
    c.query_row(&format!("SELECT COUNT(*) FROM mev {sql_where}"), [], |r| r.get(0)).unwrap()
}

/// PARITÉ P2 (garde-fou NON négociable) : 300k lignes -> DEUX row-groups (accumulation cross-batch éprouvée) +
/// NULL parsemés. Chaque forme GXQL représentative : vectorisé == oracle SQLite masqué. Deny-set VIDE ici (le
/// masquage a son propre test dédié plus bas).
#[test]
#[cfg(feature = "cold_tier")]
fn p2_vectorized_parity_no_mask() {
    let root = tmp_root("p2par");
    let p = root.join("day.parquet");
    let n: i64 = 300_000; // > ROW_GROUP_ROWS -> multi row-groups
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);
    assert!(open_cold_reader(&p, &tpass()).unwrap().metadata().num_row_groups() >= 2, "multi row-groups requis");

    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny);
    let reader = open_cold_reader(&p, &tpass()).unwrap();

    // (1) COUNT total.
    assert_eq!(vec_count(&reader, &Pred::True, &deny).unwrap(), oracle_count(&oracle, ""), "count total");

    // (2) COUNT WHERE severity>=3.
    let sev3 = Pred::Int { col: "severity", op: IntOp::Ge, val: 3 };
    assert_eq!(vec_count(&reader, &sev3, &deny).unwrap(), oracle_count(&oracle, "WHERE severity>=3"), "count sev>=3");

    // (3) COUNT WHERE severity>=3 AND source='s2' (AND multi-prédicat).
    let comp = Pred::And(vec![
        Pred::Int { col: "severity", op: IntOp::Ge, val: 3 },
        Pred::StrEq { col: "source", val: "s2".into() },
    ]);
    assert_eq!(
        vec_count(&reader, &comp, &deny).unwrap(),
        oracle_count(&oracle, "WHERE severity>=3 AND source='s2'"),
        "count sev>=3 AND source=s2"
    );

    // (4) group-by source (mono-dim).
    assert_eq!(
        vec_group_count(&reader, &Pred::True, &["source"], &deny).unwrap(),
        oracle_gb1(&oracle, "", "source"),
        "group-by source"
    );

    // (5) group-by host (mono-dim AVEC NULL : parité du groupe NULL).
    let gb_host_vec = vec_group_count(&reader, &Pred::True, &["host"], &deny).unwrap();
    assert_eq!(gb_host_vec, oracle_gb1(&oracle, "", "host"), "group-by host (NULL inclus)");
    assert!(gb_host_vec.contains_key(&vec![None]), "le groupe NULL (host absent) doit exister");

    // (6) group-by MULTI-DIM source×severity×category — LA cible (32s SQLite prod). Parité exacte.
    let gb3_vec = vec_group_count(&reader, &Pred::True, &["source", "severity", "category"], &deny).unwrap();
    let mut st = oracle
        .prepare("SELECT source, severity, category, COUNT(*) FROM mev GROUP BY source, severity, category")
        .unwrap();
    let gb3_oracle: HashMap<GroupKey, i64> = st
        .query_map([], |r| {
            Ok((
                vec![
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<i64>>(1)?.map(|v| v.to_string()),
                    r.get::<_, Option<String>>(2)?,
                ],
                r.get::<_, i64>(3)?,
            ))
        })
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    assert_eq!(gb3_vec, gb3_oracle, "group-by multi-dim source×severity×category");
    assert!(gb3_vec.len() > 150, "multi-dim doit produire de nombreux groupes (obtenu {})", gb3_vec.len());

    // (7) REGEX sur message (== UDF regexp verbatim).
    let re = Pred::Regex { col: "message", re: regex::Regex::new("code=5[0-9]").unwrap() };
    assert_eq!(
        vec_count(&reader, &re, &deny).unwrap(),
        oracle_count(&oracle, "WHERE message REGEXP 'code=5[0-9]'"),
        "regex message code=5[0-9]"
    );

    // (8) LIKE : préfixe + case-insensitive ASCII (parité du repli SQLite).
    let like1 = Pred::Like { col: "category", pat: "AUT%".into() }; // fold ASCII -> auth
    assert_eq!(
        vec_count(&reader, &like1, &deny).unwrap(),
        oracle_count(&oracle, "WHERE category LIKE 'AUT%'"),
        "LIKE category AUT% (case-insensitive)"
    );
    let like2 = Pred::Like { col: "message", pat: "%action=block%".into() };
    assert_eq!(
        vec_count(&reader, &like2, &deny).unwrap(),
        oracle_count(&oracle, "WHERE message LIKE '%action=block%'"),
        "LIKE %action=block%"
    );

    // (9) CONTAINS (substring, sensible casse == instr>0).
    let ct = Pred::Contains { col: "message", needle: "action=alert".into() };
    assert_eq!(
        vec_count(&reader, &ct, &deny).unwrap(),
        oracle_count(&oracle, "WHERE instr(message,'action=alert')>0"),
        "contains action=alert"
    );

    // (10) IN.
    let inp = Pred::StrIn { col: "source", vals: ["s1".to_string(), "s3".to_string(), "s5".to_string()].into_iter().collect() };
    assert_eq!(
        vec_count(&reader, &inp, &deny).unwrap(),
        oracle_count(&oracle, "WHERE source IN ('s1','s3','s5')"),
        "source IN (…)"
    );

    // (11) TOP-N par source.
    let topn_vec = top_n(&vec_group_count(&reader, &Pred::True, &["source"], &deny).unwrap(), 3);
    let mut st = oracle.prepare("SELECT source, COUNT(*) c FROM mev GROUP BY source ORDER BY c DESC, source ASC LIMIT 3").unwrap();
    let topn_oracle: Vec<(GroupKey, i64)> = st
        .query_map([], |r| Ok((vec![r.get::<_, Option<String>>(0)?], r.get::<_, i64>(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    assert_eq!(topn_vec, topn_oracle, "top-3 source");

    // (12) MATÉRIALISATION bornée (search/list) : colonnes projetées des lignes WHERE severity>=4, cap 100, ordre ts.
    let proj: [&str; 5] = ["ts", "source", "severity", "host", "src_ip"];
    let (mat, trunc) = vec_materialize(&reader, &sev4(), &proj, 100, &deny).unwrap();
    let mut st = oracle
        .prepare("SELECT ts,source,severity,host,src_ip FROM mev WHERE severity>=4 ORDER BY ts LIMIT 100")
        .unwrap();
    let orc: Vec<(i64, String, i64, Option<String>, Option<String>)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    assert!(trunc, "cap 100 atteint -> tronqué");
    assert_eq!(mat.len(), 100, "cap respecté");
    let mat_t: Vec<(i64, String, i64, Option<String>, Option<String>)> = mat.iter().map(mat_tuple).collect();
    assert_eq!(mat_t, orc, "matérialisation projetée == oracle (ordre ts, cap)");

    let _ = std::fs::remove_dir_all(&root);
}

/// Prédicat severity>=4 (réutilisé).
#[cfg(feature = "cold_tier")]
fn sev4() -> Pred {
    Pred::Int { col: "severity", op: IntOp::Ge, val: 4 }
}

/// Convertit une MatRow (Value) en tuple comparable (ts,source,severity,host,src_ip).
#[cfg(feature = "cold_tier")]
fn mat_tuple(row: &MatRow) -> (i64, String, i64, Option<String>, Option<String>) {
    use rusqlite::types::Value;
    let i = |v: &Value| -> i64 { if let Value::Integer(n) = v { *n } else { panic!("attendu int") } };
    let s = |v: &Value| -> String { if let Value::Text(t) = v { t.clone() } else { panic!("attendu text") } };
    let os = |v: &Value| -> Option<String> {
        match v {
            Value::Text(t) => Some(t.clone()),
            Value::Null => None,
            _ => panic!("attendu text/null"),
        }
    };
    (i(&row[0]), s(&row[1]), i(&row[2]), os(&row[3]), os(&row[4]))
}

/// PARITÉ MASQUAGE #45 : deny-set = {src_ip} -> le vectorisé DOIT masquer src_ip EXACTEMENT comme l'oracle
/// (`union_proj` NULLifie src_ip dans `mev`). filtre/group-by/projection sur src_ip == oracle.
#[test]
#[cfg(feature = "cold_tier")]
fn p2_vectorized_parity_masked() {
    let root = tmp_root("p2mask");
    let p = root.join("day.parquet");
    let n: i64 = 40_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);

    let deny: std::collections::HashSet<String> = ["src_ip".to_string()].into_iter().collect();
    let oracle = build_oracle(&rows, &deny); // mev : src_ip -> NULL AS src_ip (union_proj)
    let reader = open_cold_reader(&p, &tpass()).unwrap();

    // (a) filtre sur colonne déniée -> 0 ligne (NULL='x' faux) des DEUX côtés.
    let eqp = Pred::StrEq { col: "src_ip", val: "10.0.1.1".into() };
    assert_eq!(vec_count(&reader, &eqp, &deny).unwrap(), 0, "vectorisé: src_ip déniée -> 0");
    assert_eq!(oracle_count(&oracle, "WHERE src_ip='10.0.1.1'"), 0, "oracle: src_ip NULL -> 0");

    // (b) group-by sur colonne déniée -> un SEUL groupe NULL des deux côtés (parité).
    let gb_vec = vec_group_count(&reader, &Pred::True, &["src_ip"], &deny).unwrap();
    let gb_orc = oracle_gb1(&oracle, "", "src_ip");
    assert_eq!(gb_vec, gb_orc, "group-by src_ip déniée == oracle");
    assert_eq!(gb_vec.len(), 1, "un seul groupe (NULL)");
    assert_eq!(gb_vec.get(&vec![None]), Some(&(n)), "tout regroupé sous NULL");

    // (c) group-by MIXTE (src_ip déniée × severity claire) : src_ip -> None, severity intacte.
    let gbm_vec = vec_group_count(&reader, &Pred::True, &["src_ip", "severity"], &deny).unwrap();
    let mut st = oracle.prepare("SELECT src_ip, severity, COUNT(*) FROM mev GROUP BY src_ip, severity").unwrap();
    let gbm_orc: HashMap<GroupKey, i64> = st
        .query_map([], |r| {
            Ok((vec![r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?.map(|v| v.to_string())], r.get::<_, i64>(2)?))
        })
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    assert_eq!(gbm_vec, gbm_orc, "group-by src_ip(dénié)×severity == oracle");

    // (d) matérialisation : src_ip projetée -> NULL partout (parité union_proj).
    let proj: [&str; 3] = ["ts", "source", "src_ip"];
    let (mat, _t) = vec_materialize(&reader, &Pred::True, &proj, 500, &deny).unwrap();
    assert!(mat.iter().all(|r| matches!(r[2], rusqlite::types::Value::Null)), "src_ip déniée -> NULL dans la projection");
    // Oracle : SELECT src_ip FROM mev -> NULL partout aussi.
    let orc_nonnull: i64 = oracle.query_row("SELECT COUNT(src_ip) FROM mev", [], |r| r.get(0)).unwrap();
    assert_eq!(orc_nonnull, 0, "oracle: src_ip NULL partout");

    // (e) une colonne NON déniée (source) reste intacte sous masquage.
    assert_eq!(
        vec_group_count(&reader, &Pred::True, &["source"], &deny).unwrap(),
        oracle_gb1(&oracle, "", "source"),
        "source (non déniée) intacte sous masquage"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// FALLBACK GATE : les formes NON vectorisables (référence hors colonnes physiques, ex. clé JSON `action`)
/// DOIVENT être signalées par `can_vectorize=false` -> le planner (P4) route vers SQLite (jamais un faux résultat).
#[test]
#[cfg(feature = "cold_tier")]
fn p2_fallback_gate_rejects_nonphysical() {
    assert!(is_physical_col("source") && is_physical_col("message") && is_physical_col("fields"));
    assert!(!is_physical_col("action") && !is_physical_col("json_extract"));
    // Prédicat/dims sur colonnes physiques -> vectorisable.
    assert!(can_vectorize(&Pred::StrEq { col: "source", val: "s1".into() }, &["severity", "category"]));
    // Une dimension NON physique (clé JSON `action`) -> NON vectorisable -> fallback SQLite.
    assert!(!can_vectorize(&Pred::True, &["action"]));
    assert!(!can_vectorize(&Pred::StrEq { col: "source", val: "s1".into() }, &["source", "action"]));
}

// BENCH P2 : 800k lignes. Compare END-TO-END (décode + requête) VECTORISÉ vs HYDRATE-SQLITE pour (a) group-by
// multi-dim (la cible 32s prod), (b) filtre regex, (c) count. Imprime timings + facteur (eprintln --nocapture).
#[test]
#[cfg(feature = "cold_tier")]
fn p2_vectorized_bench() {
    let root = tmp_root("p2bench");
    let p = root.join("day.parquet");
    let n: i64 = 800_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);
    let pass = tpass();
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // ---- HYDRATE-SQLITE : décode colonnaire (P1) -> insertion SQLite (le coût AVANT toute requête). ----
    let th = std::time::Instant::now();
    let hydrated = read_day_parquet_columnar(&p, &pass).unwrap();
    let sq = Connection::open_in_memory().unwrap();
    sq.execute_batch(
        "CREATE TABLE ev(ts INTEGER, source TEXT, category TEXT, severity INTEGER, host TEXT, message TEXT)",
    )
    .unwrap();
    sq.execute_batch("BEGIN").unwrap();
    {
        let mut ins = sq.prepare("INSERT INTO ev(ts,source,category,severity,host,message) VALUES(?1,?2,?3,?4,?5,?6)").unwrap();
        for r in &hydrated {
            ins.execute(params![r.row.ts, r.row.source, r.row.category, r.row.severity, r.row.host, r.row.message]).unwrap();
        }
    }
    sq.execute_batch("COMMIT").unwrap();
    install_query_udfs(&sq);
    let hydrate_build = th.elapsed(); // décode + insertion : payé AVANT la 1re requête cold via le chemin hydraté

    // (a) GROUP-BY MULTI-DIM source×severity×category.
    let tq = std::time::Instant::now();
    let mut st = sq.prepare("SELECT source, severity, category, COUNT(*) FROM ev GROUP BY source, severity, category").unwrap();
    let sql_gb: i64 = st.query_map([], |r| r.get::<_, i64>(3)).unwrap().map(|x| x.unwrap()).sum();
    let sql_gb_t = tq.elapsed();
    let tv = std::time::Instant::now();
    let rd = open_cold_reader(&p, &pass).unwrap();
    let gbv = vec_group_count(&rd, &Pred::True, &["source", "severity", "category"], &deny).unwrap();
    let vec_gb_t = tv.elapsed();
    let vec_gb_sum: i64 = gbv.values().sum();
    assert_eq!(sql_gb, vec_gb_sum, "bench group-by : mêmes lignes couvertes");

    // (b) FILTRE REGEX count.
    let tq = std::time::Instant::now();
    let sql_re: i64 = sq.query_row("SELECT COUNT(*) FROM ev WHERE message REGEXP 'code=5[0-9]'", [], |r| r.get(0)).unwrap();
    let sql_re_t = tq.elapsed();
    let tv = std::time::Instant::now();
    let rd = open_cold_reader(&p, &pass).unwrap();
    let vec_re = vec_count(&rd, &Pred::Regex { col: "message", re: regex::Regex::new("code=5[0-9]").unwrap() }, &deny).unwrap();
    let vec_re_t = tv.elapsed();
    assert_eq!(sql_re, vec_re, "bench regex : même compte");

    // (c) COUNT total.
    let tq = std::time::Instant::now();
    let sql_c: i64 = sq.query_row("SELECT COUNT(*) FROM ev", [], |r| r.get(0)).unwrap();
    let sql_c_t = tq.elapsed();
    let tv = std::time::Instant::now();
    let rd = open_cold_reader(&p, &pass).unwrap();
    let vec_c = vec_count(&rd, &Pred::True, &deny).unwrap();
    let vec_c_t = tv.elapsed();
    assert_eq!(sql_c, vec_c);

    let e2e = |sql_q: std::time::Duration| hydrate_build + sql_q; // end-to-end hydraté = build + requête
    eprintln!(
        "[p2_vectorized_bench] {n} lignes ({} groupes multi-dim)\n  \
         HYDRATE-SQLITE build(décode+insert)={hydrate_build:?}\n  \
         (a) GROUP-BY multi-dim : vectorisé(décode+calc)={vec_gb_t:?}  vs  hydrate e2e={:?} (build + sql {sql_gb_t:?})  -> ×{:.1}\n  \
         (b) REGEX count        : vectorisé={vec_re_t:?}  vs  hydrate e2e={:?} (build + sql {sql_re_t:?})  -> ×{:.1}\n  \
         (c) COUNT              : vectorisé={vec_c_t:?}  vs  hydrate e2e={:?} (build + sql {sql_c_t:?})  -> ×{:.1}",
        gbv.len(),
        e2e(sql_gb_t), e2e(sql_gb_t).as_secs_f64() / vec_gb_t.as_secs_f64().max(1e-9),
        e2e(sql_re_t), e2e(sql_re_t).as_secs_f64() / vec_re_t.as_secs_f64().max(1e-9),
        e2e(sql_c_t), e2e(sql_c_t).as_secs_f64() / vec_c_t.as_secs_f64().max(1e-9),
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P2 — TESTS ADVERSES (hostiles). Objectif : RÉFUTER « parité vectorisé==hydrate-SQLite ET
// masquage #45 correct ». Oracle = MÊME `build_oracle`/`union_proj`/`install_query_udfs` verbatim que P2.
// ====================================================================================================

/// oracle group-by mono-INT dim (severity) -> GroupKey (`Some(v.to_string())` / None).
#[cfg(feature = "cold_tier")]
fn oracle_gb1_int(c: &Connection, sql_where: &str, dim: &str) -> HashMap<GroupKey, i64> {
    let sql = format!("SELECT {dim}, COUNT(*) FROM mev {sql_where} GROUP BY {dim}");
    let mut st = c.prepare(&sql).unwrap();
    st.query_map([], |r| Ok((vec![r.get::<_, Option<i64>>(0)?.map(|v| v.to_string())], r.get::<_, i64>(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect()
}

/// ADVERSE #4/#2 — LOGIQUE TRIVALENTE (NULL) & `Pred::Not`. Ex-RÉFUTATION, désormais GARDE-FOU DE PARITÉ.
/// SQL 3VL : `NOT (col = x)` où col est NULL -> `NOT NULL` = NULL -> ligne EXCLUE. Le kernel corrigé évalue
/// `Not` en 3VL (NOT U = U) -> parité EXACTE avec l'oracle SQLite masqué, pour col nullable ET col déniée.
/// `can_vectorize(Not(...), [])` reste TRUE (colonnes physiques) : la forme est vectorisable ET correcte.
#[test]
#[cfg(feature = "cold_tier")]
fn p2_adv_not_threevalued_divergence() {
    let root = tmp_root("p2advnot");
    let p = root.join("day.parquet");
    let n: i64 = 20_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect(); // host None si i%7==0 ; src_ip None si i%5==0
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);
    let reader = open_cold_reader(&p, &tpass()).unwrap();

    // ---- (A) NOT sur colonne NULLABLE (host), SANS masquage : PARITÉ (NOT NULL -> exclu des deux côtés). ----
    let deny_empty: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny_empty);
    let not_host = Pred::Not(Box::new(Pred::StrEq { col: "host", val: "h1".into() }));
    let vec_not = vec_count(&reader, &not_host, &deny_empty).unwrap();
    let orc_not = oracle_count(&oracle, "WHERE NOT (host='h1')");
    let null_hosts = oracle_count(&oracle, "WHERE host IS NULL");
    eprintln!("[adv_not] NOT(host='h1'): vectorisé={vec_not}  oracle_SQLite={orc_not}  (lignes host NULL={null_hosts})");
    assert!(null_hosts > 0, "précondition : des host NULL existent (sinon le test ne prouve rien)");
    // can_vectorize AUTORISE cette forme -> routée au kernel, et le kernel est maintenant CORRECT.
    assert!(can_vectorize(&not_host, &[]), "can_vectorize accepte Not(StrEq host) -> routé au kernel");
    // PARITÉ : NOT sur NULL est EXCLU (NOT U = U) des deux côtés -> comptes ÉGAUX.
    assert_eq!(vec_not, orc_not, "PARITÉ : NOT sur colonne nullable == oracle SQLite (NOT NULL exclu)");

    // ---- (B) NOT sur colonne DÉNIÉE (#45) : parité (0 == 0), aucune fuite. ----
    let deny_ip: std::collections::HashSet<String> = ["src_ip".to_string()].into_iter().collect();
    let oracle_m = build_oracle(&rows, &deny_ip); // src_ip -> NULL AS src_ip
    let not_ip = Pred::Not(Box::new(Pred::StrEq { col: "src_ip", val: "10.0.1.1".into() }));
    let vec_not_ip = vec_count(&reader, &not_ip, &deny_ip).unwrap();
    let orc_not_ip = oracle_count(&oracle_m, "WHERE NOT (src_ip='10.0.1.1')");
    eprintln!("[adv_not] NOT(src_ip='…') src_ip DÉNIÉE : vectorisé={vec_not_ip}  oracle_SQLite={orc_not_ip}  (n={n})");
    // Requête de hunting SOC ultra-courante `src_ip != known` : hot/oracle -> 0 (src_ip masqué=NULL) ; le kernel
    // corrigé -> 0 AUSSI (NOT U = U). Parité hot/cold rétablie sur la MÊME requête logique.
    assert_eq!(orc_not_ip, 0, "oracle (parité HOT) : NOT NULL -> 0 ligne");
    assert_eq!(vec_not_ip, orc_not_ip, "PARITÉ : NOT sur colonne déniée == oracle (0, aucune fuite)");

    // Et materialize ne renvoie AUCUNE ligne (comme l'oracle masqué) : plus d'exposition.
    let proj: [&str; 3] = ["ts", "source", "src_ip"];
    let (mat, _t) = vec_materialize(&reader, &not_ip, &proj, 5000, &deny_ip).unwrap();
    assert!(mat.is_empty(), "materialize NOT(déniée) -> 0 ligne (parité oracle masqué, aucune fuite)");

    let _ = std::fs::remove_dir_all(&root);
}

/// ADVERSE — NÉGATIONS COMBINÉES vs oracle SQLite VERBATIM (`build_oracle`/`union_proj`/`install_query_udfs`).
/// Couvre les FORMES RÉELLES qui compilent en `Pred::Not` : `!=` (StrNe), `NOT LIKE`, `NOT IN`, `NOT NOT`,
/// De Morgan `NOT(a AND b)`/`NOT(a OR b)`, sur colonne NULL-parsemée (host) ET déniée (#45). Le kernel 3VL doit
/// égaler l'oracle 3VL pour TOUTES ces formes (NOT U = U, jamais de résurrection de ligne NULL/déniée).
#[test]
#[cfg(feature = "cold_tier")]
fn p2_adv_combined_negations_parity() {
    let root = tmp_root("p2advnegcomb");
    let p = root.join("day.parquet");
    let n: i64 = 20_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect(); // host None si i%7==0 ; src_ip None si i%5==0
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);
    let reader = open_cold_reader(&p, &tpass()).unwrap();

    // Deux univers d'oracle : sans masquage, et avec src_ip déniée.
    let deny_empty: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny_empty);
    let deny_ip: std::collections::HashSet<String> = ["src_ip".to_string()].into_iter().collect();
    let oracle_m = build_oracle(&rows, &deny_ip);

    // Précondition : des host NULL existent -> les formes NOT sur host EXERCENT bien le cas UNKNOWN.
    assert!(oracle_count(&oracle, "WHERE host IS NULL") > 0, "précondition : host NULL présents");

    // (1) `!=` (StrNe) == Not(StrEq) sur host nullable.
    let ne_host = Pred::Not(Box::new(Pred::StrEq { col: "host", val: "h1".into() }));
    assert_eq!(
        vec_count(&reader, &ne_host, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE host <> 'h1'"),
        "host != 'h1' (Not StrEq) == oracle"
    );

    // (2) NOT LIKE sur host nullable.
    let not_like = Pred::Not(Box::new(Pred::Like { col: "host", pat: "h_".into() }));
    assert_eq!(
        vec_count(&reader, &not_like, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE host NOT LIKE 'h_'"),
        "host NOT LIKE 'h_' == oracle"
    );

    // (3) NOT IN sur host nullable.
    let not_in = Pred::Not(Box::new(Pred::StrIn {
        col: "host",
        vals: ["h1".to_string(), "h2".to_string()].into_iter().collect(),
    }));
    assert_eq!(
        vec_count(&reader, &not_in, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE host NOT IN ('h1','h2')"),
        "host NOT IN ('h1','h2') == oracle"
    );

    // (4) NOT NOT a (double négation) sur host nullable : == a (T/F/U préservés).
    let not_not = Pred::Not(Box::new(Pred::Not(Box::new(Pred::StrEq { col: "host", val: "h1".into() }))));
    assert_eq!(
        vec_count(&reader, &not_not, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE NOT (NOT (host='h1'))"),
        "NOT NOT (host='h1') == oracle == host='h1'"
    );
    assert_eq!(
        vec_count(&reader, &not_not, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE host='h1'"),
        "NOT NOT a == a"
    );

    // (5) De Morgan `NOT(a AND b)` : a=host='h1' (UNKNOWN sur NULL), b=source='s2' (jamais NULL).
    let a = || Pred::StrEq { col: "host", val: "h1".into() };
    let b = || Pred::StrEq { col: "source", val: "s2".into() };
    let not_and = Pred::Not(Box::new(Pred::And(vec![a(), b()])));
    assert_eq!(
        vec_count(&reader, &not_and, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE NOT (host='h1' AND source='s2')"),
        "NOT(host='h1' AND source='s2') == oracle (3VL)"
    );

    // (6) De Morgan `NOT(a OR b)`.
    let not_or = Pred::Not(Box::new(Pred::Or(vec![a(), b()])));
    assert_eq!(
        vec_count(&reader, &not_or, &deny_empty).unwrap(),
        oracle_count(&oracle, "WHERE NOT (host='h1' OR source='s2')"),
        "NOT(host='h1' OR source='s2') == oracle (3VL)"
    );

    // (7) Négation sur colonne DÉNIÉE (#45), formes réelles : `!=`, `NOT LIKE`, `NOT IN` sur src_ip -> 0 partout.
    for (pred, sql) in [
        (
            Pred::Not(Box::new(Pred::StrEq { col: "src_ip", val: "10.0.1.1".into() })),
            "WHERE src_ip <> '10.0.1.1'",
        ),
        (Pred::Not(Box::new(Pred::Like { col: "src_ip", pat: "10.%".into() })), "WHERE src_ip NOT LIKE '10.%'"),
        (
            Pred::Not(Box::new(Pred::StrIn {
                col: "src_ip",
                vals: ["10.0.1.1".to_string(), "10.0.2.2".to_string()].into_iter().collect(),
            })),
            "WHERE src_ip NOT IN ('10.0.1.1','10.0.2.2')",
        ),
    ] {
        assert_eq!(
            vec_count(&reader, &pred, &deny_ip).unwrap(),
            oracle_count(&oracle_m, sql),
            "négation sur colonne déniée == oracle masqué : {sql}"
        );
        assert_eq!(vec_count(&reader, &pred, &deny_ip).unwrap(), 0, "négation sur déniée -> 0 (NOT U = U) : {sql}");
    }

    // (8) `NOT(a AND b)` où a est la colonne DÉNIÉE : parité 3VL sous masquage (De Morgan + déni).
    let not_and_masked = Pred::Not(Box::new(Pred::And(vec![
        Pred::StrEq { col: "src_ip", val: "10.0.1.1".into() },
        Pred::StrEq { col: "source", val: "s2".into() },
    ])));
    assert_eq!(
        vec_count(&reader, &not_and_masked, &deny_ip).unwrap(),
        oracle_count(&oracle_m, "WHERE NOT (src_ip='10.0.1.1' AND source='s2')"),
        "NOT(src_ip(dénié)='x' AND source='s2') == oracle masqué (3VL)"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// ADVERSE #1 — MASQUAGE #45 : tenter la fuite d'une colonne déniée par CHAQUE opérateur NON-Not
/// (prédicat / group-by / top-N / materialize), + variante de CASSE du deny-set (eq_ignore_ascii_case).
/// Attendu : TENU (aucune fuite) — contrôle positif qui isole que le défaut est UNIQUEMENT `Not`.
#[test]
#[cfg(feature = "cold_tier")]
fn p2_adv_masking_all_ops_hold() {
    let root = tmp_root("p2advmask");
    let p = root.join("day.parquet");
    let n: i64 = 15_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
    assert_eq!(t_write(&p, &rows).unwrap() as i64, n);
    let reader = open_cold_reader(&p, &tpass()).unwrap();

    // Deny-set avec CASSE DIFFÉRENTE que la colonne physique ("SrC_Ip") -> doit tout de même dénier.
    let deny: std::collections::HashSet<String> = ["SrC_Ip".to_string()].into_iter().collect();
    let oracle = build_oracle(&rows, &deny); // union_proj(deny) NULLifie src_ip (eq_ignore_ascii_case)

    // (a) prédicat StrEq / (b) StrIn / (c) Like / (d) Contains / (e) Regex sur la colonne déniée -> 0.
    let eqp = Pred::StrEq { col: "src_ip", val: "10.0.1.1".into() };
    assert_eq!(vec_count(&reader, &eqp, &deny).unwrap(), oracle_count(&oracle, "WHERE src_ip='10.0.1.1'"));
    assert_eq!(vec_count(&reader, &eqp, &deny).unwrap(), 0, "casse-variante deny : StrEq dénié -> 0");
    let inp = Pred::StrIn { col: "src_ip", vals: ["10.0.1.1".to_string(), "10.0.2.2".to_string()].into_iter().collect() };
    assert_eq!(vec_count(&reader, &inp, &deny).unwrap(), oracle_count(&oracle, "WHERE src_ip IN ('10.0.1.1','10.0.2.2')"));
    assert_eq!(vec_count(&reader, &inp, &deny).unwrap(), 0, "StrIn dénié -> 0");
    let lk = Pred::Like { col: "src_ip", pat: "10.%".into() };
    assert_eq!(vec_count(&reader, &lk, &deny).unwrap(), oracle_count(&oracle, "WHERE src_ip LIKE '10.%'"));
    assert_eq!(vec_count(&reader, &lk, &deny).unwrap(), 0, "Like dénié -> 0");
    let ct = Pred::Contains { col: "src_ip", needle: "10.".into() };
    assert_eq!(vec_count(&reader, &ct, &deny).unwrap(), oracle_count(&oracle, "WHERE instr(src_ip,'10.')>0"));
    assert_eq!(vec_count(&reader, &ct, &deny).unwrap(), 0, "Contains dénié -> 0");
    let rx = Pred::Regex { col: "src_ip", re: regex::Regex::new("10\\.").unwrap() };
    assert_eq!(vec_count(&reader, &rx, &deny).unwrap(), oracle_count(&oracle, "WHERE src_ip REGEXP '10\\.'"));

    // (f) group-by clé déniée -> un seul groupe NULL == oracle.
    let gb = vec_group_count(&reader, &Pred::True, &["src_ip"], &deny).unwrap();
    assert_eq!(gb, oracle_gb1(&oracle, "", "src_ip"));
    assert_eq!(gb.get(&vec![None]), Some(&n), "tout sous NULL (casse-variante deny active)");

    // (g) top-N sur clé déniée : la vraie valeur ne doit JAMAIS apparaître en clé.
    let tn = top_n(&gb, 5);
    assert_eq!(tn, vec![(vec![None], n)], "top-N : seul le groupe NULL, jamais une IP réelle");

    // (h) materialize colonne déniée -> NULL partout == oracle.
    let (mat, _t) = vec_materialize(&reader, &Pred::True, &["ts", "src_ip"], 3000, &deny).unwrap();
    assert!(mat.iter().all(|r| matches!(r[1], rusqlite::types::Value::Null)), "src_ip projeté -> NULL");

    let _ = std::fs::remove_dir_all(&root);
}

/// ADVERSE #3 — LIKE : `_` sur multi-octets UTF-8, `%` en milieu, casse ASCII vs non-ASCII, littéral `_`.
#[test]
#[cfg(feature = "cold_tier")]
fn p2_adv_like_semantics() {
    let root = tmp_root("p2advlike");
    let p = root.join("day.parquet");
    // messages avec accents multi-octets + underscores littéraux.
    let mk = |i: i64, msg: &str| ColdRow {
        row: EventRow {
            ts: 1_000 + i, severity: 1, source: "s".into(), category: "auth".into(),
            message: msg.to_string(), host: None, src_ip: None, dst_ip: None, url: None, dedup: None,
            fields: None, engagement_id: String::new(), origin: String::new(), env_id: Some("prod".into()),
        },
        xff: None,
    };
    let samples = ["café", "cafe", "CAFÉ", "caf_", "a_b", "axb", "élève", "eleve", "événement"];
    let rows: Vec<ColdRow> = samples.iter().enumerate().map(|(i, m)| mk(i as i64, m)).collect();
    assert_eq!(t_write(&p, &rows).unwrap() as usize, samples.len());
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny);

    for pat in ["caf_", "c_fé", "%é%", "%_%", "élè_e", "a_b", "%f_", "CAF%", "____"] {
        let vecc = vec_count(&reader, &Pred::Like { col: "message", pat: pat.to_string() }, &deny).unwrap();
        // oracle : bind le motif en paramètre (évite l'échappement SQL).
        let orc: i64 = oracle
            .query_row("SELECT COUNT(*) FROM mev WHERE message LIKE ?1", params![pat], |r| r.get(0))
            .unwrap();
        eprintln!("[adv_like] pat={pat:?} vectorisé={vecc} oracle={orc}");
        assert_eq!(vecc, orc, "LIKE divergence sur motif {pat:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// ADVERSE #5/#7 — bords : 1 ligne, 0 ligne sélectionnée, cap materialize pile à la frontière de row-group,
/// group-by multi-dim dont les clés s'étalent sur plusieurs row-groups (collision de clé structurée).
#[test]
#[cfg(feature = "cold_tier")]
fn p2_adv_edges_and_multidim() {
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // (1) dataset 1 ligne.
    {
        let root = tmp_root("p2adv1");
        let p = root.join("day.parquet");
        let rows = vec![vrow(0)];
        t_write(&p, &rows).unwrap();
        let reader = open_cold_reader(&p, &tpass()).unwrap();
        assert_eq!(vec_count(&reader, &Pred::True, &deny).unwrap(), 1, "count 1 ligne");
        let (mat, tr) = vec_materialize(&reader, &Pred::True, &["ts"], 10, &deny).unwrap();
        assert_eq!(mat.len(), 1);
        assert!(!tr, "1<cap -> non tronqué");
        let _ = std::fs::remove_dir_all(&root);
    }

    // (2) 0 ligne sélectionnée (prédicat impossible).
    {
        let root = tmp_root("p2adv0");
        let p = root.join("day.parquet");
        let rows: Vec<ColdRow> = (0..500).map(vrow).collect();
        t_write(&p, &rows).unwrap();
        let reader = open_cold_reader(&p, &tpass()).unwrap();
        let none = Pred::Int { col: "severity", op: IntOp::Gt, val: 1_000 };
        assert_eq!(vec_count(&reader, &none, &deny).unwrap(), 0);
        assert!(vec_group_count(&reader, &none, &["source"], &deny).unwrap().is_empty(), "0 groupe");
        let (mat, tr) = vec_materialize(&reader, &none, &["ts"], 10, &deny).unwrap();
        assert!(mat.is_empty() && !tr);
        let _ = std::fs::remove_dir_all(&root);
    }

    // (3) cross-RG : 300k lignes -> >=2 row-groups ; count + group-by multi-dim == oracle (clés étalées).
    {
        let root = tmp_root("p2advxrg");
        let p = root.join("day.parquet");
        let n: i64 = 300_000;
        let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
        t_write(&p, &rows).unwrap();
        let reader = open_cold_reader(&p, &tpass()).unwrap();
        assert!(reader.metadata().num_row_groups() >= 2, "besoin multi-RG");
        let oracle = build_oracle(&rows, &deny);
        assert_eq!(vec_count(&reader, &Pred::True, &deny).unwrap(), n, "count cross-RG exact");
        // multi-dim source×category (clés vues dans plusieurs RG).
        let gbv = vec_group_count(&reader, &Pred::True, &["source", "category"], &deny).unwrap();
        let mut st = oracle.prepare("SELECT source, category, COUNT(*) FROM mev GROUP BY source, category").unwrap();
        let gbo: HashMap<GroupKey, i64> = st
            .query_map([], |r| Ok((vec![r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?], r.get::<_, i64>(2)?)))
            .unwrap().map(|x| x.unwrap()).collect();
        assert_eq!(gbv, gbo, "group-by multi-dim cross-RG == oracle");

        // (4) cap materialize pile à une frontière de RG : cap == nrows du 1er row-group.
        let rg0 = reader.metadata().row_group(0).num_rows() as usize;
        let (mat, tr) = vec_materialize(&reader, &Pred::True, &["ts"], rg0, &deny).unwrap();
        assert_eq!(mat.len(), rg0, "cap == taille RG0 -> exactement rg0 lignes");
        assert!(tr, "il reste des lignes en RG1 -> tronqué");
        let _ = std::fs::remove_dir_all(&root);
    }

    // (5) group-by INT dim (severity) accumulation cross-RG (to_string bijectif).
    {
        let root = tmp_root("p2advint");
        let p = root.join("day.parquet");
        let n: i64 = 300_000;
        let rows: Vec<ColdRow> = (0..n).map(vrow).collect();
        t_write(&p, &rows).unwrap();
        let reader = open_cold_reader(&p, &tpass()).unwrap();
        let oracle = build_oracle(&rows, &deny);
        assert_eq!(
            vec_group_count(&reader, &Pred::True, &["severity"], &deny).unwrap(),
            oracle_gb1_int(&oracle, "", "severity"),
            "group-by severity (INT) cross-RG"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

// ====================================================================================================
// #18 P3 — ÉLAGAGE ROW-GROUP (pushdown de prédicat sur les statistiques natives Parquet min/max).
// ----------------------------------------------------------------------------------------------------
// INVARIANT prouvé ici : l'élagage est une OPTIMISATION TRANSPARENTE. (1) PARITÉ on/off/SQLite : même résultat
// avec pruning, sans pruning, et vs l'oracle SQLite. (2) PREUVE d'élagage : une requête sélective saute des
// row-groups (skipped>0). (3) ANTI-SUR-ÉLAGAGE : un match dans un groupe à stats larges n'est jamais sauté ;
// une colonne déniée n'est jamais élaguée (parité masquée tenue) ; des stats absentes (colonne toute-NULL) ->
// décode. Fixtures MULTI-ROW-GROUPS via `t_write_rg` (petits groupes, plages ts disjointes car lignes triées).

/// Ligne minimale à (ts, source, severity) contrôlés — pour piloter les stats min/max PAR row-group.
fn srow(ts: i64, source: &str, severity: i64) -> ColdRow {
    ColdRow {
        row: EventRow {
            ts,
            severity,
            source: source.to_string(),
            category: "cat".to_string(),
            message: "m".to_string(),
            host: None,
            src_ip: None,
            dst_ip: None,
            url: None,
            dedup: None,
            fields: None,
            engagement_id: String::new(),
            origin: String::new(),
            env_id: Some("prod".to_string()),
        },
        xff: None,
    }
}

/// Extrait la colonne ts (Integer) d'une matérialisation `proj=["ts"]`, triée -> multiset comparable à l'oracle.
fn mat_ts_sorted(mat: &[Vec<rusqlite::types::Value>]) -> Vec<i64> {
    use rusqlite::types::Value;
    let mut v: Vec<i64> = mat.iter().map(|r| match &r[0] { Value::Integer(t) => *t, _ => panic!("ts non-entier") }).collect();
    v.sort_unstable();
    v
}

// (1) PARITÉ on/off/SQLite sur données multi-row-groups (ts trié) : count / group-by / materialize AVEC pruning
//     == SANS pruning == oracle SQLite. Chaque forme aussi bien couvrante (ts range, severity, source eq, AND,
//     group-by mono/multi). Et : la requête ts-sélective PRUNE (skipped>0) tandis que prune=false ne saute rien.
#[test]
#[cfg(feature = "cold_tier")]
fn p3_parity_prune_on_off_sqlite_multi_rg() {
    let root = tmp_root("p3par");
    let p = root.join("day.parquet");
    let n: i64 = 10_000;
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect(); // ts = 1000+i (monotone -> plages RG disjointes)
    t_write_rg(&p, &rows, 1_000).unwrap(); // 10 row-groups de 1000 lignes
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    assert_eq!(reader.metadata().num_row_groups(), 10, "10 row-groups attendus");

    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny);

    // Batterie de prédicats vectorisables (dont un ts-sélectif à 1 seul RG).
    let ts_sel = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: 6000 },
        Pred::Int { col: "ts", op: IntOp::Le, val: 6999 },
    ]);
    let cases: Vec<(Pred, &str)> = vec![
        (Pred::True, ""),
        (Pred::Int { col: "ts", op: IntOp::Ge, val: 6000 }, "WHERE ts>=6000"),
        (Pred::And(vec![Pred::Int { col: "ts", op: IntOp::Ge, val: 6000 }, Pred::Int { col: "ts", op: IntOp::Le, val: 6999 }]), "WHERE ts>=6000 AND ts<=6999"),
        (Pred::Int { col: "severity", op: IntOp::Ge, val: 3 }, "WHERE severity>=3"),
        (Pred::StrEq { col: "source", val: "s2".into() }, "WHERE source='s2'"),
        (Pred::And(vec![Pred::Int { col: "ts", op: IntOp::Ge, val: 6000 }, Pred::StrEq { col: "source", val: "s2".into() }]), "WHERE ts>=6000 AND source='s2'"),
    ];
    for (pred, sql_where) in &cases {
        let mut s_on = RgPruneStats::default();
        let mut s_off = RgPruneStats::default();
        let c_on = vec_count_ex(&reader, pred, &deny, true, &mut s_on).unwrap();
        let c_off = vec_count_ex(&reader, pred, &deny, false, &mut s_off).unwrap();
        let c_oracle = oracle_count(&oracle, sql_where);
        assert_eq!(c_on, c_off, "count prune on==off ({sql_where})");
        assert_eq!(c_on, c_oracle, "count prune==oracle ({sql_where})");
        assert_eq!(s_off.skipped, 0, "prune=false ne saute JAMAIS ({sql_where})");
        assert_eq!(s_off.scanned, 10, "prune=false décode les 10 RG ({sql_where})");
    }

    // La requête ts-sélective (1 RG sur 10) PRUNE réellement sous pruning ON.
    let mut s = RgPruneStats::default();
    let _ = vec_count_ex(&reader, &ts_sel, &deny, true, &mut s).unwrap();
    assert_eq!(s.scanned, 1, "ts∈[6000,6999] -> 1 seul RG décodé");
    assert_eq!(s.skipped, 9, "les 9 autres RG sont sautés (preuve d'élagage)");

    // group-by mono (source) et multi-dim (source×severity×category) : prune on==off==oracle.
    for dims in [&["source"][..], &["source", "severity", "category"][..]] {
        let mut s_on = RgPruneStats::default();
        let mut s_off = RgPruneStats::default();
        let g_on = vec_group_count_ex(&reader, &ts_sel, dims, &deny, true, &mut s_on).unwrap();
        let g_off = vec_group_count_ex(&reader, &ts_sel, dims, &deny, false, &mut s_off).unwrap();
        assert_eq!(g_on, g_off, "group-by prune on==off (dims={dims:?})");
        assert_eq!(s_on.skipped, 9, "group-by ts-sélectif saute 9 RG (dims={dims:?})");
        // Oracle SQLite pour le même filtre.
        let sql = format!("SELECT {}, COUNT(*) FROM mev WHERE ts>=6000 AND ts<=6999 GROUP BY {}", dims.join(","), dims.join(","));
        let mut st = oracle.prepare(&sql).unwrap();
        let g_oracle: HashMap<GroupKey, i64> = st
            .query_map([], |r| {
                let mut key: GroupKey = Vec::with_capacity(dims.len());
                for (i, d) in dims.iter().enumerate() {
                    key.push(if *d == "severity" { r.get::<_, Option<i64>>(i)?.map(|v| v.to_string()) } else { r.get::<_, Option<String>>(i)? });
                }
                Ok((key, r.get::<_, i64>(dims.len())?))
            })
            .unwrap().map(|x| x.unwrap()).collect();
        assert_eq!(g_on, g_oracle, "group-by prune==oracle (dims={dims:?})");
    }

    // materialize (proj ts) : prune on==off (exact), et multiset ts == oracle. Cap large (pas de troncature).
    let mut s_on = RgPruneStats::default();
    let mut s_off = RgPruneStats::default();
    let (m_on, tr_on) = vec_materialize_ex(&reader, &ts_sel, &["ts"], 100_000, &deny, true, &mut s_on).unwrap();
    let (m_off, tr_off) = vec_materialize_ex(&reader, &ts_sel, &["ts"], 100_000, &deny, false, &mut s_off).unwrap();
    assert!(!tr_on && !tr_off, "cap large -> pas de troncature");
    assert_eq!(m_on, m_off, "materialize prune on==off (lignes identiques, même ordre)");
    assert_eq!(s_on.skipped, 9, "materialize ts-sélectif saute 9 RG");
    let oracle_ts: Vec<i64> = {
        let mut st = oracle.prepare("SELECT ts FROM mev WHERE ts>=6000 AND ts<=6999 ORDER BY ts").unwrap();
        st.query_map([], |r| r.get::<_, i64>(0)).unwrap().map(|x| x.unwrap()).collect()
    };
    assert_eq!(mat_ts_sorted(&m_on), oracle_ts, "materialize multiset ts == oracle");
    let _ = std::fs::remove_dir_all(&root);
}

// (2) PREUVE d'élagage sur une valeur RARE (source concentrée dans 1 seul row-group) : min/max lexical saute les
//     groupes hors plage. Prouve que l'égalité string élague, et vérifie le compte exact (aucune perte).
#[test]
#[cfg(feature = "cold_tier")]
fn p3_prune_rare_source_string_minmax() {
    let root = tmp_root("p3rare");
    let p = root.join("day.parquet");
    // 3 row-groups de 3 lignes. RG0 sources {aaa,aab,aac}; RG1 {mmm,mmn,mmo}; RG2 {zzx,zzy,zzz}.
    // (ts monotone -> ordre des groupes = ordre d'insertion ; sources groupées par plage lexicale disjointe.)
    let mut rows = Vec::new();
    let g0 = ["aaa", "aab", "aac"]; let g1 = ["mmm", "mmn", "mmo"]; let g2 = ["zzx", "zzy", "zzz"];
    for (gi, grp) in [g0, g1, g2].iter().enumerate() {
        for (j, s) in grp.iter().enumerate() { rows.push(srow((gi * 3 + j) as i64, s, 0)); }
    }
    t_write_rg(&p, &rows, 3).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    assert_eq!(reader.metadata().num_row_groups(), 3);
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // source='mmn' n'existe QUE dans RG1 ([mmm,mmo]). RG0 [aaa,aac] et RG2 [zzx,zzz] hors plage -> sautés.
    let pred = Pred::StrEq { col: "source", val: "mmn".into() };
    let mut s = RgPruneStats::default();
    let c = vec_count_ex(&reader, &pred, &deny, true, &mut s).unwrap();
    assert_eq!(c, 1, "1 seule ligne source=mmn");
    assert_eq!(s.scanned, 1, "seul RG1 décodé");
    assert_eq!(s.skipped, 2, "RG0 et RG2 sautés par min/max lexical (preuve d'élagage string)");

    // StrIn : {aaa, zzz} -> RG0 (aaa) et RG2 (zzz) matchent, RG1 [mmm,mmo] hors des deux -> sauté.
    let inset: std::collections::HashSet<String> = ["aaa".to_string(), "zzz".to_string()].into_iter().collect();
    let pin = Pred::StrIn { col: "source", vals: inset };
    let mut s2 = RgPruneStats::default();
    let c2 = vec_count_ex(&reader, &pin, &deny, true, &mut s2).unwrap();
    assert_eq!(c2, 2, "aaa + zzz");
    assert_eq!(s2.skipped, 1, "RG1 sauté (aucune des valeurs IN dans [mmm,mmo])");
    let _ = std::fs::remove_dir_all(&root);
}

// (3) ANTI-SUR-ÉLAGAGE (cas dédié) : (a) match dans un groupe à stats LARGES -> jamais sauté,
//     résultat complet ; (a') valeur DANS [min,max] mais ABSENTE d'un groupe -> décodé (jamais sauté à tort) ;
//     (b) prédicat sur colonne DÉNIÉE -> aucun élagage (parité masquée tenue) ; (c) stats absentes (colonne
//     toute-NULL) -> décode.
#[test]
#[cfg(feature = "cold_tier")]
fn p3_anti_over_prune_wide_stats_denied_and_null() {
    let root = tmp_root("p3anti");
    let p = root.join("day.parquet");
    // RG0 (stats LARGES) : sources {aaa, mmm, zzz} -> [aaa,zzz]. RG1 (stats étroites) : {bbb,bbb,bbb}.
    let rows = vec![
        srow(0, "aaa", 5), srow(1, "mmm", 5), srow(2, "zzz", 5), // RG0
        srow(3, "bbb", 5), srow(4, "bbb", 5), srow(5, "bbb", 5), // RG1
    ];
    t_write_rg(&p, &rows, 3).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // (a) source='mmm' : DANS [aaa,zzz] de RG0 (large) -> RG0 GARDÉ (match rendu) ; RG1 [bbb,bbb] hors -> sauté.
    let pmmm = Pred::StrEq { col: "source", val: "mmm".into() };
    let mut s = RgPruneStats::default();
    let c = vec_count_ex(&reader, &pmmm, &deny, true, &mut s).unwrap();
    assert_eq!(c, 1, "la ligne mmm de RG0 (stats larges) DOIT être rendue");
    assert_eq!(s.scanned, 1, "RG0 (large) gardé");
    assert_eq!(s.skipped, 1, "RG1 (étroit, hors plage) sauté");

    // (a') source='nnn' : DANS [aaa,zzz] de RG0 mais ABSENTE -> RG0 NE DOIT PAS être sauté (min/max ne prouve pas
    //     l'absence) -> décodé, résultat 0. RG1 [bbb,bbb] : nnn>bbb -> sauté. Prouve la conservativité min/max.
    let pnnn = Pred::StrEq { col: "source", val: "nnn".into() };
    let mut s2 = RgPruneStats::default();
    let c2 = vec_count_ex(&reader, &pnnn, &deny, true, &mut s2).unwrap();
    assert_eq!(c2, 0, "nnn absente");
    assert_eq!(s2.scanned, 1, "RG0 décodé (valeur dans [min,max] -> jamais sauté à tort)");

    // (b) COLONNE DÉNIÉE (#45) : severity déniée + prédicat sélectif `severity<=1` qui, SUR LES VRAIES stats
    //     (min=max=5), prouverait vide -> mais on NE DOIT PAS élaguer (severity lue NULL). Aucun RG sauté ;
    //     résultat == oracle masqué (0 : NULL<=1 -> UNKNOWN).
    let mut deny_sev: std::collections::HashSet<String> = std::collections::HashSet::new();
    deny_sev.insert("severity".to_string());
    let psev = Pred::Int { col: "severity", op: IntOp::Le, val: 1 };
    let mut s3 = RgPruneStats::default();
    let c3 = vec_count_ex(&reader, &psev, &deny_sev, true, &mut s3).unwrap();
    assert_eq!(s3.skipped, 0, "colonne DÉNIÉE -> AUCUN élagage (pas de fuite par les vraies stats)");
    assert_eq!(s3.scanned, 2, "les 2 RG décodés malgré des stats qui prouveraient vide");
    let oracle_sev = build_oracle(&rows, &deny_sev);
    assert_eq!(c3, oracle_count(&oracle_sev, "WHERE severity<=1"), "parité masquée tenue (severity NULL -> 0)");

    // (c) STATS ABSENTES : dst_ip est toute-NULL -> min/max non posés -> pas d'élagage -> décode (résultat 0).
    let pdst = Pred::StrEq { col: "dst_ip", val: "10.0.0.1".into() };
    let mut s4 = RgPruneStats::default();
    let c4 = vec_count_ex(&reader, &pdst, &deny, true, &mut s4).unwrap();
    assert_eq!(c4, 0, "aucun dst_ip");
    assert_eq!(s4.skipped, 0, "stats absentes (colonne toute-NULL) -> décode, jamais d'élagage");
    let _ = std::fs::remove_dir_all(&root);
}

// (4) TABLE DE DÉCISION `rg_can_match` exercée DIRECTEMENT sur les métadonnées d'un row-group réel : chaque
//     opérateur INT (ts) + le NOT conservateur + le OR (skip ssi tous vides). Un seul RG couvrant ts∈[100,199].
#[test]
#[cfg(feature = "cold_tier")]
fn p3_rg_can_match_decision_table() {
    let root = tmp_root("p3dt");
    let p = root.join("day.parquet");
    let rows: Vec<ColdRow> = (0..100).map(|i| srow(100 + i, "s", 3)).collect(); // ts 100..199, severity=3
    t_write_rg(&p, &rows, 1000).unwrap(); // 1 seul RG
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let md = reader.metadata();
    let rg = md.row_group(0);
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let ck = |pred: &Pred| rg_can_match(pred, rg, &deny);

    // ts ∈ [100,199]. Skips PROUVÉS (can_match=false) :
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Ge, val: 200 }), "Ge 200 : max199<200 -> skip");
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Gt, val: 199 }), "Gt 199 : max199<=199 -> skip");
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Le, val: 99 }), "Le 99 : min100>99 -> skip");
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Lt, val: 100 }), "Lt 100 : min100>=100 -> skip");
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Eq, val: 50 }), "Eq 50 : hors [100,199] -> skip");
    assert!(!ck(&Pred::Int { col: "ts", op: IntOp::Eq, val: 300 }), "Eq 300 : hors [100,199] -> skip");
    // Keeps (can_match=true) — dans la plage / opérateurs non prouvables :
    assert!(ck(&Pred::Int { col: "ts", op: IntOp::Ge, val: 150 }), "Ge 150 : chevauche -> keep");
    assert!(ck(&Pred::Int { col: "ts", op: IntOp::Eq, val: 150 }), "Eq 150 : dans plage -> keep");
    assert!(ck(&Pred::Int { col: "ts", op: IntOp::Ne, val: 150 }), "Ne 150 : min!=max -> keep (jamais prouvable ici)");
    // Ne prouvable seulement si min==max==val : severity=3 partout.
    assert!(!ck(&Pred::Int { col: "severity", op: IntOp::Ne, val: 3 }), "Ne 3 sur severity constante=3 -> tout==3 -> skip");
    assert!(ck(&Pred::Int { col: "severity", op: IntOp::Ne, val: 4 }), "Ne 4 : tout==3 != 4 -> des lignes matchent -> keep");
    // NOT : CONSERVATEUR -> jamais d'élagage, même si l'enfant prouve vide.
    assert!(ck(&Pred::Not(Box::new(Pred::Int { col: "ts", op: IntOp::Ge, val: 200 })), ), "Not(enfant-vide) -> keep (conservateur)");
    // OR : skip SSI tous les disjoncts prouvés vides.
    assert!(!ck(&Pred::Or(vec![Pred::Int { col: "ts", op: IntOp::Ge, val: 200 }, Pred::Int { col: "ts", op: IntOp::Le, val: 99 }])), "OR(vide,vide) -> skip");
    assert!(ck(&Pred::Or(vec![Pred::Int { col: "ts", op: IntOp::Ge, val: 200 }, Pred::Int { col: "ts", op: IntOp::Ge, val: 150 }])), "OR(vide, non-vide) -> keep");
    // Formes non-élaguables -> keep.
    assert!(ck(&Pred::Like { col: "source", pat: "z%".into() }), "Like -> keep (non élaguable)");
    assert!(ck(&Pred::Regex { col: "source", re: regex::Regex::new("^z").unwrap() }), "Regex -> keep");
    assert!(ck(&Pred::True), "True -> keep");
    let _ = std::fs::remove_dir_all(&root);
}

// BENCH P3 : élagage row-group. 800k lignes triées par ts, 16 row-groups (rg=50k). Une requête ts-SÉLECTIVE
// (1 RG sur 16) mesure le temps de décode AVEC pruning (15 RG sautés) vs SANS pruning (16 RG décodés). Le
// résultat est IDENTIQUE ; seul le temps change. `bench` dans le nom -> skippé par `--skip bench` (OOM en //).
#[test]
#[cfg(feature = "cold_tier")]
fn p3_rowgroup_prune_bench() {
    let root = tmp_root("p3bench");
    let p = root.join("day.parquet");
    let n: i64 = 800_000;
    let rg: usize = 50_000; // -> 16 row-groups
    let rows: Vec<ColdRow> = (0..n).map(vrow).collect(); // ts = 1000+i (trié -> plages RG disjointes)
    t_write_rg(&p, &rows, rg).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let ngroups = reader.metadata().num_row_groups();
    assert!(ngroups >= 8, "besoin de nombreux RG (obtenu {ngroups})");
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // ts ∈ dernier RG uniquement (les 1000 dernières valeurs) -> 1 RG retenu, le reste prouvé vide.
    let lo = 1000 + n - (rg as i64);
    let sel = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: lo },
        Pred::Int { col: "ts", op: IntOp::Le, val: 1000 + n },
    ]);

    let mut s_off = RgPruneStats::default();
    let t_off = std::time::Instant::now();
    let c_off = vec_count_ex(&reader, &sel, &deny, false, &mut s_off).unwrap();
    let d_off = t_off.elapsed();

    let mut s_on = RgPruneStats::default();
    let t_on = std::time::Instant::now();
    let c_on = vec_count_ex(&reader, &sel, &deny, true, &mut s_on).unwrap();
    let d_on = t_on.elapsed();

    assert_eq!(c_on, c_off, "résultat IDENTIQUE avec/sans pruning (invariant P3)");
    assert!(s_on.skipped >= (ngroups as u64) - 1, "quasi tous les RG sautés (scanné {}, sauté {})", s_on.scanned, s_on.skipped);
    eprintln!(
        "[p3_rowgroup_prune_bench] {n} lignes, {ngroups} row-groups ; requête ts-sélective (1 RG)\n  \
         SANS pruning : {d_off:?} (16 RG décodés, skipped={})\n  \
         AVEC pruning : {d_on:?} (scanned={}, skipped={})  -> décode ×{:.1} plus rapide",
        s_off.skipped, s_on.scanned, s_on.skipped,
        d_off.as_secs_f64() / d_on.as_secs_f64().max(1e-9),
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// TESTS ADVERSES P3 — CHASSE AU SUR-ÉLAGAGE. Objectif UNIQUE : prouver qu'AUCUN row-group
// contenant une ligne qui MATCHE n'est jamais sauté. Invariant testé partout : `prune=true` == `prune=false`
// (résultat), + la valeur PRÉSENTE est bien comptée. Un écart => SUR-ÉLAGAGE (fausse détection SOC).
// ====================================================================================================

/// MICRO-TEST : comportement RÉEL de troncature des stats string (parquet 58, défaut `statistics_truncate_length=64`).
/// Établit empiriquement : MAX tronqué INCRÉMENTÉ (>= vrai max) ; MIN tronqué (<= vrai min) -> bornes VALIDES.
#[test]
#[cfg(feature = "cold_tier")]
fn audit_truncation_preserves_string_bounds() {
    let root = tmp_root("audit_trunc");
    let p = root.join("day.parquet");
    let pre = "a".repeat(64); // préfixe commun de 64 octets
    let s_lo = format!("{pre}AAA"); // 67 o
    let s_mid = format!("{pre}MMM");
    let s_hi = format!("{pre}ZZZ"); // vrai max
    let rows = vec![srow(0, &s_lo, 0), srow(1, &s_mid, 0), srow(2, &s_hi, 0)];
    t_write_rg(&p, &rows, 3).unwrap(); // 1 RG
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let idx = PARQUET_COLS.iter().position(|c| *c == "source").unwrap();
    let st = reader.metadata().row_group(0).column(idx).statistics().unwrap();
    let mn = st.min_bytes_opt().unwrap();
    let mx = st.max_bytes_opt().unwrap();
    assert!(mn <= s_lo.as_bytes(), "min tronqué DOIT rester <= vrai min (borne basse valide)");
    assert!(
        mx >= s_hi.as_bytes(),
        "max tronqué DOIT être >= vrai max (incrément), sinon StrEq sur une valeur > max_stocké sur-élague. mx.len={} mx={:?}",
        mx.len(), String::from_utf8_lossy(mx)
    );
    eprintln!(
        "[audit_trunc] min.len={} max.len={} max_incremente={} max_octets={:?}",
        mn.len(), mx.len(), mx > pre.as_bytes(), &mx[..mx.len().min(66)]
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 1 — TRONCATURE MAX (risque n°1) : strings > 64 o, préfixes 64 o DISTINCTS par RG (élagage réel),
/// valeurs existantes AU-DELÀ du préfixe 64 o. Chaque valeur présente DOIT être trouvée (jamais sur-élaguée).
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_truncated_prefix_strings() {
    let root = tmp_root("audit_pfx");
    let p = root.join("day.parquet");
    // 3 RG, chacun un préfixe 64 o distinct (a../m../z..) + suffixe 3 lettres (dépasse 64 o).
    let mut rows = Vec::new();
    let mut ts = 0i64;
    let mut all_vals = Vec::new();
    for g in ['a', 'm', 'z'] {
        let pre = std::iter::repeat(g).take(64).collect::<String>();
        for suf in ["AAA", "AAB", "AAC"] {
            let v = format!("{pre}{suf}");
            rows.push(srow(ts, &v, 0));
            all_vals.push(v);
            ts += 1;
        }
    }
    t_write_rg(&p, &rows, 3).unwrap(); // 3 RG de 3
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    assert_eq!(reader.metadata().num_row_groups(), 3);
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny);
    for v in &all_vals {
        let pred = Pred::StrEq { col: "source", val: v.clone() };
        let mut son = RgPruneStats::default();
        let mut soff = RgPruneStats::default();
        let c_on = vec_count_ex(&reader, &pred, &deny, true, &mut son).unwrap();
        let c_off = vec_count_ex(&reader, &pred, &deny, false, &mut soff).unwrap();
        let c_or = oracle_count(&oracle, &format!("WHERE source='{v}'"));
        assert_eq!(c_off, 1, "sanity: valeur présente comptée 1 sans pruning ({})", &v[64..]);
        assert_eq!(c_on, c_off, "SUR-ÉLAGAGE tronc-préfixe: prune on({c_on})!=off({c_off}) pour suffixe {}", &v[64..]);
        assert_eq!(c_on, c_or, "prune != oracle pour suffixe {}", &v[64..]);
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 2 — ORDRE D'OCTETS (BYTE_ARRAY unsigned) : valeurs mêlant ASCII et octets >= 0x80 (é, ÿ, 日, plan
/// astral, DEL) réparties en RG mixtes (ts monotone != ordre lexical). Si `proves_no_match` comparait autrement
/// que l'ordre unsigned du writer, une valeur haute présente serait élaguée à tort. Parité on==off exigée.
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_high_byte_unsigned_order() {
    let root = tmp_root("audit_hb");
    let p = root.join("day.parquet");
    // ASCII bas, ASCII haut (~,DEL), 2-octets (é,ÿ), 3-octets (日), 4-octets (𐍈). Ordre d'INSERTION != lexical
    // -> les RG (2 lignes) mélangent des plages d'octets signés/non-signés discordantes.
    let vals = [
        "Aaa", "\u{7f}q", "Mmm", "\u{e9}a", "Zzz", "\u{ff}0", "\u{65e5}a", "~zz", "\u{10348}x", "\u{e9}z", "\u{65e5}z",
    ];
    let mut rows = Vec::new();
    for (i, s) in vals.iter().enumerate() {
        rows.push(srow(i as i64, s, 0));
    }
    t_write_rg(&p, &rows, 2).unwrap(); // 6 RG (5×2 + 1), plages mixtes
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in &vals {
        let pred = Pred::StrEq { col: "source", val: (*s).to_string() };
        let mut son = RgPruneStats::default();
        let mut soff = RgPruneStats::default();
        let c_on = vec_count_ex(&reader, &pred, &deny, true, &mut son).unwrap();
        let c_off = vec_count_ex(&reader, &pred, &deny, false, &mut soff).unwrap();
        assert_eq!(c_off, 1, "sanity: {s:?} présent");
        assert_eq!(c_on, c_off, "SUR-ÉLAGAGE octets-hauts: prune on({c_on})!=off({c_off}) pour {s:?}");
    }
    // StrIn multi-valeurs hautes : union trouvée, jamais sur-élaguée.
    let inset: std::collections::HashSet<String> =
        ["\u{e9}a".to_string(), "\u{65e5}z".to_string(), "\u{10348}x".to_string()].into_iter().collect();
    let pin = Pred::StrIn { col: "source", vals: inset };
    let mut a = RgPruneStats::default();
    let mut b = RgPruneStats::default();
    assert_eq!(
        vec_count_ex(&reader, &pin, &deny, true, &mut a).unwrap(),
        vec_count_ex(&reader, &pin, &deny, false, &mut b).unwrap(),
        "SUR-ÉLAGAGE StrIn octets-hauts"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 3 — BORNES INT : i64::MIN/MAX, ts négatifs, min==max, chaque opérateur au point de bascule EXACT.
/// Un RG par ligne (bornes isolées). Parité on==off sur une grille dense de probes autour de chaque valeur.
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_int_boundaries() {
    let root = tmp_root("audit_int");
    let p = root.join("day.parquet");
    let tss = [i64::MIN, -100, -1, 0, 1, 100, i64::MAX];
    let rows: Vec<ColdRow> = tss.iter().map(|&t| srow(t, "s", 3)).collect();
    t_write_rg(&p, &rows, 1).unwrap(); // 1 RG par ligne -> bornes min==max exactes par RG
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let ops = [IntOp::Eq, IntOp::Ne, IntOp::Lt, IntOp::Le, IntOp::Gt, IntOp::Ge];
    let probes = [
        i64::MIN, i64::MIN + 1, -101, -100, -99, -2, -1, 0, 1, 2, 99, 100, 101, i64::MAX - 1, i64::MAX,
    ];
    for &op in &ops {
        for &v in &probes {
            let pred = Pred::Int { col: "ts", op, val: v };
            let mut son = RgPruneStats::default();
            let mut soff = RgPruneStats::default();
            let c_on = vec_count_ex(&reader, &pred, &deny, true, &mut son).unwrap();
            let c_off = vec_count_ex(&reader, &pred, &deny, false, &mut soff).unwrap();
            assert_eq!(c_on, c_off, "SUR-ÉLAGAGE int: ts {op:?} {v} -> on({c_on})!=off({c_off})");
        }
    }
    // min==max sur severity constante (=3) : Ne DOIT sauter SEULEMENT val==3 ; Ge/Le/Gt/Lt au point de bascule.
    let md = reader.metadata();
    let rg = md.row_group(0); // ts=i64::MIN, severity=3
    let ck = |op: IntOp, v: i64| rg_can_match(&Pred::Int { col: "severity", op, val: v }, rg, &deny);
    assert!(ck(IntOp::Ge, 3), "Ge 3 sur sev==3 : max==val -> DOIT décoder (bascule inclusive)");
    assert!(!ck(IntOp::Ge, 4), "Ge 4 sur sev==3 : max<val -> skip");
    assert!(ck(IntOp::Le, 3), "Le 3 sur sev==3 : min==val -> décode");
    assert!(!ck(IntOp::Le, 2), "Le 2 sur sev==3 : min>val -> skip");
    assert!(!ck(IntOp::Gt, 3), "Gt 3 sur sev==3 : max<=val -> skip");
    assert!(ck(IntOp::Gt, 2), "Gt 2 sur sev==3 : décode");
    assert!(!ck(IntOp::Lt, 3), "Lt 3 sur sev==3 : min>=val -> skip");
    assert!(ck(IntOp::Lt, 4), "Lt 4 sur sev==3 : décode");
    assert!(ck(IntOp::Eq, 3), "Eq 3 : dans plage -> décode");
    assert!(!ck(IntOp::Eq, 2), "Eq 2 : hors -> skip");
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 4 — AND / OR / NOT : Or(prouvé_vide, Regex) JAMAIS sauté ; Not(...) jamais d'élagage ; And borne
/// inclusive non sautée. Testé DIRECTEMENT sur les stats + par parité on==off.
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_and_or_not() {
    let root = tmp_root("audit_bool");
    let p = root.join("day.parquet");
    // 3 RG de 3 : ts monotone 0..8, source par RG (aaa.. / mmm.. / zzz..), severity=5.
    let mut rows = Vec::new();
    let mut ts = 0i64;
    for s in ["aaa", "mmm", "zzz"] {
        for _ in 0..3 {
            rows.push(srow(ts, s, 5));
            ts += 1;
        }
    }
    t_write_rg(&p, &rows, 3).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let md = reader.metadata();
    let rg0 = md.row_group(0); // ts∈[0,2], source∈[aaa..], severity=5
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Or(prouvé_vide_sur_ts, Regex) : Regex non élaguable -> l'OR ne peut PAS être prouvé vide -> décode.
    let or_regex = Pred::Or(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: 1_000 }, // vide sur RG0
        Pred::Regex { col: "source", re: regex::Regex::new("^a").unwrap() },
    ]);
    assert!(rg_can_match(&or_regex, rg0, &deny), "Or(vide, Regex) NE DOIT JAMAIS être sauté");

    // Not(enfant-prouvé-vide) : jamais d'élagage.
    let not_empty = Pred::Not(Box::new(Pred::Int { col: "ts", op: IntOp::Ge, val: 1_000 }));
    assert!(rg_can_match(&not_empty, rg0, &deny), "Not(vide) -> keep (jamais d'élagage sous Not)");

    // And avec une borne INCLUSIVE au point exact (ts>=2 AND ts<=2) : RG0 [0,2] contient ts=2 -> décode.
    let and_incl = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: 2 },
        Pred::Int { col: "ts", op: IntOp::Le, val: 2 },
    ]);
    assert!(rg_can_match(&and_incl, rg0, &deny), "And(ts>=2,ts<=2) sur [0,2] -> ts=2 présent -> décode");

    // Parité on==off pour ces formes sur l'ensemble (résultat identique).
    for pred in [&or_regex, &not_empty, &and_incl] {
        let mut a = RgPruneStats::default();
        let mut b = RgPruneStats::default();
        let c_on = vec_count_ex(&reader, pred, &deny, true, &mut a).unwrap();
        let c_off = vec_count_ex(&reader, pred, &deny, false, &mut b).unwrap();
        assert_eq!(c_on, c_off, "SUR-ÉLAGAGE bool: prune on!=off");
    }
    // Or(prouvé_vide, StrEq présent dans un AUTRE RG) : ne doit pas rater le RG du StrEq.
    let or_str = Pred::Or(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: 1_000 },
        Pred::StrEq { col: "source", val: "mmm".into() },
    ]);
    let mut a = RgPruneStats::default();
    let mut b = RgPruneStats::default();
    assert_eq!(
        vec_count_ex(&reader, &or_str, &deny, true, &mut a).unwrap(),
        vec_count_ex(&reader, &or_str, &deny, false, &mut b).unwrap(),
        "SUR-ÉLAGAGE Or(vide, StrEq mmm)"
    );
    assert_eq!(vec_count_ex(&reader, &or_str, &deny, true, &mut a).unwrap(), 3, "3 lignes mmm trouvées");
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 5 — COLONNE DÉNIÉE (#45) : StrEq/Int sur colonne déniée -> JAMAIS d'élagage (lue NULL). Même si les
/// VRAIES stats prouveraient vide, aucun RG sauté (sinon faux résultat + fuite d'info par timing).
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_denied_column_string() {
    let root = tmp_root("audit_deny");
    let p = root.join("day.parquet");
    // 3 RG de 3, sources disjointes par plage (aaa/mmm/zzz) -> une StrEq élaguerait 2 RG SI non déniée.
    let mut rows = Vec::new();
    let mut ts = 0i64;
    for s in ["aaa", "mmm", "zzz"] {
        for _ in 0..3 {
            rows.push(srow(ts, s, 3));
            ts += 1;
        }
    }
    t_write_rg(&p, &rows, 3).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    let deny: std::collections::HashSet<String> = ["source".to_string()].into_iter().collect();

    // StrEq source='mmm' AVEC source DÉNIÉE : aucun RG sauté (source lue NULL) ; résultat 0 (NULL='mmm' -> UNKNOWN).
    let pred = Pred::StrEq { col: "source", val: "mmm".into() };
    let mut s = RgPruneStats::default();
    let c = vec_count_ex(&reader, &pred, &deny, true, &mut s).unwrap();
    assert_eq!(s.skipped, 0, "colonne DÉNIÉE -> AUCUN élagage (sinon fuite via les vraies stats)");
    assert_eq!(s.scanned, 3, "les 3 RG décodés malgré des stats disjointes qui prouveraient vide");
    let oracle = build_oracle(&rows, &deny);
    assert_eq!(c, oracle_count(&oracle, "WHERE source='mmm'"), "parité masquée (source NULL -> 0)");

    // StrIn déniée : idem, aucun skip.
    let inset: std::collections::HashSet<String> = ["aaa".to_string(), "zzz".to_string()].into_iter().collect();
    let pin = Pred::StrIn { col: "source", vals: inset };
    let mut s2 = RgPruneStats::default();
    vec_count_ex(&reader, &pin, &deny, true, &mut s2).unwrap();
    assert_eq!(s2.skipped, 0, "StrIn colonne déniée -> aucun élagage");
    let _ = std::fs::remove_dir_all(&root);
}

/// VECTEUR 6 — NULL PARTIEL / COLONNE PARTIELLEMENT VIDE : une colonne OPTIONAL présente dans certains RG,
/// toute-NULL dans d'autres. StrEq sur une valeur présente ne doit sauter AUCUN RG la contenant.
#[test]
#[cfg(feature = "cold_tier")]
fn audit_over_prune_partial_null_column() {
    let root = tmp_root("audit_null");
    let p = root.join("day.parquet");
    // host : RG0 tout-NULL ; RG1 {hA,hB,hC} ; RG2 tout-NULL. ts monotone.
    let mk = |ts: i64, host: Option<&str>| ColdRow {
        row: EventRow {
            ts,
            severity: 1,
            source: "s".to_string(),
            category: "c".to_string(),
            message: "m".to_string(),
            host: host.map(|h| h.to_string()),
            src_ip: None,
            dst_ip: None,
            url: None,
            dedup: None,
            fields: None,
            engagement_id: String::new(),
            origin: String::new(),
            env_id: Some("prod".to_string()),
        },
        xff: None,
    };
    let rows = vec![
        mk(0, None), mk(1, None), mk(2, None),           // RG0 all-NULL
        mk(3, Some("hA")), mk(4, Some("hB")), mk(5, Some("hC")), // RG1
        mk(6, None), mk(7, None), mk(8, None),           // RG2 all-NULL
    ];
    t_write_rg(&p, &rows, 3).unwrap();
    let reader = open_cold_reader(&p, &tpass()).unwrap();
    assert_eq!(reader.metadata().num_row_groups(), 3);
    let deny: std::collections::HashSet<String> = std::collections::HashSet::new();
    let oracle = build_oracle(&rows, &deny);
    for v in ["hA", "hB", "hC"] {
        let pred = Pred::StrEq { col: "host", val: v.into() };
        let mut a = RgPruneStats::default();
        let mut b = RgPruneStats::default();
        let c_on = vec_count_ex(&reader, &pred, &deny, true, &mut a).unwrap();
        let c_off = vec_count_ex(&reader, &pred, &deny, false, &mut b).unwrap();
        assert_eq!(c_off, 1, "sanity host={v} présent");
        assert_eq!(c_on, c_off, "SUR-ÉLAGAGE null-partiel: host={v} prune on({c_on})!=off({c_off})");
        assert_eq!(c_on, oracle_count(&oracle, &format!("WHERE host='{v}'")), "parité oracle host={v}");
    }
    // Une valeur ABSENTE présente NULLE PART -> 0, cohérent on==off (pas d'obligation de skip).
    let pred = Pred::StrEq { col: "host", val: "hZ".into() };
    let mut a = RgPruneStats::default();
    let mut b = RgPruneStats::default();
    assert_eq!(
        vec_count_ex(&reader, &pred, &deny, true, &mut a).unwrap(),
        vec_count_ex(&reader, &pred, &deny, false, &mut b).unwrap(),
        "host=hZ absent : on==off"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// #18 P4a — HARNAIS DE PARITÉ DU PLANNER / ROUTEUR. Prouve l'INVARIANT `résultat_routé == résultat_actuel`
// (oracle = `cold_union_query`, hydrate-SQLite) pour un large jeu de requêtes, + la DÉCISION DE ROUTE
// (vectorisé vs fallback) via le compteur exposé et le Some/None per-call de `cold_vectorized_try`.
//
// SÉRIALISATION DES COMPTEURS : le compteur de route est un état GLOBAL du process. Sous `--test-threads=2`,
// plusieurs tests p4a le toucheraient concurremment. Chaque test p4a prend donc `p4a_lock()` pour la durée
// de ses appels `cold_vectorized_try` -> les batteries ne s'entrelacent jamais -> le census (reset+assert
// exact) est DÉTERMINISTE quel que soit le nombre de threads.
// ====================================================================================================

/// Verrou de sérialisation des tests p4a (voir en-tête). Tolère l'empoisonnement (un panic sous garde ne doit
/// pas geler les autres tests p4a).
fn p4a_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

/// VERROU PARTAGÉ des tests qui LISENT/BASCULENT `PLUME_COLD_READ_PARALLELISM` (env GLOBAL) : sérialise les tests
/// P6 (dont les assertions DÉPENDENT du degré : jauge de concurrence, bench) avec les tests P2b qui basculent le
/// MÊME knob -> pas de course d'env sous `--test-threads`. Les tests P6 le prennent EN PLUS de `p4a_lock` (ordre
/// fixe p4a_lock -> par_env_lock, aucun cycle : P2b ne prend QUE ce verrou).
fn par_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

/// Ligne de fixture P4a — dims VARIÉES (source/severity/host/src_ip) + `url` SANS espace (regex/glob testables
/// sur un seul token). `message` reste le défaut de `rich_row`.
fn p4a_row(base: i64, i: i64) -> ColdRow {
    let mut r = rich_row(base + i, i);
    // Distribution SKEWED des sources -> counts DISTINCTS (web>api>db) : le top-N `head N` est alors NON
    // ambigu (pas d'égalité de count -> même choix des N premiers que l'oracle, tie-break inutile).
    r.row.source = ["web", "web", "web", "api", "api", "db"][(i % 6) as usize].to_string();
    r.row.severity = i % 4;
    r.row.host = Some(format!("h{}", i % 5));
    r.row.src_ip = Some(if i % 2 == 0 { "10.0.0.1" } else { "10.0.0.2" }.to_string());
    let code = if i % 3 == 0 { 500 } else { 200 };
    r.row.url = Some(format!("/path/{code}"));
    r
}

struct P4aFix {
    /// La fixture POSSÈDE sa racine temporaire — champ `TmpPossede`, pas `PathBuf`.
    /// Le correctif que suggère `rustc` sur l'erreur E0308 (`root: root.to_path_buf()`)
    /// serait FAUX : il laisse tomber le garde à la fin du constructeur, donc le
    /// répertoire est effacé pendant que le test s'en sert encore. Le type porte
    /// l'invariant : la racine vit exactement aussi longtemps que la fixture.
    /// `Deref`/`AsRef<Path>` rendent l'usage identique à celui d'un `PathBuf`.
    root: crate::tmp_possede::TmpPossede,
    db: Arc<Mutex<Connection>>,
    dbp: String,
    conf: HashMap<String, String>,
    b: i64,
    from: i64,
    to: i64,
}

/// Construit une fixture pur-froid : `n` lignes variées dans un jour froid (M-10), agées en Parquet ; renvoie
/// la fenêtre `[from, to]` ENTIÈREMENT sous la frontière `b` (pur-froid).
fn p4a_fixture(tag: &str, n: i64) -> P4aFix {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..n {
        insert_event(&db, &p4a_row(base, i));
    }
    insert_recent_tail_holder(&db); // tail hot -> la garde H1 laisse ager le jour froid
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid purgé du hot");
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + n - 1;
    assert!(to < b, "fenêtre pur-froid (to={to} < b={b})");
    P4aFix { root, db, dbp, conf, b, from, to }
}

impl Drop for P4aFix {
    fn drop(&mut self) {
        let _ = &self.db; // garde la connexion vivante jusqu'au drop
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// ORACLE = chemin de production ACTUEL : compile le GXQL (masques vides) puis exécute via `cold_union_query`
/// (hydrate-SQLite hot∪cold). C'est la RÉFÉRENCE de l'invariant.
fn p4a_oracle(f: &P4aFix, soql: &str, to: i64) -> Value {
    let sql = compile_ev(soql, f.from, to, FieldMaskSet::new());
    let (v, _t, _m) = union_query_oracle(&f.dbp, &f.conf, None, f.from, to, f.b, &sql, None, 60_000, None, &[]).unwrap();
    v
}

/// PLANNER = décision + exécution vectorisée. `Some(v)` = routé vectorisé ; `None` = fallback. Sans élagage
/// dimensionnel (`&[]`) -> parité de forme/route inchangée (l'élagage seal P3.5 a ses tests dédiés `p4a_prune_*`).
fn p4a_plan(f: &P4aFix, soql: &str, to: i64) -> Option<Value> {
    cold_vectorized_try(&f.dbp, &f.conf, None, f.from, to, f.b, soql, true, 60_000, &[]).unwrap()
}

/// Lignes NORMALISÉES (triées) d'un résultat — l'ordre des lignes d'un agrégat/`GROUP BY` SQL n'est PAS défini ;
/// l'invariant porte sur les DONNÉES (multiset), comme les tests P3 existants (`count_by_source` trie).
fn p4a_norm(v: &Value) -> Vec<String> {
    let empty: Vec<Value> = Vec::new();
    let mut rows: Vec<String> = v["rows"].as_array().unwrap_or(&empty).iter().map(|r| r.to_string()).collect();
    rows.sort();
    rows
}

/// PARITÉ : colonnes IDENTIQUES (ordre inclus) + lignes normalisées IDENTIQUES.
fn p4a_assert_parity(oracle: &Value, plan: &Value, label: &str) {
    assert_eq!(oracle["columns"], plan["columns"], "{label}: colonnes divergent\n oracle={}\n plan={}", oracle["columns"], plan["columns"]);
    assert_eq!(
        p4a_norm(oracle),
        p4a_norm(plan),
        "{label}: lignes divergent\n oracle={oracle}\n plan={plan}"
    );
}

// GATE 0 : son contrat a CHANGÉ (défaut ARMÉ) et son test vit désormais avec l'invariant de correction
// qu'il sert — `gate0_vectorized_router_is_armed_by_default_and_opt_out_still_works`, en fin de fichier.
// L'ancien test asseyait le défaut DORMANT, qui s'est révélé être la cause mesurée du ×203 : le conserver
// aurait été conserver la preuve que le défaut est voulu.

/// SHAPES pur-froid VECTORISABLES : chacune DOIT router vectorisé (Some) ET == oracle. Couvre count, count
/// WHERE (int/streq/!=/3VL), group mono/multi/int-dim, regex, glob-LIKE (+ NOT LIKE), top-N (desc/asc), et la
/// matérialisation projetée (+head).
#[test]
fn p4a_parity_aggregates_route_vectorized() {
    let _lk = p4a_lock();
    let f = p4a_fixture("p4a-agg", 60);
    let cases: &[&str] = &[
        "search | stats count",
        "search severity>=2 | stats count",
        "search severity=3 | stats count",
        "search severity!=0 | stats count",
        "search source=web | stats count",
        "search source!=web | stats count",       // NOT streq (3-valué)
        "search source=w* | stats count",         // glob LIKE
        "search source!=w* | stats count",        // NOT LIKE (3-valué)
        "search url=~/path/500 | stats count",    // regex
        "search url=~^/path/500$ | stats count",  // regex ancré
        "search src_ip=~^10\\.0\\.0\\.2$ | stats count",
        "search | stats count by source",
        "search | stats count by severity",       // dim INT -> valeur entière
        "search | stats count by source,severity",// multi-dim
        "search source=web | stats count by host",// filtre + group
        "search | stats count by source | sort -count | head 2", // top-N desc
        "search | stats count by source | sort count",           // top-N asc (sans head)
        "search | stats count by host | sort -count",            // top-N desc sans head
        "search source=web | table source,severity",             // matérialisation projetée
        "search severity>=1 | table source,severity,url | head 5",// matérialisation + head (ordre canonique)
    ];
    for soql in cases {
        let plan = p4a_plan(&f, soql, f.to);
        assert!(plan.is_some(), "DOIT router vectorisé : {soql}");
        let oracle = p4a_oracle(&f, soql, f.to);
        p4a_assert_parity(&oracle, plan.as_ref().unwrap(), soql);
    }
}

/// SHAPES qui DOIVENT tomber en FALLBACK (None) : forme/prédicat non couverts. On PROUVE le fallback (None),
/// pas juste la parité (le fallback est trivialement == oracle puisque c'est le MÊME chemin).
#[test]
fn p4a_fallback_shapes_route_fallback() {
    let _lk = p4a_lock();
    let f = p4a_fixture("p4a-fb", 40);
    let cases: &[&str] = &[
        "search | stats dc(host)",                 // agrégat != count
        "search | stats avg(severity)",            // agrégat != count
        "search | timechart count",                // stage non supporté
        "search | stats count | where count>1",    // stage en trop
        "search | eval x=1 | stats count",         // eval
        "search | stats count by fields.user",     // dim JSON (non-physique)
        "search foo=bar | stats count",            // champ non-physique
        "search boom | stats count",               // terme libre (message LIKE)
        "search source in (web,api) | stats count",// in(...)
        "search host>h2 | stats count",            // comparaison string >/< (affinité)
        "search",                                  // search NU (projection implicite)
        "search | table *",                        // passe-plat
        "search | table source | head 3",          // head SANS sort n'est PAS le souci ici -> table+head OK...
    ];
    // NB : la DERNIÈRE ("table source | head 3") est en réalité VECTORISABLE (matérialisation + head) -> on la
    // retire de l'attendu fallback et on la vérifie routée+parité, pour éviter un faux négatif.
    let (fallbacks, vectorizable) = cases.split_at(cases.len() - 1);
    for soql in fallbacks {
        assert!(p4a_plan(&f, soql, f.to).is_none(), "DOIT fallback (None) : {soql}");
    }
    for soql in vectorizable {
        let plan = p4a_plan(&f, soql, f.to);
        assert!(plan.is_some(), "DOIT router : {soql}");
        p4a_assert_parity(&p4a_oracle(&f, soql, f.to), plan.as_ref().unwrap(), soql);
    }
}

/// BORDS DE FENÊTRE + CENSUS DU COMPTEUR DE ROUTE (déterministe sous le verrou p4a). Prouve : (a) fenêtre
/// ENTIÈREMENT froide -> routé vectorisé ; (b) borne haute == frontière `b` -> fallback (ne pas rater le hot) ;
/// (c) borne haute DANS le hot -> fallback ; (d) borne haute non bornée (to=0) -> fallback. Puis reset+census
/// exact des compteurs (vectorized vs fallback).
#[test]
fn p4a_window_edges_and_route_counter_census() {
    let _lk = p4a_lock();
    let f = p4a_fixture("p4a-edge", 30);
    // (a) pur-froid -> Some ; (b) to==b -> None ; (c) to dans le hot -> None ; (d) to=0 (non borné) -> None.
    route_counters_reset();
    assert!(p4a_plan(&f, "search | stats count", f.to).is_some(), "entièrement froide -> vectorisé");
    assert!(p4a_plan(&f, "search | stats count", f.b).is_none(), "borne haute == frontière -> fallback (hot possible)");
    assert!(p4a_plan(&f, "search | stats count", f.b + 10_000).is_none(), "borne haute dans le hot -> fallback");
    assert!(p4a_plan(&f, "search | stats count", 0).is_none(), "borne haute non bornée -> fallback");
    let (vec_n, fb_n) = route_counters();
    assert_eq!((vec_n, fb_n), (1, 3), "census exact : 1 vectorisé, 3 fallback (compteur exposé)");

    // Parité au bord froid maximal : to = b-1 (encore pur-froid) doit router et == oracle.
    route_counters_reset();
    let to_edge = f.b - 1;
    let plan = p4a_plan(&f, "search | stats count by source", to_edge);
    assert!(plan.is_some(), "to=b-1 encore pur-froid -> vectorisé");
    p4a_assert_parity(&p4a_oracle(&f, "search | stats count by source", to_edge), plan.as_ref().unwrap(), "bord froid b-1");
    assert_eq!(route_counters(), (1, 0), "census : 1 vectorisé, 0 fallback");
}

/// MASQUAGE #45 — DEUX volets :
///  (A) ROUTEUR : en production, un masque/deny actif rend `effective_masks` NON VIDE -> gate #3 -> le routeur
///      DOIT FALLBACK. C'est la POSTURE CORRECTE : le chemin oracle applique HASH/MASK DANS le SQL compilé + un
///      AUTHORIZER qui DÉNIE la lecture d'une colonne déniée (une projection de colonne déniée sur la vue
///      d'union ÉCHOUE côté oracle) — le moteur vectorisé ne reproduit PAS ces sémantiques en P4a. Fallback ->
///      l'oracle sert EXACTEMENT comme aujourd'hui (invariant préservé). On prouve None pour toutes les surfaces.
///  (B) KERNEL `denied()` (défense en profondeur, réutilisé en P4b) : sur un fichier froid RÉEL, la colonne
///      déniée est NULLifiée en projection — EXACTEMENT la règle de `union_proj`. Prouvé par appel DIRECT au
///      kernel (découplé de l'authorizer, qui est le chemin oracle).
#[test]
fn p4a_masking_router_falls_back_and_kernel_denies() {
    let _lk = p4a_lock();
    let f = p4a_fixture("p4a-mask", 30);

    // (A) ROUTEUR : masques actifs (masks_empty=false) -> FALLBACK (None) sur toutes les surfaces.
    for soql in [
        "search | stats count",
        "search | stats count by src_ip",
        "search | table source,src_ip",
        "search src_ip=10.0.0.1 | stats count",
    ] {
        let r = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, /*masks_empty=*/ false, 60_000, &[]).unwrap();
        assert!(r.is_none(), "masques actifs -> fallback (None) : {soql}");
    }

    // (B) KERNEL denied() : projection d'une colonne déniée -> NULL sur toutes les lignes ; sans deny -> présente.
    let pass = cold_aead_passphrase(&f.conf, &f.dbp).expect("passphrase cold");
    let cold_dir = cold_root(&f.conf, &f.dbp);
    let path = file_path(&cold_dir, "prod", M - 10, 0);
    let reader = open_cold_reader(&path, &pass).expect("reader cold");
    let mut deny = std::collections::HashSet::new();
    deny.insert("src_ip".to_string());
    let (rows_denied, _t) = vec_materialize(&reader, &Pred::True, &["source", "src_ip"], 1000, &deny).unwrap();
    assert!(!rows_denied.is_empty(), "des lignes froides existent");
    assert!(
        rows_denied.iter().all(|r| matches!(r[1], rusqlite::types::Value::Null)),
        "src_ip DÉNIÉ -> NULL partout (kernel #45, parité union_proj)"
    );
    let (rows_clear, _t2) = vec_materialize(&reader, &Pred::True, &["source", "src_ip"], 1000, &std::collections::HashSet::new()).unwrap();
    assert!(
        rows_clear.iter().any(|r| !matches!(r[1], rusqlite::types::Value::Null)),
        "sans deny : src_ip PRÉSENT (le NULL vient bien du masquage)"
    );
}

/// GATE 5 — SA PORTÉE A CHANGÉ, ET C'EST LA CORRECTION.
///
/// Avant : au-delà de `cold_hydrate_row_cap` (5 000), le routeur retombait sur l'oracle POUR TOUTE FORME,
/// « pour préserver le comportement actuel ». Or le comportement actuel, au-delà du cap, c'est un agrégat
/// calculé sur 5 000 lignes hydratées — 289 au lieu de 58 747 sur le banc. Préserver ça n'était pas une
/// vertu de parité, c'était la propagation d'un nombre faux.
///
/// Maintenant :
///   • AGRÉGAT au-delà du cap  -> ROUTÉ, et EXACT (les kernels balaient tout le froid).
///   • MATÉRIALISATION au-delà -> FALLBACK inchangé (les deux chemins rendent un préfixe de lignes VRAIES,
///                                simplement pas le même : aucun n'est faux, la gate reste iso-oracle).
///   • Sous le cap             -> routé + parité avec l'oracle, comme avant (l'oracle y est exact).
#[test]
fn p4a_truncation_over_cap_routes_aggregates_exactly_and_still_falls_back_for_rows() {
    let _lk = p4a_lock();
    // Cap PAR DÉFAUT (PLUME_QUERY_MAX=5000) — on NE touche PAS l'env (process-global : casserait les tests
    // concurrents). On écrit 5001 lignes (comme p3_truncated_surfaced) pour dépasser le cap réel.
    let f = p4a_fixture("p4a-trunc", 5001);
    // AGRÉGAT : routé, et la valeur est LA VRAIE (5001), pas l'échantillon (5000).
    let plan = p4a_plan(&f, "search | stats count", f.to).expect("> cap : l'agrégat est ROUTÉ (exact), plus renvoyé à l'échantillon");
    assert_eq!(plan["rows"][0][0].as_i64().unwrap(), 5001, "count EXACT sur toute la fenêtre froide");
    // ... et l'oracle, lui, se trompe : c'est la MESURE du défaut, faite ici plutôt que sur un banc.
    let oracle_cnt = p4a_oracle(&f, "search | stats count", f.to)["rows"][0][0].as_i64().unwrap();
    assert_eq!(oracle_cnt, 5000, "l'ancien chemin agrège sur l'ÉCHANTILLON hydraté (plafond 5000) — c'est le défaut");
    assert!(oracle_cnt < 5001, "le chemin d'union SOUS-COMPTE : c'est pour ça qu'il ne peut plus servir d'oracle d'agrégat");
    // MATÉRIALISATION au-delà du cap : fallback conservé (iso-oracle ; aucun des deux n'est faux).
    assert!(
        p4a_plan(&f, "search | table source,severity", f.to).is_none(),
        "> cap + matérialisation -> fallback (préfixe de l'oracle préservé)"
    );
    // Sous le cap : routé + parité avec l'oracle (qui y est exact).
    let to_small = f.from + 50; // ~51 lignes <= 5000
    let plan = p4a_plan(&f, "search | stats count", to_small);
    assert!(plan.is_some(), "<= cap -> vectorisé");
    assert_eq!(plan.as_ref().unwrap()["rows"][0][0].as_i64().unwrap(), 51, "51 lignes dans [from, from+50]");
    p4a_assert_parity(&p4a_oracle(&f, "search | stats count", to_small), plan.as_ref().unwrap(), "sous le cap");
}

/// BENCH (exécuté hors `--skip bench`) — group-by multi-dim + regex : ROUTEUR vectorisé vs chemin ACTUEL
/// (`cold_union_query`), MÊME requête pur-froid, gain end-to-end mesuré. Vérifie AUSSI la parité (résultat
/// identique). N < cap pour que le routeur s'arme.
#[test]
fn p4a_bench_group_and_regex_vectorized_vs_current() {
    let _lk = p4a_lock();
    let n = 4000i64; // < cap 5000 -> routé
    let f = p4a_fixture("p4a-bench", n);
    let iters = 5;

    let bench = |soql: &str| -> (f64, f64) {
        // Chemin ACTUEL (oracle).
        let sql = compile_ev(soql, f.from, f.to, FieldMaskSet::new());
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            let _ = union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &sql, None, 60_000, None, &[]).unwrap();
        }
        let cur_ms = t0.elapsed().as_secs_f64() * 1000.0 / iters as f64;
        // ROUTEUR vectorisé.
        let t1 = std::time::Instant::now();
        for _ in 0..iters {
            assert!(cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &[]).unwrap().is_some());
        }
        let vec_ms = t1.elapsed().as_secs_f64() * 1000.0 / iters as f64;
        // Parité (une fois).
        let o = union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &sql, None, 60_000, None, &[]).unwrap().0;
        let p = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &[]).unwrap().unwrap();
        p4a_assert_parity(&o, &p, soql);
        (cur_ms, vec_ms)
    };

    let (g_cur, g_vec) = bench("search | stats count by source,severity");
    let (r_cur, r_vec) = bench("search url=~/path/500 | stats count");
    println!(
        "P4a BENCH (n={n}, {iters} iters):\n  group-by src,sev : actuel {g_cur:.2}ms  vectorisé {g_vec:.2}ms  x{:.2}\n  regex count      : actuel {r_cur:.2}ms  vectorisé {r_vec:.2}ms  x{:.2}",
        g_cur / g_vec.max(1e-6),
        r_cur / r_vec.max(1e-6)
    );
}

// ====================================================================================================
// #28 P3.5 — ÉLAGAGE SEAL DU CHEMIN VECTORISÉ. Un fichier dont le seal (min/max + bloom, lisibles SANS
// déchiffrer) PROUVE 0 match est SAUTÉ sans le déchiffrer -> c'est LE levier des requêtes sélectives
// longue-portée (`source=rare` sur N fichiers -> 1 seul déchiffré). ORACLE = `cold_union_query`, qui reçoit
// les MÊMES `dim_preds` -> il élague les MÊMES fichiers (cohérence du gate cap ; résultat IDENTIQUE).
// Serialisé par `p4a_lock` (les compteurs prune/decrypt sont globaux, comme les compteurs de route).
// ====================================================================================================

/// Fixture pur-froid MULTI-FICHIERS (cap=1 -> 1 ligne == 1 fichier -> élagage par-fichier OBSERVABLE). `rows` =
/// (source, host, src_ip, severity), ts = base+idx. Renvoie la P4aFix + le nombre de fichiers scellés.
fn prune_fixture(tag: &str, rows: &[(&str, &str, &str, i64)]) -> (P4aFix, usize) {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = pb_conf(Some(1)); // 1 ligne/fichier -> N fichiers -> files_pruned observable par-fichier
    let day = M - 20;
    let base = day * SECS_PER_DAY;
    for (i, (src, host, ip, sev)) in rows.iter().enumerate() {
        insert_event(&db, &ev_full(base + i as i64, src, "web", Some(host), Some(ip), *sev));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid purgé");
    let nfiles = file_seal_rows(&db, "prod", day).len();
    assert_eq!(nfiles, rows.len(), "1 fichier par ligne (cap=1)");
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + rows.len() as i64 - 1;
    assert!(to < b, "pur-froid");
    (P4aFix { root, db, dbp, conf, b, from, to }, nfiles)
}

/// Preds d'élagage = ceux du SQL COMPILÉ (BYTE-IDENTIQUES à ceux que l'oracle reçoit dans le handler).
fn prune_preds(f: &P4aFix, soql: &str, to: i64) -> Vec<DimEq> {
    extract_cold_dim_preds(&compile_ev(soql, f.from, to, FieldMaskSet::new()))
}

/// Oracle AVEC preds (le handler passe les MÊMES preds au chemin vectorisé ET à `cold_union_query`).
fn prune_oracle(f: &P4aFix, soql: &str, preds: &[DimEq]) -> Value {
    let sql = compile_ev(soql, f.from, f.to, FieldMaskSet::new());
    union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &sql, None, 60_000, None, preds).unwrap().0
}

/// (1) PARITÉ prune-ON / prune-OFF / ORACLE sur count / group-by / matérialisation multi-fichiers, + PREUVE
/// d'élagage (files_pruned). L'élagage ne change JAMAIS le résultat, seulement le nombre de fichiers déchiffrés.
#[test]
fn p4a_prune_parity_on_off_oracle() {
    let _lk = p4a_lock();
    // 6 fichiers : 5 "common", 1 "rare" (idx 3), host/ip localisés au fichier rare.
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("common", "h1", "10.0.0.2", 2),
        ("common", "h2", "10.0.0.1", 1),
        ("rare", "h9", "10.9.9.9", 3),
        ("common", "h2", "10.0.0.2", 2),
        ("common", "h1", "10.0.0.1", 1),
    ];
    let (f, n) = prune_fixture("p4a-prune-eq", &rows);

    // Cas SÉLECTIFS (1 fichier sur N matche). source/host portent min/max -> élagage DÉTERMINISTE (pas de FP
    // bloom possible) ; src_ip est bloom-seul -> élagage quasi-certain (FP ≈ 2e-8) mais on n'assert que >= 1.
    for soql in [
        "search source=rare | stats count",
        "search source=rare | stats count by host",
        "search source=rare | table source,host,severity",
        "search host=h9 | stats count",
        "search src_ip=10.9.9.9 | stats count",
    ] {
        let preds = prune_preds(&f, soql, f.to);
        assert!(!preds.is_empty(), "prédicat d'élagage extrait du SQL compilé : {soql}");
        let oracle = prune_oracle(&f, soql, &preds);
        // PRUNE ON.
        route_counters_reset();
        let on = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
        assert!(on.is_some(), "routé vectorisé : {soql}");
        let (pruned, scanned) = prune_counters();
        assert!(pruned >= 1, "{soql}: au moins 1 fichier élagué (files_pruned={pruned})");
        assert_eq!(pruned + scanned, n as u64, "{soql}: élagués + scannés == N fichiers");
        // PRUNE OFF (mêmes lignes rendues, mais AUCUN élagage -> tous scannés).
        route_counters_reset();
        let off = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &[]).unwrap();
        assert!(off.is_some(), "routé (prune off) : {soql}");
        assert_eq!(prune_counters(), (0, n as u64), "{soql}: prune OFF -> 0 élagué, N scannés");
        // PARITÉ TRIPLE : on == off == oracle.
        p4a_assert_parity(&oracle, on.as_ref().unwrap(), &format!("{soql} [prune-on == oracle]"));
        p4a_assert_parity(&oracle, off.as_ref().unwrap(), &format!("{soql} [prune-off == oracle]"));
    }

    // PREUVE FORTE (chemin min/max déterministe) : `source=rare` -> EXACTEMENT N-1 élagués, 1 scanné.
    route_counters_reset();
    let soql = "search source=rare | stats count";
    let preds = prune_preds(&f, soql, f.to);
    let _ = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
    assert_eq!(prune_counters(), ((n - 1) as u64, 1), "source=rare -> N-1 élagués, 1 scanné (élagage déterministe min/max)");
}

/// (2) PREUVE DE NON-DÉCHIFFREMENT : les fichiers non-matchants sont CORROMPUS -> s'ils étaient déchiffrés,
/// l'AEAD/parquet échouerait (Err). L'élagage les saute -> la requête RÉUSSIT, et le COMPTEUR de déchiffrements
/// ne compte QUE le fichier scanné. CONTRÔLE : sans élagage (`&[]`), les mêmes fichiers corrompus -> Err.
#[test]
fn p4a_prune_avoids_decryption_of_pruned_files() {
    let _lk = p4a_lock();
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("common", "h1", "10.0.0.2", 2),
        ("rare", "h9", "10.9.9.9", 3), // fichier idx 2 = le SEUL à devoir être déchiffré
        ("common", "h2", "10.0.0.2", 2),
        ("common", "h1", "10.0.0.1", 1),
    ];
    let (f, n) = prune_fixture("p4a-prune-nodecrypt", &rows);
    let cold = cold_root(&f.conf, &f.dbp);
    for seq in 0..n as i64 {
        if seq != 2 {
            pb_corrupt(&file_path(&cold, "prod", M - 20, seq));
        }
    }
    let soql = "search source=rare | stats count";
    let preds = prune_preds(&f, soql, f.to);
    cold_decrypt_count_reset();
    let on = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds)
        .expect("élagage -> fichiers corrompus JAMAIS ouverts -> pas d'Err");
    assert!(on.is_some(), "routé");
    assert_eq!(on.as_ref().unwrap()["rows"][0][0].as_i64().unwrap(), 1, "1 ligne rare comptée");
    // Le SEUL fichier scanné passe par open_verified (verify + open_cold_reader = 2 déchiffrements bornés) ; les
    // 4 corrompus = 0. Le compteur PROUVE que l'élagage a évité N-1 déchiffrements (le gain enterprise).
    let d = cold_decrypt_count();
    assert!(d >= 1 && d <= 2, "seul le fichier scanné déchiffré (compteur={d}, jamais les {} corrompus)", n - 1);
    // CONTRÔLE : sans élagage, les fichiers corrompus SONT ouverts -> Err fail-closed (prouve que c'est bien
    // l'élagage — pas un autre effet — qui évite le déchiffrement).
    let off = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &[]);
    assert!(off.is_err(), "sans élagage : fichiers corrompus ouverts -> Err (fail-closed), got {off:?}");
}

/// (3) COLONNE DÉNIÉE #45 — GARDE : un deny-set injecté sur `source` -> l'élagage NE s'appuie JAMAIS sur son
/// seal (défense-en-profondeur) -> 0 fichier élagué même avec un pred `source=rare`. (En prod une dim déniée ne
/// peut PAS apparaître dans un pred — rejet compilation #45 ; ici on injecte le deny pour exercer le garde.)
#[test]
fn p4a_prune_denied_column_never_prunes() {
    let _lk = p4a_lock();
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("rare", "h9", "10.9.9.9", 3),
        ("common", "h2", "10.0.0.2", 2),
    ];
    let (f, _n) = prune_fixture("p4a-prune-deny", &rows);
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("source".to_string());
        w.insert(f.dbp.clone(), s);
    }
    // Pred DIRECT sur la dim déniée (le garde doit le retirer avant l'élagage).
    let preds = vec![DimEq { dim: ColdDim::Source, value: "rare".into() }];
    route_counters_reset();
    let r = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search source=rare | stats count", true, 60_000, &preds).unwrap();
    assert!(r.is_some(), "routé");
    assert_eq!(prune_counters().0, 0, "colonne DÉNIÉE -> AUCUN élagage seal (garde #45)");
    crate::field_deny_cols_cell().write().remove(&f.dbp); // hygiène
}

/// (4) ANTI-SUR-ÉLAGAGE : regex/LIKE (aucune égalité extraite) et valeur PRÉSENTE partout (bloom la retient
/// dans TOUS les fichiers) -> AUCUN fichier élagué (tous scannés), résultat == oracle.
#[test]
fn p4a_prune_no_overprune_regex_and_present_value() {
    let _lk = p4a_lock();
    let rows = [
        ("web", "h1", "10.0.0.1", 1),
        ("web", "h1", "10.0.0.2", 2),
        ("web", "h2", "10.0.0.1", 3),
    ];
    let (f, n) = prune_fixture("p4a-prune-noover", &rows);
    // regex / glob-LIKE : extract_cold_dim_preds n'émet RIEN d'élaguable -> 0 pred -> 0 élagage, N scannés.
    for soql in ["search source=~^web$ | stats count", "search source=w* | stats count"] {
        let preds = prune_preds(&f, soql, f.to);
        assert!(preds.is_empty(), "regex/LIKE -> aucun pred d'élagage : {soql}");
        route_counters_reset();
        let r = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
        assert!(r.is_some(), "routé : {soql}");
        assert_eq!(prune_counters(), (0, n as u64), "{soql}: 0 élagué, N scannés");
        p4a_assert_parity(&prune_oracle(&f, soql, &preds), r.as_ref().unwrap(), soql);
    }
    // VALEUR PRÉSENTE partout : `source=web` est dans les 3 blooms + dans [min,max] -> aucun fichier élagué.
    let soql = "search source=web | stats count";
    let preds = prune_preds(&f, soql, f.to);
    assert!(!preds.is_empty());
    route_counters_reset();
    let r = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
    assert!(r.is_some());
    assert_eq!(prune_counters(), (0, n as u64), "source=web présent partout -> 0 élagué, N scannés");
    p4a_assert_parity(&prune_oracle(&f, soql, &preds), r.as_ref().unwrap(), soql);
}

// ====================================================================================================
// ADVERSARIAL P4a — HOSTILE PARITY PROBES (tests seuls ; NE MODIFIE PAS LE PROD).
// Cible : TIE-BREAK top-N (le fixture p4a_row a des counts DISTINCTS -> ne l'exerce JAMAIS) + drapeau
// `truncated` de la matérialisation `head`. L'oracle = `cold_union_query` (chemin actuel), comme p4a_*.
// ====================================================================================================

/// Fixture pur-froid à lignes ARBITRAIRES (ts = base+idx, in-window). Renvoie la fenêtre [from,to] pur-froid.
fn hostile_fixture(tag: &str, rows: &[(i64 /*severity*/, &str /*source*/)]) -> P4aFix {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for (i, (sev, src)) in rows.iter().enumerate() {
        let mut r = rich_row(base + i as i64, i as i64);
        r.row.severity = *sev;
        r.row.source = (*src).to_string();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid purgé");
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + rows.len() as i64 - 1;
    assert!(to < b, "pur-froid");
    P4aFix { root, db, dbp, conf, b, from, to }
}

/// H1 — INT-DIM TIE-BREAK LEXICOGRAPHIQUE : `stats count by severity | sort -count | head N`. Le kernel
/// stocke la clé severity comme `to_string()` et tie-break `key ASC` = comparaison STRING ("10" < "2").
/// L'oracle groupe sur la colonne ENTIÈRE et `ORDER BY count DESC` a un ordre intra-égalité INDÉFINI. Un `head`
/// qui coupe une égalité de count fait diverger le SET.
/// FIX A : le routeur DÉTECTE le tie au bord du head-cut (count[N-1]==count[N]) et FALLBACK (None) -> l'oracle
/// sert (invariant préservé). On PROUVE donc le fallback (None), plus une divergence de SET.
#[test]
fn hostile_int_dim_tiebreak_head_cut() {
    let _lk = p4a_lock();
    // severity 2 ×5, severity 10 ×5 (ÉGALITÉ au sommet), severity 1 ×3 (plus bas). head 1 coupe l'égalité.
    let mut rows: Vec<(i64, &str)> = Vec::new();
    for _ in 0..5 { rows.push((2, "s")); }
    for _ in 0..5 { rows.push((10, "s")); }
    for _ in 0..3 { rows.push((1, "s")); }
    let f = hostile_fixture("hostile-int-tie", &rows);
    let soql = "search | stats count by severity | sort -count | head 1";
    // Tie de count (sev 2 et 10 à 5 chacun) STRADDLE le `head 1` -> FALLBACK.
    assert!(p4a_plan(&f, soql, f.to).is_none(), "FIX A : tie au bord du head-cut -> fallback (None) : {soql}");
}

/// H1b — ÉGALITÉ à 3 voies (sev 2/3/10 à 5 chacun), `head 2` coupe l'égalité (2 des 3). FIX A : tie au bord ->
/// FALLBACK (None). (Anciennement le kernel servait le mauvais SET via tie-break lexicographique "10"<"2"<"3".)
#[test]
fn hostile_int_dim_tiebreak_head_cut_top2() {
    let _lk = p4a_lock();
    let mut rows: Vec<(i64, &str)> = Vec::new();
    for _ in 0..5 { rows.push((2, "s")); }
    for _ in 0..5 { rows.push((3, "s")); }
    for _ in 0..5 { rows.push((10, "s")); }
    let f = hostile_fixture("hostile-int-tie3", &rows);
    let soql = "search | stats count by severity | sort -count | head 2";
    assert!(p4a_plan(&f, soql, f.to).is_none(), "FIX A : tie à 3 voies au bord du head-cut -> fallback (None) : {soql}");
}

/// H2 — STRING-DIM 3-WAY TIE, head 2 : counts égaux sur source a/b/c. L'ordre intra-égalité de l'oracle est
/// tout aussi INDÉFINI pour les strings (le byte-order du kernel ≈ la collation BINARY par COÏNCIDENCE de plan,
/// PAS une garantie). FIX A applique la MÊME règle robuste : tie au bord du head-cut -> FALLBACK (None). Ce test
/// (contrôle) RESTE VERT sous le nouveau contrat de route (fallback), au lieu de dépendre d'un ordre fragile.
#[test]
fn hostile_str_dim_tiebreak_head_cut() {
    let _lk = p4a_lock();
    let mut rows: Vec<(i64, &str)> = Vec::new();
    for _ in 0..4 { rows.push((0, "aaa")); }
    for _ in 0..4 { rows.push((0, "bbb")); }
    for _ in 0..4 { rows.push((0, "ccc")); }
    let f = hostile_fixture("hostile-str-tie", &rows);
    let soql = "search | stats count by source | sort -count | head 2";
    assert!(p4a_plan(&f, soql, f.to).is_none(), "FIX A : tie de count au bord du head-cut -> fallback (None) : {soql}");
}

/// H3 — `table ... | head 0` : drapeau `truncated`. Kernel Materialize (cap=0) pose truncated=true ; l'oracle
/// (`LIMIT 0`) rend 0 ligne SANS troncature. Résultat "vide" identique mais métadonnée divergente.
#[test]
fn hostile_table_head_zero_truncated_flag() {
    let _lk = p4a_lock();
    let rows: Vec<(i64, &str)> = (0..10).map(|i| (i % 3, "s")).collect();
    let f = hostile_fixture("hostile-head0", &rows);
    let soql = "search | table source,severity | head 0";
    let plan = p4a_plan(&f, soql, f.to).expect("route (materialize+head)");
    let oracle = p4a_oracle(&f, soql, f.to);
    eprintln!("H3 oracle stats = {}", oracle["stats"]);
    eprintln!("H3 plan   stats = {}", plan["stats"]);
    assert_eq!(
        oracle["stats"]["truncated"], plan["stats"]["truncated"],
        "H3: drapeau truncated diverge — oracle={} plan={}", oracle["stats"]["truncated"], plan["stats"]["truncated"]
    );
}

/// H4 — CONTRÔLE : la MÊME égalité SANS `head` (sort seul). p4a_norm TRIE les lignes -> une divergence d'ORDRE
/// est masquée (le SET est identique). Démontre la LACUNE du harnais : la parité "normalisée" ne teste pas
/// l'ordre de tri, seulement le multiset. (Ce test DOIT passer — il documente pourquoi H1/H2 sont nécessaires.)
#[test]
fn hostile_sort_without_head_is_masked_by_norm() {
    let _lk = p4a_lock();
    let mut rows: Vec<(i64, &str)> = Vec::new();
    for _ in 0..5 { rows.push((2, "s")); }
    for _ in 0..5 { rows.push((10, "s")); }
    let f = hostile_fixture("hostile-nohead", &rows);
    let soql = "search | stats count by severity | sort -count";
    let plan = p4a_plan(&f, soql, f.to).expect("route");
    let oracle = p4a_oracle(&f, soql, f.to);
    // Ordre BRUT (non normalisé) des severities de chaque côté.
    eprintln!("H4 oracle sev order = {:?}", col_vals(&oracle, "severity"));
    eprintln!("H4 plan   sev order = {:?}", col_vals(&plan, "severity"));
    p4a_assert_parity(&oracle, &plan, soql); // passe (normalisé) même si l'ORDRE diffère
}

/// H3b — `table ... | head N` (N>0) avec PLUS de N lignes matchantes : le kernel Materialize pose
/// truncated=true (out.len()>=cap==N) alors que l'oracle (`LIMIT N`) rend N lignes truncated=false.
/// Divergence RÉALISTE (tout panneau `| table … | head N`). Le harnais p4a ne compare PAS stats.truncated.
#[test]
fn hostile_table_head_n_truncated_flag() {
    let _lk = p4a_lock();
    let rows: Vec<(i64, &str)> = (0..10).map(|_| (0, "s")).collect(); // 10 lignes matchantes
    let f = hostile_fixture("hostile-headn", &rows);
    let soql = "search | table source | head 3"; // 3 < 10 -> l'oracle LIMIT 3, pas de troncature
    let plan = p4a_plan(&f, soql, f.to).expect("route");
    let oracle = p4a_oracle(&f, soql, f.to);
    eprintln!("H3b oracle = rows={} trunc={}", oracle["stats"]["rows"], oracle["stats"]["truncated"]);
    eprintln!("H3b plan   = rows={} trunc={}", plan["stats"]["rows"], plan["stats"]["truncated"]);
    assert_eq!(oracle["rows"].as_array().unwrap().len(), 3, "les deux rendent 3 lignes");
    assert_eq!(plan["rows"].as_array().unwrap().len(), 3, "les deux rendent 3 lignes");
    assert_eq!(
        oracle["stats"]["truncated"], plan["stats"]["truncated"],
        "H3b: truncated diverge sur `head N` — oracle={} plan={}", oracle["stats"]["truncated"], plan["stats"]["truncated"]
    );
}

/// H5 — FIX A ciblé : la détection de tie au bord du head-cut ne FALLBACK que si nécessaire.
///  (a) counts DISTINCTS coupés par `head` (cut STRICT, PAS de tie au bord) -> DOIT rester routé vectorisé
///      (Some) + == oracle ; census route = (1 vectorisé, 0 fallback) (pas de fallback inutile).
///  (b) égalité de count qui STRADDLE le bord du `head` -> DOIT tomber en fallback (None) ; census = (0, 1).
#[test]
fn hostile_tiebreak_fallback_only_on_boundary_tie() {
    let _lk = p4a_lock();

    // (a) counts distincts : web×5, api×3, db×1. `head 2` coupe ENTRE api(3) et db(1) -> cut STRICT -> vectorisé.
    let mut rows_a: Vec<(i64, &str)> = Vec::new();
    for _ in 0..5 { rows_a.push((0, "web")); }
    for _ in 0..3 { rows_a.push((0, "api")); }
    for _ in 0..1 { rows_a.push((0, "db")); }
    let fa = hostile_fixture("hostile-notie", &rows_a);
    let soql = "search | stats count by source | sort -count | head 2";
    route_counters_reset();
    let plan = p4a_plan(&fa, soql, fa.to);
    assert!(plan.is_some(), "cut NON-ambigu -> DOIT router vectorisé (pas de fallback inutile) : {soql}");
    assert_eq!(route_counters(), (1, 0), "cut strict : 1 vectorisé, 0 fallback");
    p4a_assert_parity(&p4a_oracle(&fa, soql, fa.to), plan.as_ref().unwrap(), soql);

    // (b) tie au bord : web×5, api×5 (ÉGALITÉ au sommet), db×1. `head 1` coupe DANS l'égalité web/api -> fallback.
    let mut rows_b: Vec<(i64, &str)> = Vec::new();
    for _ in 0..5 { rows_b.push((0, "web")); }
    for _ in 0..5 { rows_b.push((0, "api")); }
    for _ in 0..1 { rows_b.push((0, "db")); }
    let fb = hostile_fixture("hostile-boundtie", &rows_b);
    let soql_tie = "search | stats count by source | sort -count | head 1";
    route_counters_reset();
    let plan_tie = p4a_plan(&fb, soql_tie, fb.to);
    assert!(plan_tie.is_none(), "tie au bord du head-cut -> DOIT fallback (None) : {soql_tie}");
    assert_eq!(route_counters(), (0, 1), "tie au bord : 0 vectorisé, 1 fallback");
}

// ====================================================================================================
// #28 P3.5 — TESTS ADVERSARIAUX (hostiles ; NE MODIFIE PAS LE PROD, tests SEULS).
// Cible les 4 risques de la revue P3.5 : (1) régression de l'ORACLE `cold_union_query` (le chemin prod servi
// aujourd'hui), (2) SUR-ÉLAGAGE vectorisé, (3) contournement du garde colonne-déniée #45, (4) cohérence du
// gate-cap / double-chemin. Le harnais P3.5 compare le vectorisé à l'oracle AVEC preds ; ces tests ajoutent
// la RÉFÉRENCE MANQUANTE = `union_query_oracle(&[])` = HYDRATATION SQLITE COMPLÈTE SANS ÉLAGAGE (ni prune ni
// kernel) -> ground truth indépendant qui casse si l'élagage (oracle OU vectorisé) perd/ajoute une ligne.
// ====================================================================================================

/// Oracle SANS élagage (`&[]`) = HYDRATATION SQLite COMPLÈTE de la fenêtre froide -> ground truth le plus fort
/// (aucun prune, aucun kernel). C'est la référence AVANT-P3.5 : l'oracle post-P3.5 (avec preds hissés) DOIT
/// rendre exactement les mêmes lignes.
fn adv_full_scan(f: &P4aFix, soql: &str) -> Value {
    prune_oracle(f, soql, &[])
}

/// (RISQUE 1) — RÉGRESSION DE L'ORACLE. Le harnais P3.5 vérifie `vec(preds) == oracle(preds)` : il NE VERRAIT PAS
/// une régression si l'élagage interne de l'oracle perdait une ligne (les deux seraient faux de la même façon).
/// Ici on PIN `oracle(preds) == oracle(&[])` (hydratation SQLite complète sans élagage) sur un jeu de requêtes
/// count/group-by/table/regex/multi-fichiers -> si l'élagage hissé retirait un fichier avec un vrai match, le
/// full-scan aurait PLUS de lignes -> échec. Prouve : l'oracle post-P3.5 == comportement AVANT P3.5.
#[test]
fn adv_prune_oracle_no_row_loss_vs_full_scan() {
    let _lk = p4a_lock();
    // 6 fichiers, `rare`/`h9`/`10.9.9.9` localisés au fichier idx 3 ; le reste dispersé.
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("common", "h1", "10.0.0.2", 2),
        ("common", "h2", "10.0.0.1", 1),
        ("rare",   "h9", "10.9.9.9", 3),
        ("common", "h2", "10.0.0.2", 2),
        ("common", "h1", "10.0.0.1", 1),
    ];
    let (f, _n) = prune_fixture("adv-oracle-selfparity", &rows);
    for soql in [
        "search source=rare | stats count",              // min/max déterministe -> l'oracle élague N-1
        "search source=rare | stats count by host",
        "search source=rare | table source,host,src_ip,severity",
        "search host=h9 | stats count",                  // host localisé
        "search src_ip=10.9.9.9 | stats count",          // bloom-seul
        "search severity=3 | stats count",               // dim numérique
        "search source=common | stats count by host",    // valeur MAJORITAIRE (aucun élagage attendu)
        "search source=common | table source,host,severity",
    ] {
        let preds = prune_preds(&f, soql, f.to);
        let full = adv_full_scan(&f, soql);          // GROUND TRUTH = SQLite complet, 0 élagage.
        let pruned = prune_oracle(&f, soql, &preds); // ORACLE PROD post-P3.5, preds hissés (IDENTIQUES au handler).
        p4a_assert_parity(&full, &pruned, &format!("{soql} [oracle(preds) == full-scan]"));
        // Et le vectorisé avec les MÊMES preds == la MÊME ground truth (triangulation).
        if let Some(v) = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap() {
            p4a_assert_parity(&full, &v, &format!("{soql} [vec(preds) == full-scan]"));
        }
    }
}

/// (RISQUE 2) — SUR-ÉLAGAGE. Pour CHAQUE valeur PRÉSENTE de chaque dim élaguable, le(s) fichier(s) porteur(s)
/// NE DOIT/DOIVENT PAS être élagué(s). On vérifie : (a) `scanned >= nb de fichiers porteurs` (sinon un porteur a
/// été sauté = ligne perdue), (b) résultat == full-scan, (c) count == nb de porteurs. Couvre min/max (source),
/// host (min/max+bloom), src_ip (BLOOM-SEUL), severity (numérique) -> un faux-négatif de bloom se manifesterait
/// ici comme un porteur sauté.
#[test]
fn adv_prune_no_overprune_every_present_value() {
    let _lk = p4a_lock();
    let rows = [
        ("alpha", "h1", "10.0.0.1", 1),
        ("beta",  "h2", "10.0.0.2", 2),
        ("alpha", "h3", "10.0.0.3", 3),
        ("gamma", "h1", "10.0.0.1", 4),
        ("beta",  "h2", "10.0.0.9", 2),
    ];
    let (f, _n) = prune_fixture("adv-overprune", &rows);
    let cases: &[(&str, &str)] = &[
        ("source", "alpha"), ("source", "beta"), ("source", "gamma"),
        ("host", "h1"), ("host", "h2"), ("host", "h3"),
        ("src_ip", "10.0.0.1"), ("src_ip", "10.0.0.2"), ("src_ip", "10.0.0.3"), ("src_ip", "10.0.0.9"),
        ("severity", "1"), ("severity", "2"), ("severity", "3"), ("severity", "4"),
    ];
    for (col, val) in cases {
        let soql = format!("search {col}={val} | stats count");
        let preds = prune_preds(&f, &soql, f.to);
        assert!(!preds.is_empty(), "pred d'élagage extrait : {soql}");
        // Fichiers PORTEURS de la valeur (cap=1 -> 1 ligne == 1 fichier).
        let want: usize = rows.iter().filter(|(s, h, ip, sev)| match *col {
            "source" => s == val,
            "host" => h == val,
            "src_ip" => ip == val,
            "severity" => &sev.to_string() == val,
            _ => false,
        }).count();
        route_counters_reset();
        let on = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, &soql, true, 60_000, &preds).unwrap().unwrap();
        let (_pruned, scanned) = prune_counters();
        assert!(scanned as usize >= want, "{soql}: {scanned} scannés < {want} porteurs = SUR-ÉLAGAGE (ligne perdue)");
        p4a_assert_parity(&adv_full_scan(&f, &soql), &on, &format!("{soql} [vec == full-scan]"));
        assert_eq!(on["rows"][0][0].as_i64().unwrap(), want as i64, "{soql}: count == nb porteurs ({want})");
    }
}

/// (RISQUE 3) — GARDE COLONNE-DÉNIÉE #45 : variantes que le test P3.5 (`source` seul) ne couvre pas.
/// (a) DENY sur une dim BLOOM-SEULE (`src_ip`) -> 0 élagage (le garde couvre AUSSI les dims sans min/max).
/// (b) COMPOSITE And(dénié, non-dénié) : deny `source`, preds=[source=rare, host=h9] -> `source` retiré,
///     `host=h9` reste élaguable (correct, non dénié) -> prune>=1 via host, résultat == full-scan (aucune fuite
///     via la dim déniée, aucune perte via la dim autorisée).
#[test]
fn adv_prune_denied_bloom_only_and_composite() {
    let _lk = p4a_lock();
    // host=h9 dans idx1 ET idx2 ; source=rare SEULEMENT idx1 -> `source` et `host` élaguent des ENSEMBLES
    // DIFFÉRENTS (source=rare prune {idx0,idx2} ; host=h9 prune {idx0}) -> le compteur DISTINGUE si le garde a
    // bien RETIRÉ `source` (pruned==1, host-seul) ou non (pruned==2).
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("rare",   "h9", "10.9.9.9", 3),
        ("common", "h9", "10.0.0.2", 2),
    ];
    let (f, _n) = prune_fixture("adv-deny", &rows);

    // (a) src_ip DÉNIÉ (bloom-seul) -> aucun élagage sur son seal (garde défense-en-profondeur ; le test P3.5 ne
    // couvre QUE `source` qui porte min/max — ici la dim n'a QUE le bloom).
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("src_ip".to_string());
        w.insert(f.dbp.clone(), s);
    }
    let preds = vec![DimEq { dim: ColdDim::SrcIp, value: "10.9.9.9".into() }];
    route_counters_reset();
    let r = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search src_ip=10.9.9.9 | stats count", true, 60_000, &preds).unwrap();
    assert!(r.is_some(), "routé");
    assert_eq!(prune_counters().0, 0, "src_ip DÉNIÉ (bloom-seul) -> 0 élagage seal (garde #45)");
    crate::field_deny_cols_cell().write().remove(&f.dbp);

    // (b) COMPOSITE And(dénié, autorisé) : deny `source` ; preds INJECTÉS=[source=rare (dénié), host=h9 (autorisé)].
    // OBSERVABLE = le COMPTEUR d'élagage (le signal de sécurité direct : la dim déniée a-t-elle piloté l'élagage ?).
    // Le garde retire `source` -> l'élagage n'utilise QUE `host=h9` -> pruned==1 (idx0 seul, PAS idx2 que
    // `source=rare` aurait aussi élagué). Si le garde échouait -> pruned==2. Le GXQL ne référence PAS `source`
    // (sinon l'authorizer #45 rejetterait la requête AVANT tout) -> découplé des preds injectés.
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("source".to_string());
        w.insert(f.dbp.clone(), s);
    }
    let preds = vec![
        DimEq { dim: ColdDim::Source, value: "rare".into() },
        DimEq { dim: ColdDim::Host, value: "h9".into() },
    ];
    route_counters_reset();
    let on = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search host=h9 | stats count", true, 60_000, &preds).unwrap();
    let (pruned, _scanned) = prune_counters();
    crate::field_deny_cols_cell().write().remove(&f.dbp);
    assert!(on.is_some(), "routé (GXQL n'implique pas la colonne déniée)");
    assert_eq!(pruned, 1, "garde: `source` RETIRÉ -> élagage host-SEUL (pruned==1=idx0), PAS l'élagage source (idx2) -> aucune fuite via la dim déniée");
}

/// (RISQUE 3bis / RISQUE 4) — ASYMÉTRIE DE CASSE + PRUNE-SETS DIVERGENTS. DOCUMENTE deux propriétés du code
/// ACTUEL :
///  - le garde `eff_preds` (planner.rs) filtre le deny-set par `HashSet::contains` = SENSIBLE À LA CASSE, alors
///    que le kernel `denied()` (vectorized.rs) est INSENSIBLE À LA CASSE (`eq_ignore_ascii_case`). Un deny-set
///    en casse non-canonique ("Source") CONTOURNE donc le garde d'élagage (l'élagage se produit) MAIS PAS le
///    masquage kernel. NON exploitable en PROD (le peuplement de `field_deny_cols` n'insère QUE des noms de
///    colonnes physiques EXACTS, tous minuscules -> jamais "Source") ; c'est un durcissement latent (aligner le
///    garde sur `eq_ignore_ascii_case`).
///  - même quand vectorisé (eff_preds ⊂ preds) et oracle (preds bruts) élaguent des ENSEMBLES DIFFÉRENTS, le
///    RÉSULTAT reste identique (l'élagage ne retire que des fichiers prouvés sans match) -> cohérence gate-cap
///    dans la direction SÛRE (vectorisé élague ≤ oracle -> au pire fallback, jamais un résultat divergent).
#[test]
fn adv_prune_deny_case_insensitive_guard() {
    let _lk = p4a_lock();
    let rows = [
        ("common", "h1", "10.0.0.1", 1),
        ("rare",   "h9", "10.9.9.9", 3),
        ("common", "h2", "10.0.0.2", 2),
    ];
    let (f, _n) = prune_fixture("adv-deny-case", &rows);
    // GXQL SANS la colonne déniée (l'authorizer #45 rejetterait sinon) ; le pred `source=rare` est INJECTÉ pour
    // exercer le garde. OBSERVABLE = compteur d'élagage. source=rare élague {idx0,idx2} (les 2 `common`).
    let soql = "search | stats count";
    let preds = vec![DimEq { dim: ColdDim::Source, value: "rare".into() }];

    // DURCISSEMENT : le garde d'élagage est aligné sur `denied()` (eq_ignore_ascii_case),
    // plus `contains` sensible à la casse. Un deny-set en CASSE NON-CANONIQUE ("Source") est désormais CAPTÉ ->
    // l'élagage est BLOQUÉ comme pour la casse canonique -> pas de fuite par canal TIMING (fichiers sautés /
    // compteur de déchiffrement). Cohérence stricte garde-élagage <-> masquage kernel #45.
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("Source".to_string()); // casse non-canonique -> désormais captée par eq_ignore_ascii_case.
        w.insert(f.dbp.clone(), s);
    }
    route_counters_reset();
    let _ = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
    let (pruned, _scanned) = prune_counters();
    crate::field_deny_cols_cell().write().remove(&f.dbp);
    assert_eq!(pruned, 0, "DURCISSEMENT : deny \"Source\" (casse-variante) DOIT être capté (eq_ignore_ascii_case) -> 0 élagage, pas de fuite timing ; pruned={pruned}");

    // Contre-preuve : la casse CANONIQUE ("source") — la SEULE que le peuplement prod produit — bloque bien
    // l'élagage (le garde fonctionne au cas nominal -> le gap est purement théorique en prod).
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("source".to_string());
        w.insert(f.dbp.clone(), s);
    }
    route_counters_reset();
    let _ = cold_vectorized_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, &preds).unwrap();
    let (pruned2, _s2) = prune_counters();
    crate::field_deny_cols_cell().write().remove(&f.dbp);
    assert_eq!(pruned2, 0, "casse canonique \"source\" -> garde ACTIF -> 0 élagage (comportement voulu)");
}

// ====================================================================================================
// #18 P4b — HARNAIS DE PARITÉ DU MERGE hot∪cold (fenêtres CHEVAUCHANTES). Prouve l'INVARIANT
// `résultat_routé_P4b == cold_union_query` (l'oracle qui fait DÉJÀ hot∪cold) pour un large jeu de requêtes
// dont la fenêtre CHEVAUCHE la frontière (`from < boundary <= to`) : count / count WHERE / group mono-multi
// (clés hot-seul / froid-seul / LES DEUX -> somme) / regex / LIKE / top-N (dont tie APRÈS merge -> fallback) /
// table+head / masquage (colonne déniée) / bords. Le merge = froid vectorisé + hot SQLite fusionnés au niveau
// OPÉRATEUR ; l'oracle hydrate TOUT dans SQLite. Sérialisé par `p4a_lock` (compteurs de route globaux).
// ====================================================================================================

/// Fixture CHEVAUCHANTE : `cold_rows` (severity, source) dans le jour FROID M-10 (agés en Parquet, ts<boundary)
/// + `hot_rows` dans le jour HOT M-2 (= jour frontière, ts>=boundary, NON agés -> restent dans main.event).
/// Fenêtre `[from, to]` = froid_base .. dernier hot -> `from < boundary <= to` (chevauchante, vérifié).
fn p4b_fixture(tag: &str, cold_rows: &[(i64, &str)], hot_rows: &[(i64, &str)]) -> P4aFix {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let cold_day = M - 10;
    let cold_base = cold_day * SECS_PER_DAY;
    for (i, (sev, src)) in cold_rows.iter().enumerate() {
        let mut r = rich_row(cold_base + i as i64, i as i64);
        r.row.severity = *sev;
        r.row.source = (*src).to_string();
        insert_event(&db, &r);
    }
    // HOT : jour frontière M-HOT_WIN (= M-2). ts = boundary + i -> >= boundary -> hot. NON éligible à l'aging
    // (jours éligibles [M-30, M-2)) -> conservé dans main.event -> c'est l'ARM HOT de l'union.
    let hot_day = M - HOT_WIN;
    let hot_base = hot_day * SECS_PER_DAY;
    for (i, (sev, src)) in hot_rows.iter().enumerate() {
        let mut r = rich_row(hot_base + i as i64, 1_000 + i as i64);
        r.row.severity = *sev;
        r.row.source = (*src).to_string();
        insert_event(&db, &r);
    }
    insert_recent_tail_holder(&db); // garde H1 d'aging (jour M-1, HORS fenêtre : ts > to)
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", cold_day), 0, "jour froid purgé du hot");
    assert_eq!(count_hot_day(&db, "prod", hot_day), hot_rows.len() as i64, "jour hot conservé dans main.event");
    let b = union_boundary(&db, &conf);
    let from = cold_base;
    let to = hot_base + hot_rows.len() as i64 - 1;
    assert!(from < b && b <= to, "fenêtre CHEVAUCHANTE requise (from={from} < b={b} <= to={to})");
    assert_eq!(hot_base, b, "les lignes hot commencent PILE à la frontière (bord boundary==premier hot)");
    P4aFix { root, db, dbp, conf, b, from, to }
}

/// ORACLE P4b = production ACTUELLE : compile le GXQL via le MÊME choke-point que le handler
/// (`soql_to_sql_masked_x`, masques vides) puis exécute via `cold_union_query` (hydrate-SQLite hot∪cold).
fn p4b_oracle(f: &P4aFix, soql: &str) -> Value {
    let sql = crate::soql_glue::soql_to_sql_masked_x(soql, f.from, f.to, None, &FieldMaskSet::new()).expect("compile");
    let (v, _t, _m) = union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &sql, None, 60_000, None, &[]).unwrap();
    v
}

/// MERGE P4b = décision + exécution du merge hot∪cold vectorisé. `Some(v)` = routé merge ; `None` = fallback.
fn p4b_merge(f: &P4aFix, soql: &str) -> Option<Value> {
    cold_vectorized_merge_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, true, 60_000, None, &[]).unwrap()
}

/// SHAPES CHEVAUCHANTES vectorisables : chacune DOIT router (Some) ET == oracle. Couvre count, count WHERE
/// (int/streq/!=/regex/glob-LIKE), group mono/multi/int-dim, top-N non-ambigu, table+head sans troncature.
#[test]
fn p4b_parity_aggregates_route_merge() {
    let _lk = p4a_lock();
    // Sources DISTRIBUÉES des deux côtés (skew stable pour un top-N non ambigu au global).
    let cold: Vec<(i64, &str)> = vec![
        (0, "web"), (1, "web"), (2, "web"), (3, "api"), (1, "api"), (2, "db"), (0, "web"), (3, "api"),
    ];
    let hot: Vec<(i64, &str)> = vec![
        (0, "web"), (2, "api"), (1, "db"), (3, "db"), (0, "web"), (1, "web"),
    ];
    let f = p4b_fixture("p4b-agg", &cold, &hot);
    let cases: &[&str] = &[
        "search | stats count",
        "search severity>=2 | stats count",
        "search severity=3 | stats count",
        "search severity!=0 | stats count",
        "search source=web | stats count",
        "search source!=web | stats count",
        "search source=w* | stats count",
        "search source!=w* | stats count",
        "search source=~^web$ | stats count",
        "search | stats count by source",
        "search | stats count by severity",
        "search | stats count by source,severity",
        "search source=web | stats count by severity",
        "search | stats count by source | sort -count",
        "search | table source,severity",
    ];
    for soql in cases {
        let plan = p4b_merge(&f, soql);
        assert!(plan.is_some(), "DOIT router (merge) : {soql}");
        p4b_assert_parity(&p4b_oracle(&f, soql), plan.as_ref().unwrap(), soql);
    }
}

/// PARITÉ (réutilise la normalisation P4a : colonnes ordre-inclus + lignes multiset-triées).
fn p4b_assert_parity(oracle: &Value, plan: &Value, label: &str) {
    p4a_assert_parity(oracle, plan, label)
}

/// CŒUR DU MERGE — une clé de group-by présente DES DEUX CÔTÉS (froid ET hot) DOIT voir ses counts ADDITIONNÉS
/// (pas dupliquée, pas écrasée). "web" apparaît froid×3 + hot×2 = 5 ; "api" froid×1 + hot×0 = 1 ; "db" froid×0
/// + hot×2 = 2. On PROUVE la somme exacte + la parité avec l'oracle.
#[test]
fn p4b_group_key_present_both_sides_sums() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = vec![(0, "web"), (0, "web"), (0, "web"), (0, "api")];
    let hot: Vec<(i64, &str)> = vec![(0, "web"), (0, "web"), (0, "db"), (0, "db")];
    let f = p4b_fixture("p4b-bothsides", &cold, &hot);
    let soql = "search | stats count by source";
    let plan = p4b_merge(&f, soql).expect("routé");
    let oracle = p4b_oracle(&f, soql);
    p4b_assert_parity(&oracle, &plan, soql);
    // Somme EXACTE par clé (web des DEUX côtés = 3+2=5).
    let got = count_by_source(&plan);
    assert_eq!(got, vec![("api".into(), 1), ("db".into(), 2), ("web".into(), 5)], "clé des deux côtés ADDITIONNÉE, pas dupliquée/écrasée");
    // Contrôle : l'oracle donne la MÊME somme.
    assert_eq!(count_by_source(&oracle), got, "oracle == merge sur la somme par clé");
}

/// BOUNDARY-UNE-FOIS : une ligne PILE à la frontière (premier hot, ts==boundary) est comptée UNE fois (pas
/// zéro, pas deux). Le count global == cold_len + hot_len (aucune ligne perdue ni dupliquée au bord).
#[test]
fn p4b_count_boundary_row_counted_once() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = vec![(0, "c"), (1, "c"), (2, "c")]; // 3 froid
    let hot: Vec<(i64, &str)> = vec![(0, "h"), (1, "h")]; // 2 hot ; hot[0] est PILE à boundary
    let f = p4b_fixture("p4b-boundary", &cold, &hot);
    let soql = "search | stats count";
    let plan = p4b_merge(&f, soql).expect("routé");
    let oracle = p4b_oracle(&f, soql);
    p4b_assert_parity(&oracle, &plan, soql);
    let n = col_vals(&plan, "count")[0].as_i64().unwrap();
    assert_eq!(n, 5, "3 froid + 2 hot = 5 ; la ligne au bord comptée UNE fois");
    assert_eq!(col_vals(&oracle, "count")[0].as_i64().unwrap(), 5, "oracle == 5");
}

/// TOP-N — TIE INDUIT PAR LE MERGE : web (froid3+hot2=5) et api (froid1+hot4=5) ÉGALENT au sommet APRÈS fusion
/// alors qu'AUCUN côté n'est à égalité seul (froid: web3>api1 ; hot: api4>web2). `head 1` coupe DANS l'égalité
/// -> le SET est ambigu (ordre intra-égalité de l'oracle indéfini) -> le merge DOIT FALLBACK (None). Le CUT
/// STRICT (head 2, prend les deux) reste routé + parité.
#[test]
fn p4b_topn_tie_after_merge_falls_back() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = vec![(0, "web"), (0, "web"), (0, "web"), (0, "api"), (0, "db")];
    let hot: Vec<(i64, &str)> = vec![(0, "web"), (0, "web"), (0, "api"), (0, "api"), (0, "api"), (0, "api")];
    let f = p4b_fixture("p4b-tie", &cold, &hot);
    // web=5, api=5 (tie), db=1. head 1 -> tie STRADDLE -> fallback.
    assert!(p4b_merge(&f, "search | stats count by source | sort -count | head 1").is_none(), "tie APRÈS merge au bord du head-cut -> fallback (None)");
    // head 2 -> prend web+api (les deux membres de l'égalité) ; db(1) exclu, cut STRICT (5>1) -> routé + parité.
    let soql2 = "search | stats count by source | sort -count | head 2";
    let plan2 = p4b_merge(&f, soql2).expect("cut strict -> routé");
    p4b_assert_parity(&p4b_oracle(&f, soql2), &plan2, soql2);
}

/// MASQUAGE #45 — POSTURE PRODUCTION (identique à P4a) : en production, une colonne masquée/déniée rend
/// `effective_masks` NON VIDE -> le handler ne pose PAS `cold_vec_soql` -> le merge n'est jamais tenté (gate
/// #3). On PROUVE donc : (A) `masks_empty=false` -> le merge FALLBACK (None) sur toutes les surfaces (l'oracle
/// applique HASH/MASK dans le SQL + l'authorizer DENY, que le merge ne reproduit pas). (B) DÉFENSE EN
/// PROFONDEUR : sur les DEUX côtés du merge, une colonne déniée est NULLifiée — FROID via le kernel `denied()`
/// (mirroir `union_proj`), HOT via `union_proj` de `cold_union_query` — prouvé par appel DIRECT (découplé de
/// l'authorizer, qui est le chemin oracle). NB : le merge routé + un deny runtime injecté SANS masque est un
/// état INCOHÉRENT (jamais atteint en prod : deny <=> masks non vides) -> non testé (l'authorizer erre alors
/// des DEUX côtés, comportement consistant mais non représentatif).
#[test]
fn p4b_masking_forces_fallback_and_kernel_denies_both_sides() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = vec![(0, "web"), (1, "api"), (2, "web")];
    let hot: Vec<(i64, &str)> = vec![(0, "db"), (1, "web")];
    let f = p4b_fixture("p4b-deny", &cold, &hot);

    // (A) ROUTEUR : masques actifs (masks_empty=false) -> FALLBACK (None) sur toutes les surfaces chevauchantes.
    for soql in ["search | stats count", "search | stats count by src_ip", "search | table source,src_ip", "search src_ip=10.0.0.1 | stats count"] {
        let r = cold_vectorized_merge_try(&f.dbp, &f.conf, None, f.from, f.to, f.b, soql, /*masks_empty=*/ false, 60_000, None, &[]).unwrap();
        assert!(r.is_none(), "masques actifs -> merge fallback (None) : {soql}");
    }

    // (B) KERNEL `denied()` (FROID) : projection d'une colonne déniée -> NULL sur toutes les lignes froides.
    let pass = cold_aead_passphrase(&f.conf, &f.dbp).expect("passphrase cold");
    let cold_dir = cold_root(&f.conf, &f.dbp);
    let path = file_path(&cold_dir, "prod", M - 10, 0);
    let reader = open_cold_reader(&path, &pass).expect("reader cold");
    let mut deny = std::collections::HashSet::new();
    deny.insert("src_ip".to_string());
    let (rows_denied, _t) = vec_materialize(&reader, &Pred::True, &["source", "src_ip"], 1000, &deny).unwrap();
    assert!(!rows_denied.is_empty(), "des lignes froides existent");
    assert!(
        rows_denied.iter().all(|r| matches!(r[1], rusqlite::types::Value::Null)),
        "FROID : src_ip DÉNIÉ -> NULL partout (kernel #45, parité union_proj)"
    );

    // (B') MASQUE HOT : `union_proj` NULLifie la MÊME colonne côté hot (chemin `cold_union_query` restreint au
    // hot). Le deny injecté dans `field_deny_cols_cell` fait émettre `NULL AS src_ip` à la vue d'union ; on
    // compile un `| table` MASQUÉ (FieldMask DENY) pour éviter l'authorizer (parité EXACTE avec la prod, où
    // masque non vide -> SQL émet NULL). src_ip côté HOT -> NULL.
    {
        let mut w = crate::field_deny_cols_cell().write();
        let mut s = std::collections::HashSet::new();
        s.insert("src_ip".to_string());
        w.insert(f.dbp.clone(), s);
    }
    let mut masks = FieldMaskSet::new();
    masks.insert("src_ip".to_string(), MaskAction::Deny);
    let hot_masked_sql = crate::soql_glue::soql_to_sql_masked_x("search | table source,src_ip", f.b, f.to, None, &masks).expect("compile masqué");
    // Fenêtre hot-only [boundary, to] (q_from=boundary -> pas d'hydratation cold), comme le fait le merge.
    let (hv, _t2, _m2) = union_query_oracle(&f.dbp, &f.conf, None, f.b, f.to, f.b, &hot_masked_sql, None, 60_000, None, &[]).unwrap();
    assert!(!col_vals(&hv, "src_ip").is_empty(), "des lignes HOT existent dans [boundary,to]");
    assert!(col_vals(&hv, "src_ip").iter().all(|x| x.is_null()), "HOT : src_ip DÉNIÉ -> NULL (union_proj)");
    crate::field_deny_cols_cell().write().remove(&f.dbp); // hygiène
}

/// TABLE + HEAD — TRONCATURE ORDRE-AMBIGUË : quand `| table … | head N` tronque (total matché > N), l'ordre de
/// l'`UNION ALL` de l'oracle (hot-arm puis cold-arm, sous plan SQLite) n'est PAS reproductible -> le merge
/// FALLBACK (None). Sans troncature (head >= total) -> routé + parité.
#[test]
fn p4b_table_head_truncation_falls_back_else_routes() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = (0..4).map(|i| (i % 3, "c")).collect(); // 4 froid
    let hot: Vec<(i64, &str)> = (0..3).map(|i| (i % 3, "h")).collect(); // 3 hot ; total 7
    let f = p4b_fixture("p4b-tablehead", &cold, &hot);
    // head 3 < 7 -> troncature -> ordre ambigu -> fallback.
    assert!(p4b_merge(&f, "search | table source | head 3").is_none(), "table|head tronquant -> fallback (None)");
    // head 20 >= 7 -> pas de troncature -> routé + parité (multiset complet).
    let soql = "search | table source,severity | head 20";
    let plan = p4b_merge(&f, soql).expect("routé (pas de troncature)");
    p4b_assert_parity(&p4b_oracle(&f, soql), &plan, soql);
}

/// BORDS DE FENÊTRE + CENSUS DU COMPTEUR DE ROUTE. Prouve : (a) chevauchante -> merge routé (1,0) ; (b) PUR-FROID
/// (`to < boundary`) -> le merge DÉCLINE (c'est le domaine de P4a) ; (c) PUR-HOT (`from >= boundary`) -> décline ;
/// (d) bord exact `boundary == to` (un seul hot, PILE au bord) -> routé + parité.
#[test]
fn p4b_window_edges_and_route_census() {
    let _lk = p4a_lock();
    let cold: Vec<(i64, &str)> = vec![(0, "c"), (1, "c"), (2, "c")];
    let hot: Vec<(i64, &str)> = vec![(0, "h"), (1, "h"), (2, "h")];
    let f = p4b_fixture("p4b-edges", &cold, &hot);

    // (a) chevauchante -> routé, census (1,0).
    route_counters_reset();
    assert!(p4b_merge(&f, "search | stats count").is_some(), "chevauchante -> merge routé");
    assert_eq!(route_counters(), (1, 0), "census : 1 merge, 0 fallback");

    // (b) PUR-FROID (to = b-1 < boundary) -> le merge DÉCLINE (domaine de P4a), census (0,1).
    route_counters_reset();
    let r_cold = cold_vectorized_merge_try(&f.dbp, &f.conf, None, f.from, f.b - 1, f.b, "search | stats count", true, 60_000, None, &[]).unwrap();
    assert!(r_cold.is_none(), "pur-froid -> merge décline (None)");
    assert_eq!(route_counters(), (0, 1), "census : 0 merge, 1 fallback");

    // (c) PUR-HOT (from = boundary >= boundary) -> décline, census (0,1).
    route_counters_reset();
    let r_hot = cold_vectorized_merge_try(&f.dbp, &f.conf, None, f.b, f.to, f.b, "search | stats count", true, 60_000, None, &[]).unwrap();
    assert!(r_hot.is_none(), "pur-hot -> merge décline (None)");
    assert_eq!(route_counters(), (0, 1), "census : 0 merge, 1 fallback");

    // (d) bord exact boundary == to : fenêtre [from, boundary] -> un seul instant hot (ts==boundary) -> routé + parité.
    let soql = "search | stats count by source";
    let plan_edge = cold_vectorized_merge_try(&f.dbp, &f.conf, None, f.from, f.b, f.b, soql, true, 60_000, None, &[]).unwrap();
    assert!(plan_edge.is_some(), "boundary==to -> routé");
    let sql = crate::soql_glue::soql_to_sql_masked_x(soql, f.from, f.b, None, &FieldMaskSet::new()).unwrap();
    let (oracle_edge, _t, _m) = union_query_oracle(&f.dbp, &f.conf, None, f.from, f.b, f.b, &sql, None, 60_000, None, &[]).unwrap();
    p4b_assert_parity(&oracle_edge, plan_edge.as_ref().unwrap(), "boundary==to");
}

/// GATE 0 sur le MERGE : ARMÉ par défaut (comme P4a), `=0` le désarme. Même raison qu'en P4a — le
/// fallback n'est pas un chemin équivalent plus lent, c'est le chemin qui agrège sur un échantillon.
#[test]
fn p4b_gate0_armed_by_default_and_opt_out_still_works() {
    let _lk = p4a_lock();
    let f = p4b_fixture("p4b-gate0", &[(0, "c"), (1, "c")], &[(0, "h"), (1, "h")]);
    assert!(p4b_merge(&f, "search | stats count").is_some(), "flag posé -> routé");
    let mut dflt = f.conf.clone();
    dflt.remove("PLUME_COLD_VECTORIZED");
    let r = cold_vectorized_merge_try(&f.dbp, &dflt, None, f.from, f.to, f.b, "search | stats count", true, 60_000, None, &[]).unwrap();
    assert!(r.is_some(), "GATE 0 ABSENT = défaut -> ARMÉ -> merge routé (exact)");
    let mut off = f.conf.clone();
    off.insert("PLUME_COLD_VECTORIZED".to_string(), "0".to_string());
    let r0 = cold_vectorized_merge_try(&f.dbp, &off, None, f.from, f.to, f.b, "search | stats count", true, 60_000, None, &[]).unwrap();
    assert!(r0.is_none(), "opt-out explicite `=0` -> merge dormant -> fallback (qui REFUSE au-delà du cap)");
}

/// FORMES NON VECTORISABLES sur fenêtre chevauchante -> le merge DÉCLINE (None) et l'oracle sert (dc/quantile/
/// json_extract). Prouve que le merge ne route QUE les formes proprement fusionnables.
#[test]
fn p4b_nonvectorizable_shapes_fall_back() {
    let _lk = p4a_lock();
    let f = p4b_fixture("p4b-nonvec", &[(0, "c"), (1, "c")], &[(0, "h"), (1, "h")]);
    for soql in [
        "search | stats dc(source)",
        "search | stats avg(severity)",
        "search | stats count by k",              // dim JSON non physique
        "search foo=bar | stats count",           // champ non physique
    ] {
        assert!(p4b_merge(&f, soql).is_none(), "forme non vectorisable/non mergeable -> fallback (None) : {soql}");
    }
}

// ====================================================================================================
// #18 P4b — TESTS ADVERSES (AJOUTÉS ; AUCUNE modification du code prod). Cherche une requête
// CHEVAUCHANTE ROUTÉE par P4b dont le résultat DIVERGE de l'oracle `cold_union_query`.
// ====================================================================================================

/// Fixture chevauchante GRAND VOLUME, inserts BATCHÉS (une transaction, synchronous=OFF/journal=MEMORY) pour
/// rester rapide malgré des milliers de lignes. `n_cold` lignes froides (source="COLD", jour M-10, agées en
/// Parquet, ts<boundary) + `n_hot` lignes hot (source="HOT", jour frontière M-2, ts>=boundary). Mirroir EXACT
/// de `p4b_fixture` (même frontière, même garde tail-holder) — seuls le débit d'insertion et les libellés source
/// changent. Renvoie la fenêtre `[from, to]` avec `from < b <= to`.
fn p4b_bigfix(tag: &str, n_cold: i64, n_hot: i64) -> P4aFix {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let cold_day = M - 10;
    let cold_base = cold_day * SECS_PER_DAY;
    let hot_day = M - HOT_WIN;
    let hot_base = hot_day * SECS_PER_DAY;
    {
        let conn = db.lock();
        conn.execute_batch("PRAGMA synchronous=OFF; PRAGMA journal_mode=MEMORY; BEGIN;").unwrap();
        {
            let mut st = conn
                .prepare(
                    "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                )
                .unwrap();
            let mut ins = |r: &ColdRow| {
                st.execute(params![
                    r.row.ts, r.row.severity, r.row.source, r.row.category, r.row.host, r.row.src_ip,
                    r.row.dst_ip, r.row.url, r.xff, r.row.dedup, r.row.engagement_id, r.row.origin,
                    r.row.env_id, r.row.message, r.row.fields
                ])
                .unwrap();
            };
            for i in 0..n_cold {
                let mut r = rich_row(cold_base + i, i);
                r.row.source = "COLD".to_string();
                ins(&r);
            }
            for i in 0..n_hot {
                let mut r = rich_row(hot_base + i, 1_000 + i);
                r.row.source = "HOT".to_string();
                ins(&r);
            }
            // tail-holder récent (jour M-1, hors fenêtre) -> détient le tail rowid, laisse ager le froid (garde H1).
            let mut tail = rich_row((M - 1) * SECS_PER_DAY + 1, 88_888);
            tail.row.source = "recent-tail".to_string();
            ins(&tail);
        }
        conn.execute_batch("COMMIT;").unwrap();
    }
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", cold_day), 0, "jour froid purgé du hot");
    assert_eq!(count_hot_day(&db, "prod", hot_day), n_hot, "jour hot conservé dans main.event");
    let b = union_boundary(&db, &conf);
    let from = cold_base;
    let to = hot_base + n_hot - 1;
    assert!(from < b && b <= to, "fenêtre CHEVAUCHANTE requise (from={from} < b={b} <= to={to})");
    assert_eq!(hot_base, b, "les lignes hot commencent PILE à la frontière");
    P4aFix { root, db, dbp, conf, b, from, to }
}

/// VECTEUR 5/6 — EX-BUG, MAINTENANT GARDE-FOU DE FALLBACK : `| table … | head N` avec `N > cap` ET
/// `total(froid+hot) > cap`.
///
/// Avant le fix, la garde matérialisation de `cold_vectorized_merge_try` (arm `VecAgg::Materialize`) n'inspectait,
/// pour un `head` EXPLICITE, QUE `total > N` — jamais le PLAFOND `PLUME_QUERY_MAX` que `run_on_conn` applique à
/// l'oracle. Or l'oracle `cold_union_query` exécute `SELECT … LIMIT N` via `run_on_conn`, qui TRONQUE À `cap`
/// (défaut 5000) quel que soit `LIMIT N`. Donc pour `N=100000` avec 3 froid + 5001 hot, l'oracle rendait 5000
/// lignes `truncated=true` tandis que P4b ROUTAIT 5003 lignes `truncated=false` (FAUX complet) -> DIVERGENCE.
///
/// FIX (`oracle_would_truncate_rows`, borne effective `min(N, cap)`) : `total(5004) > min(100000, 5000)=5000`
/// -> P4b DÉCLINE (fallback `None`) -> l'appelant sert l'oracle (tronqué correctement). On PROUVE le fallback,
/// et on documente que l'oracle serait bien tronqué (== ce que l'analyste reçoit désormais).
#[test]
fn p4b_ADVERSE_table_head_over_runconn_cap_diverges() {
    let _lk = p4a_lock();
    let cap = 5000i64; // PLUME_QUERY_MAX par défaut — on NE mute PAS l'env (process-global : casserait les concurrents).
    let f = p4b_bigfix("p4b-adv-headcap", 3, cap + 1); // 3 froid "COLD" + 5001 hot "HOT" -> total 5004 > cap
    let soql = "search | table source | head 100000"; // head EXPLICITE, N >> cap et N >> total

    // FIX : P4b ne route PLUS (l'oracle tronquerait à cap ; router servirait un sur-ensemble) -> FALLBACK.
    assert!(
        p4b_merge(&f, soql).is_none(),
        "FIX : head explicite N>cap avec total>cap -> P4b DÉCLINE (oracle_would_truncate_rows) ; l'appelant sert l'oracle"
    );
    // Documente le résultat DÉSORMAIS servi (l'oracle, tronqué correctement à cap, truncated=true).
    let oracle = p4b_oracle(&f, soql);
    assert_eq!(oracle["rows"].as_array().unwrap().len(), cap as usize, "oracle servi : tronqué au plafond run_on_conn (cap)");
    assert_eq!(oracle["stats"]["truncated"], json!(true), "oracle servi : truncated=true (complétude honnête)");
}

/// CONTRÔLE (même fixture-classe, petit volume) : `| table … | head N` SANS franchir le cap (total<=cap) ->
/// P4b == oracle. Isole le bug ci-dessus au FRANCHISSEMENT du plafond run_on_conn (pas au `head` en soi).
#[test]
fn p4b_ADVERSE_table_head_under_cap_is_fine_control() {
    let _lk = p4a_lock();
    let f = p4b_bigfix("p4b-adv-ctl", 3, 10); // 3 COLD + 10 HOT = 13 << cap
    let soql = "search | table source | head 100000";
    let plan = p4b_merge(&f, soql).expect("routé");
    let oracle = p4b_oracle(&f, soql);
    p4b_assert_parity(&oracle, &plan, soql); // sous le cap -> parité OK (contrôle)
}

/// VECTEUR GROUP-BY sur-cap (#2) — EX-BUG, MAINTENANT GARDE-FOU DE FALLBACK : `stats count by dims` dont le
/// HOT porte PLUS DE `cap` GROUPES DISTINCTS. Le HOT-arm de P4b (`count by host` SANS limite) passe par
/// `run_on_conn`, capé à `cap` GROUPES -> subset ARBITRAIRE des 5000 hôtes (sur 5001) -> le merge raterait des
/// groupes ET l'oracle lui-même TRONQUE le combiné (5004 hôtes distincts) à `cap`. Résultats INCOMPARABLES ->
/// P4b DOIT DÉCLINER (`oracle_would_truncate_groups`, `hot_groups >= cap`). On PROUVE le fallback + que l'oracle
/// servi est bien tronqué (== ce que reçoit l'analyste, honnêtement incomplet).
#[test]
fn p4b_ADVERSE_groupby_over_cap_hot_groups_falls_back() {
    let _lk = p4a_lock();
    let cap = 5000i64; // PLUME_QUERY_MAX défaut — NON muté (process-global).
    // 3 froid (host-0..host-2) + 5001 hot (host-1000..host-6000, TOUS distincts) -> hot a 5001 > cap groupes.
    let f = p4b_bigfix("p4b-adv-gb-hostcap", 3, cap + 1);
    let soql = "search | stats count by host";
    assert!(
        p4b_merge(&f, soql).is_none(),
        "FIX : hot > cap groupes distincts -> HOT-arm capé (subset arbitraire) -> P4b DÉCLINE (fallback oracle)"
    );
    // L'oracle servi tronque le COMBINÉ (5004 hôtes distincts) à cap groupes -> incomplet mais HONNÊTE.
    let oracle = p4b_oracle(&f, soql);
    assert_eq!(oracle["rows"].as_array().unwrap().len(), cap as usize, "oracle servi : {cap} groupes (combiné tronqué)");
    assert_eq!(oracle["stats"]["truncated"], json!(true), "oracle servi : truncated=true");
}

/// CONTRÔLE group-by SOUS le cap (#2) — PEU de groupes des DEUX côtés : `stats count by source` (source∈{COLD,
/// HOT}) à GROS VOLUME (100 froid + 200 hot). hot=1 groupe, mergé=2 groupes, tous < cap -> P4b ROUTE + PARITÉ
/// (somme correcte par clé : COLD=100, HOT=200). Prouve que le fix ne SUR-fallback PAS le cas courant (volume
/// élevé mais faible cardinalité de groupes).
#[test]
fn p4b_groupby_under_cap_routes_and_parity() {
    let _lk = p4a_lock();
    let f = p4b_bigfix("p4b-gb-undercap", 100, 200); // 100 COLD + 200 HOT, 2 sources distinctes seulement
    let soql = "search | stats count by source";
    let plan = p4b_merge(&f, soql).expect("2 groupes << cap -> DOIT router (pas de sur-fallback)");
    let oracle = p4b_oracle(&f, soql);
    p4b_assert_parity(&oracle, &plan, soql);
    // Somme EXACTE par clé (froid et hot ne partagent aucune source ici).
    assert_eq!(count_by_source(&plan), vec![("COLD".into(), 100), ("HOT".into(), 200)], "somme par clé correcte");
    assert_eq!(plan["stats"]["truncated"], json!(false), "sous le cap : truncated=false");
}

/// VECTEUR TOP-N sur-cap (#3) — MÊME chemin group-by hot que #2 : `stats count by host | sort -count | head N`.
/// Le HOT-arm (sort/head STRIPPÉS -> plain `count by host`) est capé à `cap` groupes -> le top-N pourrait rater
/// un hôte à fort count présent dans les 1 hôte(s) écarté(s). La MÊME garde cap (`oracle_would_truncate_groups`)
/// s'applique AVANT la garde tie-au-bord -> P4b DÉCLINE. Prouve le fallback.
#[test]
fn p4b_ADVERSE_topn_over_cap_hot_groups_falls_back() {
    let _lk = p4a_lock();
    let cap = 5000i64;
    let f = p4b_bigfix("p4b-adv-topn-hostcap", 3, cap + 1); // hot 5001 > cap groupes distincts
    let soql = "search | stats count by host | sort -count | head 5";
    assert!(
        p4b_merge(&f, soql).is_none(),
        "FIX : top-N sur hot > cap groupes -> HOT-arm capé -> top-N potentiellement faux -> P4b DÉCLINE (fallback)"
    );
}

// ====================================================================================================
// #18 P6 — DÉCODE ROW-GROUP/FICHIER PARALLÈLE BORNÉ. Le chemin vectorisé décode+déchiffre les fichiers cold
// RETENUS sur un POOL BORNÉ (`PLUME_COLD_READ_PARALLELISM`, MÊME knob que P2b), agrège les partiels. On PROUVE :
//   (1) PARITÉ : parallèle (degré 3) == séquentiel (degré 1) == ORACLE (cold_union_query) — count / group mono
//       + multi-dim / top-N / matérialisation ; ordre final DÉTERMINISTE pour materialize/top-N.
//   (2) 2Go-safe : le PIC de fichiers décodés SIMULTANÉMENT est <= degré, INDÉPENDANT du nombre de fichiers.
//   (3) BENCH : sur BEAUCOUP de fichiers, degré 3 accélère le décode+déchiffrement vs degré 1.
// Sérialisé par `p4a_lock` (compteurs de route + jauge de décode globaux) + `par_env_lock` (le knob d'env, partagé
// avec les tests P2b). Le degré est basculé via l'env var SOUS ces verrous -> pas de course.
// ====================================================================================================

/// Fixture pur-froid MULTI-FICHIERS : `n` lignes variées (`p4a_row`) dans UN jour froid, agées avec un plafond de
/// `file_cap` lignes/fichier -> ~ceil(n/file_cap) fichiers cold. Renvoie la P4aFix + le nombre de fichiers scellés.
fn p6_fixture(tag: &str, n: i64, file_cap: usize) -> (P4aFix, usize) {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let mut conf = conf_union(HOT_WIN);
    conf.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), file_cap.to_string()); // force le split multi-fichiers
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..n {
        insert_event(&db, &p4a_row(base, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid purgé du hot");
    let nfiles = file_seal_rows(&db, "prod", day).len();
    let b = union_boundary(&db, &conf);
    let from = base;
    let to = base + n - 1;
    assert!(to < b, "fenêtre pur-froid (to={to} < b={b})");
    (P4aFix { root, db, dbp, conf, b, from, to }, nfiles)
}

/// Exécute `p4a_plan` (chemin vectorisé pur-froid) à un degré de parallélisme DONNÉ (env sous verrou).
fn p6_plan_at(f: &P4aFix, soql: &str, degree: usize) -> Option<Value> {
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", degree.to_string());
    let v = p4a_plan(f, soql, f.to);
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
    v
}

/// Lignes BRUTES (ORDRE PRÉSERVÉ, non trié) d'un résultat — pour prouver le DÉTERMINISME D'ORDRE (materialize/
/// top-N), là où `p4a_norm` (trié) ne verrait pas une divergence d'ordre.
fn p6_raw_rows(v: &Value) -> Vec<Value> {
    v["rows"].as_array().cloned().unwrap_or_default()
}

/// (1) PARITÉ : parallèle (degré 3) == séquentiel (degré 1) == ORACLE, sur count / group mono+multi-dim / top-N /
/// matérialisation. La parallélisation ne change QUE la vitesse.
#[test]
fn p6_parity_parallel_eq_sequential_eq_oracle() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-parity", 300, 25); // 300/25 -> ~12 fichiers
    assert!(nfiles >= 8, "assez de fichiers pour exercer le pool parallèle (nfiles={nfiles})");
    let cases: &[&str] = &[
        "search | stats count",
        "search severity>=2 | stats count",
        "search source=web | stats count",
        "search source!=web | stats count",
        "search url=~/path/500 | stats count",             // regex
        "search | stats count by source",                   // group mono
        "search | stats count by severity",                 // dim INT
        "search | stats count by source,severity",          // group MULTI-dim
        "search source=web | stats count by host",          // filtre + group
        "search | stats count by source | sort -count | head 2", // top-N desc + head
        "search | stats count by host | sort -count",       // top-N desc sans head
        "search | stats count by source | sort count",      // top-N asc
        "search source=web | table source,severity",        // matérialisation
        "search severity>=1 | table source,severity,url | head 5", // matérialisation + head
    ];
    for soql in cases {
        let oracle = p4a_oracle(&f, soql, f.to);
        let seq = p6_plan_at(&f, soql, 1).unwrap_or_else(|| panic!("séquentiel DOIT router : {soql}"));
        let par = p6_plan_at(&f, soql, 3).unwrap_or_else(|| panic!("parallèle DOIT router : {soql}"));
        p4a_assert_parity(&oracle, &seq, &format!("{soql} [séquentiel(1)==oracle]"));
        p4a_assert_parity(&oracle, &par, &format!("{soql} [parallèle(3)==oracle]"));
        p4a_assert_parity(&seq, &par, &format!("{soql} [parallèle(3)==séquentiel(1)]"));
    }
}

/// (1bis) DÉTERMINISME D'ORDRE : pour la matérialisation (ordre canonique day/seq/position) ET le top-N (count
/// DESC/ASC, tie-break clé), l'ORDRE des lignes rendu est IDENTIQUE degré 1 vs 3 (fusion parallèle ré-imposant
/// l'ordre) ET conforme au canonique (ts croissant pour la matérialisation).
#[test]
fn p6_materialize_and_topn_order_deterministic() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-order", 300, 25); // ~12 fichiers
    assert!(nfiles >= 6, "multi-fichiers (nfiles={nfiles})");

    // MATÉRIALISATION : ordre CANONIQUE == ts croissant (p4a_row insère ts=base+i strictement croissant, préservé
    // par l'aging file/row-group/position).
    let mat = "search | table ts,source | head 60";
    let seq_m = p6_raw_rows(&p6_plan_at(&f, mat, 1).unwrap());
    let par_m = p6_raw_rows(&p6_plan_at(&f, mat, 3).unwrap());
    assert_eq!(seq_m, par_m, "matérialisation : ORDRE des lignes IDENTIQUE degré 1 vs 3");
    assert_eq!(par_m.len(), 60, "head 60 respecté");
    let ts: Vec<i64> = par_m.iter().map(|r| r[0].as_i64().expect("ts entier")).collect();
    let mut sorted = ts.clone();
    sorted.sort_unstable();
    assert_eq!(ts, sorted, "ordre canonique (ts croissant) RÉ-IMPOSÉ après fusion parallèle");

    // TOP-N : ordre count DESC déterministe, IDENTIQUE degré 1 vs 3 (comparaison BRUTE, ordre inclus).
    let topn = "search | stats count by source | sort -count";
    let seq_t = p6_raw_rows(&p6_plan_at(&f, topn, 1).unwrap());
    let par_t = p6_raw_rows(&p6_plan_at(&f, topn, 3).unwrap());
    assert_eq!(seq_t, par_t, "top-N : ORDRE (count DESC, tie-break clé) IDENTIQUE degré 1 vs 3");
}

/// (2) 2Go-safe : le PIC de fichiers décodés SIMULTANÉMENT (jauge test-only = 1 buffer déchiffré + 1 ColumnBatch
/// chacun) est <= degré configuré, INDÉPENDAMMENT du grand nombre de fichiers -> RAM bornée par le POOL, pas par
/// le volume. Preuve à plusieurs degrés + preuve que la concurrence est RÉELLE au degré 4.
#[test]
fn p6_ram_bounded_peak_concurrency_le_degree() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-ram", 300, 10); // ~30 fichiers -> pool saturable (>> degré 4)
    assert!(nfiles >= 20, "BEAUCOUP de fichiers (nfiles={nfiles}) — la RAM ne doit PAS croître avec eux");
    let soql = "search | stats count by source,severity"; // scanne TOUS les fichiers (aucun élagage)
    for degree in [1usize, 2, 3, 4] {
        std::env::set_var("PLUME_COLD_READ_PARALLELISM", degree.to_string());
        decode_gauge_reset();
        let v = p4a_plan(&f, soql, f.to).expect("routé vectorisé");
        let (cur, peak) = decode_gauge();
        std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
        // parité rapide vs oracle à ce degré.
        p4a_assert_parity(&p4a_oracle(&f, soql, f.to), &v, &format!("ram-degré-{degree}"));
        assert_eq!(cur, 0, "jauge revenue à 0 (tous les décodes terminés)");
        assert!(peak >= 1, "au moins 1 fichier décodé (degré {degree})");
        assert!(
            (peak as usize) <= degree,
            "PIC de décodes SIMULTANÉS ({peak}) <= degré ({degree}) — borné par le pool, PAS par les {nfiles} fichiers"
        );
    }
    // CONCURRENCE RÉELLE : au degré 4 sur ~80 fichiers, au moins 2 décodes se chevauchent (sinon pas de gain).
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "4");
    decode_gauge_reset();
    let _ = p4a_plan(&f, soql, f.to).unwrap();
    let (_c, peak4) = decode_gauge();
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
    assert!(peak4 >= 2, "au degré 4 la parallélisation est RÉELLE (pic observé {peak4} >= 2)");
}

/// (3) BENCH : sur BEAUCOUP de fichiers, mesure le décode+déchiffrement au degré 3 vs au degré 1, et
/// vérifie la PARITÉ (résultat identique). Le temps est IMPRIMÉ, il n'est plus ASSERTÉ — voir pourquoi.
///
/// CE COMMENTAIRE AFFIRMAIT UNE PROTECTION QUI N'EXISTAIT PAS. Il disait « le nom contient "bench" ->
/// SKIPPÉ par la suite de non-régression (`--skip bench`) ». Mesuré le 2026-07-30 : le job `cold-tier`
/// de `.github/workflows/ci.yml` lance `cargo test --locked --features cold_tier` **sans aucun
/// `--skip`** (`grep -n skip ci.yml` ne rend aucune option de test). Ce banc tournait donc bel et bien
/// dans la suite qui garde la fusion, et la garde annoncée était imaginaire.
///
/// POURQUOI L'ASSERTION SUR LE TEMPS EST RETIRÉE, et pas seulement assouplie. Une comparaison de temps
/// de mur mesure la MACHINE autant que le code. Mesuré ici sur 12 cœurs occupés par d'autres travaux :
/// séquentiel 147 712 ms, parallèle 616 222 ms — le rapport s'INVERSE d'un facteur 4, et 147 s pour
/// 1 200 lignes est cinq ordres de grandeur au-dessus du plausible (le banc `docs/BENCHMARK.md` scanne
/// 1,4 M lignes en ~3 s). La garde `available_parallelism() >= 3` n'y change rien : un runner GitHub
/// partagé à 4 vCPU l'ARME, sans garantir qu'un décode à 3 fils y batte le séquentiel de 10 %. Cette
/// assertion était donc un générateur de faux échecs sur le seul environnement qu'elle prétendait
/// protéger.
///
/// VÉRIFIÉ QUE L'ASSERTION NE CACHAIT PAS UNE VRAIE RÉGRESSION — c'est la question qu'on doit se poser
/// avant de retirer une garde, et elle a été mesurée plutôt que supposée. Le MÊME test rejoué sur la
/// même machine REDEVENUE AU REPOS (charge 3 au lieu de 16) : séquentiel 47 097 ms, parallèle 18 108 ms,
/// soit **x2,60 de gain RÉEL**. La parallélisation paie donc bel et bien ; les x0,24 et x0,60 observés
/// plus tôt mesuraient l'ordonnanceur, pas le code. Retirer l'assertion ne masque rien.
/// (Et les valeurs absolues n'ont de toute façon aucune valeur publiable : `cargo test` construit en
/// profil DEBUG, non optimisé — d'où 47 s là où le binaire release du harnais `bench/` scanne 1,4 M
/// lignes en ~3 s. Une raison de plus pour que le chiffre de perf vive dans `bench/` et pas ici.)
///
/// ET ELLE N'APPORTAIT AUCUNE COUVERTURE. La parallélisation est déjà prouvée juste au-dessus, par
/// OBSERVATION DE LA CONCURRENCE et non par chronomètre : `p6_ram_*` lit une jauge de décodes
/// simultanés et exige `pic <= degré` (borné par le pool, pas par le nombre de fichiers) puis
/// `pic >= 2` au degré 4 (chevauchement RÉEL). Ces assertions sont indépendantes de la charge.
/// Le chiffre de performance, lui, appartient au harnais de mesure (`bench/`, `docs/BENCHMARK.md`),
/// qui contrôle la pression mémoire et refuse une série prise sous swap — ce qu'un `cargo test`
/// ne peut pas faire.
///
/// CE QUI RESTE ASSERTÉ ICI, et c'est le vrai contenu du test : la PARITÉ séquentiel == parallèle ==
/// oracle. Un décode parallèle qui rendrait un résultat différent est un défaut de corrélation
/// silencieux — exactement le mode de panne redouté du tier froid.
#[test]
fn p6_bench_parallel_vs_sequential_decode() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let n = 1200i64; // < cap 5000 -> routé vectorisé
    let (f, nfiles) = p6_fixture("p6-bench", n, 30); // ~40 fichiers (assez pour voir le gain décode/déchiffrement)
    let iters = 2;
    let soql = "search | stats count by source,severity"; // scanne tous les fichiers (décode dominant)

    // PARITÉ (une fois) : séquentiel(1) == parallèle(3) == oracle.
    let seq_v = p6_plan_at(&f, soql, 1).unwrap();
    let par_v = p6_plan_at(&f, soql, 3).unwrap();
    p4a_assert_parity(&p4a_oracle(&f, soql, f.to), &par_v, "bench parité vs oracle");
    p4a_assert_parity(&seq_v, &par_v, "bench parité seq==par");

    let run = |degree: usize| -> f64 {
        std::env::set_var("PLUME_COLD_READ_PARALLELISM", degree.to_string());
        let t = std::time::Instant::now();
        for _ in 0..iters {
            assert!(p4a_plan(&f, soql, f.to).unwrap().get("columns").is_some());
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
        std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
        ms
    };
    let seq_ms = run(1);
    let par_ms = run(3);
    println!(
        "P6 BENCH (n={n}, {nfiles} fichiers, {iters} iters): séquentiel(1) {seq_ms:.2}ms  parallèle(3) {par_ms:.2}ms  x{:.2}",
        seq_ms / par_ms.max(1e-6)
    );
    // Le rapport est IMPRIMÉ, jamais asserté (cf. l'en-tête du test) : sur une machine chargée il
    // s'inverse, et l'inversion mesurerait l'ordonnanceur, pas le code. Un rapport < 1 sur un runner
    // occupé n'est donc PAS un défaut — le défaut serait une divergence de RÉSULTAT, et c'est ce que
    // les assertions de parité ci-dessus interdisent.
    let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1);
    println!(
        "P6 BENCH: {cores} cœurs visibles — rapport séquentiel/parallèle x{:.2} (INDICATIF, non asserté ; \
         le chiffre publiable est celui du harnais `bench/`, qui contrôle la pression mémoire)",
        seq_ms / par_ms.max(1e-6)
    );
}

// ====================================================================================================
// #18 P6 — TESTS ADVERSES (AJOUTÉS ; le code PROD n'est PAS modifié). But : casser un invariant du
// parallélisme borné. Chaque test RÉPÈTE la requête PARALLÈLE plusieurs fois (le non-déterminisme
// d'ordonnancement des threads se cache dans 1 run sur N) en AMORTISSANT l'oracle (coûteux : déchiffrement
// age/scrypt par fichier) — calculé UNE fois, comparé à K exécutions parallèles. Vecteurs : (A) parité
// par==seq==oracle sur clés CHEVAUCHANTES, (B) déterminisme d'ORDRE brut (materialize/top-N) multi-run,
// (C) borne RAM (pic gauge <= degré) sous BEAUCOUP de fichiers, (D) fail-closed sans deadlock ni résultat
// partiel sur fichier corrompu au MILIEU du décode parallèle. Fixtures VOLONTAIREMENT petites (~8-12
// fichiers) : le déchiffrement domine, mais >= degré suffit à exercer le pool. Sérialisation identique aux
// p6_* : p4a_lock (compteurs/jauge globaux) + par_env_lock (knob d'env).
// ====================================================================================================

/// Nombre de répétitions de la requête PARALLÈLE par cas (stress du non-déterminisme d'ordonnancement).
const P6_ADV_REPEAT: usize = 6;

/// (A) PARITÉ MULTI-RUN, clés CHEVAUCHANTES. `p6_fixture` répartit source(web/api/db)/severity(0..3)/
/// host(h0..h4)/src_ip cycliquement -> CHAQUE fichier contient les MÊMES clés -> la fusion parallèle DOIT
/// SOMMER par clé (jamais perdre/dupliquer). Oracle calculé UNE fois/cas ; séquentiel (deg 1) + K exécutions
/// parallèles (deg 3) comparées à l'oracle. Toute divergence (même 1 exécution sur K) = merge cassé / course.
#[test]
fn p6_adv_multirun_parity_overlapping_keys() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-adv-parity", 160, 20); // ~8 fichiers, clés très chevauchantes
    assert!(nfiles >= 6, "assez de fichiers aux clés répétées (nfiles={nfiles})");
    let cases: &[&str] = &[
        "search | stats count",
        "search | stats count by source,severity",       // multi-dim, clés dans TOUS les fichiers
        "search | stats count by host,src_ip",            // multi-dim, forte redondance inter-fichiers
        "search | stats count by source | sort -count",   // top-N desc (liste complète)
        "search source=web | table source,severity,host | head 40", // materialize borné
    ];
    for soql in cases {
        let oracle = p4a_oracle(&f, soql, f.to);
        // séquentiel (chemin sans thread = oracle interne).
        let seq = p6_plan_at(&f, soql, 1).unwrap_or_else(|| panic!("séquentiel DOIT router : {soql}"));
        p4a_assert_parity(&oracle, &seq, &format!("{soql} [seq(1)==oracle]"));
        // K exécutions PARALLÈLES (deg 3) — chacune re-décode/re-fusionne avec un ordonnancement potentiellement
        // différent ; toutes DOIVENT égaler l'oracle.
        for rep in 0..P6_ADV_REPEAT {
            let v = p6_plan_at(&f, soql, 3).unwrap_or_else(|| panic!("parallèle DOIT router : {soql}"));
            p4a_assert_parity(&oracle, &v, &format!("{soql} [par(3) rep{rep}==oracle]"));
        }
    }
}

/// (B) DÉTERMINISME d'ORDRE BRUT MULTI-RUN. Là où `p4a_norm` TRIE (masque un désordre), on compare l'ordre
/// BRUT (`p6_raw_rows`) : la matérialisation (ordre canonique day/seq/position) ET le top-N (count DESC/ASC,
/// tie-break clé) doivent rendre EXACTEMENT la MÊME séquence à CHAQUE exécution parallèle. On choisit un
/// top-N à ÉGALITÉS MASSIVES (host h0..h4 équi-répartis -> tous à count égal) pour maximiser le stress du
/// tie-break sous fusion parallèle non ordonnée.
#[test]
fn p6_adv_order_determinism_multirun() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-adv-order", 160, 20); // ~8 fichiers
    assert!(nfiles >= 6, "multi-fichiers (nfiles={nfiles})");

    let mat = "search | table ts,source,host | head 77"; // head < total (160) -> troncature canonique
    let topn = "search | stats count by host | sort -count"; // ties massifs -> tie-break clé
    // Référence séquentielle (degré 1 = aucun thread).
    let mat_ref = p6_raw_rows(&p6_plan_at(&f, mat, 1).unwrap());
    let topn_ref = p6_raw_rows(&p6_plan_at(&f, topn, 1).unwrap());
    assert_eq!(mat_ref.len(), 77, "head 77 respecté");
    // Ordre canonique attendu : ts STRICTEMENT croissant (insertion ts=base+i, préservé par l'aging).
    let ts: Vec<i64> = mat_ref.iter().map(|r| r[0].as_i64().expect("ts entier")).collect();
    let mut ts_sorted = ts.clone();
    ts_sorted.sort_unstable();
    assert_eq!(ts, ts_sorted, "materialize : ordre canonique ts croissant (degré 1)");
    assert!(topn_ref.len() >= 3, "top-N host multi-groupes (len={})", topn_ref.len());

    // K exécutions PARALLÈLES (deg 3) : ordre BRUT DOIT être identique à la référence à chaque fois.
    for rep in 0..P6_ADV_REPEAT {
        let m = p6_raw_rows(&p6_plan_at(&f, mat, 3).unwrap());
        assert_eq!(m, mat_ref, "rep{rep} : ORDRE materialize BRUT (deg 3) doit être STABLE == séquentiel");
        let t = p6_raw_rows(&p6_plan_at(&f, topn, 3).unwrap());
        assert_eq!(t, topn_ref, "rep{rep} : ORDRE top-N BRUT (tie-break clé, deg 3) doit être STABLE");
    }
}

/// (C) BORNE RAM : sous BEAUCOUP de fichiers (>> degré), le PIC de décodes SIMULTANÉS (jauge = buffers
/// déchiffrés en vol) ne dépasse JAMAIS le degré. Prouve que le `sync_channel(degree)` borne la concurrence
/// (RAM par le POOL, pas par le volume). On lit aussi `cur==0` post-requête (aucun worker pendu) et on exige
/// une concurrence RÉELLE observée (pic>=2). Répété pour débusquer un pic transitoire > degré.
#[test]
fn p6_adv_gauge_bound_multirun_high_filecount() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-adv-ram", 240, 12); // ~20 fichiers (>> degré 4)
    assert!(nfiles >= 12, "fichiers >> degré (nfiles={nfiles})");
    let soql = "search | stats count by source,severity"; // scanne TOUS les fichiers (aucun élagage)
    let oracle = p4a_oracle(&f, soql, f.to);
    let mut ever_peak = 0u64;
    for rep in 0..2 {
        for degree in [2usize, 3, 4] {
            std::env::set_var("PLUME_COLD_READ_PARALLELISM", degree.to_string());
            decode_gauge_reset();
            let v = p4a_plan(&f, soql, f.to).expect("routé vectorisé");
            let (cur, peak) = decode_gauge();
            std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
            p4a_assert_parity(&oracle, &v, &format!("rep{rep} deg{degree} ram-parité"));
            assert_eq!(cur, 0, "rep{rep} deg{degree} : jauge revenue à 0 (aucun worker pendu)");
            assert!(peak >= 1, "rep{rep} deg{degree} : au moins 1 décode");
            assert!(
                (peak as usize) <= degree,
                "rep{rep} deg{degree} : PIC décodes SIMULTANÉS ({peak}) > degré malgré {nfiles} fichiers = RAM NON bornée"
            );
            ever_peak = ever_peak.max(peak);
        }
    }
    assert!(ever_peak >= 2, "concurrence RÉELLE jamais observée (pic max {ever_peak}) — le pool ne parallélise pas ?");
}

/// (D) FAIL-CLOSED SANS DEADLOCK : un fichier corrompu AU MILIEU de l'ensemble scanné en parallèle doit faire
/// ÉCHOUER la requête ENTIÈRE (Err), JAMAIS rendre un count partiel silencieux (= données manquantes), et
/// JAMAIS pendre le join du `thread::scope`. WATCHDOG : la requête tourne dans un thread ; si elle ne rend pas
/// en 45 s -> panique « DEADLOCK ». On code le résultat (0=Err attendu, 1=Ok(None), 2=Ok(Some)=PARTIEL suspect,
/// 3=panic worker) pour distinguer un vrai résultat partiel d'un simple Err. Répété à degrés 2/3/4.
#[test]
fn p6_adv_corruption_midset_failclosed_no_deadlock() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let (f, nfiles) = p6_fixture("p6-adv-corrupt", 160, 16); // ~10 fichiers
    assert!(nfiles >= 6, "assez de fichiers pour un décode parallèle réel (nfiles={nfiles})");
    let day = M - 10; // p6_fixture âge ce jour
    let cold = cold_root(&f.conf, &f.dbp);
    let seals = file_seal_rows(&f.db, "prod", day);
    assert!(seals.len() >= 6, "seals={}", seals.len());
    // Fichier VICTIME au MILIEU (ni premier ni dernier -> l'Err survient en plein décode parallèle, pas au bord).
    let victim = &seals[seals.len() / 2];
    let p = file_path(&cold, "prod", day, victim.seq);
    let mut bytes = std::fs::read(&p).expect("lecture fichier victime");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    bytes[mid / 2] ^= 0xFF; // 2 octets pour maximiser l'échec de déchiffrement/décode
    std::fs::write(&p, &bytes).expect("écriture fichier corrompu");

    // Toutes les lignes sont DANS la fenêtre -> fichiers « couverts » -> window_rows_capped compte GRATUITEMENT
    // (seal, aucun décode) et PASSE le gate cap ; la corruption ne surgit donc QUE dans le décode PARALLÈLE de
    // l'agrégat (scan_group), exactement le chemin visé.
    let soql = "search | stats count by source,severity";
    for degree in [2usize, 3, 4] {
        std::env::set_var("PLUME_COLD_READ_PARALLELISM", degree.to_string());
        decode_gauge_reset();
        let (dbp, conf, from, to, b) = (f.dbp.clone(), f.conf.clone(), f.from, f.to, f.b);
        let sq = soql.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<(i32, i64)>();
        let handle = std::thread::spawn(move || {
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match cold_vectorized_try(&dbp, &conf, None, from, to, b, &sq, true, 60_000, &[]) {
                    Ok(Some(v)) => (2i32, v["rows"][0][0].as_i64().unwrap_or(-1)), // ROUTÉ un résultat = PARTIEL ?!
                    Ok(None) => (1i32, -1),
                    Err(_) => (0i32, -1),
                }
            }))
            .unwrap_or((3i32, -1)); // panic d'un worker propagée au join du scope
            let _ = tx.send(out);
        });
        let (code, partial) = match rx.recv_timeout(std::time::Duration::from_secs(45)) {
            Ok(v) => v,
            Err(_) => panic!("deg{degree} : DEADLOCK — cold_vectorized_try n'a pas rendu en 45 s (join du scope pendu ?)"),
        };
        handle.join().expect("thread watchdog joint");
        let (cur, _peak) = decode_gauge();
        std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
        assert_ne!(code, 2, "deg{degree} : fichier corrompu mais un RÉSULTAT PARTIEL a été rendu (count={partial}) — DONNÉES MANQUANTES silencieuses");
        assert_ne!(code, 3, "deg{degree} : PANIC d'un worker (devrait être une Err propre, pas un unwind)");
        assert_eq!(code, 0, "deg{degree} : corruption -> Err fail-closed attendue (code={code})");
        assert_eq!(cur, 0, "deg{degree} : jauge=0 après échec (aucun worker pendu / fuite de compteur)");
    }
}

/// (D-bis) INTÉGRITÉ APRÈS ÉCHEC : après qu'un fichier corrompu a fait échouer la requête (l'abort/la jauge
/// sont locaux à l'appel), une requête sur une fixture SAINE au MÊME degré rend un résultat CORRECT == oracle.
/// Prouve qu'aucun `abort`/canal résiduel ne contamine les requêtes suivantes.
#[test]
fn p6_adv_healthy_after_corruption_failure() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    // 1) une fixture corrompue échoue (degré 3).
    let (fc, nfc) = p6_fixture("p6-adv-after-c", 120, 16); // ~8 fichiers
    assert!(nfc >= 5);
    let day = M - 10;
    let seals = file_seal_rows(&fc.db, "prod", day);
    let victim = &seals[seals.len() / 2];
    let p = file_path(&cold_root(&fc.conf, &fc.dbp), "prod", day, victim.seq);
    let mut bytes = std::fs::read(&p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&p, &bytes).unwrap();
    let soql = "search | stats count by source,severity";
    // Appel DIRECT (pas p4a_plan qui `.unwrap()` la Result -> paniquerait sur l'Err attendue).
    std::env::set_var("PLUME_COLD_READ_PARALLELISM", "3");
    let bad = cold_vectorized_try(&fc.dbp, &fc.conf, None, fc.from, fc.to, fc.b, soql, true, 60_000, &[]);
    std::env::remove_var("PLUME_COLD_READ_PARALLELISM");
    assert!(bad.is_err(), "fixture corrompue -> Err");

    // 2) une fixture SAINE au MÊME degré -> résultat correct == oracle (aucune contamination d'état).
    let (fh, nfh) = p6_fixture("p6-adv-after-h", 120, 16);
    assert!(nfh >= 5);
    let v = p6_plan_at(&fh, soql, 3).expect("saine -> routé vectorisé");
    p4a_assert_parity(&p4a_oracle(&fh, soql, fh.to), &v, "saine après échec corrompu");
}

// ====================================================================================================
// ①a — MATÉRIALISATION KEYSET du BRUT FROID (browse Explore raw par curseur, SANS cap).
// PROUVE l'invariant DÉPLOIEMENT :
//   • COMPLÉTUDE / PARITÉ : paginer keyset TOUTE la fenêtre (hot∪cold, > cap) rend EXACTEMENT l'ensemble du scan
//     raw complet (oracle = `cold_union_query` à cap large, ORDRE `ts,id` desc), CHAQUE ligne UNE FOIS, ZÉRO trou/
//     dup — y compris aux frontières de PAGE, de FICHIER, et de la frontière HOT/COLD, avec des TIES massifs.
//   • SANS CAP : le chemin colonnaire paginé rend les `n_cold+n_hot` lignes alors que le cap d'hydratation
//     (`PLUME_QUERY_MAX`) est ÉCRASÉ à 20 << volume (le chemin `cold_union_query` capé TRONQUE, lui — prouvé).
//   • 2Go-safe : chaque page rend <= `n` lignes (RAM bornée à la page), quel que soit le volume/nb de fichiers.
// ====================================================================================================

/// Fixture keyset : cold jour M-10 (multi-fichiers via `file_cap`) avec `n_cold_ts` ts DISTINCTS × `ties` lignes au
/// MÊME ts (tie-break éprouvé) + `n_hot` lignes HOT jour M-1 (au-dessus de la frontière), TOUTES `source=auditd`.
/// Renvoie (fixture window from=0/to=0 = non bornée, n_cold, n_hot, nfiles).
fn ks_fixture(tag: &str, n_cold_ts: i64, ties: i64, n_hot: i64, file_cap: usize) -> (P4aFix, i64, i64, usize) {
    let root = tmp_root(tag);
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let mut conf = conf_union(HOT_WIN);
    conf.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), file_cap.to_string()); // force le split multi-fichiers
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let mut idx = 0i64;
    for t in 0..n_cold_ts {
        for _ in 0..ties {
            let mut r = rich_row(base + t, idx); // ts = base+t (TIES : `ties` lignes au même ts)
            r.row.source = "auditd".to_string();
            insert_event(&db, &r);
            idx += 1;
        }
    }
    insert_recent_tail_holder(&db); // source=recent-tail (exclue du filtre source=auditd) -> tail hot, ager OK
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid purgé du hot");
    let nfiles = file_seal_rows(&db, "prod", day).len();
    // HOT auditd au-dessus de la frontière (jour M-1, fenêtre chaude -> jamais agé).
    let hbase = (M - 1) * SECS_PER_DAY;
    for h in 0..n_hot {
        let mut r = rich_row(hbase + h, 70_000 + h);
        r.row.source = "auditd".to_string();
        insert_event(&db, &r);
    }
    let b = union_boundary(&db, &conf);
    (P4aFix { root, db, dbp, conf, b, from: 0, to: 0 }, n_cold_ts * ties, n_hot, nfiles)
}

/// Enlève la colonne `id` d'un résultat {columns,rows} -> lignes comparables (l'`id` cold est SYNTHÉTIQUE, l'`id`
/// oracle est un rowid éphémère ; l'invariant porte sur les VALEURS + l'ORDRE, pas sur la valeur d'`id`).
fn ks_rows_no_id(v: &Value) -> Vec<Vec<Value>> {
    let cols: Vec<&str> = v["columns"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    let id_i = cols.iter().position(|c| *c == "id").expect("colonne id présente");
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let a = r.as_array().unwrap();
            a.iter().enumerate().filter(|(i, _)| *i != id_i).map(|(_, x)| x.clone()).collect()
        })
        .collect()
}

/// UNE page keyset hot-puis-cold SÉQUENTIELLE — RÉPLIQUE EXACTE de la logique du handler `cold_keyset_vectorized_page`
/// (inaccessible depuis ce module) : HOT (keyset SQLite borné `ts>=b`) puis COMPLÉTION COLD (`cold_keyset_page`).
fn ks_page(f: &P4aFix, base_sql: &str, cursor: Option<(i64, i64)>, n: i64) -> Value {
    let pure_cold = matches!(cursor, Some((cts, _)) if cts < f.b);
    let mut rows: Vec<Value> = Vec::new();
    let hot_cols: Option<Vec<Value>> = if pure_cold {
        None
    } else {
        let hot_sql = format!("SELECT * FROM ({base_sql}) WHERE ts >= {}", f.b);
        let page_sql = crate::page_sql(&hot_sql, crate::keyset_plan(cursor, 0), n);
        let hv = crate::run_query_ex(&f.dbp, &page_sql, 60_000, None).unwrap();
        for r in hv["rows"].as_array().unwrap() {
            rows.push(r.clone());
        }
        Some(hv["columns"].as_array().unwrap().clone())
    };
    let hot_count = rows.len() as i64;
    let cold_limit = if pure_cold { n } else { (n - hot_count).max(0) };
    let cold_cursor = if pure_cold { cursor } else { None };
    let (cold_cols, cold_rows) = if cold_limit > 0 {
        cold_keyset_page(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search source=auditd", true, cold_cursor, cold_limit as usize, &[])
            .unwrap()
            .expect("bare search auditd DOIT être routable (keyset vectorisé)")
    } else {
        (Vec::new(), Vec::new())
    };
    let columns: Vec<Value> = match &hot_cols {
        Some(hc) => hc.clone(),
        None => cold_cols.iter().map(|s| json!(s)).collect(),
    };
    for r in cold_rows {
        rows.push(Value::Array(r));
    }
    let mut v = json!({ "columns": columns, "rows": rows, "stats": { "truncated": false } });
    crate::keyset_finalize(&mut v, n);
    v
}

#[test]
fn ks_full_traversal_hot_cold_eq_raw_scan_no_gap_no_dup() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    // 20 ts × 3 ties = 60 cold + 15 hot = 75 lignes ; 8 lignes/fichier -> ~8 fichiers cold (frontières de fichier).
    let (f, n_cold, n_hot, nfiles) = ks_fixture("ks-full", 20, 3, 15, 8);
    assert!(nfiles >= 6, "assez de fichiers cold pour éprouver les frontières de fichier (nfiles={nfiles})");
    let total = n_cold + n_hot;
    let base_sql = crate::soql_to_sql_masked_keyset_x("search source=auditd", f.from, f.to, None, &FieldMaskSet::new()).unwrap();

    // ORACLE = scan raw COMPLET (cap large -> aucune troncature), ordre ts,id desc.
    std::env::set_var("PLUME_QUERY_MAX", "100000");
    let oracle_page = crate::page_sql(&base_sql, crate::keyset_plan(None, 0), 100_000);
    let (oracle_v, _t, ometa) =
        union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &oracle_page, None, 60_000, None, &[]).unwrap();
    assert!(!ometa.truncated, "oracle (cap large) doit être COMPLET");
    let oracle_rows = ks_rows_no_id(&oracle_v);
    assert_eq!(oracle_rows.len() as i64, total, "oracle = toutes les lignes hot∪cold");
    std::env::remove_var("PLUME_QUERY_MAX");

    // SANS CAP : on ÉCRASE le cap d'hydratation à 20 << 60 cold. Le chemin `cold_union_query` capé TRONQUE (preuve
    // de la limite de l'ancien chemin) ; le chemin keyset colonnaire, lui, pagine TOUT.
    std::env::set_var("PLUME_QUERY_MAX", "20");
    let capped_page = crate::page_sql(&base_sql, crate::keyset_plan(None, 0), 100_000);
    let (_cv, _ct, cmeta) =
        union_query_oracle(&f.dbp, &f.conf, None, f.from, f.to, f.b, &capped_page, None, 60_000, None, &[]).unwrap();
    assert!(cmeta.truncated, "sous cap=20, l'ancien chemin cold_union_query TRONQUE (60 cold > 20)");

    // PARCOURS KEYSET INTÉGRAL (page=7, curseur), cap TOUJOURS à 20 -> prouve l'indépendance au cap.
    let n = 7i64;
    let mut cursor: Option<(i64, i64)> = None;
    let mut seen: Vec<Vec<Value>> = Vec::new();
    let mut pages = 0usize;
    loop {
        let mut v = ks_page(&f, &base_sql, cursor, n);
        let page_len = v["rows"].as_array().unwrap().len() as i64;
        assert!(page_len <= n, "2Go-safe : une page borne la RAM à <= n lignes (page_len={page_len})");
        seen.extend(ks_rows_no_id(&v));
        crate::keyset_finalize(&mut v, n); // idempotent (déjà appelé) ; garantit has_more/next_cursor cohérents
        pages += 1;
        if !v["has_more"].as_bool().unwrap() {
            assert!(v["next_cursor"].is_null(), "dernière page -> next_cursor null");
            break;
        }
        let nc = &v["next_cursor"];
        cursor = Some((nc["ts"].as_i64().unwrap(), nc["id"].as_i64().unwrap()));
        assert!(pages < (total as usize + 10), "garde-fou anti-boucle infinie");
    }
    std::env::remove_var("PLUME_QUERY_MAX");

    // COMPLÉTUDE + ORDRE : la concaténation de toutes les pages == le scan raw complet, ligne par ligne (ordre
    // ts,id desc). Égalité de Vec ORDONNÉS -> zéro trou, zéro dup, zéro désordre, aux frontières page/fichier/boundary.
    assert_eq!(seen.len() as i64, total, "keyset paginé rend EXACTEMENT toutes les lignes (aucune manquante/dup)");
    assert_eq!(seen, oracle_rows, "keyset paginé (hot∪cold, sans cap) == scan raw complet, ordre ts,id desc");
    // Traversée MULTI-PAGES réelle (pas tout en une page) qui FRANCHIT la frontière hot->cold.
    assert!(pages >= (total as usize) / (n as usize), "plusieurs pages parcourues (pages={pages})");
}

/// GATE du browse KEYSET colonnaire : ARMÉ par défaut, `=0` le désarme. Le défaut a changé parce que le
/// fallback (`cold_union_query` keyset) hydrate au plus `cold_hydrate_row_cap` lignes PUIS filtre le
/// curseur : il est STRUCTURELLEMENT incapable de paginer au-delà du plafond, donc de montrer l'histoire
/// froide. Les autres refus (masque actif, forme agrégat) restent inchangés.
#[test]
fn ks_gate_armed_by_default_opt_out_and_unsupported_shapes_fall_back() {
    let _lk = p4a_lock();
    let (f, _nc, _nh, _nf) = ks_fixture("ks-gate", 6, 2, 3, 8);
    let mut dflt = f.conf.clone();
    dflt.remove("PLUME_COLD_VECTORIZED");
    let r_d = cold_keyset_page(&f.dbp, &dflt, None, f.from, f.to, f.b, "search source=auditd", true, None, 10, &[]).unwrap();
    assert!(r_d.is_some(), "GATE 0 ABSENT = défaut -> ARMÉ -> browse keyset colonnaire (parcours intégral)");
    let mut off = f.conf.clone();
    off.insert("PLUME_COLD_VECTORIZED".to_string(), "0".to_string());
    let r = cold_keyset_page(&f.dbp, &off, None, f.from, f.to, f.b, "search source=auditd", true, None, 10, &[]).unwrap();
    assert!(r.is_none(), "opt-out explicite `=0` -> None (fallback cold_union_query capé)");
    // Masque actif -> None aussi (fallback), même gate ON.
    let r2 = cold_keyset_page(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search source=auditd", false, None, 10, &[]).unwrap();
    assert!(r2.is_none(), "masks_empty=false -> None (fallback)");
    // Forme non supportée (agrégat) -> None (fallback).
    let r3 = cold_keyset_page(&f.dbp, &f.conf, None, f.from, f.to, f.b, "search source=auditd | stats count", true, None, 10, &[]).unwrap();
    assert!(r3.is_none(), "forme agrégat -> None (fallback)");
}

/// GATE MONO-ENV. Deux envs (`prodA`/`prodB`) portent des lignes cold au MÊME `ts` :
/// l'id synthétique `seq*COLD_FILE_MAX_ROWS+position` COLLIDERAIT entre envs (`seq` redémarre par `(env,day)`) ->
/// clé de curseur `(ts,id)` non unique -> gap/dup. Le fix : browse env-NON-scopé (`env_filter=None`) avec >1 env
/// distinct -> `cold_keyset_page` renvoie `None` (FALLBACK `cold_union_query`, rowid oracle GLOBAL unique, capé mais
/// correct). Browse env-SCOPÉ (`Some`) -> routable (id unique DANS un env). Sans le fix, le non-scopé servirait des
/// pages aux ids collidés (ligne SOC ratée) ; ce test échouerait (Some au lieu de None).
#[test]
fn ks_multi_env_unscoped_falls_back_scoped_serves() {
    let _lk = p4a_lock();
    let _el = par_env_lock();
    let root = tmp_root("ks-multienv");
    let db = mkdb(&root);
    let dbp = dbp(&root);
    let mut conf = conf_union(HOT_WIN);
    conf.insert("PLUME_COLD_FILE_MAX_ROWS".to_string(), "8".to_string()); // split -> plusieurs seq/env
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    // MÊME plage `ts` pour les DEUX envs -> collisions `ts` inter-env (le cœur du Finding 1).
    let mut idx = 0i64;
    for env in ["prodA", "prodB"] {
        for t in 0..12 {
            let mut r = rich_row(base + t, idx);
            r.row.source = "auditd".to_string();
            r.row.env_id = Some(env.to_string());
            insert_event(&db, &r);
            idx += 1;
        }
    }
    insert_recent_tail_holder(&db); // tail hot -> aging OK
    cold_age_run(&db, &dbp, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prodA", day), 0, "prodA agé en froid");
    assert_eq!(count_hot_day(&db, "prodB", day), 0, "prodB agé en froid");
    let b = union_boundary(&db, &conf);

    // NON-SCOPÉ (env_filter=None) + 2 envs distincts -> None (fallback oracle). C'EST le fix Finding 1.
    let unscoped = cold_keyset_page(&dbp, &conf, None, 0, 0, b, "search source=auditd", true, None, 10, &[]).unwrap();
    assert!(unscoped.is_none(), "multi-env non-scopé -> None (fallback oracle ; évite la collision d'id synthétique)");

    // SCOPÉ prodA -> routable (id unique dans un env), rend ses 12 lignes cold.
    let scoped = cold_keyset_page(&dbp, &conf, Some("prodA"), 0, 0, b, "search source=auditd", true, None, 100, &[]).unwrap();
    let (cols, rows) = scoped.expect("env-scopé (mono-env) DOIT être routable");
    assert!(cols.iter().any(|c| c == "id"), "colonne id synthétique présente");
    assert_eq!(rows.len(), 12, "prodA scopé rend ses 12 lignes (page 1, limite 100)");
    let _ = std::fs::remove_dir_all(&root);
}

// ====================================================================================================
// ALIAS DE LECTURE CIM (`exec` ⊃ `process`) — ANTI-DIVERGENCE DE ROUTE. Dette de migration expirant le
// 2027-07-23 ; ce test se retire AVEC elle (cf. `soql_glue::cim_read_alias_exec`).
// ====================================================================================================

/// L'alias est posé à l'ÉMISSION SQL (store) ; le moteur colonnaire, lui, parse le GXQL LUI-MÊME. Une
/// requête `category=exec` DOIT donc être refusée par les mappeurs vectorisés, sinon la route rapide
/// rendrait `category='exec'` (sans l'historique) là où l'oracle `cold_union_query` rend
/// `IN ('exec','process')` : DEUX réponses pour UNE question, selon la route choisie, en silence.
/// MUTATION : retirer la garde `carries_cim_read_alias` de `map_soql`/`map_keyset_soql` -> rouge.
#[test]
fn cim_aliased_query_is_never_vectorized() {
    assert!(planner::carries_cim_read_alias("search category=exec"), "la requête aliasée doit être reconnue");
    assert!(!planner::vec_agg_routable("search category=exec | stats count"), "agrégat aliasé vectorisé -> divergence");
    assert!(!planner::vec_keyset_routable("search category=exec"), "keyset aliasé vectorisé -> divergence");
    // TÉMOIN : la garde ne condamne QUE les requêtes aliasées — la même forme sans l'alias reste routée.
    assert!(!planner::carries_cim_read_alias("search category=auth"));
    assert!(planner::vec_agg_routable("search category=auth | stats count"), "la garde ne doit pas assommer la route");
    assert!(planner::vec_keyset_routable("search category=auth"), "la garde ne doit pas assommer le keyset");
}

// ====================================================================================================
// PARITÉ CHAUD/FROID — LE TEST QUI MANQUAIT.
// ----------------------------------------------------------------------------------------------------
// CE QU'IL FERME. Rien, dans cette suite, ne comparait la réponse AVEC et SANS tier froid. Les harnais
// p4a/p4b comparent le chemin ROUTÉ au chemin d'UNION — deux chemins froids — et prennent le second pour
// oracle. Quand le second s'est mis à agréger sur un échantillon de 5 000 lignes, ils sont restés VERTS :
// ils prouvaient l'égalité de deux réponses également fausses. Le banc, lui, a vu `stats count` rendre 289
// au lieu de 58 747 (×203) — mais un banc est une OBSERVATION, il ne barre pas la route à une régression.
//
// L'INVARIANT TESTÉ, DÉRIVÉ (et non « la cellule C1 doit valoir 58 747 ») :
//   (1) RIEN DE FAUX     — toute ligne rendue par le chemin froid apparaît VERBATIM dans la réponse VRAIE
//                          (celle du MÊME SQL sur les MÊMES lignes, avant columnarisation, sans plafond).
//   (2) RIEN D'AMPUTÉ EN SILENCE — si le chemin froid rend MOINS de lignes que la vérité, il DOIT le
//                          déclarer (`stats.truncated`) ou REFUSER. Jamais un sous-ensemble présenté
//                          comme complet.
// Ces deux clauses valent pour TOUTE forme : un `stats count` (une seule ligne) ne peut satisfaire (1)
// qu'en étant EXACT — c'est exactement le ×203 qui échoue ici. Une matérialisation partielle, elle, les
// satisfait toutes les deux : ses lignes sont vraies et son incomplétude est dite.
//
// LA FAMILLE EST DÉRIVÉE DU SCHÉMA, pas énumérée : produit de `PARQUET_COLS` (les colonnes RÉELLES du
// tier froid) par trois formes, plus les seuils de `severity`. Ajouter une colonne au tier froid ajoute
// ses cas de parité sans qu'on écrive une ligne de plus ici.
// ====================================================================================================

/// La RÉPONSE VRAIE : le MÊME SQL compilé, exécuté sur les MÊMES lignes AVANT columnarisation, SANS le
/// plafond de sortie de `run_on_conn`. C'est la référence « sans tier froid » — la seule qui puisse
/// arbitrer, puisque les deux chemins froids peuvent se tromper ensemble.
fn true_rows(conn: &Connection, sql: &str) -> Vec<String> {
    let mut st = conn.prepare(sql).expect("prepare référence");
    let ncol = st.column_count();
    let mut rows = st.query([]).expect("query référence");
    let mut out: Vec<String> = Vec::new();
    while let Some(r) = rows.next().expect("step référence") {
        let cells: Vec<Value> = (0..ncol)
            .map(|i| match r.get_ref(i).expect("cell") {
                rusqlite::types::ValueRef::Null => Value::Null,
                rusqlite::types::ValueRef::Integer(n) => json!(n),
                rusqlite::types::ValueRef::Real(f) => json!(f),
                rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                rusqlite::types::ValueRef::Blob(b) => json!(format!("<blob {} o>", b.len())),
            })
            .collect();
        out.push(Value::Array(cells).to_string());
    }
    out.sort();
    out
}

/// SERT COMME LA PRODUCTION : routeur vectorisé d'abord (pur-froid ou merge selon la fenêtre, comme
/// `handlers::query`), puis chemin d'union — et, sur ce dernier, l'INVARIANT DE RENDU (`ColdAnswer::render`
/// avec la forme DÉRIVÉE du GXQL). `Err` = REFUS explicite, exactement ce que le handler transforme en 422.
/// (La route de rollups, essayée avant tout ça par le handler, n'a rien à servir ici : aucune table de
/// rollup n'est alimentée dans ces fixtures.)
fn serve_like_prod(f: &P4aFix, soql: &str, from: i64, to: i64) -> Result<Value, String> {
    let pure_cold = to > 0 && to < f.b;
    let routed = if pure_cold {
        cold_vectorized_try(&f.dbp, &f.conf, None, from, to, f.b, soql, true, 60_000, &[])?
    } else {
        cold_vectorized_merge_try(&f.dbp, &f.conf, None, from, to, f.b, soql, true, 60_000, None, &[])?
    };
    if let Some(v) = routed {
        return Ok(v);
    }
    let sql = compile_ev(soql, from, to, FieldMaskSet::new());
    let (answer, _meta) = cold_union_query(&f.dbp, &f.conf, None, from, to, f.b, &sql, None, 60_000, None, &[])?;
    answer.render(AnswerShape::of_gxql(soql)).map(|r| {
        let mut v = r.value;
        if r.truncated {
            v["stats"]["truncated"] = json!(true);
        }
        v
    }).map_err(|t| t.message())
}

/// LA FAMILLE — produit `PARQUET_COLS` × {agrégat groupé, matérialisation} + les seuils de `severity`
/// (le seul domaine INT borné du schéma). Aucune requête n'est ici pour elle-même : chacune est l'image
/// d'une colonne ou d'un seuil.
fn parity_family() -> Vec<String> {
    let mut out = vec!["search | stats count".to_string()];
    for c in PARQUET_COLS {
        out.push(format!("search | stats count by {c}"));
        // SANS `head` : un `head N` est une BORNE DEMANDÉE par l'utilisateur, pas une troncature — et sur
        // une requête sans `sort`, l'ordre des lignes n'est pas défini, donc « les N premières » n'est pas
        // une valeur comparable. La forme NUE, elle, l'est : l'ensemble complet des lignes matchantes.
        out.push(format!("search | table {c}"));
    }
    // Seuils dérivés du domaine de `severity` (rich_row : i % 5) — un scalaire agrégé par seuil.
    for k in 0..5 {
        out.push(format!("search severity>={k} | stats count"));
    }
    out
}

/// Lignes NORMALISÉES d'une réponse servie (triées, comparables à `true_rows`).
fn served_rows(v: &Value) -> Vec<String> {
    let empty: Vec<Value> = Vec::new();
    let mut rows: Vec<String> = v["rows"].as_array().unwrap_or(&empty).iter().map(|r| r.to_string()).collect();
    rows.sort();
    rows
}

/// LE CŒUR DE L'ASSERTION — les deux clauses, appliquées à UNE requête.
fn assert_parity_clauses(label: &str, soql: &str, truth: &[String], served: Result<Value, String>) {
    let v = match served {
        // REFUS explicite : ce n'est ni la même réponse ni un nombre faux. C'est la position de repli
        // ADMISE par l'invariant — mais elle doit NOMMER sa cause, sinon c'est un mur.
        Err(e) => {
            assert!(
                e.contains("refus"),
                "{label} / `{soql}` : refus NON motivé (« {e} ») — une erreur qui ne nomme pas sa cause \
                 ne vaut pas mieux qu'un nombre faux"
            );
            return;
        }
        Ok(v) => v,
    };
    let got = served_rows(&v);
    let truncated = v["stats"]["truncated"].as_bool().unwrap_or(false);
    // (1) RIEN DE FAUX.
    for row in &got {
        assert!(
            truth.contains(row),
            "{label} / `{soql}` : ligne RENDUE absente de la vérité -> valeur FAUSSE.\n  rendue = {row}\n  \
             vérité ({} lignes) = {:?}",
            truth.len(),
            &truth[..truth.len().min(6)]
        );
    }
    // (2) RIEN D'AMPUTÉ EN SILENCE.
    if got.len() < truth.len() {
        assert!(
            truncated,
            "{label} / `{soql}` : {} lignes rendues pour {} vraies, SANS drapeau `truncated` -> \
             incomplétude silencieuse",
            got.len(),
            truth.len()
        );
    }
}

/// PARITÉ CHAUD/FROID sur un volume qui DÉPASSE le plafond d'hydratation (5 001 lignes > 5 000) —
/// LA configuration du défaut : sous le plafond, tous les chemins s'accordent déjà et ne prouvent rien.
///
/// DEUX FENÊTRES, une seule base : PUR-FROID (tout sous la frontière -> kernels seuls) et CHEVAUCHANTE
/// (froid ∪ chaud -> merge, ou union hydratée). Les chemins diffèrent ; l'invariant, non. Une seule
/// fixture pour les deux : la columnarisation de 5 001 lignes est ce qui coûte, et la refaire ne
/// prouverait rien de plus.
#[test]
fn parity_hot_vs_cold_over_the_row_cap() {
    let _lk = p4a_lock();
    let root = tmp_root("parity");
    let db = mkdb(&root);
    let dbp_s = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    let n = 5001i64; // > cold_hydrate_row_cap (5000) -> l'ancien chemin agrégeait sur un ÉCHANTILLON
    {
        // Une seule transaction : 5 001 commits séparés dominent la durée du test sans rien prouver.
        let c = db.lock();
        c.execute_batch("BEGIN").unwrap();
    }
    for i in 0..n {
        insert_event(&db, &p4a_row(base, i));
    }
    insert_recent_tail_holder(&db); // jour M-1 : DANS la fenêtre chaude -> jamais columnarisé
    {
        let c = db.lock();
        c.execute_batch("COMMIT").unwrap();
    }

    // Les DEUX fenêtres, nommées par ce qu'elles traversent.
    let windows: [(&str, i64, i64); 2] =
        [("pur-froid", base, base + n - 1), ("chevauchante", UWIN_FROM, UWIN_TO)];

    // VÉRITÉ : le MÊME SQL, sur les MÊMES lignes, AVANT columnarisation, sans plafond de sortie.
    let family = parity_family();
    let truths: Vec<Vec<Vec<String>>> = {
        let c = db.lock();
        windows
            .iter()
            .map(|(_, from, to)| {
                family.iter().map(|q| true_rows(&c, &compile_ev(q, *from, *to, FieldMaskSet::new()))).collect()
            })
            .collect()
    };

    cold_age_run(&db, &dbp_s, &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "jour froid columnarisé");
    let b = union_boundary(&db, &conf);
    assert!(windows[0].2 < b, "fenêtre 1 PUR-FROID (to={} < b={b})", windows[0].2);
    assert!(windows[1].1 < b && windows[1].2 >= b, "fenêtre 2 CHEVAUCHANTE");
    let f = P4aFix { root, db, dbp: dbp_s, conf, b, from: base, to: base + n - 1 };

    for (w, (label, from, to)) in windows.iter().enumerate() {
        for (q, truth) in family.iter().zip(truths[w].iter()) {
            assert_parity_clauses(label, q, truth, serve_like_prod(&f, q, *from, *to));
        }
    }
}

/// LA FORME EST DÉRIVÉE, ET LE DÉFAUT EST LE REFUS. On ne teste pas une liste d'agrégats : on teste que
/// l'INCONNU — un étage GXQL qui n'existe pas encore — retombe du côté sûr. C'est ce qui fait que le
/// prochain agrégat ajouté au langage est couvert sans que personne n'y pense.
#[test]
fn answer_shape_defaults_to_refusal_for_unknown_stages() {
    // PAR-ÉVÉNEMENT : chaque ligne rendue EST un événement d'entrée.
    for q in [
        "search",
        "search source=web",
        "search severity>=2 | where severity<4",
        "search | table ts,source | head 10",
        "search | fields ts,host",
        "search | eval x=1 | rename x as y | rex field=message \"(?<a>.)\"",
    ] {
        assert!(AnswerShape::of_gxql(q).is_per_event(), "`{q}` est par-événement");
    }
    // DÉRIVÉ DE L'ENSEMBLE : refusé sur un ensemble tronqué.
    for q in [
        "search | stats count",
        "search | stats count by source",
        "search | stats dc(host)",
        "search | stats sum(severity)",
        "search | timechart count",
        "search | top source",
        "search | rare source",
        "search | eventstats avg(severity)",
        "search | rate 1h",
        "search | dedup source",
        "search | sort -severity | head 10",
        // L'INCONNU — un étage qui n'existe pas (aujourd'hui). Le défaut le condamne SANS qu'il soit nommé
        // dans `PER_EVENT_STAGES` : c'est la propriété qui survit aux évolutions du langage.
        "search | percentile95 latence",
        "search | forecast count by source",
    ] {
        assert!(!AnswerShape::of_gxql(q).is_per_event(), "`{q}` dérive une valeur de l'ensemble -> refus sur tronqué");
    }
    // SQL BRUT : rien de dérivable -> refus.
    assert!(!AnswerShape::undecidable().is_per_event(), "SQL brut : indécidable -> refus");
}

/// L'INVARIANT DE RENDU, EXERCÉ DIRECTEMENT : un ensemble tronqué ne rend JAMAIS un agrégat, rend une
/// matérialisation partielle DÉCLARÉE, et n'émet JAMAIS de total de pagination (un COUNT est lui aussi
/// une valeur dérivée de l'ensemble).
#[test]
fn cold_answer_render_refuses_derived_values_on_a_truncated_set() {
    let body = json!({ "columns": ["count"], "rows": [[289]], "stats": {} });
    // TRONQUÉ + agrégat -> REFUS, avec un message qui nomme la cause ET les voies exactes.
    let refused = ColdAnswer::new(body.clone(), Some(289), true, 5000, 5000)
        .render(AnswerShape::of_gxql("search source=auditd severity>=2 | stats count"))
        .err()
        .expect("un agrégat sur ensemble tronqué DOIT être refusé");
    let msg = refused.message();
    for must in ["refus", "PLUME_QUERY_MAX", "restreindre la fenêtre"] {
        assert!(msg.contains(must), "le refus doit contenir « {must} » — sinon c'est un mur : {msg}");
    }
    // TRONQUÉ + par-événement -> partielle DÉCLARÉE, et total ÉCARTÉ.
    let r = ColdAnswer::new(body.clone(), Some(4242), true, 5000, 5000)
        .render(AnswerShape::of_gxql("search | table ts,source"))
        .expect("une matérialisation partielle reste rendable");
    assert!(r.truncated, "l'incomplétude est DÉCLARÉE");
    assert!(r.total.is_none(), "le total de pagination est un COUNT : jamais rendu d'un ensemble tronqué");
    // EXACT -> tout passe, total compris.
    let r = ColdAnswer::new(body, Some(58_747), false, 5000, 120)
        .render(AnswerShape::of_gxql("search source=auditd severity>=2 | stats count"))
        .expect("un ensemble complet rend tout");
    assert!(!r.truncated);
    assert_eq!(r.total, Some(58_747));
}

/// GATE 0 — le routeur vectorisé est ARMÉ PAR DÉFAUT dès que le tier froid est actif, et `=0` le désarme.
/// C'est le remplaçant de `p4a_gate0_dark_switch_off_forces_fallback`, dont le contrat (défaut DORMANT)
/// était la CAUSE MESURÉE du défaut : sur le banc du 31/07, aucune des 105 cellules froides n'a atteint
/// les kernels, et 57 d'entre elles ont donc été servies par l'échantillon hydraté.
#[test]
fn gate0_vectorized_router_is_armed_by_default_and_opt_out_still_works() {
    let _lk = p4a_lock();
    let f = p4a_fixture("gate0-default", 40);
    let soql = "search | stats count by source";
    // ABSENT (le défaut de production) -> ARMÉ.
    let mut dflt = f.conf.clone();
    dflt.remove("PLUME_COLD_VECTORIZED");
    assert!(cold_vectorized_armed(&dflt), "défaut = ARMÉ (un interrupteur entre exact et faux ne peut pas défaut-er sur faux)");
    let r_default = cold_vectorized_try(&f.dbp, &dflt, None, f.from, f.to, f.b, soql, true, 60_000, &[]).unwrap();
    assert!(r_default.is_some(), "flag absent -> routé vectorisé (exact)");
    // "0" explicite -> DÉSARMÉ (opt-out conservé) -> fallback.
    let mut off = f.conf.clone();
    off.insert("PLUME_COLD_VECTORIZED".to_string(), "0".to_string());
    assert!(!cold_vectorized_armed(&off));
    let r_off = cold_vectorized_try(&f.dbp, &off, None, f.from, f.to, f.b, soql, true, 60_000, &[]).unwrap();
    assert!(r_off.is_none(), "opt-out explicite -> fallback (qui REFUSE au-delà du cap, il ne ment pas)");
}

/// LA BARRE DE RECHERCHE DÉCLARE CE QU'ELLE N'A PAS CHERCHÉ. `/api/search` n'interroge que l'index FTS5,
/// qui n'existe que sur la fenêtre chaude : au-delà, il rendait `{"results": []}` — « rien ne correspond »
/// alors que la vérité était « je n'ai pas cherché là ». Le test porte sur la DÉCISION (déclarer ou se
/// taire), pas sur le texte de la note : elle est due quand la fenêtre atteint sous la frontière ET qu'il
/// existe vraiment du froid, et due jamais autrement (sinon la note devient du bruit qu'on apprend à ignorer).
#[test]
fn search_declares_what_it_did_not_search_only_when_cold_history_exists() {
    let _lk = p4a_lock();
    let root = tmp_root("search-cov");
    let db = mkdb(&root);
    let dbp_s = dbp(&root);
    let conf = conf_union(HOT_WIN);
    let day = M - 10;
    let base = day * SECS_PER_DAY;

    // (a) AUCUN froid encore -> aucune note, même sur une fenêtre non bornée. Une alarme permanente
    //     n'est pas une information.
    let b0 = union_boundary(&db, &conf);
    {
        let c = db.lock();
        assert!(
            crate::handlers::search::search_cold_coverage(&c, &conf, b0, 0).is_none(),
            "sans histoire froide, la barre couvre tout ce qui existe -> RIEN à déclarer"
        );
    }

    // (b) Après columnarisation d'un jour ancien : la fenêtre non bornée et la fenêtre qui atteint sous
    //     la frontière DOIVENT déclarer ; une fenêtre entièrement chaude, non.
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    cold_age_run(&db, &dbp_s, &conf, n_now(), RET_DAYS);
    let b = union_boundary(&db, &conf);
    let c = db.lock();
    let cov = crate::handlers::search::search_cold_coverage(&c, &conf, b, 0)
        .expect("fenêtre non bornée + froid présent -> DÉCLARÉ");
    assert_eq!(cov["searched_from"].as_i64(), Some(b), "la note dit À PARTIR D'OÙ elle a cherché");
    assert_eq!(cov["reason"].as_str(), Some("fts_hot_only"), "la note NOMME la cause, pas seulement l'effet");
    assert!(
        cov["notice"].as_str().unwrap_or("").contains("/api/query"),
        "la note propose la voie EXACTE (celle qui, elle, lit le froid) — sinon c'est un mur"
    );
    assert!(
        crate::handlers::search::search_cold_coverage(&c, &conf, b, base).is_some(),
        "fenêtre atteignant SOUS la frontière -> DÉCLARÉ"
    );
    assert!(
        crate::handlers::search::search_cold_coverage(&c, &conf, b, b).is_none(),
        "fenêtre entièrement CHAUDE -> rien à déclarer (la barre a tout couvert)"
    );
    // (c) Tier froid éteint -> jamais de note (mode 0 : /api/search byte-identique).
    let mut off = conf.clone();
    off.insert("PLUME_COLD_TIER".to_string(), "0".to_string());
    assert!(
        crate::handlers::search::search_cold_coverage(&c, &off, b, 0).is_none(),
        "tier froid OFF -> aucune note, aucun coût"
    );
    drop(c);
    let _ = std::fs::remove_dir_all(&root);
}

// ── P8.7-b : LES DEUX MOITIÉS DU CHIFFREMENT AT-REST DÉRIVENT DU MÊME APPEL ──────────────────────
// Ce test vit ICI parce que `cold_base_secret` est `pub(super)` : c'est le seul endroit d'où la
// moitié FROIDE s'observe sans ouvrir une porte dans la frontière du module.

/// LA GARDE DU LOT. Une clé écrite dans le fichier de configuration SEUL doit rendre le MÊME secret
/// aux deux moitiés : celle qui OUVRE la base chaude (`db_key_depuis`) et celle dont le tier froid
/// dérive sa clé AEAD (`cold_base_secret`). C'est exactement la conf qui FABRIQUAIT la divergence
/// mesurée le 2026-08-09 — jour-file `age-encryption.org/v1` d'un côté, `SQLite format 3\0` de
/// l'autre, et « rétention OK » pour tout commentaire.
#[test]
fn p87b_les_deux_moities_at_rest_derivent_du_meme_appel() {
    assert!(
        std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true),
        "environnement muet exigé : sinon c'est LUI qu'on mesure (il gagne, par construction)"
    );
    let mut conf = HashMap::new();
    conf.insert("PLUME_DB_KEY".to_string(), "cle-ecrite-dans-soc-conf-p87b".to_string());
    let ouverture = db_key_depuis(&conf);
    assert_eq!(
        ouverture,
        Some("cle-ecrite-dans-soc-conf-p87b".to_string()),
        "la voie d'OUVERTURE doit voir la clé du fichier — c'est tout le lot P8.7-b"
    );
    assert_eq!(
        cold_base_secret(&conf, ""),
        ouverture,
        "DIVERGENCE DES DEUX MOITIÉS : le tier froid et l'ouverture de la base chaude ne dérivent \
         pas du même secret. C'est l'état d'avant le 2026-08-09 — la moitié froide chiffrée, la \
         moitié chaude (les 7 derniers jours, donc les incidents récents) EN CLAIR, sans un mot."
    );
    // Le REGISTRE par-tenant reste PLUS SPÉCIFIQUE que la conf, et les deux moitiés le consultent :
    // un tenant enregistré EN CLAIR (`None`) fait fail-closer le froid au lieu de le faire chiffrer
    // avec une clé que la base chaude n'utilise pas. C'est la même règle, vérifiée sur l'autre voie.
    register_db_key("/p87b/tenant-en-clair.db", None);
    assert_eq!(
        cold_base_secret(&conf, "/p87b/tenant-en-clair.db"),
        None,
        "un tenant enregistré EN CLAIR ne doit JAMAIS voir le froid chiffrer avec la clé globale"
    );
    unregister_db_key("/p87b/tenant-en-clair.db");
}

// =====================================================================================================
// `P10.5-a` — LE VIEILLISSEMENT REND COMPTE. Mesuré en production le 2026-08-10 : une passe libérait
// 120 Mio de base chaude et écrivait 3,70 Mio de Parquet SANS ÉMETTRE UNE LIGNE, et quatre axes de coût
// (durée, CPU, crête RAM, latence) étaient inconnus POUR CETTE SEULE RAISON. Ces tests portent sur le
// CÂBLAGE : ce que la vraie passe écrit vraiment dans `metric`. La FORME de ce qui est publié (trou vs
// zéro, causes, bornes, instrument de crête) est prouvée dans le profil PAR DÉFAUT
// (`tests/vieillissement_serie.rs`) — ici on vérifie que les chiffres décrivent le travail RÉEL.
// =====================================================================================================

use crate::vieillissement_serie::{
    CAUSE_CLE_ABSENTE, NOM_CRETE_OK, NOM_DUREE, NOM_FICHIERS, NOM_JOURS, NOM_LIGNES, NOM_OCTETS_FROID, NOM_OK,
    NOM_RETARD_LIGNES, NOM_RETARD_OK, RETARD_CADENCE, RETARD_FENETRE_VIDE, RETARD_NON_ARME,
    RETARD_PASSE_SUSPENDUE, RETARD_REQUETE,
    Retard,
};

/// LA PASSE DIT CE QU'ELLE A FAIT — jours, lignes ÉCRITES, lignes RETIRÉES DU CHAUD, fichiers, et OCTETS.
/// Chaque chiffre est confronté à la réalité qu'il prétend décrire : le compte de lignes agées, la taille
/// du fichier SUR DISQUE, le vidage effectif du chaud. Sans ce test, la série pourrait publier n'importe
/// quoi de plausible — c'est exactement le risque quand on remplace un silence par des chiffres.
///
/// MUTATION : publier `f.expected` (l'espéré du seal) au lieu du retour de `delete_file_rows` ⇒ ce test
/// reste VERT (les deux valent 40 au premier passage). Celui qui rougit est
/// `un_seal_rejoue_ne_compte_que_les_lignes_reellement_supprimees` — le seul scénario où les deux nombres
/// DIVERGENT (vérifié le 2026-08-10 : 0 attendu, 25 publiés sous mutation).
#[test]
fn un_vieillissement_reussi_rend_compte_de_ce_quil_a_fait() {
    let root = tmp_root("serie-travail");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    let base = day * SECS_PER_DAY;
    for i in 0..40 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db); // garde H1 : le tail est tenu ailleurs, le jour est agéable
    assert_eq!(count_hot(&db), 41);

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    // Le travail a bien eu lieu (précondition : sans ça, ce test mesurerait une série de zéros).
    assert_eq!(count_hot_day(&db, "prod", day), 0, "précondition : le jour doit avoir été agé");
    let p = day_path(&cold, "prod", day);
    let taille = std::fs::metadata(&p).expect("le fichier cold doit exister").len() as f64;

    assert_eq!(serie(&db, NOM_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0), "la passe s'annonce réussie");
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")), Some(1.0));
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"columnarise\"}")), Some(1.0));
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"sans_travail\"}")), Some(0.0));
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"differe\"}")), Some(0.0));
    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"ecrites\"}")),
        Some(40.0),
        "la série n'annonce pas les 40 lignes réellement columnarisées"
    );
    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"retirees_du_chaud\"}")),
        Some(40.0),
        "la série n'annonce pas les 40 lignes réellement supprimées du chaud"
    );
    assert_eq!(serie(&db, NOM_FICHIERS, Some("{\"etat\":\"ecrits\"}")), Some(1.0));
    assert_eq!(serie(&db, NOM_FICHIERS, Some("{\"etat\":\"purges\"}")), Some(1.0));
    assert_eq!(
        serie(&db, NOM_OCTETS_FROID, None),
        Some(taille),
        "les octets publiés ne sont pas ceux que le fichier pèse SUR DISQUE ({taille} o) -> le chiffre \
         serait une reconstruction, pas une mesure"
    );
    assert!(serie(&db, NOM_DUREE, None).is_some(), "la durée d'une passe doit être publiée");
    // La crête RSS : mesurée ou NOMMÉE, jamais absente en silence.
    let conn = db.lock();
    let n_crete: i64 = conn
        .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", params![NOM_CRETE_OK], |r| r.get(0))
        .unwrap();
    assert_eq!(n_crete, 1, "l'état de l'instrument de crête doit être publié à chaque passe");
    drop(conn);
    let _ = std::fs::remove_dir_all(&root);
}

/// UN RE-RUN NE RÉCLAME PAS D'AVOIR DÉPLACÉ DES LIGNES. Le jour est déjà scellé ET purgé : la seconde
/// passe est un NO-OP. Si la série publiait l'ESPÉRÉ du seal (`expected_rows`) au lieu du compte rendu
/// par le `DELETE`, elle annoncerait 40 lignes drainées à CHAQUE tick horaire — un drainage imaginaire,
/// et la « quantité de données déplacées par jour » serait fausse d'un facteur 24.
///
/// CE QUE CE TEST NE PROUVE PAS — mesuré, pas supposé. J'ai cru qu'il serait la garde du choix « compte
/// RÉEL du DELETE plutôt qu'espéré du seal » : FAUX. Mutation exécutée le 2026-08-10 (publier `f.expected`)
/// ⇒ ce test reste VERT, parce que la 2e passe ne découvre AUCUN jour candidat (le chaud est vide) et
/// n'atteint donc jamais la phase 2. La garde de ce choix est le test SUIVANT, qui construit le seul
/// scénario où les deux nombres divergent.
#[test]
fn un_re_run_ne_reclame_pas_davoir_deplace_des_lignes() {
    let root = tmp_root("serie-rerun");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 6;
    let base = day * SECS_PER_DAY;
    for i in 0..25 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(serie(&db, NOM_LIGNES, Some("{\"sens\":\"retirees_du_chaud\"}")), Some(25.0), "précondition");

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS); // 2e passe : le jour est drainé, il n'y a plus rien

    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"retirees_du_chaud\"}")),
        Some(0.0),
        "la 2e passe prétend avoir retiré des lignes d'un jour DÉJÀ drainé -> le chiffre publié est \
         l'espéré du seal, pas ce que le DELETE a fait"
    );
    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"ecrites\"}")),
        Some(0.0),
        "la 2e passe prétend avoir écrit du Parquet alors qu'aucun fichier n'a été produit"
    );
    // ... et elle reste une passe RÉUSSIE : le jour drainé n'a plus de ligne chaude, donc plus rien à
    // découvrir. « 0 candidat » est un résultat publié, pas un silence.
    assert_eq!(serie(&db, NOM_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0));
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")), Some(0.0));
    let _ = std::fs::remove_dir_all(&root);
}

/// UNE PASSE QUI N'A RIEN À FAIRE PUBLIE DES ZÉROS — pas rien. C'est l'invariant du chantier vu depuis
/// la production : « le vieillissement n'a rien trouvé cette heure-ci » et « le vieillissement ne tourne
/// plus depuis trois jours » doivent avoir des signatures DIFFÉRENTES dans la série.
///
/// MUTATION : ne publier que si `jours_candidats > 0` ⇒ la table reste vide et la 1re assertion rougit.
#[test]
fn une_passe_sans_rien_a_faire_publie_des_zeros_pas_un_silence() {
    let root = tmp_root("serie-vide");
    let cold = root.join("cold");
    let db = mkdb(&root); // AUCUN event : rien n'est éligible
    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")),
        Some(0.0),
        "une passe qui n'a rien trouvé n'a rien publié -> elle est indiscernable d'un démon qui ne \
         vieillit plus (le défaut mesuré le 2026-08-10)"
    );
    assert_eq!(serie(&db, NOM_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0));
    assert_eq!(serie(&db, NOM_OCTETS_FROID, None), Some(0.0));
    let _ = std::fs::remove_dir_all(&root);
}

/// UNE SUSPENSION EST DITE, ET NE PUBLIE AUCUN COMPTEUR. Clé absente = fail-closed : rien n'est agé, le
/// chaud est intact. La série porte un TROU NOMMÉ (`ok{cause=cle_absente}=0`) et surtout AUCUN zéro de
/// travail — un `jours{candidat}=0` ici mentirait : la passe n'a jamais regardé la base.
///
/// MUTATION : rendre `Issue::Balaye` sur le chemin clé-absente ⇒ la série publie des compteurs de
/// travail pour une passe qui n'a rien regardé, et les deux dernières assertions rougissent.
#[test]
fn une_suspension_par_cle_absente_est_dite_et_ne_publie_aucun_compteur() {
    let root = tmp_root("serie-sanscle");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 10;
    for i in 0..10 {
        insert_event(&db, &rich_row(day * SECS_PER_DAY + i, i));
    }
    insert_recent_tail_holder(&db);
    // Conf cold ON mais SANS PLUME_DB_KEY -> aucune passphrase dérivable (fail-closed, hot intact).
    let mut conf = conf_on(&cold, HOT_WIN);
    conf.remove("PLUME_DB_KEY");

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    assert_eq!(count_hot_day(&db, "prod", day), 10, "précondition : fail-closed, le chaud reste intact");
    assert_eq!(
        serie(&db, NOM_OK, Some(&format!("{{\"cause\":\"{CAUSE_CLE_ABSENTE}\"}}"))),
        Some(0.0),
        "la suspension n'est pas publiée -> un vieillissement qui ne draine plus resterait invisible"
    );
    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")),
        None,
        "une passe qui n'a JAMAIS regardé la base publie des jours -> elle se lirait « rien à faire »"
    );
    assert_eq!(serie(&db, NOM_OCTETS_FROID, None), None, "aucun octet ne peut être annoncé par une passe suspendue");
    let _ = std::fs::remove_dir_all(&root);
}

/// TIER FROID ÉTEINT = AUCUNE SÉRIE. L'absence totale de point dit « ça ne tourne pas ici » ; un `0`
/// dirait « ça tourne et ça ne fait rien ». C'est aussi la garde de mode 0 : gate runtime OFF, la base
/// n'est pas touchée — pas même par la mesure.
#[test]
fn le_tier_froid_eteint_ne_publie_aucune_serie() {
    let root = tmp_root("serie-off");
    let cold = root.join("cold");
    let db = mkdb(&root);
    for i in 0..5 {
        insert_event(&db, &rich_row((M - 10) * SECS_PER_DAY + i, i));
    }
    let mut conf = conf_on(&cold, HOT_WIN);
    conf.remove("PLUME_COLD_TIER"); // gate RUNTIME absent

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    let n: i64 = db.lock().query_row("SELECT COUNT(*) FROM metric", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0, "le tier froid éteint a écrit dans `metric` -> mode 0 n'est plus byte-identique");
    let _ = std::fs::remove_dir_all(&root);
}

/// UNE DÉCOUVERTE QUI ÉCHOUE NE SE LIT PAS « RIEN À FAIRE ». C'est la forme la plus coûteuse du défaut
/// que ce chantier ferme, et elle n'apparaît QU'UNE FOIS la passe instrumentée : la requête qui liste les
/// jours agéables avalait ses erreurs (`if let Ok(..)` + `flatten()`) et rendait une liste VIDE. Sans
/// série, ça ressemblait à un tick sans travail ; AVEC une série naïve, ça publierait « 0 jour candidat »
/// — un ZÉRO MESURÉ affirmant qu'on a regardé. Ici la table `event` est retirée sous les pieds de la
/// passe : elle doit le DIRE, pas compter zéro.
///
/// MUTATION : revenir au `if let Ok(mut st) = conn.prepare(&sql)` silencieux ⇒ `ok{cause=aucune}` vaut 1,
/// `jours{issue=candidat}` vaut 0, et les deux assertions rougissent.
#[test]
fn une_decouverte_impossible_ne_se_publie_pas_comme_zero_jour() {
    let root = tmp_root("serie-decouverte");
    let cold = root.join("cold");
    let db = mkdb(&root);
    db.lock().execute_batch("DROP TABLE event").unwrap(); // la découverte ne PEUT plus regarder

    cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), n_now(), RET_DAYS);

    assert_eq!(
        serie(&db, NOM_OK, Some("{\"cause\":\"decouverte_impossible\"}")),
        Some(0.0),
        "la découverte a échoué et la série ne le dit pas -> l'échec est indiscernable d'un tick sans travail"
    );
    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")),
        None,
        "un `0 candidat` publié ici AFFIRMERAIT qu'on a regardé la base : c'est un zéro pour une mesure \
         qui n'a pas eu lieu"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// UN SEAL REJOUÉ NE COMPTE QUE LES LIGNES RÉELLEMENT SUPPRIMÉES. C'est le SEUL scénario où « ce que le
/// seal espérait » et « ce que le DELETE a fait » divergent, et il est réel : un crash entre le DELETE et
/// le `purged=1` laisse un seal à rejouer sur un chaud déjà vidé. On le reconstruit exactement — jour agé,
/// seal remis à `purged=0`, puis des lignes BACKDATÉES ingérées après coup (des stragglers : leur `id` est
/// au-dessus du `max_id` scellé, donc le DELETE borné ne peut pas les prendre). La phase 2 rejoue, VERIFY
/// passe, le DELETE ne supprime RIEN — et c'est ce ZÉRO que la série doit publier.
///
/// Sans ça, un déploiement qui rejoue des seals publierait à chaque tick horaire les milliers de lignes
/// que le seal ANNONCE : la question « combien de données le vieillissement déplace-t-il par jour ? »
/// serait fausse d'un facteur égal au nombre de rejeux, et fausse VERS LE HAUT (le sens qui rassure).
///
/// MUTATION (exécutée le 2026-08-10) : `compte.lignes_retirees += f.expected` ⇒ la série publie 25 lignes
/// « retirées du chaud » alors que le DELETE en a supprimé 0, et l'assertion rougit.
#[test]
fn un_seal_rejoue_ne_compte_que_les_lignes_reellement_supprimees() {
    let root = tmp_root("serie-rejeu");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 8;
    let base = day * SECS_PER_DAY;
    for i in 0..25 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "précondition : le jour est agé et purgé");

    // CRASH SIMULÉ entre le DELETE et le `purged=1` : le seal est à rejouer.
    db.lock().execute("UPDATE cold_seal SET purged=0 WHERE day=?1", params![day]).unwrap();
    // Des lignes BACKDATÉES arrivent après le scellement : leur id dépasse le max_id scellé -> le DELETE
    // borné `id<=max_id` ne peut pas les prendre (stragglers, sémantique P1 : pas de perte, pas de cold).
    for i in 0..10 {
        insert_event(&db, &rich_row(base + 100 + i, i));
    }

    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    assert_eq!(
        count_hot_day(&db, "prod", day), 10,
        "précondition : les stragglers survivent (sinon ce test ne mesure pas le rejeu qu'il annonce)"
    );
    assert_eq!(
        serie(&db, NOM_FICHIERS, Some("{\"etat\":\"purges\"}")),
        Some(1.0),
        "précondition : la phase 2 a bien REJOUÉ le fichier (sans ça, la ligne mutée n'est pas atteinte)"
    );
    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"retirees_du_chaud\"}")),
        Some(0.0),
        "le rejeu publie l'ESPÉRÉ du seal au lieu de ce que le DELETE a fait -> « combien de données le \
         vieillissement déplace-t-il ? » devient faux, et faux vers le HAUT"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// =====================================================================================================
// `P10.13-a` — L'INSTRUMENT QUI MANQUAIT : la sonde `cold-aging-plan`. Elle rejoue LES ÉNONCÉS DE LA
// PASSE (dérivés de `enonces`, cf. la garde de source `aucun_enonce_de_lecture_ne_vit_hors_du_module_enonces`
// qui tourne dans le profil PAR DÉFAUT) en LECTURE SEULE, et rend leur plan + leur chronométrage. Ce
// bloc prouve les trois propriétés qu'on ne peut pas se contenter de promettre : elle N'ÉCRIT PAS, elle
// REFUSE d'écrire même si on le lui demandait, et elle mesure bien la requête de la passe.
// =====================================================================================================

use super::sonde_vieillissement::{
    brider_en_lecture_seule, executer_et_chronometrer, ouvrir_en_lecture_seule, Chaud, Mesure,
    CHAUD_REJEU_EN_ECHEC,
};

/// L'AUTHORIZER DE SONDE REFUSE TOUT CE QUI N'EST PAS UNE LECTURE — prouvé SUR UNE CONNEXION ÉCRIVABLE,
/// et c'est le point : sur une connexion déjà ouverte en `SQLITE_OPEN_READ_ONLY`, un refus ne prouverait
/// pas QUI a refusé, les deux gardes se couvriraient l'une l'autre et aucune mutation ne pourrait les
/// départager. Ici l'écriture EST possible ; seul l'authorizer l'empêche.
///
/// MUTATION (exécutée le 2026-08-11) : remplacer le bras `_ => Authorization::Deny` par
/// `_ => Authorization::Allow` ⇒ les 6 écritures passent, les 6 assertions de refus rougissent
/// (`INSERT`, `UPDATE`, `DELETE`, `CREATE TABLE`, `ANALYZE`, `PRAGMA user_version=1`), et le témoin
/// positif reste vert (il ne masque donc pas la régression).
#[test]
fn l_authorizer_de_sonde_refuse_tout_ce_qui_n_est_pas_une_lecture() {
    let root = tmp_root("sonde-authz");
    let db = mkdb(&root);
    insert_event(&db, &rich_row(1_700_000_000, 1));
    let conn = db.lock();

    // TÉMOIN POSITIF, AVANT l'authorizer : sur CETTE connexion, écrire est parfaitement possible.
    conn.execute_batch("CREATE TABLE temoin_avant(x)").expect("précondition : la connexion écrit");

    brider_en_lecture_seule(&conn);

    // Les lectures dont la sonde a besoin passent : `Read` + `Select` + `Function` (COUNT/MAX/COALESCE).
    let n: i64 = conn
        .query_row("SELECT COUNT(*), COALESCE(MAX(id),0) FROM event", [], |r| r.get(0))
        .expect("une LECTURE doit rester possible : sinon la sonde ne mesure plus rien");
    assert_eq!(n, 1);
    conn.prepare("EXPLAIN QUERY PLAN SELECT env_id, ts/86400 FROM event GROUP BY env_id")
        .expect("EXPLAIN QUERY PLAN doit rester possible : c'est l'objet même de la sonde");

    // On les essaie TOUTES avant de conclure : un `expect_err` s'arrêterait à la première et une
    // mutation ne dirait plus COMBIEN d'écritures elle rouvre.
    let mut acceptees: Vec<&str> = Vec::new();
    let mut mauvaise_raison: Vec<String> = Vec::new();
    for interdit in [
        "INSERT INTO event(ts,source,severity) VALUES(1,'x',0)",
        "UPDATE event SET severity=9",
        "DELETE FROM event",
        "CREATE TABLE apres(x)",
        // `ANALYZE` écrirait `sqlite_stat1` -> il CHANGERAIT les plans qu'on est venu mesurer.
        "ANALYZE",
        "PRAGMA user_version=1",
    ] {
        match conn.execute_batch(interdit) {
            Ok(()) => acceptees.push(interdit),
            Err(e) if !e.to_string().to_lowercase().contains("not authorized") => {
                mauvaise_raison.push(format!("{interdit} -> {e}"));
            }
            Err(_) => {}
        }
    }
    assert!(
        acceptees.is_empty(),
        "{} écriture(s) ACCEPTÉE(s) par la connexion de sonde -> l'instrument peut muter la base qu'il \
         prétend seulement observer : {acceptees:?}",
        acceptees.len()
    );
    assert!(
        mauvaise_raison.is_empty(),
        "des refus viennent d'AUTRE CHOSE que l'authorizer -> la garde testée n'est pas celle qui a \
         mordu : {mauvaise_raison:?}"
    );
    drop(conn);
    let _ = std::fs::remove_dir_all(&root);
}

/// LA CONNEXION DE LA SONDE EST READ-ONLY AU NIVEAU DU DESCRIPTEUR — verdict de SQLite lui-même
/// (`sqlite3_db_readonly`), indépendant de l'authorizer. Les deux gardes sont ainsi prouvées SÉPARÉMENT :
/// celle-ci tient même si l'authorizer disparaissait.
///
/// MUTATION (exécutée le 2026-08-11) : retirer `SQLITE_OPEN_READ_ONLY` de `ouvrir_en_lecture_seule`
/// (`Connection::open(db_path)`) ⇒ `is_readonly` rend `false` et l'assertion rougit, alors que TOUS les
/// autres tests de la sonde restent verts (l'authorizer les couvre) — c'est exactement pour ça qu'il
/// faut cette assertion-là.
#[test]
fn une_connexion_de_sonde_refuse_d_ecrire() {
    let root = tmp_root("sonde-ro");
    let chemin = root.join("plume.db");
    {
        let db = mkdb(&root);
        insert_event(&db, &rich_row(1_700_000_000, 1));
    }
    let conn = ouvrir_en_lecture_seule(&chemin.to_string_lossy()).expect("la base de test doit s'ouvrir");
    assert!(
        conn.is_readonly(rusqlite::DatabaseName::Main).expect("verdict de SQLite lisible"),
        "SQLite considère la base OUVERTE EN ÉCRITURE -> le descripteur de la sonde n'est pas read-only"
    );
    // Et la lecture, elle, fonctionne (sans ça, « read-only » serait trivialement vrai sur une base
    // qu'on n'a pas su ouvrir).
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
    drop(conn);
    let _ = std::fs::remove_dir_all(&root);
}

/// LA SONDE MESURE LA PASSE, ET NE TOUCHE PAS LA BASE. Deux propriétés en un scénario, parce qu'elles
/// n'ont de valeur qu'ensemble : un instrument qui n'écrit pas mais ne mesure rien est inutile, et un
/// instrument qui mesure en écrivant est dangereux.
///   * CE QU'ELLE MESURE : le rapport doit porter le plan ET le chronométrage de la requête de
///     DÉCOUVERTE (l'énoncé sous suspicion), plus les énoncés PAR-JOUR du premier candidat retenu.
///   * CE QU'ELLE NE TOUCHE PAS : le fichier de base est comparé OCTET POUR OCTET avant/après. C'est la
///     preuve la plus large disponible — elle couvre aussi bien un `INSERT` qu'un `ANALYZE` (qui aurait
///     créé `sqlite_stat1`, donc CHANGÉ les plans qu'on vient lire).
///
/// La fixture est datée sur l'HORLOGE RÉELLE (la sonde appelle `now()`, comme la passe) : un jour à
/// `now-10 j` tombe dans la bande [now-30 j, now-2 j) que la conf de test produit.
///
/// CE QUE LA MUTATION A RÉFUTÉ, ET CE QU'ELLE A CONFIRMÉ (exécuté le 2026-08-11 — la première version de
/// ce commentaire annonçait autre chose, et la mesure l'a démentie). J'ai cru qu'ajouter un `ANALYZE` dans
/// `ouvrir_en_lecture_seule` suffirait à faire rougir l'octet-pour-octet : **FAUX, le test reste VERT**.
/// `ANALYZE` sur un descripteur `SQLITE_OPEN_READ_ONLY` ÉCHOUE — la première garde l'avale avant qu'il
/// n'écrive. Retirer SEULEMENT le drapeau read-only laisse le test vert AUSSI (le code, lui, n'écrit
/// vraiment rien). Cette assertion est donc un FILET DE SÉCURITÉ de bout en bout, pas la garde de l'une
/// des deux épaisseurs : sa bite exige la mutation COMPOSÉE — descripteur écrivable **et** une écriture —
/// et celle-là, mesurée, la fait rougir en nommant les octets : « LA SONDE A MODIFIÉ LA BASE
/// (45 056 o -> 53 248 o) », les 8 192 o de `sqlite_stat1`. C'est ce qu'elle garde réellement : qu'un
/// futur remaniement qui rendrait la connexion écrivable ET ajouterait une écriture ne passe pas.
#[test]
fn la_sonde_rejoue_les_enonces_de_la_passe_sans_toucher_la_base() {
    let root = tmp_root("sonde-plan");
    let cold = root.join("cold");
    let chemin = root.join("plume.db");
    let jour = crate::now().div_euclid(SECS_PER_DAY) - 10; // dans la bande, hors fenêtre chaude
    let base_ts = jour * SECS_PER_DAY;
    {
        let db = mkdb(&root);
        for i in 0..30 {
            insert_event(&db, &rich_row(base_ts + i, i));
        }
        // Tail-holder RÉCENT (comme en production : la fenêtre chaude est toujours alimentée) -> la
        // garde H1 ne diffère pas le jour, et `cold_seal` existe après la passe.
        let mut r = rich_row(crate::now(), 99_999);
        r.row.source = "recent-tail".to_string();
        insert_event(&db, &r);
        // On fait TOURNER la vraie passe une fois : elle crée `cold_seal` (que la sonde, read-only, ne
        // peut pas créer) et laisse un état réaliste. Les stragglers ci-dessous rendront ensuite le jour
        // à nouveau candidat, ce que la sonde doit voir.
        cold_age_run(&db, "", &conf_on(&cold, HOT_WIN), crate::now(), RET_DAYS);
        for i in 0..5 {
            insert_event(&db, &rich_row(base_ts + 500 + i, i)); // stragglers : id > max_id scellé
        }
    }

    let avant = std::fs::read(&chemin).expect("la base de test doit être lisible");
    let rapport = crate::cold_store::cold_aging_plan(&conf_on(&cold, HOT_WIN), &chemin.to_string_lossy())
        .expect("la sonde doit rendre un rapport sur une base lisible");
    let apres = std::fs::read(&chemin).expect("la base de test doit être lisible");

    assert_eq!(
        avant, apres,
        "LA SONDE A MODIFIÉ LA BASE ({} o -> {} o) — un instrument de diagnostic qui écrit sur la \
         production est pire que pas d'instrument",
        avant.len(),
        apres.len()
    );

    // Elle a bien LU le plan de l'énoncé sous suspicion, et l'a CHRONOMÉTRÉ (pas seulement affiché).
    for attendu in [
        "decouverte_des_jours",
        "SELECT env_id, ts/86400 AS day FROM event",
        "seals_du_jour",
        "compte_et_max_id_du_jour",
        "premiere_page_froide",
        "tail_du_compteur_de_rowid",
        "LECTURE SEULE",
    ] {
        assert!(rapport.contains(attendu), "le rapport ne porte pas `{attendu}` :\n{rapport}");
    }
    assert!(
        rapport.matches("exécution ").count() >= 6,
        "seulement {} énoncé(s) CHRONOMÉTRÉ(s) -> la sonde affiche des plans sans les mesurer, et un \
         plan indexé qui met 17 s se lirait comme un plan sain :\n{rapport}",
        rapport.matches("exécution ").count()
    );
    assert!(
        rapport.contains("balayage="),
        "les compteurs SQLITE_STMTSTATUS manquent -> rien ne départage « plan indexé lent » de \
         « balayage complet » :\n{rapport}"
    );
    // Le candidat est celui que la PASSE aurait retenu (même prédicat `Bande::retenu`).
    assert!(
        rapport.contains("1 découvert(s), 1 retenu(s)"),
        "la sonde n'a pas retenu le jour que la passe traiterait :\n{rapport}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// CHAQUE ÉNONCÉ SE PRÉPARE, SE PLANIFIE ET S'EXÉCUTE. Une erreur de nombre de paramètres, un `?7`
/// oublié ou une colonne renommée ne se voit pas à la compilation : ce test exerce TOUS les énoncés que
/// la sonde construit, sur une base réelle, et refuse le moindre `MESURE IMPOSSIBLE` — sans quoi la
/// sonde rendrait un rapport d'excuses qu'on lirait comme « il n'y a rien à voir ».
#[test]
fn aucun_enonce_de_la_sonde_ne_rend_une_mesure_impossible() {
    let root = tmp_root("sonde-enonces");
    let cold = root.join("cold");
    let chemin = root.join("plume.db");
    let jour = crate::now().div_euclid(SECS_PER_DAY) - 5;
    {
        let db = mkdb(&root);
        for i in 0..12 {
            insert_event(&db, &rich_row(jour * SECS_PER_DAY + i, i));
        }
        let mut r = rich_row(crate::now(), 77_777);
        r.row.source = "recent-tail".to_string();
        insert_event(&db, &r);
        // `cold_seal` doit exister : la sonde est read-only, elle ne peut pas la créer.
        db.lock().execute_batch(
            "CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
             expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
             max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
             lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
             dim_stats BLOB, PRIMARY KEY(env_id, day, seq))",
        ).unwrap();
    }
    let rapport = crate::cold_store::cold_aging_plan(&conf_on(&cold, HOT_WIN), &chemin.to_string_lossy()).unwrap();
    assert!(
        !rapport.contains("MESURE IMPOSSIBLE"),
        "un énoncé de la sonde ne se prépare/n'exécute pas — le rapport porte une excuse là où on \
         attend une mesure :\n{rapport}"
    );
    // Et l'exécution directe, énoncé par énoncé, sur la connexion de la sonde : la même vérité, sans
    // passer par le rendu (si le rapport changeait de forme, cette assertion tiendrait quand même).
    let conn = ouvrir_en_lecture_seule(&chemin.to_string_lossy()).unwrap();
    let conf = conf_on(&cold, HOT_WIN);
    let n = crate::now();
    let bande = Bande::calculer(&conn, &conf, n, RET_DAYS);
    let tir = bande.tir_du_retard(n, dernier_tir_du_retard(&conn));
    let mut vus = 0usize;
    for e in enonces_sans_candidat(&bande, n, &tir) {
        executer_et_chronometrer(&conn, &e).unwrap_or_else(|err| panic!("énoncé `{}` : {err}", e.nom));
        vus += 1;
    }
    for e in enonces_du_candidat(&bande, "prod", jour) {
        executer_et_chronometrer(&conn, &e).unwrap_or_else(|err| panic!("énoncé `{}` : {err}", e.nom));
        vus += 1;
    }
    let page = enonce_de_la_page(&bande, "prod", jour, i64::MAX);
    executer_et_chronometrer(&conn, &page).unwrap_or_else(|err| panic!("énoncé `{}` : {err}", page.nom));
    vus += 1;
    assert_eq!(vus, 8, "le nombre d'énoncés rejoués a changé -> relire ce que la sonde couvre RÉELLEMENT");
    drop(conn);
    let _ = std::fs::remove_dir_all(&root);
}

/// `P10.13-a` LEVIER ① — LA SONDE DIT LA CADENCE, ET MESURE QUAND MÊME. Deux exigences opposées, et
/// aucune des deux n'est négociable :
///   * elle doit DIRE que la passe ne paie plus cet énoncé qu'une fois par jour — sinon la durée affichée
///     se lirait « à chaque passe », c'est-à-dire ×24 ;
///   * elle doit CONTINUER de le chronométrer — c'est le SEUL instrument capable d'attribuer un coût à
///     UN énoncé (la série ne donne que la durée totale de la passe), et le rendre aveugle 23 h sur 24 à
///     l'énoncé même que le levier change ferait de la re-mesure une impossibilité.
/// L'énoncé n'est déclaré « NON EXÉCUTÉ » que quand un gate de CONFIGURATION est fermé (non armé,
/// fenêtre vide) — là, la passe ne l'exécuterait à AUCUNE heure.
///
/// MUTATION : rendre `ParLaPasse::Jamais` sur la cause `cadence` ⇒ l'assertion « toujours chronométré »
/// rougit en montrant « NON EXÉCUTÉ PAR LA PASSE » à la place de la durée.
#[test]
fn la_sonde_annonce_la_cadence_du_detecteur_sans_cesser_de_le_mesurer() {
    let root = tmp_root("sonde-cadence");
    let cold = root.join("cold");
    let chemin = root.join("plume.db");
    let jour = crate::now().div_euclid(SECS_PER_DAY) - 50;
    let db = mkdb(&root);
    for i in 0..10 {
        insert_event(&db, &rich_row(jour * SECS_PER_DAY + i, i));
    }
    // `cold_seal` doit exister (la sonde est read-only et l'anti-jointure la référence).
    db.lock()
        .execute_batch(
            "CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
             expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
             max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
             lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
             dim_stats BLOB, PRIMARY KEY(env_id, day, seq))",
        )
        .unwrap();
    let conf = conf_ext(&cold, 365); // extension -> détecteur ARMÉ
    let chemin_s = chemin.to_string_lossy().to_string();

    /// Le bloc de rapport de l'énoncé n° 5, isolé — les assertions doivent porter sur LUI, pas sur un
    /// mot qui traînerait ailleurs dans le rapport.
    fn bloc_du_retard(rapport: &str) -> String {
        let d = rapport.find("── retard_de_vieillissement").expect("le rapport doit porter l'énoncé n° 5");
        let reste = &rapport[d..];
        match reste[3..].find("\n── ") {
            Some(f) => reste[..f + 3].to_string(),
            None => reste.to_string(),
        }
    }

    // ---- (a) AUCUN horodatage -> le tick TIRERAIT, et la sonde le dit ET le mesure. ----
    let a = bloc_du_retard(&crate::cold_store::cold_aging_plan(&conf, &chemin_s).unwrap());
    assert!(a.contains("cadence :"), "la sonde n'annonce pas la cadence :\n{a}");
    assert!(a.contains("TIRE"), "sans horodatage, CE tick tirerait :\n{a}");
    assert!(a.contains("exécution "), "l'énoncé n'est plus chronométré :\n{a}");

    // ---- (b) Horodatage RÉCENT -> le tick NE tirerait PAS... et la sonde le mesure QUAND MÊME. ----
    db.lock()
        .execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![META_DERNIER_TIR_DU_RETARD, crate::now().to_string()],
        )
        .unwrap();
    let b = bloc_du_retard(&crate::cold_store::cold_aging_plan(&conf, &chemin_s).unwrap());
    assert!(b.contains("NE TIRE PAS"), "avec un tir tout juste passé, CE tick ne tire pas :\n{b}");
    assert!(
        b.contains("exécution "),
        "la sonde a CESSÉ de chronométrer l'énoncé sous cadence -> elle devient aveugle 23 h sur 24 à \
         l'énoncé même que le levier ① change, et la re-mesure devient impossible :\n{b}"
    );
    assert!(
        !b.contains("NON EXÉCUTÉ PAR LA PASSE"),
        "« NON EXÉCUTÉ » est réservé aux gates de CONFIGURATION : la passe exécute bel et bien cet \
         énoncé, une fois par jour :\n{b}"
    );

    // ---- (c) SANS extension : là, c'est bien « NON EXÉCUTÉ » (gate de configuration fermé). ----
    let c = bloc_du_retard(&crate::cold_store::cold_aging_plan(&conf_on(&cold, HOT_WIN), &chemin_s).unwrap());
    assert!(
        c.contains("NON EXÉCUTÉ PAR LA PASSE") && !c.contains("cadence :"),
        "gate de configuration fermé -> plan montré, durée NON mesurée, et aucune cadence à annoncer :\n{c}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// =====================================================================================================
// `P10.12-a` (résiduel) — LE MOT « AGÉ » MENTAIT PAR OMISSION. En production le 2026-08-10, la passe a
// publié `plume_cold_aging_jours{issue="age"} = 10` pour DIX JOURS SANS AUCUN TRAVAIL. Le comportement
// (compromis « stragglers », verrouillé par `fix1_straggler_in_sealed_day_stays_hot_no_loss`) ne change
// PAS ; ce que la série en DIT, si.
// =====================================================================================================

/// UN JOUR NO-OP NE SE COMPTE PAS COMME COLUMNARISÉ. Le scénario est EXACTEMENT celui de la production :
/// un jour entièrement scellé ET purgé, qui redevient candidat parce que des lignes BACKDATÉES y ont
/// atterri après le scellement (des stragglers : leur `id` dépasse le `max_id` scellé, donc aucune
/// fenêtre keyset ne les couvre — elles restent chaudes, sans perte). La passe le « traite » : elle
/// relit ses seals, traverse une phase 2 où tout est déjà `purged=1`, et ne fait RIEN.
///
/// TÉMOIN POSITIF INTÉGRÉ : la PREMIÈRE passe, elle, columnarise vraiment. Sans lui, une implémentation
/// qui compterait TOUT en « sans travail » passerait ce test.
///
/// MUTATION (exécutée le 2026-08-11) : faire rendre `Journee::Columnarisee` inconditionnellement à
/// `Journee::selon_le_travail` ⇒ la 2e passe publie `columnarise=1` / `sans_travail=0` et les deux
/// assertions de la seconde moitié rougissent (le témoin positif, lui, reste vert).
#[test]
fn un_jour_sans_travail_ne_se_compte_pas_comme_columnarise() {
    let root = tmp_root("serie-sanstravail");
    let cold = root.join("cold");
    let db = mkdb(&root);
    let day = M - 9;
    let base = day * SECS_PER_DAY;
    for i in 0..20 {
        insert_event(&db, &rich_row(base + i, i));
    }
    insert_recent_tail_holder(&db);
    let conf = conf_on(&cold, HOT_WIN);

    // ---- 1re passe : du VRAI travail. ----
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);
    assert_eq!(count_hot_day(&db, "prod", day), 0, "précondition : le jour doit avoir été drainé");
    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"columnarise\"}")),
        Some(1.0),
        "TÉMOIN POSITIF : un jour réellement columnarisé doit être compté comme tel"
    );
    assert_eq!(serie(&db, NOM_JOURS, Some("{\"issue\":\"sans_travail\"}")), Some(0.0));

    // ---- Des stragglers rendent le jour à nouveau CANDIDAT, sans qu'il y ait quoi que ce soit à faire. ----
    for i in 0..7 {
        insert_event(&db, &rich_row(base + 300 + i, i));
    }
    cold_age_run(&db, "", &conf, n_now(), RET_DAYS);

    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"candidat\"}")),
        Some(1.0),
        "précondition : les stragglers doivent bien re-rendre le jour CANDIDAT (sinon ce test ne mesure \
         pas le no-op qu'il annonce)"
    );
    assert_eq!(
        serie(&db, NOM_LIGNES, Some("{\"sens\":\"retirees_du_chaud\"}")),
        Some(0.0),
        "précondition : la 2e passe ne doit RIEN retirer du chaud"
    );
    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"columnarise\"}")),
        Some(0.0),
        "un jour NO-OP est publié comme COLUMNARISÉ -> c'est le chiffre faux mesuré en production le \
         2026-08-10 (« 10 jour(s) agé(s) » pour 10 jours qui n'ont rien fait)"
    );
    assert_eq!(
        serie(&db, NOM_JOURS, Some("{\"issue\":\"sans_travail\"}")),
        Some(1.0),
        "le jour no-op n'est comptabilisé nulle part -> la comptabilité des jours ne fermerait plus et \
         AUCUN compteur de travail ne serait publié"
    );
    // La comptabilité FERME toujours : sinon `verdict` refuserait de publier et les assertions
    // ci-dessus auraient rendu `None`, pas `Some(0.0)`.
    assert_eq!(serie(&db, NOM_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0));
    let _ = std::fs::remove_dir_all(&root);
}

// =================================================================================================
// `P10.15-a` — LA SONDE PRÉSENTAIT DES DURÉES À FROID COMME LE PRIX DE LA PASSE
// =================================================================================================

/// `P10.15-a` — LE PIÈGE QUE LE REJEU A FAILLI OUVRIR, ET QUI EST LE VRAI DANGER DE CE CORRECTIF.
///
/// `sqlite3_stmt_status(..., resetFlg=0)` — ce que fait `Statement::get_status` — rend un CUMUL sur la
/// durée de vie de l'INSTRUCTION PRÉPARÉE, pas le coût de la dernière exécution. Ajouter un second passage
/// sans déplacer la lecture des compteurs aurait donc DOUBLÉ `balayage`, `tris` et `pas_de_machine` — en
/// silence, et dans le rapport même dont on est en train de réparer l'honnêteté. Les 1 708 241 balayages
/// relevés en production le 2026-08-15 seraient devenus ~3,4 M sans qu'une seule ligne ne change de forme.
///
/// LE TÉMOIN NÉGATIF EST DANS LE TEST : on prouve d'abord que le compteur DOUBLE VRAIMENT quand on exécute
/// deux fois la même instruction. Sans cette moitié-là, l'égalité vérifiée ensuite pourrait tenir parce
/// que le compteur ne cumule pas du tout — et le test passerait au vert en ne gardant rien.
///
/// MUTATION : déplacer la lecture des trois compteurs APRÈS `rejouer_a_chaud` dans
/// `executer_recolter_et_chronometrer` ⇒ `pas_de_machine` passe de la valeur d'UNE exécution à celle de
/// DEUX, et l'assertion finale rougit en nommant les deux nombres.
#[test]
fn les_compteurs_ne_comptent_que_le_passage_froid() {
    let root = tmp_root("sonde-compteurs");
    let chemin = root.join("plume.db");
    let jour = crate::now().div_euclid(SECS_PER_DAY) - 5;
    {
        let db = mkdb(&root);
        for i in 0..40 {
            insert_event(&db, &rich_row(jour * SECS_PER_DAY + i, i));
        }
    }
    let conn = ouvrir_en_lecture_seule(&chemin.to_string_lossy()).unwrap();

    // Un énoncé qui BALAIE (pas d'index sur `source`) : sans balayage, `FullscanStep` resterait à 0 et
    // l'égalité vérifiée plus bas serait vraie pour la mauvaise raison.
    let sql = "SELECT COUNT(*) FROM event WHERE source LIKE '%o%'";

    // ---- TÉMOIN NÉGATIF : le compteur CUMULE bien d'une exécution à l'autre. ----
    let (apres_une, apres_deux) = {
        let mut st = conn.prepare(sql).unwrap();
        let compter = |st: &mut rusqlite::Statement<'_>| {
            let mut rows = st.query([]).unwrap();
            while rows.next().unwrap().is_some() {}
        };
        compter(&mut st);
        let une = i64::from(st.get_status(rusqlite::StatementStatus::VmStep));
        compter(&mut st);
        (une, i64::from(st.get_status(rusqlite::StatementStatus::VmStep)))
    };
    assert!(apres_une > 0, "l'énoncé témoin n'exécute rien : le test ne garderait rien");
    assert!(
        apres_deux >= apres_une * 2 - 2,
        "PRÉMISSE DU TEST FAUSSE : `VmStep` ne cumule pas d'une exécution à l'autre ({apres_une} puis \
         {apres_deux}). Alors l'égalité vérifiée ensuite ne prouve plus rien — c'est le test qu'il faut \
         refaire, pas le code."
    );

    // ---- CE QUE LA SONDE PUBLIE : la valeur d'UNE exécution, malgré ses deux passages. ----
    let e = Enonce {
        nom: "temoin_de_comptage",
        role: "énoncé fabriqué pour ce test — il balaie `event`",
        sql: sql.to_string(),
        params: Vec::new(),
        par_la_passe: ParLaPasse::ChaqueTick,
    };
    let m = executer_et_chronometrer(&conn, &e).unwrap();
    assert_eq!(
        m.pas_de_machine, apres_une,
        "la sonde publie {} pas de machine là où UNE exécution en coûte {apres_une} : le second passage \
         (`P10.15-a`) est compté dans les compteurs, donc tous les chiffres de travail du rapport sont \
         doublés en silence.",
        m.pas_de_machine
    );
    assert!(m.balayage > 0, "l'énoncé témoin devait balayer -> `FullscanStep` ne peut pas être nul");
    assert_eq!(
        m.balayage,
        apres_une.min(m.balayage), // borne : jamais au-delà d'une exécution
        "même vérité sur `balayage` : {} publié pour une seule exécution",
        m.balayage
    );
    // Et la mesure a bien EU LIEU deux fois : sinon on aurait « corrigé » le doublement en supprimant le
    // rejeu, ce qui remettrait exactement le défaut d'origine.
    assert!(
        matches!(m.execution_chaud, Chaud::Mesure(_)),
        "aucun passage chaud mesuré -> la sonde est revenue à une durée unique, sans dire de quel cache \
         elle vient : c'est le défaut `P10.15-a` réintroduit"
    );
    drop(conn);
    let _ = std::fs::remove_dir_all(&root);
}

/// `P10.15-a` — LE VERDICT DÉPARTAGE, ET IL NE DIT PAS LA MÊME CHOSE DANS LES DEUX CAS.
///
/// Les couples ne sont pas inventés : ce sont les DEUX relevés de production du 2026-08-15.
///   * `decouverte_des_jours` : 3 847 ms à froid, tandis que la passe VIVANTE bouclait tout entière en
///     12 à 31 ms -> le cache absorbe l'essentiel, le froid ne décrit PAS la passe ;
///   * `retard_de_vieillissement` : 37 471 ms pour la sonde contre 38 836 ms pour la passe -> aucun cache
///     n'absorbe un balayage de 1,7 M lignes, le froid DÉCRIT la passe.
/// Un verdict qui rendrait la même phrase pour ces deux couples ne servirait à rien : c'est ce que la
/// dernière assertion refuse.
#[test]
fn le_verdict_de_cache_separe_ce_que_le_cache_absorbe_de_ce_qu_il_n_absorbe_pas() {
    let fabriquer = |froid: f64, chaud: Chaud| Mesure {
        plan: vec!["SCAN event".to_string()],
        compilation_ms: 0.1,
        execution_froid_ms: froid,
        execution_chaud: chaud,
        lignes: 1,
        balayage: 0,
        tris: 0,
        pas_de_machine: 0,
    };

    let absorbe = fabriquer(3847.1, Chaud::Mesure(21.0)).verdict_de_cache();
    assert!(
        absorbe.contains("SURESTIME") && absorbe.contains("21.0 ms"),
        "le couple mesuré en prod (3847 ms à froid, 21 ms chauds) doit être annoncé comme surestimé, et \
         nommer la valeur que la passe paie vraiment : {absorbe}"
    );

    let reel = fabriquer(37470.6, Chaud::Mesure(36000.0)).verdict_de_cache();
    assert!(
        reel.contains("DÉCRIT la passe"),
        "un balayage que le cache n'absorbe pas doit être annoncé comme décrivant la passe : {reel}"
    );
    assert_ne!(
        absorbe, reel,
        "le verdict rend la MÊME phrase pour un énoncé surestimé ×183 et pour un énoncé exact à 3,5 % : \
         il ne départage rien et la ligne `cache` du rapport est décorative"
    );

    let court = fabriquer(0.2, Chaud::Mesure(0.1)).verdict_de_cache();
    assert!(
        court.contains("trop court"),
        "sous le plancher, un rapport ×2 n'est que du bruit d'ordonnancement -> on ne conclut pas : {court}"
    );
    assert!(
        !court.contains("SURESTIME"),
        "un énoncé à 0,2 ms est annoncé comme « surestimant la passe » : le plancher ne joue pas, et le \
         rapport criera au cache sur chaque énoncé trivial : {court}"
    );

    let muet = fabriquer(12.0, Chaud::NonMesure(CHAUD_REJEU_EN_ECHEC)).verdict_de_cache();
    assert!(
        muet.contains("NON DÉPARTAGÉ") && muet.contains("rien ne dit ce que le cache en absorbe"),
        "sans second passage, la sonde doit dire qu'elle N'A PAS départagé — pas laisser la durée sur \
         connexion neuve passer pour le prix de la passe. (Le mot « BORNE HAUTE » a été RETIRÉ le \
         2026-08-15 : la vérification en production a montré que ce n'en était pas une — même énoncé, \
         10,1 / 3 847 / 11,3 ms selon l'état du cache de l'OS.) : {muet}"
    );
}

/// `P10.15-a` — AUCUNE DURÉE N'EST PUBLIÉE SANS SA LIGNE `cache`. La garde porte sur le RAPPORT RÉEL, pas
/// sur `verdict_de_cache` en isolation : le défaut d'origine n'était pas que la sonde ignorait la nuance
/// (elle l'écrivait, mot pour mot, en tête du module) — c'est qu'elle ne la METTAIT PAS DANS SA SORTIE.
/// Une garde qui ne testerait que la fonction pure raterait exactement le défaut qu'on ferme.
///
/// La règle est DÉRIVÉE du texte rendu, pas d'une liste d'énoncés : tout bloc qui contient `exécution `
/// doit contenir `cache   :`. Un énoncé ajouté demain y est soumis sans que personne n'y pense.
///
/// MUTATION : retirer la ligne `cache   :` de `rendre` ⇒ le test nomme les blocs fautifs.
#[test]
fn le_rapport_ne_publie_aucune_duree_sans_dire_de_quel_cache_elle_vient() {
    let root = tmp_root("sonde-cache-rapport");
    let cold = root.join("cold");
    let chemin = root.join("plume.db");
    let jour = crate::now().div_euclid(SECS_PER_DAY) - 50;
    let db = mkdb(&root);
    for i in 0..10 {
        insert_event(&db, &rich_row(jour * SECS_PER_DAY + i, i));
    }
    db.lock()
        .execute_batch(
            "CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
             expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
             max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
             lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
             dim_stats BLOB, PRIMARY KEY(env_id, day, seq))",
        )
        .unwrap();
    let rapport =
        crate::cold_store::cold_aging_plan(&conf_ext(&cold, 365), &chemin.to_string_lossy()).unwrap();

    // Découpage en blocs d'énoncé, sur le SEUL séparateur que `rendre` émet.
    let blocs: Vec<&str> = rapport.split("\n── ").skip(1).collect();
    assert!(blocs.len() >= 5, "le rapport ne porte que {} bloc(s) -> le découpage a changé", blocs.len());
    let mut chronometres = 0usize;
    for b in &blocs {
        if !b.contains("exécution ") {
            continue;
        }
        chronometres += 1;
        let nom = b.lines().next().unwrap_or("<sans nom>");
        assert!(
            b.contains("cache   :"),
            "l'énoncé `{nom}` publie une durée SANS dire si elle décrit la passe ou un cache vide — c'est \
             le défaut `P10.15-a` (mesuré : ×183 d'écart sur `decouverte_des_jours`) :\n{b}"
        );
        assert!(
            b.contains("FROID") && b.contains("CHAUD"),
            "l'énoncé `{nom}` ne publie plus les DEUX bornes : un seul nombre redevient indéchiffrable\n{b}"
        );
    }
    assert!(
        chronometres >= 4,
        "seulement {chronometres} énoncé(s) chronométré(s) dans le rapport -> la garde ne couvre presque \
         rien, et passerait au vert sur une sonde devenue muette"
    );
    // Et la mise en garde est dans la SORTIE, là où l'opérateur la lit.
    // `P10.15-a` RÉSIDUEL — CE QUE LE RAPPORT DOIT DIRE A CHANGÉ, ET EN MIEUX. La première version
    // annonçait le passage froid comme une « BORNE HAUTE ». La vérification en production l'a REFUTÉ : le
    // même énoncé a rendu 10,1 ms, 3 847 ms puis 11,3 ms selon le jour, parce que le cache de l'OS n'est
    // pas remis à zéro et que la sonde ne le mesure pas. Un majorant qui varie de ×341 n'en est pas un.
    // La garde suit donc la propriété RÉELLE : le rapport doit annoncer la double mesure, nommer le CHAUD
    // comme PLANCHER, et NIER explicitement que le froid soit un majorant.
    assert!(
        rapport.contains("MESURÉ DEUX FOIS"),
        "le rapport ne dit pas à son lecteur que ses durées sont mesurées deux fois : la nuance est \
         retournée dans le code, invisible depuis `kubectl exec`\n{rapport}"
    );
    assert!(
        rapport.contains("PLANCHER"),
        "le rapport ne nomme pas le passage CHAUD comme un plancher — or c'est la seule des deux valeurs \
         qui borne vraiment quelque chose\n{rapport}"
    );
    assert!(
        rapport.contains("n'est PAS un majorant"),
        "LE RAPPORT LAISSE CROIRE QUE LE FROID MAJORE LA PASSE. Mesuré le 2026-08-15 : le même énoncé rend \
         10,1 ms, 3 847 ms ou 11,3 ms selon l'état du cache de l'OS, que cette sonde ne remet pas à zéro \
         et ne mesure pas. Annoncer une borne qu'on n'a pas est exactement le défaut que `P10.15-a` \
         ferme\n{rapport}"
    );
    drop(db);
    let _ = std::fs::remove_dir_all(&root);
}
