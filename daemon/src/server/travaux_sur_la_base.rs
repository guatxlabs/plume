//! server::travaux_sur_la_base — LES TRAVAUX DE FOND QUI AGISSENT SUR LA BASE PRIMAIRE elle-même, par
//! opposition aux boucles de service qui traitent des tenants : l'auto-vacuum incrémental
//! (`OPS NATIVE #2`, non bloquant et inopérant en silence annoncé si la base n'est pas en
//! `auto_vacuum=INCREMENTAL`), l'`ANALYZE` de démarrage, la réconciliation des index d'expression et
//! les familles d'index créées ou retirées au bind, le remplissage FTS, et le PRÉ-CHAUFFAGE de lecture
//! qui paie le déchiffrement à froid hors du premier clic. Tous sont gatés sur le drapeau `bound` ou
//! sur une grâce après le bind : aucun ne touche au verrou d'écriture tant que le port n'écoute pas.
//! Sous-module de `server` (cf. `server/mod.rs`). Les fonctions appelées par la façade sont
//! `pub(super)` — visibles dans `server` et ses sous-modules, invisibles du reste du crate ;
//! `spawn_autovacuum_loop`, lui, garde son chemin `crate::server::spawn_autovacuum_loop` par
//! ré-export.
use super::*;

// OPS NATIVE #2 — AUTO-VACUUM INCRÉMENTAL IN-DAEMON (best-effort, NON-BLOQUANT). Gaté sur
// `PLUME_AUTOVACUUM_INTERVAL` (secondes ; 0/absent = DÉSACTIVÉ -> aucun thread -> byte-identique).
// Contrairement au VACUUM plein (réécrit toute la base sous lock -> bloque TOUTES les requêtes : inacceptable
// in-daemon sous trafic), `PRAGMA incremental_vacuum(N)` réclame la freelist par PETITS LOTS de pages sans
// réécrire la base -> non-bloquant et borné. MAIS il n'opère QUE si la base est en `auto_vacuum=INCREMENTAL`
// (PRAGMA auto_vacuum==2). Sur une base `auto_vacuum=NONE` (==0, le cas PROD actuel, vérifié via `db-stats`)
// il est INOPÉRANT : on logge un warn HONNÊTE et on ne force JAMAIS un VACUUM plein bloquant (le reclaim plein
// reste une maintenance manuelle / restart via `vacuum-compact`). Seuil `PLUME_AUTOVACUUM_MIN_FREE_PAGES` :
// évite un travail inutile quand la freelist est petite (régime permanent ingest≈purge -> reclaim marginal).
pub(crate) fn spawn_autovacuum_loop(conf: HashMap<String, String>, db: Arc<Mutex<Connection>>) {
        let interval: u64 = cfg(&conf, "PLUME_AUTOVACUUM_INTERVAL", "0").parse().unwrap_or(0);
        if interval == 0 { return; } // DÉSACTIVÉ (défaut) -> aucun thread -> byte-identique.
        let min_free: i64 = cfg(&conf, "PLUME_AUTOVACUUM_MIN_FREE_PAGES", "1000").parse().unwrap_or(1000).max(1);
        let batch_pages: i64 = cfg(&conf, "PLUME_AUTOVACUUM_BATCH_PAGES", "256").parse().unwrap_or(256).max(1);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(120)); // après le bind + la liveness + le 1er rollup.
            // DIAGNOSTIC une fois : mode auto_vacuum réel. NONE/FULL -> on prévient que incremental_vacuum est inopérant.
            {
                let c = db.lock();
                let av: i64 = c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap_or(-1);
                if av != 2 {
                    eprintln!(
                        "[autovacuum] PLUME_AUTOVACUUM_INTERVAL posé MAIS auto_vacuum={av} (≠INCREMENTAL=2) : \
                         incremental_vacuum INOPÉRANT sur cette base. Le reclaim plein exige un VACUUM plein \
                         BLOQUANT (maintenance manuelle / restart via vacuum-compact) — NON forcé ici. Boucle \
                         inerte (aucune requête bloquée).");
                } else {
                    eprintln!(
                        "[autovacuum] ACTIF : intervalle={interval}s min_free={min_free}p batch={batch_pages}p \
                         (auto_vacuum=INCREMENTAL, non-bloquant, best-effort)");
                }
            }
            loop {
                std::thread::sleep(Duration::from_secs(interval));
                let c = db.lock();
                let av: i64 = c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap_or(-1);
                if av != 2 { continue; } // NONE/FULL -> incremental_vacuum inopérant ; on ne BLOQUE JAMAIS.
                let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0)).unwrap_or(0);
                if free < min_free { continue; } // freelist petite -> reclaim marginal, on saute (cheap).
                // Lot BORNÉ (batch_pages) -> tenue du lock writer COURTE ; les LECTURES restent servies (WAL).
                match c.execute_batch(&format!("PRAGMA incremental_vacuum({batch_pages});")) {
                    Ok(_) => eprintln!("[autovacuum] incremental_vacuum({batch_pages}) (freelist était {free}p)"),
                    Err(e) => eprintln!("[autovacuum] incremental_vacuum échoué : {e} (best-effort -> on continue)"),
                }
            }
        });
}

pub(super) fn spawn_analyze_full(db: Arc<Mutex<Connection>>, bound: Arc<std::sync::atomic::AtomicBool>) {
        std::thread::spawn(move || {
            // gate structurel : ne PAS toucher au lock writer tant que le port n'écoute pas (readiness OK).
            while !bound.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
            std::thread::sleep(Duration::from_secs(20)); // grâce : laisse la liveness probe passer après le bind
            analyze_full_background(&db);
        });
}

pub(super) fn spawn_reconcile_expr_indexes(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(25)); // laisse le bind + la liveness probe passer
            reconcile_expr_indexes_background(&db);
        });
}

pub(super) fn spawn_ensure_event_category_index(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(28)); // après le bind + la liveness probe
            ensure_event_category_index_background(&db);
        });
}

pub(super) fn spawn_drop_redundant_event_indexes(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(29)); // après le bind + la liveness probe
            drop_redundant_event_indexes_background(&db);
        });
}

pub(super) fn spawn_drop_prefix_subsumed_indexes(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30)); // après le bind + la liveness probe (P10.2-d)
            drop_prefix_subsumed_indexes_background(&db);
        });
}

pub(super) fn spawn_drop_orphan_auto_field_indexes(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(32)); // après le bind + la liveness probe (P6.8-b)
            drop_orphan_auto_field_indexes_background(&db);
        });
}

pub(super) fn spawn_ensure_host_rollup_scan_indexes(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(31)); // après le bind + la liveness probe
            ensure_host_rollup_scan_indexes_background(&db);
        });
}

pub(super) fn spawn_ensure_event_src_ts_index(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(33)); // après le bind + la liveness probe (v108)
            ensure_event_src_ts_index_background(&db);
        });
}

pub(super) fn spawn_ensure_event_health_beat_index(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(35)); // après le bind + la liveness probe (P3.7-a)
            ensure_event_health_beat_index_background(&db);
        });
}

pub(super) fn spawn_fts_backfill(db: Arc<Mutex<Connection>>) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30)); // laisse passer bind + liveness avant l'IO de fond
            fts_backfill_background(&db);
        });
}

// #23 — Requêtes de PRÉ-CHAUFFAGE façon /api/overview (tables alert/incident/event_rollup), BORNÉES et
// read-only. compute_integrations/compute_freshness réchauffent déjà event/metric/snapshot/host_rollup ;
// celles-ci couvrent en plus les pages des tables d'overview. Best-effort (erreurs ignorées).
const PREWARM_QUERIES: &[&str] = &[
    "SELECT COUNT(*) FROM alert WHERE status='new'",
    "SELECT COUNT(*) FROM incident WHERE status<>'closed'",
    "SELECT COALESCE(SUM(n),0) FROM event_rollup",
    "SELECT MAX(ts) FROM alert",
];

// #23 — pré-chauffage lecture au boot. Toggle PLUME_BOOT_PREWARM (défaut ON) ; OFF -> ne fait rien.
// Gaté comme les autres one-shot de boot : attend le drapeau `bound` (le port écoute) + une courte grâce
// (liveness passée) AVANT toute lecture -> ne perturbe jamais la readiness. Jamais bloquant : tout est
// best-effort et hors du chemin de service.
pub(super) fn spawn_boot_prewarm(conf: HashMap<String, String>, db_path: String, bound: Arc<std::sync::atomic::AtomicBool>) {
        if cfg(&conf, "PLUME_BOOT_PREWARM", "1") != "1" {
            return; // désactivé explicitement.
        }
        std::thread::spawn(move || {
            while !bound.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
            }
            std::thread::sleep(Duration::from_secs(22)); // grâce : après le bind + la liveness probe.
            boot_prewarm_run(&db_path);
        });
}

// Exécute le pré-chauffage : intégrations (le pire à froid) + fraîcheur, EN REMPLISSANT leurs caches SWR
// (clé = db_path, cf. spawn_rollup_loop / handler integrations), puis quelques agrégats overview pour
// réchauffer les pages restantes. Tout best-effort (erreurs avalées). Idempotent, hors chemin de service.
fn boot_prewarm_run(db_path: &str) {
    // 1) intégrations : ~12 s FROID -> on paie le déchiffrement ICI (hors requête utilisateur) et on garnit
    //    le cache SWR pour que le 1er clic soit instantané.
    let iv = compute_integrations(db_path);
    integrations_map().lock().insert(db_path.to_string(), (Instant::now(), iv));
    // 2) fraîcheur tous-env (scan 7 j) -> même clé que la boucle de rollup (db_path, env=None).
    let fv = compute_freshness(db_path, None);
    freshness_map().lock().insert(db_path.to_string(), (Instant::now(), fv));
    // 3) agrégats overview : réchauffe les pages alert/incident/event_rollup (best-effort).
    for q in PREWARM_QUERIES {
        let _ = read_with(db_path, (), |c| {
            let _ = c.query_row(q, [], |_| Ok(()));
        });
    }
    eprintln!("[prewarm] pré-chauffage lecture terminé (intégrations + fraîcheur + {} agrégats overview) pour {db_path}", PREWARM_QUERIES.len());
}
