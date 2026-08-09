//! DAY-2 OPS (#51) — SELF-MÉTRIQUES & SANTÉ PAR COMPOSANT. Compteurs/jauges PROCESS-GLOBAUX (atomics)
//! incrémentés EN LIGNE sur les chemins déjà chauds (HTTP, ingest, recherche, scheduler) — JAMAIS un scan
//! de `event` par requête (doctrine 2 Go). `gather_prom` produit l'exposition Prometheus texte ; `gather_json`
//! la même donnée pour le panneau UI « Système » ; `component_health` dérive un état R/J/V par sous-système
//! (ingest / détection / rollups / store / forwarder) depuis la fraîcheur + les horodatages de tick + les
//! compteurs d'erreur. Additif : rien de ceci n'altère une réponse HTTP ni une écriture DB -> mode 0
//! byte-identique (les atomics sont invisibles du client).
use crate::*;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// ---------- compteurs / jauges process-globaux (mis à jour EN LIGNE, coût ~1 ns) ----------
/// Requêtes HTTP servies (toutes routes) — bumpé dans `security_headers` (une couche déjà traversée par
/// TOUTES les requêtes) : aucune nouvelle couche, aucune State requise, invisible du client.
pub(crate) static HTTP_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Réponses 5xx (erreurs serveur) — signal d'anomalie côté opérateur.
pub(crate) static HTTP_5XX_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Events ingérés depuis le démarrage (compteur monotone) — bumpé dans `ingest_events_batch_env`.
pub(crate) static INGEST_EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Fichiers spool consommés — bumpé dans `ingest_once`.
pub(crate) static INGEST_FILES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// P-HEC (LOW#2) — batches PUSH (Firehose/Pub-Sub) ACCEPTÉS mais mappés à ZÉRO event (base64/JSON indécodable
/// ou field_map/records_path mal configuré). Rend OBSERVABLE un misconfig de source push qui, sinon, serait
/// silencieusement ACK-droppé (200/204) : un compteur qui grimpe sans `ingest_events_total` correspondant.
pub(crate) static PUSH_ZERO_MAP_TOTAL: AtomicU64 = AtomicU64::new(0);
/// P4.1-p — un compteur PAR RAISON d'ACK-DROP Pub/Sub. Pourquoi pas un seul total : `push_zero_map_total`
/// était incrémenté aussi bien par un `field_map` mal configuré que par une bombe gzip. L'exploitant qui le
/// voyait grimper allait donc inspecter son mapping alors que la cause pouvait être une TAILLE. Un compteur
/// qui NOMME mal ce qu'il compte oriente l'enquête à côté ; il vaut à peine mieux que pas de compteur.
///
/// La longueur est VÉRIFIÉE À LA COMPILATION contre `AckDrop::TOUTES` (assertion sous la déclaration de
/// l'énumération, ingest/pubsub.rs) : une raison ajoutée demain sans sa case NE COMPILE PAS.
pub(crate) static PUBSUB_ACKDROP: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Recherches interactives (query/search) servies.
pub(crate) static SEARCH_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Ticks du scheduler de règles + horodatage (unix s) du dernier tick — santé « détection ».
pub(crate) static SCHED_RULE_TICKS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCHED_RULE_LAST_TS: AtomicI64 = AtomicI64::new(0);
/// Ticks de rollup + horodatage (unix s) du dernier tick — santé « rollups ».
pub(crate) static SCHED_ROLLUP_TICKS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCHED_ROLLUP_LAST_TS: AtomicI64 = AtomicI64::new(0);
/// Horodatage (unix s) de démarrage du process — posé une fois au boot (process_start_time_seconds).
pub(crate) static START_TS: AtomicI64 = AtomicI64::new(0);
/// READINESS (k8s /readyz) : passe à true APRÈS migrate + bind (port écoute). Lu par le handler readyz.
pub(crate) static READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Réservoir borné des dernières latences de recherche (ms) pour p50/p95. Petit (cap 512) : lock trivial,
/// aucune allocation par point après remplissage. Jamais un vecteur de fuite (que des durées).
static SEARCH_LAT: std::sync::OnceLock<Mutex<std::collections::VecDeque<u32>>> = std::sync::OnceLock::new();
pub(crate) const SEARCH_LAT_CAP: usize = 512;
fn search_lat() -> &'static Mutex<std::collections::VecDeque<u32>> {
    SEARCH_LAT.get_or_init(|| Mutex::new(std::collections::VecDeque::with_capacity(SEARCH_LAT_CAP)))
}

/// Enregistre une latence de recherche (ms) : compteur + réservoir borné (évince le plus ancien).
pub(crate) fn record_search(ms: u32) {
    SEARCH_TOTAL.fetch_add(1, Ordering::Relaxed);
    let mut q = search_lat().lock();
    if q.len() >= SEARCH_LAT_CAP {
        q.pop_front();
    }
    q.push_back(ms);
}

/// GARDE-CHRONO (RAII) : posé en tête des handlers query/search (`let _t = search_timer();`), il enregistre
/// la latence à la SORTIE (Drop) quel que soit le chemin de retour. Coût nul hors ces deux handlers.
pub(crate) struct SearchTimer(Instant);
pub(crate) fn search_timer() -> SearchTimer {
    SearchTimer(Instant::now())
}
impl Drop for SearchTimer {
    fn drop(&mut self) {
        record_search(self.0.elapsed().as_millis().min(u32::MAX as u128) as u32);
    }
}

/// Quantile (nearest-rank) d'un échantillon TRIÉ. Vide -> None.
fn quantile_sorted(sorted: &[u32], q: f64) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    Some(sorted[rank - 1])
}

/// (p50, p95, count) des latences de recherche observées. count=0 -> (0,0,0).
pub(crate) fn search_quantiles() -> (u32, u32, usize) {
    let q = search_lat().lock();
    if q.is_empty() {
        return (0, 0, 0);
    }
    let mut v: Vec<u32> = q.iter().copied().collect();
    v.sort_unstable();
    (quantile_sorted(&v, 0.50).unwrap_or(0), quantile_sorted(&v, 0.95).unwrap_or(0), v.len())
}

// ---------- lecture /proc/self (CPU + RSS) — cheap, sans dépendance, sans scan ----------
/// (cpu_seconds cumulés, rss_bytes) du process via /proc/self. None si /proc indisponible (non-Linux/CI).
pub(crate) fn proc_self_cpu_rss() -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Le champ `comm` (2e) peut contenir des espaces/parenthèses -> on repart APRÈS la dernière ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // Après la ')': index 0 = state (champ 3). utime=champ 14 -> index 11 ; stime=champ 15 -> index 12.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as f64 } else { 100.0 };
    let cpu = (utime + stime) as f64 / hz;
    // RSS = champ 2 (pages résidentes) de /proc/self/statm × taille de page.
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let pg = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let pg = if pg > 0 { pg as u64 } else { 4096 };
    Some((cpu, rss_pages * pg))
}

/// Nombre de fichiers en attente dans le spool (profondeur de file d'ingest) — read_dir borné, no-op si absent.
pub(crate) fn spool_queue_depth(spool: &str) -> u64 {
    match std::fs::read_dir(spool) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                !n.starts_with('.') && (n.ends_with(".json") || n.ends_with(".ndjson"))
            })
            .count() as u64,
        Err(_) => 0,
    }
}

/// Taille de la base (fichier principal + WAL) en octets — stat cheap, jamais un COUNT(*).
pub(crate) fn db_size_bytes(db_path: &str) -> u64 {
    if db_path.is_empty() {
        return 0;
    }
    let main = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
    let wal = std::fs::metadata(format!("{db_path}-wal")).map(|m| m.len()).unwrap_or(0);
    main + wal
}

// ---------- santé par composant (R/J/V) ----------
/// État santé d'un composant : "green" (V) / "yellow" (J) / "red" (R) / "idle" (inactif = non déployé, sain).
/// `score` = 1.0 / 0.5 / 0.0 / 1.0 -> jauge Prometheus `plume_component_up`.
pub(crate) fn health_score(state: &str) -> f64 {
    match state {
        "green" | "idle" => 1.0,
        "yellow" => 0.5,
        _ => 0.0,
    }
}

/// SNAPSHOT complet des composants (ingest / détection / rollups / store / forwarder) sous forme de valeurs
/// JSON {component, state, detail, ...}. Lecture SEULE, sur PETITES tables (rollup/alert/destination) +
/// atomics + statvfs : jamais un scan de `event`. Appelé par /metrics, /api/system/health et le diag-bundle.
pub(crate) fn component_health(conn: &Connection, spool: &str, db_path: &str, disk_warn_pct: u8) -> Vec<Value> {
    let now_ts = now();
    let mut out = Vec::new();

    // INGEST : santé du pipeline (fraîcheur globale) + backlog spool. Un silence n'est PAS une panne
    // (doctrine fraîcheur) -> stale = jaune (jamais rouge) ; backlog important = jaune (ingest en retard).
    let fresh = pipeline_is_fresh(conn, now_ts);
    let queue = spool_queue_depth(spool);
    let had_data: Option<i64> = conn
        .query_row(
            "SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event UNION ALL SELECT MAX(ts) FROM metric UNION ALL SELECT MAX(ts) FROM snapshot)",
            [], |r| r.get::<_, Option<i64>>(0),
        )
        .ok()
        .flatten();
    let (istate, idetail) = if queue > 500 {
        ("yellow", format!("backlog spool : {queue} fichiers en attente"))
    } else if had_data.is_none() {
        ("idle", "aucune donnée encore ingérée".to_string())
    } else if fresh {
        ("green", "données fraîches (< 10 min)".to_string())
    } else {
        ("yellow", "aucune donnée récente (source calme ou collecte arrêtée)".to_string())
    };
    out.push(json!({ "component": "ingest", "state": istate, "detail": idetail, "queue_depth": queue }));

    // DÉTECTION : le scheduler de règles tick-t-il ? (SCHED_RULE_LAST_TS). 0 = pas encore tické (boot) -> idle.
    let rule_last = SCHED_RULE_LAST_TS.load(Ordering::Relaxed);
    let (dstate, ddetail) = tick_health(rule_last, now_ts, 120, 600, "scheduler de règles");
    let n_rules: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE enabled=1", [], |r| r.get(0)).unwrap_or(0);
    out.push(json!({ "component": "detection", "state": dstate, "detail": ddetail, "enabled_rules": n_rules, "last_tick": rule_last }));

    // ROLLUPS : la boucle de rollup tick-t-elle ? (intervalle défaut 120 s).
    let rollup_last = SCHED_ROLLUP_LAST_TS.load(Ordering::Relaxed);
    let (rstate, rdetail) = tick_health(rollup_last, now_ts, 300, 900, "boucle de rollup");
    out.push(json!({ "component": "rollups", "state": rstate, "detail": rdetail, "last_tick": rollup_last }));

    // STORE : disque de données (statvfs). >95% rouge, > seuil jaune, sinon vert. DB ouvrable (on lit ici) = ok.
    let dir = std::path::Path::new(db_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let (sstate, sdetail, used_pct) = match fs_total_avail_mb(&dir).and_then(|(t, a)| disk_used_pct(t, a).map(|p| (p, t, a))) {
        Some((pct, total, avail)) => {
            let warn = if disk_warn_pct == 0 { 85 } else { disk_warn_pct };
            let st = if pct > 95 { "red" } else if pct > warn { "yellow" } else { "green" };
            (st, format!("disque données {pct}% utilisé ({avail} Mo libres / {total} Mo)"), pct)
        }
        None => ("green", "usage disque indisponible (statvfs)".to_string(), 0),
    };
    out.push(json!({ "component": "store", "state": sstate, "detail": sdetail, "disk_used_pct": used_pct, "db_size_bytes": db_size_bytes(db_path) }));

    // FORWARDER (#50 outputs/destinations) : table vide -> idle (mode 0). Une destination ACTIVE en erreur
    // (last_error non vide) -> jaune. Sinon vert. Table absente (schéma < v92) -> idle.
    let (fstate, fdetail) = destination_health(conn);
    out.push(json!({ "component": "forwarder", "state": fstate, "detail": fdetail }));

    out
}

/// Santé d'un tick de fond depuis son dernier horodatage : 0 = jamais tické (boot) -> idle ; frais < warn ->
/// green ; < crit -> yellow ; au-delà -> red (le worker est probablement bloqué).
fn tick_health(last_ts: i64, now_ts: i64, warn_s: i64, crit_s: i64, what: &str) -> (&'static str, String) {
    if last_ts == 0 {
        return ("idle", format!("{what} : pas encore exécuté (démarrage)"));
    }
    let age = now_ts - last_ts;
    if age < warn_s {
        ("green", format!("{what} actif (dernier tick il y a {age}s)"))
    } else if age < crit_s {
        ("yellow", format!("{what} en retard (dernier tick il y a {age}s)"))
    } else {
        ("red", format!("{what} bloqué ? (dernier tick il y a {age}s)"))
    }
}

/// Santé du forwarder depuis la table `destination` (#50). Table absente/vide -> idle. Best-effort.
fn destination_health(conn: &Connection) -> (&'static str, String) {
    let total: i64 = match conn.query_row("SELECT COUNT(*) FROM destination", [], |r| r.get(0)) {
        Ok(n) => n,
        Err(_) => return ("idle", "aucune destination configurée".to_string()),
    };
    if total == 0 {
        return ("idle", "aucune destination configurée".to_string());
    }
    let errored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM destination WHERE enabled=1 AND COALESCE(last_error,'')<>''",
            [], |r| r.get(0),
        )
        .unwrap_or(0);
    if errored > 0 {
        ("yellow", format!("{errored}/{total} destination(s) en erreur"))
    } else {
        ("green", format!("{total} destination(s) OK"))
    }
}

/// L'état PIRE d'un ensemble de composants -> posture globale (red > yellow > green/idle).
pub(crate) fn worst_state(components: &[Value]) -> &'static str {
    let mut worst = "green";
    for c in components {
        match c.get("state").and_then(|s| s.as_str()) {
            Some("red") => return "red",
            Some("yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

// ---------- exposition ----------
/// Échantillon de self-métriques (valeurs numériques uniquement — jamais un secret/PII), factorisé pour
/// /metrics (texte Prometheus) ET /api/system/metrics (JSON du panneau UI). Lecture SEULE, tables petites.
pub(crate) fn gather_json(conn: &Connection, spool: &str, db_path: &str, schema_version: i64, disk_warn_pct: u8) -> Value {
    let now_ts = now();
    let (cpu, rss) = proc_self_cpu_rss().unwrap_or((0.0, 0));
    let (p50, p95, lat_n) = search_quantiles();
    // ingest « dernière heure » depuis event_rollup (pré-agrégé, ~ms) -> débit sans scanner `event`.
    let events_1h: i64 = conn
        .query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket>=?1", params![now_ts - 3600], |r| r.get(0))
        .unwrap_or(0);
    let alerts_open: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE status='new'", [], |r| r.get(0)).unwrap_or(0);
    let components = component_health(conn, spool, db_path, disk_warn_pct);
    let posture = worst_state(&components);
    // ACK-DROP Pub/Sub : la surface est DÉRIVÉE de `AckDrop::TOUTES`, jamais réécrite ici. Une raison ajoutée
    // demain apparaît dans `/metrics` sans qu'on y pense — l'oubli d'exposition n'est pas une option offerte.
    let pubsub_ackdrop_par_raison: serde_json::Map<String, Value> = crate::ingest::pubsub::AckDrop::TOUTES
        .iter()
        .map(|r| (r.libelle().to_string(), json!(PUBSUB_ACKDROP[r.rang()].load(Ordering::Relaxed))))
        .collect();
    let pubsub_ackdrop_total: u64 = PUBSUB_ACKDROP.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    json!({
        "ts": now_ts,
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": schema_version,
        "uptime_s": (now_ts - START_TS.load(Ordering::Relaxed)).max(0),
        "process": { "cpu_seconds": cpu, "rss_bytes": rss },
        "http": {
            "requests_total": HTTP_REQUESTS_TOTAL.load(Ordering::Relaxed),
            "responses_5xx_total": HTTP_5XX_TOTAL.load(Ordering::Relaxed),
        },
        "ingest": {
            "events_total": INGEST_EVENTS_TOTAL.load(Ordering::Relaxed),
            "files_total": INGEST_FILES_TOTAL.load(Ordering::Relaxed),
            "events_1h": events_1h,
            "queue_depth": spool_queue_depth(spool),
            "push_zero_map_total": PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed),
            "pubsub_ackdrop_total": pubsub_ackdrop_total,
            "pubsub_ackdrop_par_raison": pubsub_ackdrop_par_raison,
        },
        "search": { "requests_total": SEARCH_TOTAL.load(Ordering::Relaxed), "p50_ms": p50, "p95_ms": p95, "samples": lat_n },
        "scheduler": {
            "rule_ticks_total": SCHED_RULE_TICKS.load(Ordering::Relaxed),
            "rule_last_tick": SCHED_RULE_LAST_TS.load(Ordering::Relaxed),
            "rollup_ticks_total": SCHED_ROLLUP_TICKS.load(Ordering::Relaxed),
            "rollup_last_tick": SCHED_ROLLUP_LAST_TS.load(Ordering::Relaxed),
        },
        // `ventilation` = la DERNIÈRE tentative du tick lent, servie DEPUIS LE CACHE : lire /metrics ou
        // le panneau Système ne déclenche JAMAIS un parcours dbstat (35,4 s mesurés en production).
        // `null` = jamais mesuré ; `{"mesuree":false,…}` = mesure REFUSÉE (jamais un objet de zéros).
        "db": { "size_bytes": db_size_bytes(db_path), "ventilation": ventilation_serie::json(&ventilation_serie::derniere(), now_ts) },
        "alerts_open": alerts_open,
        "posture": posture,
        "components": components,
    })
}

fn prom_line(out: &mut String, name: &str, typ: &str, help: &str, value: String) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {typ}\n{name} {value}\n"));
}

/// Exposition Prometheus TEXTE (content-type text/plain; version=0.0.4). Uniquement des compteurs/jauges —
/// aucune étiquette porteuse de PII (les seules étiquettes sont des constantes : version/schema, composant,
/// quantile). Dérivé de `gather_json` pour une source de vérité unique.
pub(crate) fn gather_prom(conn: &Connection, spool: &str, db_path: &str, schema_version: i64, disk_warn_pct: u8) -> String {
    let j = gather_json(conn, spool, db_path, schema_version, disk_warn_pct);
    let mut o = String::with_capacity(2048);
    prom_line(&mut o, "plume_up", "gauge", "1 si le daemon sert des requêtes", "1".into());
    // build info en étiquettes constantes (motif Prometheus build_info).
    o.push_str("# HELP plume_build_info Version applicative et version de schéma (étiquettes constantes)\n");
    o.push_str("# TYPE plume_build_info gauge\n");
    o.push_str(&format!(
        "plume_build_info{{version=\"{}\",schema=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"), schema_version
    ));
    let g = |o: &mut String, name: &str, typ: &str, help: &str, ptr: &str| {
        if let Some(v) = j.pointer(ptr) {
            let s = if v.is_f64() { format!("{:.3}", v.as_f64().unwrap_or(0.0)) } else { v.to_string() };
            prom_line(o, name, typ, help, s);
        }
    };
    g(&mut o, "plume_process_cpu_seconds_total", "counter", "Temps CPU cumulé du process (s)", "/process/cpu_seconds");
    g(&mut o, "plume_process_resident_memory_bytes", "gauge", "RSS du process (octets)", "/process/rss_bytes");
    prom_line(&mut o, "plume_process_start_time_seconds", "gauge", "Horodatage de démarrage (unix s)", START_TS.load(Ordering::Relaxed).to_string());
    g(&mut o, "plume_http_requests_total", "counter", "Requêtes HTTP servies", "/http/requests_total");
    g(&mut o, "plume_http_responses_5xx_total", "counter", "Réponses 5xx", "/http/responses_5xx_total");
    g(&mut o, "plume_ingest_events_total", "counter", "Events ingérés depuis le démarrage", "/ingest/events_total");
    g(&mut o, "plume_ingest_files_total", "counter", "Fichiers spool consommés", "/ingest/files_total");
    g(&mut o, "plume_ingest_events_1h", "gauge", "Events ingérés sur la dernière heure (rollup)", "/ingest/events_1h");
    g(&mut o, "plume_spool_queue_files", "gauge", "Fichiers en attente dans le spool", "/ingest/queue_depth");
    g(&mut o, "plume_push_zero_map_total", "counter", "Batches push acceptés mais mappés à 0 event (misconfig source push)", "/ingest/push_zero_map_total");
    g(&mut o, "plume_search_requests_total", "counter", "Recherches interactives servies", "/search/requests_total");
    // quantiles de latence de recherche (résumé pré-calculé côté serveur).
    let (p50, p95, _) = search_quantiles();
    o.push_str("# HELP plume_search_latency_ms Latence des recherches interactives (ms)\n# TYPE plume_search_latency_ms summary\n");
    o.push_str(&format!("plume_search_latency_ms{{quantile=\"0.5\"}} {p50}\n"));
    o.push_str(&format!("plume_search_latency_ms{{quantile=\"0.95\"}} {p95}\n"));
    g(&mut o, "plume_scheduler_rule_ticks_total", "counter", "Ticks du scheduler de règles", "/scheduler/rule_ticks_total");
    g(&mut o, "plume_scheduler_rollup_ticks_total", "counter", "Ticks de la boucle de rollup", "/scheduler/rollup_ticks_total");
    g(&mut o, "plume_db_size_bytes", "gauge", "Taille de la base (db + wal, octets)", "/db/size_bytes");
    // VENTILATION PAR POSTE — servie depuis le CACHE du tick lent, jamais recalculée ici (un scrape ne
    // peut pas déclencher 35 s de parcours dbstat). Le rendu N'EST PAS passé par `g()` : ce helper
    // n'imprime que ce qu'il trouve, mais il ne sait pas dire « refusé » — or ici l'ABSENCE des jauges
    // d'octets EST le message quand la comptabilité n'a pas fermé. Cf. `ventilation_serie`.
    o.push_str(&ventilation_serie::exposition_prom(&ventilation_serie::derniere(), now()));
    g(&mut o, "plume_alerts_open", "gauge", "Alertes ouvertes (status=new)", "/alerts_open");
    // santé par composant : jauge 1/0.5/0 (V/J/R) étiquetée par composant (constantes).
    o.push_str("# HELP plume_component_up Santé par composant (1=vert, 0.5=jaune, 0=rouge)\n# TYPE plume_component_up gauge\n");
    if let Some(cs) = j.get("components").and_then(|c| c.as_array()) {
        for c in cs {
            if let Some(name) = c.get("component").and_then(|s| s.as_str()) {
                let st = c.get("state").and_then(|s| s.as_str()).unwrap_or("red");
                o.push_str(&format!("plume_component_up{{component=\"{name}\"}} {}\n", health_score(st)));
            }
        }
    }
    o
}

