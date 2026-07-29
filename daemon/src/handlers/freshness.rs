//! Fraîcheur & heartbeats (P4) : santé pipeline `pipeline_is_fresh`, handler `integrations`, cache
//! SWR `FRESHNESS_CACHE`/handler `freshness`, extraction de sources `extract_query_sources`, calcul
//! par-source `compute_freshness`, et alerte capteur muet `check_heartbeats`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Santé du pipeline d'ingestion : la donnée la PLUS récente, TOUTES sources confondues, est-elle fraîche
/// (< 10 min) ? Sert à la logique ÉVÉNEMENTIELLE des capteurs (un hôte calme n'est pas « muet » tant que
/// QUELQUE CHOSE arrive). Même seuil/requête que compute_freshness (cohérence statut UI <-> alerte muet).
/// COÛT : `MAX(ts)` par table = un simple max INDEXÉ (O(1), dernière entrée d'index) dès lors qu'un index
/// ts-leading existe : idx_event_ts (event) + idx_metric_ts / idx_snapshot_ts (ensure_host_rollup_scan_indexes_
/// background). Sans eux (fenêtre transitoire du 1er boot), metric/snapshot retombent en full-scan -> c'est
/// justement ce que ces index suppriment (MAX(ts) non borné par-requête = risque watchdog).
pub(crate) fn pipeline_is_fresh(conn: &Connection, now_ts: i64) -> bool {
    let global_last: Option<i64> = conn.query_row(
        "SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event UNION ALL SELECT MAX(ts) FROM metric UNION ALL SELECT MAX(ts) FROM snapshot)",
        [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
    global_last.map(|m| now_ts - m < 600).unwrap_or(false)
}

// SWR pour /api/integrations (#23) — même motif que /api/freshness ci-dessus. ROOT CAUSE du ~6 s À CHAUD :
// le handler exécute les 23 requêtes de COLLECTORS, chacune `SELECT MAX(ts) FROM event WHERE source=?[ AND
// category='health']`. `event` (~4,7 M lignes CHIFFRÉES) n'a qu'un idx_event_src MONOCOLONNE — AUCUN composite
// (source,ts) ni (source,category,ts) — donc chaque MAX(ts) doit balayer TOUTES les lignes de la source (avec
// lookup table pour lire `ts`, absent de l'index) => ~6 s CUMULÉS, à chaud comme à froid (contrairement à
// /api/overview désormais servi par les rollups). La liste des collecteurs + l'inventaire host_rollup évoluent
// LENTEMENT (last_seen) et l'UI re-poll (auto-refresh) -> on sert le JSON en STALE-WHILE-REVALIDATE (TTL 30 s,
// comme /api/freshness) : HIT frais instantané ; PÉRIMÉ servi tout de suite + revalidation ASYNC bornée
// (refresh_sem, anti-stampede) ; FROID = calcul SYNCHRONE une seule fois (même latence qu'avant sur le 1er
// appel, et le pré-chauffage boot le remplit d'ordinaire AVANT le 1er clic). Données IDENTIQUES à un calcul
// frais, à ≤TTL près. Clé = db_path (l'inventaire n'est PAS filtré par environnement). NB : la vue reste
// hors du lock writer (read pool + watchdog 5 s) — inchangé. Fix alternatif plus profond NON retenu (risque) :
// un composite (source,category,ts) rendrait chaque MAX(ts) O(1) mais impose un build sur 4,7 M lignes +
// amplification d'écriture sur le chemin d'ingest chaud ; le SWR est byte-identique et sans risque ingest.
pub(crate) const INTEGRATIONS_TTL: Duration = Duration::from_secs(30);
pub(crate) static INTEGRATIONS_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = std::sync::OnceLock::new();
pub(crate) static INTEGRATIONS_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn integrations_map() -> &'static Mutex<HashMap<String, (Instant, Value)>> {
    INTEGRATIONS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) async fn integrations(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    use std::sync::atomic::Ordering;
    let db_path = req_db_path(&st, &au);
    let ckey = db_path.clone();
    // HIT frais -> instantané.
    if let Some((t, v)) = integrations_map().lock().get(&ckey) {
        if t.elapsed() < INTEGRATIONS_TTL {
            return Json(v.clone());
        }
    }
    // PÉRIMÉ présent -> SWR : sert le périmé immédiatement + revalidation async bornée (anti-stampede).
    let stale = integrations_map().lock().get(&ckey).cloned();
    if let Some((_, v)) = stale {
        if !INTEGRATIONS_REFRESHING.swap(true, Ordering::AcqRel) {
            let db = db_path.clone();
            let ck = ckey.clone();
            let sem = st.refresh_sem.clone();
            tokio::spawn(async move {
                // try_acquire (PAS await) : lane refresh saturée -> on renonce (le périmé reste servi).
                if let Ok(_permit) = sem.try_acquire_owned() {
                    let db2 = db.clone();
                    if let Ok(nv) = tokio::task::spawn_blocking(move || compute_integrations(&db2)).await {
                        integrations_map().lock().insert(ck, (Instant::now(), nv));
                    }
                }
                INTEGRATIONS_REFRESHING.store(false, Ordering::Release);
            });
        }
        return Json(v);
    }
    // FROID : calcul SYNCHRONE une seule fois (même latence qu'avant sur le 1er appel) PUIS mise en cache.
    // On NE renvoie PAS de placeholder « warming » (contrairement à freshness) -> aucune régression de forme :
    // le 1er appel voit exactement les mêmes données qu'aujourd'hui, juste mises en cache pour la suite.
    let dbp = db_path.clone();
    let nv = tokio::task::spawn_blocking(move || compute_integrations(&dbp))
        .await
        .unwrap_or_else(|_| json!({ "collectors": [], "hosts": [] }));
    integrations_map().lock().insert(ckey, (Instant::now(), nv.clone()));
    Json(nv)
}

/// Calcul (LOURD — cf. ROOT CAUSE ci-dessus) du panneau intégrations. Mis en cache SWR par le handler
/// `integrations` ; NE PAS appeler directement depuis le chemin requête (passer par le handler / le cache).
/// Lecture seule (read pool + watchdog 5 s), JAMAIS le lock writer (st.db). L'INVENTAIRE D'HÔTES est lu du
/// rollup pré-agrégé `host_rollup` (v77, cf. rollup_hosts) : AUCUN scan de event∪metric∪snapshot.
pub(crate) fn compute_integrations(db_path: &str) -> Value {
    let now_ts = now();
    read_with_watchdog(db_path, json!({ "collectors": [], "hosts": [] }), move |conn| {
        // FIX #2 — capteurs ÉVÉNEMENTIELS : leur statut suit la SANTÉ DU PIPELINE global, pas leur propre
        // intervalle (sinon hôte calme = faux MUET permanent). Calculé une fois pour tous les collecteurs.
        let pipe_fresh = pipeline_is_fresh(conn, now_ts);
        let collectors: Vec<Value> = COLLECTORS
            .iter()
            .map(|(id, label, interval, q, event_based)| {
                let ls: Option<i64> = conn.query_row(q, [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
                let status = if *event_based {
                    // ÉVÉNEMENTIEL : 'inconnu' si jamais vu ; sinon 'actif' tant que le pipeline est frais
                    // (silence = hôte calme, PAS une panne) ; 'muet' SEULEMENT si le pipeline global décroche.
                    match ls {
                        None => "inconnu",
                        _ if pipe_fresh => "actif",
                        _ => "muet",
                    }
                } else {
                    // CONTINU : statut basé sur SON intervalle (inchangé).
                    match ls {
                        None => "inconnu",
                        Some(t) if now_ts - t <= interval * 3 => "actif",
                        Some(_) => "muet",
                    }
                };
                json!({ "id": id, "label": label, "interval_s": interval, "last_seen": ls, "status": status, "event_based": event_based })
            })
            .collect();
        // INVENTAIRE d'hôtes = host_rollup pré-agrégé (cf. rollup_hosts) : AUCUN scan de event∪metric∪snapshot.
        let hosts = host_inventory_simple(conn);
        json!({ "collectors": collectors, "hosts": hosts })
    })
}
/// Fraîcheur PAR SOURCE (data-driven, pas la liste figée des collecteurs) : pour chaque feed —
/// source d'event, kind de snapshot, et les métriques (agrégées) — l'âge du dernier point + un statut
/// ok/warn/late. La cadence ATTENDUE est ESTIMÉE depuis le débit 24h (86400/n_24h) -> s'adapte à chaque
/// source (un feed 1/min flaggé seulement s'il a des minutes de retard ; un feed rare jamais faux-positif).
/// "Voir si un feed décroche" d'un coup d'œil. Lecture seule (read pool + watchdog).
// SWR pour /api/freshness : la requête de fraîcheur agrège 7 JOURS d'events par source (GROUP BY + SUM
// conditionnel) -> scan LOURD sur la base chiffrée qui TOUCHE le watchdog 5 s à CHAQUE appel (mesuré ~5,1 s).
// Or la fraîcheur évolue lentement (last_seen / cadence) ET l'UI la rappelle à chaque tick d'auto-refresh
// (30 s) + au chargement (dans le Promise.all de refresh()). On la sert donc en stale-while-revalidate :
//   - HIT frais (< TTL) -> instantané ;
//   - périmé -> on sert le périmé TOUT DE SUITE + refresh ASYNC borné (refresh_sem, JAMAIS query_sem ;
//     anti-stampede : un seul refresh en vol) ;
//   - froid (1re fois / après redémarrage) -> calcul synchrone hors runtime (spawn_blocking).
// N'affecte PAS l'alerte « capteur muet » (check_heartbeats, séparé, sur son propre timer).
pub(crate) const FRESHNESS_TTL: Duration = Duration::from_secs(30);
// MT-KEY: par db_path (R3). Chaque base (tenant) a sa propre valeur SWR de fraîcheur (feeds/last_seen) ;
// jamais de partage inter-tenant. TTL/SWR inchangés. En mono-tenant : une seule entrée -> identique.
pub(crate) static FRESHNESS_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = std::sync::OnceLock::new();
// Gate anti-stampede GLOBAL (booléen, AUCUNE donnée tenant -> pas un vecteur de fuite) : borne à UN refresh
// en vol. En multi-tenant il sérialise les refresh entre tenants (staleness bornée, pas de fuite) ;
// #2a-2 pourra le clé par db_path si la contention devient sensible. En mono-tenant : comportement identique.
pub(crate) static FRESHNESS_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn freshness_map() -> &'static Mutex<HashMap<String, (Instant, Value)>> {
    FRESHNESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) async fn freshness(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    use std::sync::atomic::Ordering;
    let dbp_owned = req_db_path(&st, &au); // #2a-2b : fraîcheur de la base du tenant courant (cache keyé db_path)
    // FILTRE ENVIRONNEMENT (#2d) : la clé de cache inclut l'env (env_range_key) -> une fraîcheur env=staging
    // n'écrase pas env=prod. Mode 0 (env None) -> clé = db_path (byte-identique) -> cache inchangé.
    let env_owned = au.env_filter().map(|e| e.to_string());
    let ckey_owned = env_range_key(env_owned.as_deref(), dbp_owned.as_str());
    let ckey = ckey_owned.as_str();
    // HIT frais -> instantané.
    if let Some((t, v)) = freshness_map().lock().get(ckey) {
        if t.elapsed() < FRESHNESS_TTL {
            return Json(v.clone());
        }
    }
    // STALE présent -> SWR : sert le périmé immédiatement + déclenche un refresh async borné.
    let stale = freshness_map().lock().get(ckey).cloned();
    if let Some((_, v)) = stale {
        if !FRESHNESS_REFRESHING.swap(true, Ordering::AcqRel) {
            let db = dbp_owned.clone();
            let ck = ckey_owned.clone();
            let envc = env_owned.clone();
            let sem = st.refresh_sem.clone();
            tokio::spawn(async move {
                // try_acquire (PAS await) : lane refresh saturée -> on renonce (le périmé reste servi).
                if let Ok(_permit) = sem.try_acquire_owned() {
                    let db2 = db.clone();
                    let env2 = envc.clone();
                    if let Ok(nv) = tokio::task::spawn_blocking(move || compute_freshness(&db2, env2.as_deref())).await {
                        freshness_map().lock().insert(ck, (Instant::now(), nv)); // MT-KEY : entrée de CE (db_path, env)
                    }
                }
                FRESHNESS_REFRESHING.store(false, Ordering::Release);
            });
        }
        return Json(v);
    }
    // FROID : aucune valeur en cache (1re fois / après redémarrage du pod). On NE bloque PLUS la requête
    // ~5 s (scan 7 j chiffré) : sous une rafale de F5 cela faisait attendre TOUTES les requêtes jusqu'à 10 s.
    // À la place — exactement comme le SWR des panneaux sert « warming » à froid — on déclenche le calcul
    // en ASYNC sur la lane refresh (anti-stampede via FRESHNESS_REFRESHING : UN seul calcul en vol même
    // sous 40 appels parallèles) et on renvoie TOUT DE SUITE un payload « warming ». Les appels suivants
    // (tick 30 s du front, ou re-poll rapproché) récupèrent la valeur dès qu'elle est calculée, via le
    // chemin HIT/STALE ci-dessus. (N'affecte PAS check_heartbeats, alerte « capteur muet » séparée.)
    if !FRESHNESS_REFRESHING.swap(true, Ordering::AcqRel) {
        let db = dbp_owned.clone();
        let ck = ckey_owned.clone();
        let envc = env_owned.clone();
        let sem = st.refresh_sem.clone();
        tokio::spawn(async move {
            // try_acquire (PAS await) : lane refresh saturée -> on renonce ; un prochain appel relancera.
            if let Ok(_permit) = sem.try_acquire_owned() {
                let db2 = db.clone();
                let env2 = envc.clone();
                if let Ok(nv) = tokio::task::spawn_blocking(move || compute_freshness(&db2, env2.as_deref())).await {
                    freshness_map().lock().insert(ck, (Instant::now(), nv)); // MT-KEY : entrée de CE (db_path, env)
                }
            }
            FRESHNESS_REFRESHING.store(false, Ordering::Release);
        });
    }
    // payload « warming » non bloquant : feeds vides + flag -> l'UI affiche un placeholder « … » et re-poll.
    Json(json!({ "warming": true, "feeds": [], "ts": now() }))
}

/// FIX #5 — extrait les valeurs `source=<x>` d'une requête de règle (stockée dans alert.detail par
/// run_due_rules). Gère la forme GXQL `source=foo` ET la forme SQL `source='foo'` / `source="foo"`.
/// Sert à corréler une alerte ACTIVE à la SOURCE qu'elle surveille -> surlignage des feeds « chauds ».
/// Tolérant : token lu jusqu'au prochain séparateur (espace/tab/newline/pipe ou guillemet fermant).
pub(crate) fn extract_query_sources(detail: &str) -> Vec<String> {
    let bytes = detail.as_bytes();
    let needle = b"source=";
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            let quote = if j < bytes.len() && (bytes[j] == b'\'' || bytes[j] == b'"') {
                let q = bytes[j]; j += 1; Some(q)
            } else { None };
            let start = j;
            while j < bytes.len() {
                let c = bytes[j];
                let stop = match quote { Some(qc) => c == qc, None => matches!(c, b' ' | b'\t' | b'\n' | b'|') };
                if stop { break; }
                j += 1;
            }
            if j > start {
                // from_utf8_lossy : ne panique jamais sur une frontière non-UTF8 (sources = ASCII en pratique).
                out.push(String::from_utf8_lossy(&bytes[start..j]).into_owned());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

/// Calcul (LOURD, borné par read_with_watchdog 5 s) de la fraîcheur des sources. Mis en cache SWR par
/// le handler `freshness` ci-dessus — ne PAS appeler directement depuis le chemin requête.
pub(crate) fn compute_freshness(db_path: &str, env: Option<&str>) -> Value {
    let now_ts = now();
    // FILTRE ENVIRONNEMENT (#2d) : None (mode 0 / all) -> prédicats VIDES -> SQL byte-identique (cache
    // tous-env inchangé). Some("<env>") -> chaque feed est filtré `env_id='<env>'` (event_rollup/snapshot/
    // metric portent env_id v66/v67). Valeur validée (env_slug_ok) + échappée (soql_esc) -> anti-injection.
    let envp = env_and_pred(env);
    let wenv = env_where_pred(env);
    read_with_watchdog(db_path, json!({ "feeds": [], "ts": now_ts }), move |conn| {
        let d1 = now_ts - 86400;        // fenêtre 24h -> estimation de cadence
        let cut7 = now_ts - 7 * 86400;  // ne liste que les feeds vus dans les 7 derniers jours
        let mut feeds: Vec<Value> = Vec::new();
        // SANTÉ DU PIPELINE : la donnée la PLUS récente, TOUTES sources confondues. Tant qu'au moins une
        // source arrive (<10 min), l'ingestion fonctionne. Si même la plus fraîche est vieille -> ingestion
        // en panne (réseau / corruption / collecte arrêtée) = le SEUL cas où on alerte ("muet"). Sinon l'âge
        // d'une source ne reflète QUE son activité (normal qu'une source rare soit "vieille") -> jamais "retard".
        let global_last: Option<i64> = conn.query_row(
            &format!("SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event{wenv} UNION ALL SELECT MAX(ts) FROM metric{wenv} UNION ALL SELECT MAX(ts) FROM snapshot{wenv})"),
            [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
        let pipeline_fresh = global_last.map(|m| now_ts - m < 600).unwrap_or(false);
        // FIX #5 — alertes ACTIVES (status='new') corrélées à chaque SOURCE, pour que le front surligne les
        // feeds « chauds ». Corrélation au mieux : l'alerte d'une règle stocke la requête de la règle dans
        // `detail` (run_due_rules) ; on en extrait les jetons `source=<x>` -> tally par source. Les alertes
        // sans jeton source (heartbeat.*, règles filtrant par category/host plutôt que source) ne comptent
        // pour aucun feed -> active_alerts=0 (limite assumée, cf tâche : version simple).
        let mut alert_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        if let Ok(mut s) = conn.prepare(&format!("SELECT COALESCE(detail,'') FROM alert WHERE status='new'{envp}")) {
            if let Ok(rows) = s.query_map([], |r| r.get::<_, String>(0)) {
                for d in rows.flatten() {
                    for src in extract_query_sources(&d) { *alert_counts.entry(src).or_insert(0) += 1; }
                }
            }
        }
        let mk = |kind: &str, name: String, last: i64, n24: i64| -> Value {
            let age = now_ts - last;
            let expected = if n24 > 0 { 86400 / n24 } else { 0 };   // intervalle moyen entre données (s)
            // type : explique les âges différents -> continu (logs/métriques) / périodique (collecteur sur timer)
            // / événement (déclenché par une menace) / dormant (vu récemment mais rien depuis 24 h).
            let typ = if matches!(name.as_str(), "crowdsec" | "fail2ban" | "ufw" | "nft") { "événement" }
                else if n24 == 0 { "dormant" } else if expected <= 90 { "continu" } else { "périodique" };
            // STATUT = SANTÉ DE COLLECTE, pas activité : 'muet' SEULEMENT si l'ingestion est en panne ;
            // sinon 'frais' (donnée < 15 min) ou 'calme' (collecte OK, source peu active = normal).
            let status = if !pipeline_fresh { "muet" } else if age <= 900 { "frais" } else { "calme" };
            // active_alerts : nb d'alertes 'new' dont la règle référence `source=<name>` (0 si aucune / feed
            // non corrélable comme les snapshots/métriques). Calculé avant le move de `name` dans json!.
            let active_alerts = alert_counts.get(&name).copied().unwrap_or(0);
            json!({ "kind": kind, "name": name, "type": typ, "last_seen": last, "age_s": age, "n_24h": n24, "expected_s": expected, "status": status, "active_alerts": active_alerts })
        };
        // SOURCE = event_rollup pré-agrégé (~ms ; mêmes colonnes que les panneaux : source, bucket horaire, n)
        // au lieu d'un scan 7 j de `event` chiffré (~14,6 s -> tué par le watchdog 5 s, qui faisait disparaître
        // TOUS les feeds event de /api/freshness). n24 = somme des n sur les buckets < 24 h. HAVING SUM(n)>=3 :
        // écarte les artefacts one-shot (selftest, mtls-test… 1 event) -> pas de faux muet permanent.
        // ?1 = cut 24 h (d1), ?2 = cut 7 j (cut7).
        // FRAÎCHEUR RÉELLE — last = MAX(last_ts) : le VRAI horodatage du dernier event, matérialisé PAR LE
        // ROLLUP lui-même (rollup_events écrit MAX(ts) AS last_ts à chaque ré-agrégation de la fenêtre chaude
        // = heure courante+précédente, toutes les ~120 s ; migration v64). Une source CONTINUE a donc un âge
        // de quelques SECONDES (le vrai dernier event), PAS le plancher horaire MAX(bucket) qui dérivait
        // 0->59 min puis « rajeunissait » au changement d'heure. COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)) :
        // fallback sur le plancher horaire pour une source dont les buckets sont TOUS encore à 0 (anciens, pas
        // ré-agrégés depuis la migration) — jamais reforcée à « frais ». Lecture sur la PETITE table rollup
        // (qq ms, bien dans le budget 5 s) : AUCUN scan de `event`. (L'ancien correctif `SELECT source,MAX(ts)
        // FROM event WHERE ts>=now-3600 GROUP BY source` full-scannait les 3,9 M lignes chiffrées en ~21 s
        // faute d'index (source,ts) -> tué par le watchdog -> map vide -> retombait sur le plancher : RETIRÉ.)
        if let Ok(mut s) = conn.prepare(&format!("SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) FROM event_rollup WHERE bucket>=?2 AND source<>''{envp} GROUP BY source HAVING SUM(n)>=3")) {
            if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                for (src, last, n) in rows.flatten() {
                    feeds.push(mk("event", src, last, n));
                }
            }
        }
        if let Ok(mut s) = conn.prepare(&format!("SELECT kind, MAX(ts), SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) FROM snapshot WHERE ts>?2{envp} GROUP BY kind")) {
            if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                for (k, m, n) in rows.flatten() { feeds.push(mk("snapshot", k, m, n)); }
            }
        }
        // métriques : un feed agrégé (remote-write) + DÉTAIL par série (déplié dans l'UI sur clic)
        let mlast: Option<i64> = conn.query_row(&format!("SELECT MAX(ts) FROM metric WHERE ts>?1{envp}"), params![cut7], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
        if let Some(m) = mlast {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM metric WHERE ts>?1{envp}"), params![d1], |r| r.get(0)).unwrap_or(0);
            let series: i64 = conn.query_row(&format!("SELECT COUNT(DISTINCT name) FROM metric WHERE ts>?1{envp}"), params![d1], |r| r.get(0)).unwrap_or(0);
            // liste des séries (nom + dernière donnée + statut) -> l'UI les déplie sous le feed agrégé.
            let mut series_list: Vec<Value> = Vec::new();
            if let Ok(mut s) = conn.prepare(&format!("SELECT name, MAX(ts), SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) FROM metric WHERE ts>?2{envp} GROUP BY name ORDER BY name")) {
                if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                    for (nm, ls, n24) in rows.flatten() {
                        let age = now_ts - ls;
                        let st = if !pipeline_fresh { "muet" } else if age <= 900 { "frais" } else { "calme" };
                        series_list.push(json!({ "name": nm, "last_seen": ls, "age_s": age, "n_24h": n24, "status": st }));
                    }
                }
            }
            let mut mf = mk("metric", format!("métriques · {series} séries"), m, n);
            if let Some(o) = mf.as_object_mut() { o.insert("series".into(), json!(series_list)); }
            feeds.push(mf);
        }
        json!({ "feeds": feeds, "ts": now_ts, "pipeline_fresh": pipeline_fresh })
    })
}

/// Alerte si un capteur ayant DÉJÀ remonté devient muet (> 5x son intervalle) = angle mort.
pub(crate) fn check_heartbeats(db: &Arc<Mutex<Connection>>) {
    let now_ts = now();
    let conn = db.lock();
    // FIX #2 — pour un capteur ÉVÉNEMENTIEL (auth), le « muet » NE se juge PAS sur son propre intervalle
    // (un hôte sans login serait un faux MUET permanent) mais sur la SANTÉ DU PIPELINE global : tant que la
    // donnée la plus récente, toutes sources confondues, est fraîche, l'auth n'est PAS muette (silence
    // normal). Les capteurs CONTINUS gardent leur logique 5x-intervalle (vraies alertes muet préservées).
    let pipe_fresh = pipeline_is_fresh(&conn, now_ts);
    for (id, label, interval, q, event_based) in COLLECTORS.iter() {
        let ls: Option<i64> = conn.query_row(q, [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
        let dedup = format!("hb-{id}"); // clé STABLE -> une seule alerte par épisode (zéro répétition horaire)
        // MUET ? ÉVÉNEMENTIEL -> seulement si le pipeline global est en panne ; CONTINU -> silence > 5x son
        // intervalle (logique d'origine, None ne déclenche jamais d'alerte).
        let mute = if *event_based {
            !pipe_fresh
        } else {
            matches!(ls, Some(t) if now_ts - t > interval * 5)
        };
        if mute {
            // détail : ancienneté de CE capteur si connue, sinon état du pipeline (cas événementiel sans
            // historique). Sévérité 2 inchangée.
            let detail = match ls {
                Some(t) => format!("aucune donnée depuis {} min", (now_ts - t) / 60),
                None => "pipeline d'ingestion muet".to_string(),
            };
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup) VALUES(?1,?2,2,?3,?4,?5)",
                params![now_ts, format!("heartbeat.{id}"), format!("Capteur muet : {label}"), detail, dedup],
            );
        } else {
            // capteur de nouveau actif (ou jamais vu / pipeline frais) -> résout l'alerte ouverte et libère la clé
            let _ = conn.execute(
                "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                params![dedup],
            );
        }
    }
}
