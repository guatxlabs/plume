//! Flotte d'agents (P0 UI, lecture) : inventaire des hôtes qui remontent des données, avec statut
//! frais/en-retard/muet (`fleet_status`/`fleet_status_rank`), inventaire simple `host_inventory_simple`,
//! scan `fleet_scan_all`, tri/pagination `fleet_sort_paginate`, cache SWR `FLEET_CACHE`/`fleet_map`,
//! et handler `fleet`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ================================================================================================
// FLEET / FLOTTE D'AGENTS (P0 UI, LECTURE) — inventaire des HÔTES qui remontent des données (= endpoints où
// un agent pousse). Répond à « quels agents rapportent, depuis quand, sont-ils encore vivants, lesquels sont
// enrôlés ». MÊME source que /api/integrations : le rollup pré-agrégé `host_rollup` (v77, cf. rollup_hosts) au
// lieu d'un scan event∪metric∪snapshot GROUP BY host (read pool + watchdog 5 s + spawn_blocking + query_sem) :
// purement LECTURE, aucune touche mode 0 / data-plane / ingest / responder. RBAC : GET non-mutant -> route_min_role case 6 -> MinRole::Read (viewer+),
// aucune modif de gating. L'authorizer read-pool DENY de toute façon token.token_hash / user.hash (jamais
// sélectionnés ici). ENRÔLEMENT best-effort (table `token` mode 0 : name/created/last_used, liés à l'hôte par
// token.host) : en mode 1 la table `token(hash,tenant_id,env_id,host,created)` n'a NI `name` NI `last_used`
// -> la préparation échoue -> map d'enrôlement VIDE -> l'inventaire reste complet (hôtes + last_seen + statut),
// seul l'enrôlement est absent (dégradation gracieuse). VERSION / OS de l'agent : NON disponibles — le shipper
// (collectors/ship.sh) ne transmet ni en-tête de version ni /etc/os-release, et aucune colonne ne les stocke
// -> DIFFÉRÉS (suivi doc ; nécessiterait que l'agent les émette + une colonne de contrôle, hors ce périmètre).
// ================================================================================================
pub(crate) const FLEET_FRESH_S: i64 = 900;    // <= 15 min : l'agent rapporte normalement (frais)
pub(crate) const FLEET_STALE_S: i64 = 3600;   // <= 1 h : en retard (à surveiller) ; au-delà = muet (agent probablement mort)

/// Statut d'un hôte d'après l'ÂGE de son dernier signal (fresh/stale/silent). Contrairement à une SOURCE (qui
/// peut être légitimement calme sans que rien n'aille mal), un HÔTE qui cesse TOUT signal = son agent est
/// probablement tombé -> l'âge du dernier signal EST le signal pertinent pour une flotte. Jetons d'API STABLES
/// (le front les mappe au vocabulaire UI frais/en-retard/muet).
pub(crate) fn fleet_status(age_s: i64) -> &'static str {
    if age_s <= FLEET_FRESH_S { "fresh" } else if age_s <= FLEET_STALE_S { "stale" } else { "silent" }
}
/// Rang de tri d'un statut (problèmes d'abord en tri ASCENDANT) : silent < stale < fresh.
pub(crate) fn fleet_status_rank(s: &str) -> i64 { match s { "silent" => 0, "stale" => 1, "fresh" => 2, _ => 3 } }
/// Clé de tri WHITELISTÉE : le tri se fait EN RUST (jamais d'ORDER BY interpolé depuis le client). Défaut = last_seen.
pub(crate) fn fleet_sort_key(sort: &str) -> &'static str {
    match sort { "host" => "host", "first_seen" => "first_seen", "signals" => "signals", "status" => "status", _ => "last_seen" }
}

/// Inventaire d'hôtes SIMPLE ({host, last_seen}) lu du rollup pré-agrégé `host_rollup` (v77, cf. rollup_hosts) —
/// partagé par /api/integrations. AUCUN scan de event∪metric∪snapshot (lecture sub-ms d'une table de cardinalité
/// = taille de flotte) : le `SELECT host,MAX(ts) FROM (union) GROUP BY host` non borné qui tuait le watchdog 5 s
/// est SUPPRIMÉ. GROUP BY host collapse les env (#2d ; mode 0 = tout 'prod' -> 1 ligne/hôte). Trié last_seen DESC.
pub(crate) fn host_inventory_simple(conn: &Connection) -> Vec<Value> {
    let mut hosts: Vec<Value> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT host, MAX(last_ts) m FROM host_rollup WHERE host<>'' GROUP BY host ORDER BY m DESC",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok(json!({ "host": r.get::<_, String>(0)?, "last_seen": r.get::<_, i64>(1)? }))) {
            hosts = rows.flatten().collect();
        }
    }
    hosts
}

/// FLOTTE — inventaire (fonction PURE sur &Connection). Renvoie la liste COMPLÈTE d'hôtes (non triée, non
/// paginée) + `pipeline_fresh`. Les hôtes sont lus du rollup pré-agrégé `host_rollup` (v77, cf. rollup_hosts) :
/// last_seen=MAX(last_ts), first_seen=MIN(first_ts), signals=SUM(sig_total+sig_hot) — PLUS de `MAX(ts) GROUP BY
/// host` sur event∪metric∪snapshot (~4,7 M lignes, ~39 s -> tué par le watchdog 5 s -> liste VIDE cachée -> flotte
/// figée à 0). host_rollup a la cardinalité de la FLOTTE -> lecture sub-ms. Enrichi d'un statut fresh/stale/silent
/// et de l'enrôlement (jointure best-effort avec `token`). Le handler `fleet` garde un CACHE SWR par-dessus (défense
/// en profondeur ; le scan lourd n'existe plus). Le tri (clé whitelistée) + LIMIT/OFFSET sont appliqués À PART
/// (fleet_sort_paginate). NB : host_rollup n'étant JAMAIS prunée, un hôte dont TOUS les events ont été purgés par
/// la rétention reste VISIBLE (son last_ts colle) — comportement VOULU pour une flotte (agent mort = visible).
pub(crate) fn fleet_scan_all(conn: &Connection, now_ts: i64) -> (Vec<Value>, bool) {
    let pipeline_fresh = pipeline_is_fresh(conn, now_ts);
    // ENRÔLEMENT (best-effort, mode 0) : host -> (name, created, last_used). token_hash JAMAIS lu (l'authorizer
    // read-pool le refuserait de toute façon). ORDER BY created DESC + or_insert -> on garde l'enrôlement le
    // PLUS RÉCENT quand un hôte a plusieurs tokens. Un échec de prepare (schéma mode 1 sans name/last_used)
    // laisse la map VIDE -> l'inventaire reste complet, l'enrôlement simplement absent (jamais d'erreur dure).
    let mut enroll: std::collections::HashMap<String, (String, Option<i64>, Option<i64>)> = std::collections::HashMap::new();
    if let Ok(mut s) = conn.prepare("SELECT host, name, created, last_used FROM token WHERE host IS NOT NULL AND host<>'' ORDER BY created DESC") {
        if let Ok(rows) = s.query_map([], |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
        ))) {
            for (h, n, c, l) in rows.flatten() { enroll.entry(h).or_insert((n, c, l)); }
        }
    }
    // HÔTES (garanti) : dernier/premier signal + nb de signaux, lus du rollup pré-agrégé host_rollup (cf.
    // rollup_hosts) -> AUCUN scan de event∪metric∪snapshot. last_seen=MAX(last_ts), first_seen=MIN(first_ts),
    // signals=SUM(sig_total+sig_hot). GROUP BY host collapse les env (#2d ; mode 0 = tout 'prod' -> 1 ligne/hôte).
    let mut hosts: Vec<Value> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT host, MAX(last_ts) AS last_seen, MIN(first_ts) AS first_seen, \
         SUM(sig_total + sig_hot) AS signals FROM host_rollup WHERE host<>'' GROUP BY host",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))) {
            for (h, last, first, n) in rows.flatten() {
                let age = now_ts - last;
                let status = fleet_status(age);
                let e = enroll.get(&h);
                hosts.push(json!({
                    "host": h,
                    "last_seen": last,
                    "first_seen": first,
                    "signals": n,
                    "age_s": age,
                    "status": status,
                    "enrolled": e.is_some(),
                    "enroll_name": e.map(|x| x.0.clone()).unwrap_or_default(),
                    "enroll_created": e.and_then(|x| x.1),
                    "token_last_used": e.and_then(|x| x.2),
                }));
            }
        }
    }
    (hosts, pipeline_fresh)
}
/// TRI (clé whitelistée) + pagination EN RUST sur la liste COMPLÈTE (déjà scannée / servie du cache SWR).
/// `total` = nb d'hôtes distincts = longueur du vecteur. Défaut = last_seen (hôtes vus le plus récemment
/// d'abord) ; le tri par statut place les problèmes d'abord (silent < stale < fresh) en ASCENDANT.
pub(crate) fn fleet_sort_paginate(mut hosts: Vec<Value>, sort: &str, dir_desc: bool, limit: i64, offset: i64) -> (Vec<Value>, i64) {
    let total = hosts.len() as i64;
    let key = fleet_sort_key(sort);
    hosts.sort_by(|a, b| {
        let o = match key {
            "host" => a["host"].as_str().unwrap_or("").cmp(b["host"].as_str().unwrap_or("")),
            "first_seen" => a["first_seen"].as_i64().unwrap_or(0).cmp(&b["first_seen"].as_i64().unwrap_or(0)),
            "signals" => a["signals"].as_i64().unwrap_or(0).cmp(&b["signals"].as_i64().unwrap_or(0)),
            "status" => fleet_status_rank(a["status"].as_str().unwrap_or("")).cmp(&fleet_status_rank(b["status"].as_str().unwrap_or(""))),
            _ => a["last_seen"].as_i64().unwrap_or(0).cmp(&b["last_seen"].as_i64().unwrap_or(0)),
        };
        if dir_desc { o.reverse() } else { o }
    });
    let start = offset.max(0) as usize;
    let page: Vec<Value> = hosts.into_iter().skip(start).take(limit.max(0) as usize).collect();
    (page, total)
}
/// Wrapper (compat tests + chemin non-caché) : scan lourd + tri/pagination en une passe. Le handler `fleet`
/// n'appelle PAS ceci (il scanne via le cache SWR) ; conservé pour fleet_query_page(&conn, …) direct (tests).
#[allow(dead_code)] // utilisé uniquement par les tests (le handler passe par fleet_scan_all + le cache SWR)
pub(crate) fn fleet_query_page(conn: &Connection, now_ts: i64, sort: &str, dir_desc: bool, limit: i64, offset: i64) -> (Vec<Value>, i64, bool) {
    let (hosts, pipeline_fresh) = fleet_scan_all(conn, now_ts);
    let (page, total) = fleet_sort_paginate(hosts, sort, dir_desc, limit, offset);
    (page, total, pipeline_fresh)
}

// SWR pour /api/fleet : DÉFENSE EN PROFONDEUR. Depuis v77 la lecture vient de
// host_rollup (sub-ms, cardinalité de flotte) -> le scan non borné event∪metric∪snapshot qui matérialisait/triait
// TOUTES les lignes à chaque appel (et touchait le watchdog 5 s au volume -> flotte VIDE) N'EXISTE PLUS. Le cache
// est CONSERVÉ (inoffensif, absorbe les rafales d'auto-refresh de l'UI), EXACTEMENT comme /api/freshness :
//   - HIT frais (< TTL) -> tri/pagination sur la liste COMPLÈTE en cache (AUCUNE lecture) ;
//   - périmé -> on sert le périmé + revalidation ASYNC bornée (refresh_sem, JAMAIS query_sem ; un seul en vol) ;
//   - froid (1re fois / après redémarrage) -> lecture SYNCHRONE sous query_sem (host_rollup, quasi-instantanée),
//     puis mise en cache. Une lecture interrompue par le watchdog (done=false) N'EST PAS cachée -> la requête
//     suivante retente (jamais un vide FIGÉ) — désormais théorique, host_rollup ne pouvant plus atteindre 5 s.
// Le tri/limit/offset s'appliquent PAR REQUÊTE sur la liste complète -> tous les paramètres réutilisent la même
// lecture cachée. MT-KEY : clé = db_path (R3) -> jamais de partage inter-tenant. Lecture seule (read pool + watchdog) :
// aucune touche mode 0 / data-plane / ingest.
pub(crate) const FLEET_TTL: Duration = Duration::from_secs(30);
// MT-KEY: cache par db_path. Valeur = (liste COMPLÈTE d'hôtes NON paginée, pipeline_fresh).
pub(crate) static FLEET_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, (Vec<Value>, bool))>>> = std::sync::OnceLock::new();
// Gate anti-stampede GLOBAL (booléen, AUCUNE donnée tenant -> pas un vecteur de fuite) : UN refresh en vol.
pub(crate) static FLEET_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn fleet_map() -> &'static Mutex<HashMap<String, (Instant, (Vec<Value>, bool))>> {
    FLEET_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Tri + pagination de la liste complète (en cache) -> payload d'API stable {hosts,total,pipeline_fresh,now}.
pub(crate) fn fleet_response(hosts_full: &[Value], pipeline_fresh: bool, sort: &str, dir_desc: bool, limit: i64, offset: i64, now_ts: i64) -> Value {
    let (page, total) = fleet_sort_paginate(hosts_full.to_vec(), sort, dir_desc, limit, offset);
    json!({ "hosts": page, "total": total, "pipeline_fresh": pipeline_fresh, "now": now_ts })
}

/// GET /api/fleet?limit=&offset=&sort=&dir= — inventaire de la flotte d'agents (viewer+ ; cf. bloc FLEET).
/// Servi en SWR (cf. bloc ci-dessus) : instantané sur HIT/STALE, scan synchrone borné (query_sem + read pool +
/// watchdog) seulement à froid. Dégradation gracieuse : scan trop long à froid -> `hosts` vide, non caché.
pub(crate) async fn fleet(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    use std::sync::atomic::Ordering;
    let now_ts = now();
    let sort = q.get("sort").cloned().unwrap_or_default();
    // défaut = desc (last_seen : le plus récent d'abord) ; ?dir=asc pour inverser.
    let dir_desc = q.get("dir").map(|d| d != "asc").unwrap_or(true);
    let limit = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let offset = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
    let db_path = req_db_path(&st, &au); // #2a : base du tenant courant ; sert aussi de clé de cache (R3)
    let ckey = db_path.clone();
    // HIT frais -> tri/pagination sur la liste complète en cache (aucun scan).
    if let Some((t, (hosts_full, pf))) = fleet_map().lock().get(&ckey) {
        if t.elapsed() < FLEET_TTL {
            return Json(fleet_response(hosts_full, *pf, &sort, dir_desc, limit, offset, now_ts));
        }
    }
    // STALE présent -> SWR : sert le périmé + revalidation async bornée (refresh_sem, JAMAIS query_sem).
    let stale = fleet_map().lock().get(&ckey).cloned();
    if let Some((_, (hosts_full, pf))) = stale {
        if !FLEET_REFRESHING.swap(true, Ordering::AcqRel) {
            let db = db_path.clone();
            let ck = ckey.clone();
            let sem = st.refresh_sem.clone();
            tokio::spawn(async move {
                // try_acquire (PAS await) : lane refresh saturée -> on renonce (le périmé reste servi).
                if let Ok(_permit) = sem.try_acquire_owned() {
                    let ts2 = now();
                    if let Ok((hosts_new, pf_new, done)) = tokio::task::spawn_blocking(move || {
                        read_with_watchdog(db.as_str(), (Vec::<Value>::new(), false, false), move |conn| {
                            let (h, p) = fleet_scan_all(conn, ts2);
                            (h, p, true)
                        })
                    })
                    .await
                    {
                        if done { fleet_map().lock().insert(ck, (Instant::now(), (hosts_new, pf_new))); }
                    }
                }
                FLEET_REFRESHING.store(false, Ordering::Release);
            });
        }
        return Json(fleet_response(&hosts_full, pf, &sort, dir_desc, limit, offset, now_ts));
    }
    // FROID : aucune valeur en cache. Scan SYNCHRONE sous query_sem (borne les déchiffrements concurrents),
    // puis cache. Watchdog dépassé (done=false) -> résultat NON caché (la prochaine requête retente).
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(json!({ "hosts": [] })),
    };
    let db2 = db_path.clone();
    let scan = tokio::task::spawn_blocking(move || {
        read_with_watchdog(db2.as_str(), (Vec::<Value>::new(), false, false), move |conn| {
            let (h, p) = fleet_scan_all(conn, now_ts);
            (h, p, true)
        })
    })
    .await;
    match scan {
        Ok((hosts_full, pf, done)) => {
            if done {
                fleet_map().lock().insert(ckey, (Instant::now(), (hosts_full.clone(), pf)));
            }
            Json(fleet_response(&hosts_full, pf, &sort, dir_desc, limit, offset, now_ts))
        }
        Err(_) => Json(json!({ "hosts": [] })),
    }
}
