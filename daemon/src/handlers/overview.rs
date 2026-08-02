//! Vue d'ensemble & panneaux de tête : cache court du COUNT(*) event (`events_count_cached`/
//! `EVENTS_COUNT_CACHE`, TTL/SWR par db_path), handlers `overview`/`environments`/`panel` et
//! l'échelle de sévérité `sev_num`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// FIX perf : cache court (TTL) du COUNT(*) FROM event. Ce comptage scanne 2,3 M+ lignes CHIFFRÉES
// (0,5–9 s de déchiffrement) et est polled en boucle par l'UI (« Vue d'ensemble »). On mémoïse la
// valeur < TTL (léger décalage acceptable pour un chiffre indicatif), recalcul à la demande au-delà.
pub(crate) const EVENTS_COUNT_TTL: Duration = Duration::from_secs(45);
// MT-KEY: par db_path (R2). Chaque base (tenant) mémoïse SON propre COUNT(*) FROM event ; un tenant ne
// sert jamais le compte d'un autre. TTL/SWR inchangés. En mono-tenant : une seule entrée -> identique.
pub(crate) static EVENTS_COUNT_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, i64)>>> = std::sync::OnceLock::new();
pub(crate) fn events_count_cached(db_path: &str, conn: &Connection) -> i64 {
    let cell = EVENTS_COUNT_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let g = cell.lock();
        if let Some((t, v)) = g.get(db_path) {
            if t.elapsed() < EVENTS_COUNT_TTL {
                return *v; // valeur fraîche : on évite le scan chiffré
            }
        }
    } // verrou relâché avant le recalcul (ne sérialise pas les lecteurs derrière un scan lent)
    // périmé/absent : recalcul HORS verrou puis republication. Deux recalculs concurrents = inoffensif.
    let events: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap_or(0);
    cell.lock().insert(db_path.to_string(), (Instant::now(), events));
    events
}
pub(crate) async fn overview(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    // FILTRE ENVIRONNEMENT (#2d) : None (mode 0) -> chemin STRICTEMENT identique (compteur d'events CACHÉ
    // inclus). Some("<env>") -> chaque compteur est filtré `env_id='<env>'` (alert/incident/event portent
    // env_id v66) ; le count d'events passe alors par un COUNT direct filtré (le cache tous-env ne
    // s'applique plus). Valeur validée (env_slug_ok) + échappée (soql_esc) -> anti-injection.
    let env = au.env_filter().map(|e| e.to_string());
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "open_alerts": 0, "events": 0, "ts": now() })), |conn| {
        // suffixe `AND <col>.env_id='<env>'` (ou '' en mode 0/all) pour une table donnée.
        let envp = |col: &str| -> String {
            match env.as_deref() {
                Some(e) => format!(" AND {col}.env_id='{}'", guatx_core::soql::soql_esc(e)),
                None => String::new(),
            }
        };
        // open_alerts = backlog de notifications : 'new' ET PAS ENCORE rattachée à un cas (exclut les
        // alertes déjà prises en charge dans un incident) -> le badge colle à la file ?uncased des alertes.
        let open_alerts: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM alert WHERE status='new' AND NOT EXISTS (SELECT 1 FROM incident_item ii WHERE ii.ref='alert:'||alert.id){}", envp("alert")), [], |r| r.get(0))
            .unwrap_or(0);
        // events : mode 0 -> compteur CACHÉ (inchangé) ; env fixé -> COUNT direct filtré (env-scopé, non caché).
        let events: i64 = match env.as_deref() {
            Some(e) => conn.query_row("SELECT COUNT(*) FROM event WHERE env_id=?1", params![e], |r| r.get(0)).unwrap_or(0),
            None => events_count_cached(req_db_path(&st, &au).as_str(), conn),
        };
        let cases_open: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM incident WHERE status<>'closed'{}", envp("incident")), [], |r| r.get(0)).unwrap_or(0);
        let cases_closed: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM incident WHERE status='closed'{}", envp("incident")), [], |r| r.get(0)).unwrap_or(0);
        let alerts_ack: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM alert WHERE status='ack'{}", envp("alert")), [], |r| r.get(0)).unwrap_or(0);
        Json(json!({ "open_alerts": open_alerts, "events": events, "ts": now(),
                     "cases_open": cases_open, "cases_closed": cases_closed, "alerts_ack": alerts_ack }))
    })
}

/// FILTRE ENVIRONNEMENT (#2d) — GET /api/environments : liste les environnements DISTINCTS du tenant
/// courant + un compte d'events par env. SOURCE = event_rollup (petite table pré-agrégée : réponse en
/// qq ms, aucun scan de `event`). `SUM(n)` = volume approximatif d'events par env (le rollup cape src_ip/
/// dims mais préserve la somme par (bucket,env) -> total par env EXACT). Renvoie AUSSI `current` = l'env
/// filtré de la requête (X-Plume-Env), pour que le sélecteur UI reflète l'état. MODE 0 : le rollup est
/// tout-prod -> `[{env:"prod", n:N}]` (fallback « prod » garanti même rollup vide) ; sélecteur caché côté UI.
pub(crate) async fn environments(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let current = au.env_filter().map(|e| e.to_string());
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "environments": [{ "env": "prod", "n": 0 }], "current": Value::Null })), |conn| {
        let mut envs: Vec<Value> = Vec::new();
        if let Ok(mut s) = conn.prepare("SELECT env_id, COALESCE(SUM(n),0) FROM event_rollup GROUP BY env_id ORDER BY env_id") {
            if let Ok(rows) = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
                for (e, n) in rows.flatten() { envs.push(json!({ "env": e, "n": n })); }
            }
        }
        // 'prod' TOUJOURS présent (mode 0 / rollup encore vide) -> le sélecteur a une valeur par défaut.
        if !envs.iter().any(|v| v.get("env").and_then(|x| x.as_str()) == Some("prod")) {
            envs.insert(0, json!({ "env": "prod", "n": 0 }));
        }
        Json(json!({ "environments": envs, "current": current }))
    })
}

/// GET /api/panel/:kind — état point-in-time d'un `kind` d'instantané (firewall / contrôles).
///
/// PAR HÔTE, PAS « LE » PARC. Cette route rendait `… ORDER BY ts DESC LIMIT 1` : l'état de la DERNIÈRE
/// machine à avoir parlé, présenté comme l'état du déploiement (MESURÉ le 2026-08-02 : `srv00` rendu seul
/// pour un parc de 50 hôtes, sans que rien n'indique les 49 autres). Les champs de tête (`ts`/`hash`/
/// `data`) sont CONSERVÉS — c'est la machine la plus fraîche, et sur un déploiement mono-hôte la réponse
/// est strictement celle d'avant — mais ils sont désormais ATTRIBUÉS (`host`) et accompagnés de la
/// ventilation complète (`hosts`) et de son dénominateur (`n_hosts`) : aucune surface ne peut plus
/// présenter une machine comme le parc SANS LE DIRE.
pub(crate) async fn panel(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(kind): Path<String>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let par_hote = crate::ingest::store::dernier_instantane_par_hote(&conn, &kind, 500);
    let jhosts: Vec<Value> = par_hote
        .iter()
        .map(|(h, ts, hash, data)| json!({
            "host": h, "ts": ts, "hash": hash,
            "data": serde_json::from_str::<Value>(data).unwrap_or_else(|_| json!({}))
        }))
        .collect();
    match par_hote.first() {
        Some((h, ts, hash, data)) => Json(json!({
            "kind": kind, "ts": ts, "hash": hash, "host": h,
            "data": serde_json::from_str::<Value>(data).unwrap_or_else(|_| json!({})),
            "hosts": jhosts, "n_hosts": jhosts.len()
        })),
        None => Json(json!({ "kind": kind, "data": Value::Null, "hosts": [], "n_hosts": 0 })),
    }
}

/// label de sévérité -> entier (info..critical) ; accepte aussi directement le nombre.
pub(crate) fn sev_num(s: &str) -> Option<i64> {
    match s {
        "info" | "0" => Some(0),
        "low" | "1" => Some(1),
        "medium" | "med" | "2" => Some(2),
        "high" | "3" => Some(3),
        "critical" | "crit" | "4" => Some(4),
        // niveaux de log usuels (Loki/syslog) -> sévérité Plume
        "debug" | "trace" => Some(0),
        "notice" => Some(1),
        "warn" | "warning" => Some(2),
        "err" | "error" => Some(3),
        "emerg" | "emergency" | "alert" | "fatal" | "panic" => Some(4),
        _ => None,
    }
}
