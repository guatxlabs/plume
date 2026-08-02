//! DAY-2 OPS (#51) — CONSOLE D'OPÉRABILITÉ. Endpoints d'infra standard + self-métriques + santé par
//! composant + bundle de diagnostic + bulletin/MOTD.
//!  - `/healthz`  : LIVENESS (200 si le process sert) — UNAUTH (sonde k8s), aucune donnée sensible.
//!  - `/readyz`   : READINESS (DB ouvrable + migrations faites + port bindé) — UNAUTH.
//!  - `/metrics`  : exposition Prometheus texte — jeton de scrape (Bearer PLUME_METRICS_TOKEN) OU viewer+
//!    (gaté dans auth_guard) ; JAMAIS anonyme au monde (les compteurs fuient des volumes).
//!  - `/api/system/metrics` : self-métriques JSON (panneau UI « Système ») — viewer+.
//!  - `/api/system/health`  : santé R/J/V par composant — viewer+.
//!  - `/api/system/diag`    : bundle de diagnostic NON-SECRET (support hand-off) — ADMIN-ONLY, allowlist.
//!  - `/api/bulletin`       : MOTD/bandeau diffusé à tous — GET viewer+, POST/DELETE admin (setting row).
//! ADDITIF : aucun bulletin posé -> aucun bandeau ; aucune écriture DB en lecture -> mode 0 byte-identique.
use crate::*;

/// Version de schéma courante (meta) — lecture O(1). Défaut 1 (base neuve avant migrate, ne devrait pas arriver).
pub(crate) fn schema_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// LIVENESS — 200 tant que le process sert. UNAUTH (bypass host_guard + auth_guard). Ne révèle QUE
/// ok/version/schema (aucun compte, aucun volume). k8s : `livenessProbe.httpGet { path: /healthz }`.
pub(crate) async fn healthz(State(st): State<AppState>) -> Response {
    let schema = { let c = st.db.lock(); schema_version(&c) };
    (StatusCode::OK, Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION"), "schema": schema }))).into_response()
}

/// READINESS — 200 si (migrations faites + port bindé = flag READY) ET la base est ouvrable (SELECT 1).
/// Sinon 503 (le pod est retiré du service jusqu'à ce qu'il soit prêt). UNAUTH. k8s : `readinessProbe`.
pub(crate) async fn readyz(State(st): State<AppState>) -> Response {
    let ready_flag = crate::READY.load(std::sync::atomic::Ordering::Relaxed);
    // DB ouvrable MAINTENANT (pas seulement au boot) : un SELECT 1 sur le writer (cheap). Lock indisponible
    // (writer occupé, ex. ANALYZE) -> on considère la DB vivante (ne pas sortir du service pour une écriture
    // en cours) : la readiness reflète « prêt à servir », pas « writer libre ».
    // parking_lot `try_lock` renvoie Option (pas de poison) : Some=libre, None=occupé (WouldBlock) -> vivant.
    let db_ok = match st.db.try_lock() {
        Some(c) => c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).map(|v| v == 1).unwrap_or(false),
        None => true,
    };
    let ready = ready_flag && db_ok;
    let code = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(json!({ "ready": ready, "bound": ready_flag, "db": db_ok, "version": env!("CARGO_PKG_VERSION") }))).into_response()
}

/// Seuil % d'usage disque pour la santé « store » — même clé que le garde-fou d'ingest (#29), défaut 80.
fn disk_warn_pct() -> u8 {
    cfg(&load_config(), "PLUME_DISK_WARN_PCT", "80").parse().unwrap_or(80)
}

/// EXPOSITION PROMETHEUS (texte). Auth déjà appliquée en amont (auth_guard : jeton de scrape OU viewer+).
/// Lit la base OPÉRATEUR (host-wide) — les self-métriques sont process-globales, pas tenant. Reads petits/
/// indexés (rollup SUM, MAX(ts) indexé, COUNT status) -> lock writer bref, jamais un scan de `event`.
pub(crate) async fn metrics_endpoint(State(st): State<AppState>) -> Response {
    let spool = st.spool.as_str().to_string();
    let db_path = st.db_path.as_ref().clone();
    let warn = disk_warn_pct();
    let body = {
        let c = st.db.lock();
        let sv = schema_version(&c);
        crate::gather_prom(&c, &spool, &db_path, sv, warn)
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// SELF-MÉTRIQUES JSON (panneau UI « Système »). viewer+. Base du tenant courant (req_db).
pub(crate) async fn system_metrics(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let c = db.lock();
    let sv = schema_version(&c);
    Json(crate::gather_json(&c, &spool, &db_path, sv, warn))
}

/// SANTÉ PAR COMPOSANT (R/J/V) + posture globale. viewer+. Base du tenant courant.
pub(crate) async fn system_health(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let c = db.lock();
    let components = crate::component_health(&c, &spool, &db_path, warn);
    let posture = crate::worst_state(&components);
    Json(json!({ "ts": now(), "posture": posture, "components": components }))
}

// ---------- BUNDLE DE DIAGNOSTIC (admin-only, allowlist NON-SECRET) ----------
/// Clés de config SÛRES à exposer dans le bundle (drapeaux opérationnels, JAMAIS un secret/clé/mot de passe).
/// Allowlist EXPLICITE : tout ce qui n'est pas listé est absent. Garde-fou supplémentaire `key_is_secretish`.
const DIAG_CONFIG_KEYS: &[&str] = &[
    "PLUME_MULTI_TENANT", "PLUME_ADDR", "PLUME_HOST", "PLUME_HOST_STRICT", "PLUME_PUBLIC_DEMO",
    "PLUME_RETENTION_DAYS", "PLUME_ROLLUP_INTERVAL_S", "PLUME_PANEL_REFRESH_S", "PLUME_QUERY_CONCURRENCY",
    "PLUME_PANEL_REFRESH_CONCURRENCY", "PLUME_SEARCH_LIMIT", "PLUME_SEARCH_MAX", "PLUME_FTS_FIELDS",
    "PLUME_AUTOINDEX", "PLUME_EXPRINDEX", "PLUME_AUTOINDEX_SLOW_MS", "PLUME_INGEST_MIN_FREE_MB",
    "PLUME_INGEST_MAX_EVENTS", "PLUME_DISK_WARN_PCT", "PLUME_RL_IP_MAX", "PLUME_RL_AUTH_MAX",
    "PLUME_RL_GLOBAL_MAX", "PLUME_AUTH_LOCK_THRESHOLD", "PLUME_SESSION_TTL_S", "PLUME_GENERIC_EXTRACT",
    "PLUME_TLS_CERT", "PLUME_TLS_KEY", "PLUME_ENGAGEMENT_MODE",
];

/// Une clé de config a-t-elle une APPARENCE de secret ? Belt-and-suspenders : même si l'allowlist ne contient
/// que des clés sûres, on refuse d'émettre toute clé dont le nom évoque un secret (défense en profondeur).
pub(crate) fn key_is_secretish(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    ["KEY", "SECRET", "PASS", "TOKEN", "HASH", "CRED", "PRIVATE"].iter().any(|m| u.contains(m))
}

/// CONSTRUIT le bundle de diagnostic (fonction PURE testable) : schéma, résumé de config (drapeaux
/// non-secrets), self-métriques, santé, échantillon d'events opérationnels NON-PII, comptes agrégés.
/// N'exécute QUE des SELECT sur un ALLOWLIST de tables/colonnes -> ne peut PAS lire user.hash / token.* /
/// *.config / *.secret / user_mfa.* (les colonnes de la denylist query_exec) ni de PII (username/src_ip).
pub(crate) fn diag_bundle_json(conn: &Connection, spool: &str, db_path: &str, warn: u8) -> Value {
    let sv = schema_version(conn);
    // Résumé de config : allowlist + garde secretish. Valeur "" pour une clé non posée. Les chemins TLS_CERT/
    // KEY sont des CHEMINS de fichier (pas la clé elle-même) -> sûrs ; mais on émet juste "posé"/"" (booléen)
    // pour ne rien divulguer d'un chemin. TOKEN/PASS/KEY sont exclus par key_is_secretish de toute façon.
    let mut cfgmap = serde_json::Map::new();
    let conf = load_config();
    for k in DIAG_CONFIG_KEYS {
        if key_is_secretish(k) {
            // n'expose QUE la présence (posé/absent), jamais la valeur.
            let present = !cfg(&conf, k, "").trim().is_empty();
            cfgmap.insert((*k).to_string(), json!(if present { "set" } else { "" }));
            continue;
        }
        cfgmap.insert((*k).to_string(), json!(cfg(&conf, k, "")));
    }
    // Events opérationnels self (NON-PII) : santé disque + changements de config audités (source plume-config/
    // plume-disk, jamais plume-auth/plume-operator-access qui portent username/src_ip). Derniers 30.
    let mut recent: Vec<Value> = Vec::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT ts, source, severity, message FROM event \
         WHERE source IN ('plume-disk','plume-config') ORDER BY ts DESC LIMIT 30",
    ) {
        if let Ok(rows) = s.query_map([], |r| {
            Ok(json!({ "ts": r.get::<_, i64>(0)?, "source": r.get::<_, String>(1)?, "severity": r.get::<_, i64>(2)?, "message": r.get::<_, String>(3)? }))
        }) {
            recent = rows.flatten().collect();
        }
    }
    // Alertes heartbeat (capteur muet) ouvertes — signal d'angle mort, NON-PII (rule=heartbeat.<id>).
    let mut heartbeats: Vec<Value> = Vec::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT ts, rule, title FROM alert WHERE rule LIKE 'heartbeat.%' AND status IN ('new','ack') ORDER BY ts DESC LIMIT 20",
    ) {
        if let Ok(rows) = s.query_map([], |r| {
            Ok(json!({ "ts": r.get::<_, i64>(0)?, "rule": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)? }))
        }) {
            heartbeats = rows.flatten().collect();
        }
    }
    // Comptes AGRÉGÉS (des NOMBRES, jamais des lignes) — donnent l'échelle sans exposer de contenu.
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    let counts = json!({
        "rules_enabled": count("SELECT COUNT(*) FROM rule WHERE enabled=1"),
        "rules_total": count("SELECT COUNT(*) FROM rule"),
        "dashboards": count("SELECT COUNT(*) FROM dashboard"),
        "users": count("SELECT COUNT(*) FROM user"),
        "alerts_open": count("SELECT COUNT(*) FROM alert WHERE status='new'"),
        "destinations": count("SELECT COUNT(*) FROM destination"),
        "connectors": count("SELECT COUNT(*) FROM connector"),
        // TAXONOMIE — CE QUE PLUME N'A PAS CLASSÉ, MESURÉ SUR LES DONNÉES ET NON SUR UN COMPTEUR DE
        // PROCESSUS. Une ligne à `category` vide est invisible à TOUTE règle `category=…` (l'axe de
        // composition des détections, docs/CIM.md §2) et le produit n'en disait rien : ni refus, ni
        // repli, ni journal (mesuré le 2026-08-02 : 4 événements à catégorie vide -> 4 stockés, 0
        // ligne). Le compte est fait EN SQL, donc il survit aux redémarrages et décrit l'état RÉEL de
        // la base — un compteur en mémoire n'aurait mesuré que la vie du process courant.
        "events_without_category": count("SELECT COUNT(*) FROM event WHERE category IS NULL OR category=''"),
    });
    // Quel ÉMETTEUR n'a pas classé. Sans cette ventilation, le compte ci-dessus dit qu'il y a un trou
    // sans dire où le boucher. Borné à 20 sources (des NOMBRES et des noms de source, jamais de ligne).
    let mut unclassified: Vec<Value> = Vec::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT source, COUNT(*) n FROM event WHERE category IS NULL OR category='' \
         GROUP BY source ORDER BY n DESC LIMIT 20",
    ) {
        if let Ok(rows) = s.query_map([], |r| {
            Ok(json!({ "source": r.get::<_, String>(0)?, "events": r.get::<_, i64>(1)? }))
        }) {
            unclassified = rows.flatten().collect();
        }
    }
    json!({
        "generated_at": now(),
        "kind": "plume-diagnostic-bundle",
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": sv,
        "config": Value::Object(cfgmap),
        "metrics": crate::gather_json(conn, spool, db_path, sv, warn),
        "health": crate::component_health(conn, spool, db_path, warn),
        "recent_events": recent,
        "heartbeat_alerts": heartbeats,
        "counts": counts,
        "unclassified_by_source": unclassified,
    })
}

/// GET /api/system/diag — ADMIN-ONLY (route_min_role Admin + re-check ici). Bundle JSON pour le support.
/// Content-Disposition attachment -> le navigateur le télécharge en fichier. Aucun secret (allowlist).
pub(crate) async fn system_diag(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let bundle = {
        let c = db.lock();
        diag_bundle_json(&c, &spool, &db_path, warn)
    };
    let fname = format!("plume-diag-{}.json", now());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{fname}\""))],
        Json(bundle),
    )
        .into_response()
}

// ---------- BULLETIN / MOTD (setting row 'bulletin', diffusé à tous) ----------
const BULLETIN_KEY: &str = "bulletin";
/// Niveaux d'affichage autorisés du bandeau (enum fermé -> pas d'injection de classe CSS arbitraire).
fn bulletin_level_ok(l: &str) -> bool {
    matches!(l, "info" | "warn" | "critical")
}

/// Lit le bulletin courant (setting global). None si absent (mode 0 : aucun bandeau). Value {message,level,...}.
pub(crate) fn bulletin_read(conn: &Connection) -> Option<Value> {
    let raw: String = conn
        .query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY], |r| r.get(0))
        .ok()?;
    serde_json::from_str::<Value>(&raw).ok().filter(|v| v.get("message").and_then(|m| m.as_str()).map(|s| !s.is_empty()).unwrap_or(false))
}

/// GET /api/bulletin — viewer+ (tous les rôles voient le MOTD). {bulletin: {...} | null}.
pub(crate) async fn bulletin_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db = req_db(&st, &au);
    let c = db.lock();
    Json(json!({ "bulletin": bulletin_read(&c) }))
}

/// POST /api/bulletin — ADMIN-ONLY (route_min_role default-deny Admin + re-check). {message, level?}.
/// Message vide -> efface (équivaut à DELETE). Ledgerisé (audit_config_change) — gouvernance.
pub(crate) async fn bulletin_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let message = body.get("message").and_then(|m| m.as_str()).unwrap_or("").trim().to_string();
    let level = body.get("level").and_then(|l| l.as_str()).unwrap_or("info");
    let level = if bulletin_level_ok(level) { level } else { "info" };
    let db = req_db(&st, &au);
    let c = db.lock();
    if message.is_empty() {
        let _ = c.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY]);
        let _ = audit_config_change(&c, "bulletin.clear", &format!("bulletin effacé par {}", au.name), 1, "bulletin effacé", "{}");
        return (StatusCode::OK, Json(json!({ "ok": true, "bulletin": Value::Null }))).into_response();
    }
    if message.len() > 2000 {
        return bad_req("message trop long (max 2000 caractères)");
    }
    let val = json!({ "message": message, "level": level, "updated_by": au.name, "updated": now() });
    let _ = c.execute(
        "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
         ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
        params![BULLETIN_KEY, val.to_string(), now(), au.name],
    );
    let _ = audit_config_change(&c, "bulletin.set", &format!("bulletin posé par {} (niveau {level})", au.name), 1, "bulletin/MOTD mis à jour", &json!({ "level": level, "by": au.name }).to_string());
    (StatusCode::OK, Json(json!({ "ok": true, "bulletin": val }))).into_response()
}

/// DELETE /api/bulletin — ADMIN-ONLY. Efface le bandeau (retour à l'état mode 0 : aucun bandeau).
pub(crate) async fn bulletin_clear(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let db = req_db(&st, &au);
    let c = db.lock();
    let _ = c.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY]);
    let _ = audit_config_change(&c, "bulletin.clear", &format!("bulletin effacé par {}", au.name), 1, "bulletin effacé", "{}");
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}
