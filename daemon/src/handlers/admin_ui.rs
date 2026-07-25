//! Administration UI (#1b) : rétention éditable (`retention_settings_get/put`, `retention_preview`),
//! journal d'intégrité (`ledger_page`/`ledger_get`), inventaire/métadonnées sources
//! (`sources_inventory`, `source_settings_get/put`), et registre d'exclusions unifié
//! (`ExclType`/`ExclEntry`/`daemon_excl_registry`, `suppressions_get/put`, `apply_display_excl_edit`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// Plafonds de longueur (caractères) des métadonnées de source éditables (Partie B) — bornage anti-abus
// avant écriture. Valeurs inchangées, simplement nommées (revue hygiène refactor #25).
const LABEL_MAX: usize = 200;
const NOTE_MAX: usize = 2000;
const CAT_MAX: usize = 100;

// ================================ #1b ADMINISTRATION UI (daemon) ================================
// Rétention éditable (Partie A) + inventaire/métadonnées sources (Partie B). Toutes les mutations sont
// admin-only (path-guard `:920` + revérif interne), doublement auditées (ledger + event SOC) dans UNE
// transaction fail-closed, et bornées par des planchers durs. Aucun de ces endpoints ne touche l'ingest.

/// GET /api/retention -> valeurs EFFECTIVES courantes (résolveur setting->env/conf->défaut, correctif H2) +
/// bornes (min/max/défaut/unité) pour la validation miroir côté client. Admin only (B9).
pub(crate) async fn retention_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    with_write(&st, &au, |conn| {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".into(), json!(true));
    let mut bounds = serde_json::Map::new();
    for (skey, env_key, def, floor, ceil) in RETENTION_FIELDS {
        obj.insert(skey.to_string(), json!(setting_days(&conn, &conf, skey, env_key, def, floor, ceil)));
        let unit = if skey == "metric_raw_hours" { "hours" } else { "days" };
        bounds.insert(skey.to_string(), json!({ "min": floor, "max": ceil, "default": def, "unit": unit }));
    }
    obj.insert("bounds".into(), Value::Object(bounds));
    Json(Value::Object(obj)).into_response()
    })
}

/// POST|PUT /api/retention {retention_days?,snapshot_days?,alert_days?,metric_days?,metric_raw_hours?} (i64).
/// Chaque champ présent est clampé aux planchers (M6) puis écrit dans `setting`, avec double-audit (ledger +
/// event) DANS UNE TRANSACTION fail-closed (M5). L'« ancienne » valeur auditée = valeur EFFECTIVE résolue (H2).
/// Une baisse (new<current) = sev 3 (destructif) ; hausse/égal = sev 2. No-op (new==current) ignoré (pas d'audit).
pub(crate) async fn retention_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
    }
    let outcome: rusqlite::Result<Vec<(String, i64, i64)>> = (|| {
        let mut changes: Vec<(String, i64, i64)> = Vec::new();
        for (skey, env_key, def, floor, ceil) in RETENTION_FIELDS {
            let Some(v) = b.get(skey).and_then(|x| x.as_i64()) else { continue };
            let cur = setting_days(&conn, &conf, skey, env_key, def, floor, ceil); // valeur EFFECTIVE (H2)
            let n = v.clamp(floor, ceil); // plancher/plafond DURS (M6)
            if n == cur {
                continue; // no-op : ni écriture ni audit
            }
            conn.execute(
                "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
                 ON CONFLICT(scope,key) DO UPDATE SET value=?2,updated=?3,updated_by=?4",
                params![skey, n.to_string(), now(), au.name.as_str()],
            )?;
            let sev = if n < cur { 3 } else { 2 }; // baisse = destructif -> audit bruyant (H3)
            audit_config_change(
                &conn,
                &format!("config.retention.{skey}"),
                &format!("{cur}->{n} par {}", au.name),
                sev,
                &format!("rétention {skey}: {cur}->{n} par {}", au.name),
                &json!({ "key": skey, "old": cur, "new": n, "actor": au.name, "destructive": n < cur }).to_string(),
            )?;
            changes.push((skey.to_string(), cur, n));
        }
        Ok(changes)
    })();
    match outcome {
        Ok(changes) => {
            let _ = conn.execute_batch("COMMIT");
            let applied: serde_json::Map<String, Value> = changes.iter().map(|(k, _, n)| (k.clone(), json!(n))).collect();
            (StatusCode::OK, Json(json!({ "ok": true, "changed": changes.len(), "applied": applied }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : mutation NON persistée si l'audit échoue
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}

/// GET /api/retention/preview?key=<champ>&value=<n> -> aperçu NON destructif du volume purgeable si `key`
/// passait à `value`. Budget 2 Go : events via event_rollup (SUM(n), jamais `event` ni event_dim_rollup) ;
/// snapshot/alert/metric via COUNT index-borné. `destructive`=true si new<current (résolu H2). Tous les champs
/// (H3). Admin only (B9). Le count events est au bucket horaire -> approx=true (afficher « ~N »).
pub(crate) async fn retention_preview(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let key = q.get("key").map(|s| s.as_str()).unwrap_or("");
    let Some((skey, env_key, def, floor, ceil)) = RETENTION_FIELDS.iter().copied().find(|f| f.0 == key) else {
        return (StatusCode::BAD_REQUEST, "clé de rétention inconnue").into_response();
    };
    let new_val = q.get("value").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(def).clamp(floor, ceil);
    let unit_secs = if skey == "metric_raw_hours" { 3600 } else { 86400 };
    let conf = load_config();
    let n = now();
    crate::req_conn!(st, au, conn);
    let cur = setting_days(&conn, &conf, skey, env_key, def, floor, ceil); // MÊME résolveur que l'application (H2)
    let cutoff = n - new_val * unit_secs; // tout ce qui est < cutoff serait purgé au prochain tick
    let (deleted, oldest, kind, approx): (i64, Option<i64>, &str, bool) = match skey {
        "retention_days" => {
            // event_rollup UNIQUEMENT (jamais event_dim_rollup : surcompte par dimension), idx bucket-borné.
            let (s, o) = conn
                .query_row("SELECT COALESCE(SUM(n),0), MIN(bucket) FROM event_rollup WHERE bucket < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "events", true)
        }
        "snapshot_days" => {
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM snapshot WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "snapshots", false)
        }
        "alert_days" => {
            // reflète le filtre status<>'new' de retention_run : les alertes OUVERTES ne sont JAMAIS purgées.
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM alert WHERE status<>'new' AND ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "alerts_closed", false)
        }
        "metric_days" => {
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM metric_rollup WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "metric_rollups", false)
        }
        "metric_raw_hours" => {
            // raw metrics rollupées AVANT purge -> destructif « doux » (agrégat conservé), mais aperçu quand même (H3).
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM metric WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "metrics_raw", false)
        }
        _ => (0, None, "", false),
    };
    Json(json!({
        "ok": true,
        "key": skey,
        "unit": if skey == "metric_raw_hours" { "hours" } else { "days" },
        "current": cur,
        "new": new_val,
        "destructive": new_val < cur,
        "deleted": deleted,
        "deleted_kind": kind,
        "oldest": oldest,
        "approx": approx,
    }))
    .into_response()
}

/// Page du journal d'intégrité (BATCH 1) : `total` = COUNT total du ledger + `entries` = fenêtre
/// LIMIT/OFFSET (ordre id décroissant). Fonction pure sur &Connection -> testable sans AppState.
pub(crate) fn ledger_page(conn: &Connection, limit: i64, offset: i64) -> (Vec<Value>, i64) {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap_or(0);
    let entries: Vec<Value> = match conn.prepare("SELECT id,ts,kind,detail,hash FROM ledger ORDER BY id DESC LIMIT ?1 OFFSET ?2") {
        Ok(mut stmt) => stmt
            .query_map(params![limit, offset], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "ts": r.get::<_, i64>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "detail": r.get::<_, Option<String>>(3)?,
                    "hash": r.get::<_, String>(4)?,
                }))
            })
            .map(|it| it.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    (entries, total)
}

/// GET /api/ledger?limit=<n>&offset=<n> -> page du journal d'intégrité (audit tamper-evident), ordre
/// décroissant + `total`. Rend l'audit config RÉELLEMENT consultable in-UI (correctif H1 : le ledger n'avait
/// qu'un `verify` CLI). Lecture seule, admin only (B9). limit clampé [1,1000] ; offset absent -> 0 (rétro-compat).
pub(crate) async fn ledger_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(100).clamp(1, 1000);
    let offset: i64 = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).max(0);
    with_write(&st, &au, |conn| {
    let (entries, total) = ledger_page(&conn, limit, offset);
    Json(json!({ "ok": true, "entries": entries, "total": total })).into_response()
    })
}

/// GET /api/sources -> INVENTAIRE read-only dérivé (join observé x attendu x métadonnées display). Observé =
/// event_rollup GROUP BY source (budget : jamais `event`) ; attendu = source_is_known (COLLECTORS + sources
/// builtin) ; métadonnées = source_settings. `unexpected` = SIGNAL (source ni connue ni marquée expected).
/// Accessible à TOUS les rôles (pas de contrôle de mutation ici) -> PAS de guard admin (délibéré).
pub(crate) async fn sources_inventory(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let now_ts = now();
    let db_path = req_db_path(&st, &au);
    tokio::task::spawn_blocking(move || {
        read_with_watchdog(db_path.as_str(), Json(json!({ "ok": false, "sources": [], "generated": now_ts })), move |conn| {
            let d1 = now_ts - 86400;
            let cut7 = now_ts - 7 * 86400;
            let pipe_fresh = pipeline_is_fresh(conn, now_ts);
            // OBSERVÉ (event_rollup uniquement : ~ms, jamais un scan de `event`). source -> (last_seen, n_24h).
            let mut obs: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
            if let Ok(mut s) = conn.prepare(
                "SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) \
                 FROM event_rollup WHERE bucket>=?2 AND source<>'' GROUP BY source HAVING SUM(n)>=3",
            ) {
                if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                    for (src, last, n) in rows.flatten() {
                        obs.insert(src, (last, n));
                    }
                }
            }
            // MÉTADONNÉES DISPLAY (source_settings). Une source labellisée mais dormante reste listée (entry 0,0).
            #[allow(clippy::type_complexity)]
            let mut meta: HashMap<String, (bool, Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>)> = HashMap::new();
            if let Ok(mut s) = conn.prepare("SELECT source,expected,label,note,category,updated_by,updated FROM source_settings WHERE scope='global'") {
                if let Ok(rows) = s.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)? != 0,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                    ))
                }) {
                    for (src, exp, lbl, note, cat, by, upd) in rows.flatten() {
                        obs.entry(src.clone()).or_insert((0, 0));
                        meta.insert(src, (exp, lbl, note, cat, by, upd));
                    }
                }
            }
            let mut sources: Vec<Value> = Vec::new();
            for (src, (last, n24)) in &obs {
                let known = source_is_known(src);
                let m = meta.get(src);
                let expected = m.map(|x| x.0).unwrap_or(known); // pas de settings -> défaut = connue?
                let age = now_ts - last;
                let status = if !pipe_fresh {
                    "muet"
                } else if *last == 0 {
                    "dormant"
                } else if age <= 900 {
                    "frais"
                } else {
                    "calme"
                };
                let typ = if *n24 == 0 {
                    "dormant"
                } else if 86400 / (*n24).max(1) <= 90 {
                    "continu"
                } else {
                    "périodique"
                };
                sources.push(json!({
                    "source": src,
                    "in_collectors": known,
                    "expected": expected,
                    "unexpected": !expected,
                    "label": m.and_then(|x| x.1.clone()),
                    "note": m.and_then(|x| x.2.clone()),
                    "category": m.and_then(|x| x.3.clone()),
                    "updated_by": m.and_then(|x| x.4.clone()),
                    "updated": m.and_then(|x| x.5),
                    "last_seen": if *last == 0 { Value::Null } else { json!(last) },
                    "age_s": if *last == 0 { Value::Null } else { json!(age) },
                    "n_24h": n24,
                    "status": status,
                    "type": typ,
                }));
            }
            Json(json!({ "ok": true, "generated": now_ts, "pipeline_fresh": pipe_fresh, "sources": sources }))
        })
    })
    .await
    .unwrap_or_else(|_| Json(json!({ "ok": false, "sources": [], "generated": now_ts })))
}

/// GET /api/sources/settings -> liste brute source_settings (métadonnées display). Admin only (B9).
pub(crate) async fn source_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare("SELECT source,expected,label,note,category,updated,updated_by FROM source_settings WHERE scope='global' ORDER BY source") {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("source_settings indisponible: {e}")).into_response(),
    };
    let settings: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "source": r.get::<_, String>(0)?,
                "expected": r.get::<_, i64>(1)? != 0,
                "label": r.get::<_, Option<String>>(2)?,
                "note": r.get::<_, Option<String>>(3)?,
                "category": r.get::<_, Option<String>>(4)?,
                "updated": r.get::<_, Option<i64>>(5)?,
                "updated_by": r.get::<_, Option<String>>(6)?,
            }))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "ok": true, "settings": settings })).into_response()
}

/// POST|PUT /api/sources/settings {source, action, value?} -> métadonnées DISPLAY-only par source (D1 option
/// b). Enum d'actions FERMÉ : set_expected(bool) | set_label(str) | set_note(str) | set_category(str) | clear.
/// Admin only (B9) + double-audit transactionnel fail-closed (M5). B8 : set_expected(true) sur une source
/// INCONNUE = suppression d'un SIGNAL -> sev 3 (sinon sev 2). AUCUN champ ici ne touche l'ingest/la collecte/
/// les règles (mute d'affichage D4 et override rétention D3 NON implémentés).
pub(crate) async fn source_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let source = b.trimmed("source");
    if source.is_empty() {
        return (StatusCode::BAD_REQUEST, "champ 'source' requis").into_response();
    }
    if source.chars().count() > 256 {
        return (StatusCode::BAD_REQUEST, "source trop longue (max 256)").into_response();
    }
    let action = b.str_field("action");
    // ENUM FERMÉ (contrainte 8) — toute action inconnue = 400 AVANT d'ouvrir la transaction.
    if !matches!(action, "set_expected" | "set_label" | "set_note" | "set_category" | "clear") {
        return (StatusCode::BAD_REQUEST, "action inconnue (enum fermé)").into_response();
    }
    let known = source_is_known(&source);
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
    }
    let outcome: rusqlite::Result<()> = (|| {
        let ts = now();
        let (human, sev): (String, i64) = if action == "clear" {
            conn.execute("DELETE FROM source_settings WHERE scope='global' AND source=?1", params![source])?;
            ("réinitialisée (clear)".to_string(), 2)
        } else {
            // garantit la ligne (upsert), puis applique le champ selon l'enum fermé (col = littéral, jamais user-input).
            conn.execute(
                "INSERT INTO source_settings(scope,source,updated,updated_by) VALUES('global',?1,?2,?3) \
                 ON CONFLICT(scope,source) DO UPDATE SET updated=?2,updated_by=?3",
                params![source, ts, au.name.as_str()],
            )?;
            match action {
                "set_expected" => {
                    let v = b.get("value").and_then(|x| x.as_bool()).unwrap_or(true);
                    conn.execute("UPDATE source_settings SET expected=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![v as i64, ts, au.name.as_str(), source])?;
                    // B8 : reconnaître (expected=true) une source hors de l'ensemble connu = étouffer un signal -> bruyant.
                    let sev = if v && !known { 3 } else { 2 };
                    (format!("attendu={v}"), sev)
                }
                "set_label" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(LABEL_MAX).collect();
                    conn.execute("UPDATE source_settings SET label=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("label défini ({} car.)", s.chars().count()), 2)
                }
                "set_note" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(NOTE_MAX).collect();
                    conn.execute("UPDATE source_settings SET note=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    ("note définie".to_string(), 2)
                }
                "set_category" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(CAT_MAX).collect();
                    conn.execute("UPDATE source_settings SET category=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("catégorie définie ({} car.)", s.chars().count()), 2)
                }
                _ => unreachable!("action pré-validée"),
            }
        };
        audit_config_change(
            &conn,
            "source.settings",
            &format!("{source}: {human} par {}", au.name),
            sev,
            &format!("source {source}: {human} par {}", au.name),
            &json!({ "source": source, "action": action, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}

// =================================================================================================
// CHANTIER « whitelists → webui » — REGISTRE UNIQUE des suppressions/whitelists/filtres du DAEMON.
//
// AVANT : chaque exclusion vivait en CONSTANTE MAGIQUE dispersée (EXCL_CLAUSES, KNOWN_EXTRA_SOURCES,
// RETENTION_FIELDS, PROTECTED_IP_MATCHERS, HOT_FIELDS, AUTOINDEX_DENY, FTS_FIELDS_ON, generic_sources) —
// certaines invisibles = l'ANGLE MORT redouté (une suppression cachée). MAINTENANT : chacune est DÉCLARÉE
// ici comme DONNÉE {name, scope, type, value, source} et lue LIVE (aucune valeur dupliquée : le registre
// est une DÉCLARATION au-dessus des MÊMES sources de vérité que le runtime -> byte-identique par construction).
//
// Le registre alimente le panneau read-only (GET /api/suppressions) et rend la config INSPECTABLE
// (principe open-source / vendor-agnostic : déclaré/documenté, pas hardcodé magique).
//
// INVARIANT STRUCTUREL : seul le type `display-only` PROUVÉ (operator/self — jamais substitué dans
// `rule_sql`, garantie v55) porte `editable=true` ; `collection-reducing` et `host` sont TOUJOURS
// mirror-only (surfacer un filtre ≠ le rendre pilotable). Centraliser la VISIBILITÉ ≠ centraliser le CONTRÔLE.
// =================================================================================================

/// TYPE d'une suppression (test de l'angle mort) — détermine la politique d'édition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExclType {
    /// de-bruite un PANNEAU seul — jamais retiré du stockage `event` ni de la détection (`rule_sql`).
    DisplayOnly,
    /// réduit ce qui est INGÉRÉ/STOCKÉ (filtre collecteur, purge) — un changement PEUT ouvrir un angle mort.
    CollectionReducing,
    /// état firewall/enforcement/détecteur à la frontière hôte (nft, origin-fw, never-ban…).
    Host,
}
impl ExclType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ExclType::DisplayOnly => "display-only",
            ExclType::CollectionReducing => "collection-reducing",
            ExclType::Host => "host",
        }
    }
}

/// Une suppression/whitelist/filtre DÉCLARÉ comme donnée. `value`/`detail` sont résolus LIVE. `editable`
/// = true UNIQUEMENT pour operator/self (display-only prouvé) ; `edit_key` = clé passée à `suppressions_put`.
pub(crate) struct ExclEntry {
    pub(crate) name: &'static str,
    pub(crate) label: &'static str,
    pub(crate) scope: &'static str,
    pub(crate) etype: ExclType,
    pub(crate) value: String,
    pub(crate) detail: Value,
    pub(crate) source: &'static str,
    pub(crate) editable: bool,
    pub(crate) edit_key: &'static str,
}
impl ExclEntry {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "label": self.label,
            "scope": self.scope,
            "type": self.etype.as_str(),
            "value": self.value,
            "detail": self.detail,
            "source": self.source,
            "editable": self.editable,
            "edit_key": self.edit_key,
            "guarantee": "collecte/règles NON modifiées",
        })
    }
}

/// Construit le REGISTRE des exclusions DAEMON (A1..A9), valeurs LUES LIVE. Aucun état dupliqué : chaque
/// entrée lit la même source de vérité que le runtime -> le registre PROUVE ce qui est réellement en vigueur.
pub(crate) fn daemon_excl_registry(conn: &Connection, conf: &HashMap<String, String>) -> Vec<ExclEntry> {
    let mut out: Vec<ExclEntry> = Vec::new();
    // A1/A2 — exclusions d'AFFICHAGE opérateur/self (display-only, ÉDITABLES). value = CSV résolu (override
    // setting sinon env) ; detail = clauses RÉELLEMENT substituées dans compile_panel_sql (jamais rule_sql, v55).
    // SEULE catégorie editable de tout le registre.
    let op_csv = excl_display_csv(conn, conf, EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT);
    let self_csv = excl_display_csv(conn, conf, EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT);
    let e = ExclClauses::resolve(conn, conf);
    out.push(ExclEntry {
        name: "operator_excl",
        label: "Exclusion opérateur (__OPERATOR_EXCL__)",
        scope: "panneaux menace externe (web top-clients/4xx, Cloudflare 25-29, banpass)",
        etype: ExclType::DisplayOnly,
        value: op_csv,
        detail: json!({ "field": "src_ip", "sql": e.op_sql, "soql": e.op_soql, "substituted_in": "compile_panel_sql", "never_in": "rule_sql (v55)" }),
        source: "ExclClauses / PLUME_OPERATOR_IPS (override setting excl_operator_ips)",
        editable: true,
        edit_key: "operator",
    });
    out.push(ExclEntry {
        name: "self_excl",
        label: "Exclusion self/vhost (__SELF_EXCL__)",
        scope: "mêmes panneaux menace externe (vhost self)",
        etype: ExclType::DisplayOnly,
        value: self_csv,
        detail: json!({ "field": "vhost", "sql": e.self_sql, "soql": e.self_soql, "substituted_in": "compile_panel_sql", "never_in": "rule_sql (v55)" }),
        source: "ExclClauses / PLUME_SELF_HOSTS (override setting excl_self_hosts)",
        editable: true,
        edit_key: "self",
    });
    // A3 — KNOWN_EXTRA_SOURCES (flag DISPLAY-only « inattendu » + sévérité B8 ; ZÉRO effet ingest/collecte).
    out.push(ExclEntry {
        name: "known_extra_sources",
        label: "Sources connues additionnelles (flag « inattendu »)",
        scope: "inventaire /api/sources + sévérité B8",
        etype: ExclType::DisplayOnly,
        value: KNOWN_EXTRA_SOURCES.join(","),
        detail: json!({ "count": KNOWN_EXTRA_SOURCES.len(), "items": KNOWN_EXTRA_SOURCES }),
        source: "const KNOWN_EXTRA_SOURCES / source_is_known",
        editable: false,
        edit_key: "",
    });
    // A4 — planchers de RÉTENTION (collection-reducing : lifecycle des données). Valeur effective + planchers DURS.
    let ret: Vec<Value> = RETENTION_FIELDS
        .iter()
        .map(|&(k, env_key, d, floor, ceil)| json!({ "key": k, "effective": retention_effective(conn, conf, k), "floor": floor, "ceil": ceil, "default": d, "env": env_key }))
        .collect();
    out.push(ExclEntry {
        name: "retention_floors",
        label: "Rétention / purge (planchers)",
        scope: "purge retention_run (lifecycle des données)",
        etype: ExclType::CollectionReducing,
        value: format!("{} champs", RETENTION_FIELDS.len()),
        detail: json!({ "fields": ret, "note": "éditable ailleurs via /api/retention (plancher DUR anti-effacement) — surfacé ici en lecture" }),
        source: "const RETENTION_FIELDS / retention_run",
        editable: false,
        edit_key: "",
    });
    // A5 — never-ban (HOST/enforcement). PIÈGE §4 : partage l'env PLUME_OPERATOR_IPS mais N'EST PAS éditable ici.
    let nb: Vec<Value> = protected_ip_matchers().iter().map(|(v, p)| json!({ "match": v, "prefix": p })).collect();
    out.push(ExclEntry {
        name: "protected_ip_matchers",
        label: "IP protégées (never-ban)",
        scope: "responder / enforcement ban",
        etype: ExclType::Host,
        value: format!("{} matchers configurés + loopback/RFC1918/ULA (built-in)", nb.len()),
        detail: json!({ "configured": nb, "builtin": "loopback/link-local/RFC1918/ULA", "note": "HOST/enforcement — partage PLUME_OPERATOR_IPS mais JAMAIS pilotable d'ici (§4 : surfacer≠piloter)" }),
        source: "PROTECTED_IP_MATCHERS / ip_is_protected",
        editable: false,
        edit_key: "",
    });
    // A6 — HOT_FIELDS (whitelist d'index-expression : PERF ; un champ hors liste reste STOCKÉ et requêtable).
    out.push(ExclEntry {
        name: "hot_fields",
        label: "Champs chauds indexés (HOT_FIELDS)",
        scope: "index expression (perf)",
        etype: ExclType::DisplayOnly,
        value: HOT_FIELDS.join(","),
        detail: json!({ "items": HOT_FIELDS, "note": "perf uniquement — un champ hors liste reste STOCKÉ et requêtable" }),
        source: "const HOT_FIELDS / field_is_indexed",
        editable: false,
        edit_key: "",
    });
    // A7 — AUTOINDEX_DENY (denylist auto-index : PERF/RAM ; champ dénié reste STOCKÉ et requêtable).
    out.push(ExclEntry {
        name: "autoindex_deny",
        label: "Denylist auto-index (AUTOINDEX_DENY)",
        scope: "auto-index (budget RAM)",
        etype: ExclType::DisplayOnly,
        value: AUTOINDEX_DENY.join(","),
        detail: json!({ "items": AUTOINDEX_DENY, "note": "perf/RAM — champ dénié reste STOCKÉ et requêtable (jamais indexé)" }),
        source: "const AUTOINDEX_DENY",
        editable: false,
        edit_key: "",
    });
    // A8 — FTS_FIELDS (portée du search libre : commodité ; aucun effet collecte/détection).
    out.push(ExclEntry {
        name: "fts_fields",
        label: "Recherche plein-texte des champs (FTS_FIELDS)",
        scope: "search libre",
        etype: ExclType::DisplayOnly,
        value: if fts_fields_enabled() { "on".into() } else { "off".into() },
        detail: json!({ "enabled": fts_fields_enabled(), "env": "PLUME_FTS_FIELDS", "note": "commodité de recherche — aucun effet collecte/détection" }),
        source: "FTS_FIELDS_ON / PLUME_FTS_FIELDS",
        editable: false,
        edit_key: "",
    });
    // A9 — extracteur générique (collection-ENRICHISSANTE = opposé d'une suppression ; garde-fou jamais * / auditd).
    out.push(ExclEntry {
        name: "generic_extract",
        label: "Extracteur générique (opt-in par source)",
        scope: "extraction de champs (enrichit, ne supprime pas)",
        etype: ExclType::DisplayOnly,
        value: generic_sources().join(","),
        detail: json!({ "sources": generic_sources(), "env": "PLUME_GENERIC_EXTRACT", "guard": "jamais '*' ni 'auditd'", "note": "ENRICHIT la collecte (opposé d'une suppression)" }),
        source: "generic_sources / PLUME_GENERIC_EXTRACT",
        editable: false,
        edit_key: "",
    });
    out
}

/// ALLOW-LIST des clés de `fields` surfacées pour un auto-report de config collecteur (défense en
/// profondeur). Le panneau ré-émet ces `fields` VERBATIM au DOM admin ; un collecteur (futur, ou COMPROMIS /
/// un report FORGÉ) qui glisserait un champ inattendu (token, URL-avec-creds) ne doit JAMAIS voir cette valeur
/// echo-ée dans la console. On ne surface QUE les descripteurs de filtre CONNUS (l'union des clés de niveau 1
/// émises par collectors/*: type/collector/filters/note/enforcement/detector/max/source/carve_out) ; toute clé
/// hors liste est DROPPÉE. `fields` non-objet -> objet vide. Structurellement incapable d'échoyer un secret.
pub(crate) fn suppression_fields_allowlist(f: &Value) -> Value {
    const SURFACED: &[&str] = &["type", "collector", "filters", "note", "enforcement", "detector", "max", "source", "carve_out"];
    let mut out = serde_json::Map::new();
    if let Some(obj) = f.as_object() {
        for k in SURFACED {
            if let Some(v) = obj.get(*k) {
                out.insert((*k).to_string(), v.clone());
            }
        }
    }
    Value::Object(out)
}

/// GET /api/suppressions — PANNEAU read-only agrégeant TOUTES les suppressions/whitelists/filtres, quel que
/// soit leur périmètre : (1) registre DAEMON A1..A9 (lu live) ; (2) filtres des COLLECTEURS hôte, auto-reportés
/// via un event `category='config'` par source (B/C) ; (3) état FIREWALL (snapshot kind=firewall). Chaque
/// entrée porte son TYPE + « collecte/règles NON modifiées ». Admin only. LECTURE PURE : rien ici ne pilote
/// un filtre (invariant : centraliser la VISIBILITÉ ≠ centraliser le CONTRÔLE — un seul panneau, zéro angle mort).
/// Lit la base PLATEFORME (`st.db`) et non `req_db` : ce panneau est une vue OPÉRATEUR (registre daemon,
/// collecteurs hôte CENTRAUX ingérés dans la base `default`, état firewall — aucune donnée tenant) ; l'exclusion
/// display operator/self y est PLATEFORME-globale (même périmètre que le cache process-global EXCL_CLAUSES et
/// le refresh du boot). Mode 0 -> `st.db` == `req_db` -> byte-identique. Corrige la fuite/incohérence #3.
pub(crate) async fn suppressions_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    let __rc = st.db.clone();
    let conn = __rc.lock();
    // (1) DAEMON — registre déclaratif A1..A9.
    let daemon: Vec<Value> = daemon_excl_registry(&conn, &conf).iter().map(|e| e.to_json()).collect();
    // (2) COLLECTEURS HÔTE — dernier event category='config' PAR source (auto-report). idx_event_category seek
    // (borné : ces events sont dédupliqués par empreinte de config côté collecteur). On EXCLUT les audits
    // DAEMON (origin='daemon' : plume-config/…). READ-ONLY absolu : un collecteur ne peut pas se rendre éditable.
    // CONTESTE (anti-empoisonnement) : nb d'hôtes DISTINCTS ayant auto-reporté la config d'UNE même source
    // (fenêtre 14 j). >1 = un hôte usurpe une source qui appartient à un autre (ex: collecteur mail légitime +
    // hôte compromis prétendant source='mail') -> l'entrée est marquée `contested` : le conflit d'hôtes DEVIENT
    // VISIBLE, le panneau ne peut plus être empoisonné en silence. Bornée par source (cardinalité collecteurs).
    let mut host_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT source, COUNT(DISTINCT host) FROM event \
         WHERE category='config' AND origin<>'daemon' AND ts > ?1 GROUP BY source",
    ) {
        if let Ok(rows) = s.query_map(params![now() - 14 * 86400], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
            for (src, n) in rows.flatten() { host_counts.insert(src, n); }
        }
    }
    let mut collectors: Vec<Value> = Vec::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT e.source, e.ts, e.host, e.fields, e.message, e.origin FROM event e \
         JOIN (SELECT source, MAX(ts) mts FROM event WHERE category='config' AND origin<>'daemon' GROUP BY source) j \
           ON e.source=j.source AND e.ts=j.mts \
         WHERE e.category='config' AND e.origin<>'daemon' ORDER BY e.source",
    ) {
        if let Ok(rows) = s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        }) {
            for (src, ts, host, fields, msg, origin) in rows.flatten() {
                let raw: Value = fields.as_deref().and_then(|x| serde_json::from_str(x).ok()).unwrap_or(Value::Null);
                // le TYPE est DÉCLARÉ par le collecteur (champ `type` de ses fields) mais `editable` est
                // TOUJOURS false ici (structurel) : la frontière hôte garde le CONTRÔLE, le panneau la VISIBILITÉ.
                let etype = raw.get("type").and_then(|v| v.as_str()).unwrap_or("collection-reducing").to_string();
                // ALLOW-LIST : ne ré-émettre QUE les clés de descripteur connues (jamais un champ inattendu).
                let f = suppression_fields_allowlist(&raw);
                // PROVENANCE SERVEUR (origin) — `attested` seulement si le report vient d'un token
                // AGENT lié (host non-forgeable). Un report `unverified` (host auto-déclaré) ou `contested`
                // (>1 hôte pour la même source) NE peut plus se faire passer pour la vérité terrain en silence.
                let attested = origin == "agent";
                let contested = host_counts.get(&src).copied().unwrap_or(1) > 1;
                let age_s = (now() - ts).max(0);
                collectors.push(json!({
                    "source": src, "ts": ts, "host": host, "message": msg,
                    "type": etype, "fields": f, "editable": false,
                    "attested": attested, "contested": contested, "age_s": age_s,
                    "provenance": if attested { "agent (host lié au token)" } else { "auto-déclaré (non attesté)" },
                    "guarantee": "collecte/règles NON modifiées",
                }));
            }
        }
    }
    // (3) ÉTAT HÔTE/FIREWALL — dernier snapshot kind=firewall, surfacé RO (nft sets / origin-fw / etc.).
    let firewall = conn
        .query_row(
            "SELECT ts, data, host FROM snapshot WHERE kind='firewall' ORDER BY ts DESC LIMIT 1",
            [],
            |r| {
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?,
                    "data": serde_json::from_str::<Value>(&r.get::<_, String>(1)?).unwrap_or(Value::Null),
                    "host": r.get::<_, Option<String>>(2)?,
                }))
            },
        )
        .ok();
    Json(json!({
        "ok": true,
        "generated": now(),
        "daemon": daemon,
        "collectors": collectors,
        "firewall": firewall,
        "legend": {
            "display-only": "de-bruite un PANNEAU seul — jamais retiré du stockage ni de la détection (rule_sql). Operator/self = ÉDITABLE+audité.",
            "collection-reducing": "réduit ce qui est INGÉRÉ/STOCKÉ — READ-ONLY ici, contrôle à la frontière hôte.",
            "host": "état firewall/enforcement à la frontière hôte — READ-ONLY, visibilité seule.",
            "provenance": "auto-report collecteur : `attested`=host lié à un token agent (non-forgeable) ; sinon host auto-déclaré (non attesté). `contested`=plusieurs hôtes revendiquent la même source. Le `type` est DÉCLARÉ par le collecteur — un report non attesté/contesté/périmé NE fait PAS foi.",
        },
    }))
    .into_response()
}

/// POST|PUT /api/suppressions {action, value?} — édite l'UNIQUE exclusion display-only PROUVÉE (operator/self).
/// Enum FERMÉ : set_operator_excl(csv) | clear_operator_excl | set_self_excl(csv) | clear_self_excl. RIEN
/// d'autre n'est éditable — une action collection-reducing/host = 400 (le contrôle reste à la frontière). Admin
/// only + double-audit fail-closed (ledger + event plume-config) sev 3 (modifier une exclusion d'AFFICHAGE = un
/// de-bruitage auditable dans la durée, comme B8). GARANTIE angle mort : l'override n'alimente QUE
/// compile_panel_sql (jamais rule_sql ni never-ban) -> il NE PEUT créer aucun angle mort de collecte/détection.
/// Recompile le cache d'exclusion (hot-reload) -> effet immédiat sur les panneaux.
/// Cœur TESTABLE de l'édition d'une exclusion display-only : valide l'action (ENUM FERMÉ operator/self),
/// écrit/efface le `setting`, audite (ledger + event plume-config sev 3) DANS UNE TRANSACTION fail-closed,
/// renvoie (edit_key, old_csv, new_csv). Toute autre action (collection-reducing/host, ou inconnue) -> 400 :
/// le registre est read-only par conception, SEULE cette exclusion display-only est pilotable. N'appelle PAS
/// `excl_clauses_refresh` (le hot-reload du cache reste à l'appelant, hors transaction).
pub(crate) fn apply_display_excl_edit(
    conn: &Connection,
    conf: &HashMap<String, String>,
    action: &str,
    value: &str,
    actor: &str,
) -> Result<(&'static str, String, String), (StatusCode, String)> {
    let (setting_key, env_key, default, field, is_clear) = match action {
        "set_operator_excl" => (EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT, "operator", false),
        "clear_operator_excl" => (EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT, "operator", true),
        "set_self_excl" => (EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT, "self", false),
        "clear_self_excl" => (EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT, "self", true),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "action inconnue — seules les exclusions d'AFFICHAGE operator/self sont éditables (collection-reducing/host = read-only par conception)".to_string(),
            ))
        }
    };
    // valeur CSV bornée (display-only ; validée à la compilation par parse_excl_item -> une entrée non
    // interprétable devient no-op, jamais du SQL invalide ni un angle mort). Ici on borne juste la taille.
    let value: String = if is_clear { String::new() } else { value.chars().take(2000).collect() };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible".to_string()));
    }
    let outcome: rusqlite::Result<(String, String)> = (|| {
        let ts = now();
        let old = excl_display_csv(conn, conf, setting_key, env_key, default);
        if is_clear {
            conn.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![setting_key])?;
        } else {
            conn.execute(
                "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
                 ON CONFLICT(scope,key) DO UPDATE SET value=?2,updated=?3,updated_by=?4",
                params![setting_key, value, ts, actor],
            )?;
        }
        let new = excl_display_csv(conn, conf, setting_key, env_key, default);
        // sev 3 (B8-like) : de-bruitage d'affichage AUDITÉ (ledger + event plume-config SOC-visible dans la durée).
        audit_config_change(
            conn,
            &format!("config.suppression.{field}"),
            &format!("exclusion affichage {field}: [{old}]->[{new}] par {actor}"),
            3,
            &format!("exclusion d'affichage {field} (display-only): [{old}]->[{new}] par {actor} — panneaux uniquement, collecte/détection inchangées"),
            &json!({ "field": field, "old": old, "new": new, "actor": actor, "type": "display-only", "effect": "compile_panel_sql only (never rule_sql / never-ban)" }).to_string(),
        )?;
        Ok((old, new))
    })();
    match outcome {
        Ok((old, new)) => {
            let _ = conn.execute_batch("COMMIT");
            Ok((field, old, new))
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification): {e}")))
        }
    }
}

pub(crate) async fn suppressions_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let action = b.str_field("action");
    let value = b.str_field("value");
    let conf = load_config();
    // PORTÉE : l'exclusion d'affichage operator/self est PLATEFORME-globale (mêmes IP/vhosts de bruit de
    // l'opérateur/du self quel que soit le tenant) et pilote le cache PROCESS-global EXCL_CLAUSES rafraîchi
    // depuis `st.db` au boot. On écrit + rafraîchit donc sur `st.db` (base plateforme), JAMAIS sur la base
    // du tenant courant : sinon (multi-tenant) l'override écrit dans une base tenant fuit dans le cache global
    // de TOUS les tenants puis est PERDU au reboot (le boot ne relit que st.db). Mode 0 -> st.db == req_db ->
    // byte-identique. Reste STRICTEMENT display-only + audité (aucun impact collecte/détection/never-ban).
    let __rc = st.db.clone();
    let conn = __rc.lock();
    match apply_display_excl_edit(&conn, &conf, action, value, au.name.as_str()) {
        Ok((field, old, new)) => {
            // hot-reload du cache d'exclusion DEPUIS la base éditée -> effet immédiat sur les panneaux.
            excl_clauses_refresh(&conn, &conf);
            (StatusCode::OK, Json(json!({ "ok": true, "field": field, "old": old, "new": new }))).into_response()
        }
        Err((code, msg)) => (code, msg).into_response(),
    }
}
