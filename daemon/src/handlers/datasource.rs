//! DATASOURCE (#52) — plume AS A DATASOURCE : surfaces de LECTURE que Grafana/Prometheus interrogent.
//! Jusqu'ici plume ne faisait que RECEVOIR (ingest/remote_write/loki push/HEC) ; ce module expose des
//! endpoints read-only pour "aller là où sont les clients" (une Grafana existante pointe un panneau SUR plume).
//!
//! DEUX leviers construits + 1 différé :
//!   1. GXQL-over-HTTP-JSON (Grafana Infinity/JSON) — `/api/ds/query` : prend un GXQL + fenêtre, renvoie des
//!      lignes tabulaires JSON. RÉUTILISE le chemin masqué EXISTANT (`effective_masks` -> `soql_to_sql_masked_x`
//!      -> `run_query_ex`), STRICTEMENT comme /api/query -> les field-filters (#45) + le RBAC s'appliquent
//!      automatiquement. C'est le levier le plus général.
//!   2. Prometheus-compatible read (Grafana Prometheus datasource) — `/api/v1/query`, `/api/v1/query_range`,
//!      `/api/v1/label/__name__/values`, `/api/v1/labels`, `/api/v1/series` sur la table `metric` ingérée.
//!      SOUS-ENSEMBLE HONNÊTE : sélection d'UNE série par nom + matchers d'égalité (`metric{label="v"}`) +
//!      fenêtre temps -> forme JSON Prometheus (matrix/vector). PAS de moteur PromQL (rate/sum/histogram/
//!      regex-matcher/opérateurs = suite documentée). Respecte masquage + RBAC (voir INVARIANT ci-dessous).
//!   3. Loki-query (`/loki/api/v1/query_range` LogQL) — STUB + note de conception (docs/DATASOURCE.md).
//!
//! INVARIANT DE SÉCURITÉ (critère de revue #1) : c'est une NOUVELLE surface de LECTURE EXTERNE ; elle NE
//! contourne NI #45 NI le RBAC. L'appelant est résolu par `auth_guard` (token->role/tenant) EXACTEMENT comme
//! toute autre route ; CHAQUE lecture passe par le masque effectif du rôle/tenant/env de l'appelant :
//!   - GXQL-HTTP : `soql_to_sql_masked_x` (masque ÉMIS DANS LE SQL, avant agrégation — même choke-point que l'UI).
//!   - Prometheus : (a) un matcher sur un champ MASQUÉ est REJETÉ (oracle interdit, miroir de search_mask_guard) ;
//!     (b) les valeurs de labels/host masquées sont CAVIARDÉES en sortie via `mask_named_row`. Fail-closed : si
//!     le masque ne peut être appliqué, on refuse (jamais servir en clair).
use crate::*;
use guatx_core::soql::FieldMaskSet;

// ================================================================================================
// AUTH / RÔLE — helpers partagés (l'appelant est déjà résolu par auth_guard ; on hérite de son AuthUser).
// ================================================================================================

/// Jeu de masques EFFECTIF de l'appelant courant — RÉSOLU IDENTIQUEMENT à /api/query (#45). VIDE en mode 0 /
/// sans règle -> compilation byte-identique.
fn caller_masks(st: &AppState, au: &AuthUser) -> FieldMaskSet {
    effective_masks(req_db_path(st, au).as_str(), &au.role, &au.tenant, au.env_filter())
}

/// Plafond de lignes d'une réponse datasource. Réutilise le plafond de lecture (`PLUME_QUERY_MAX`, borné dur
/// à 100k par run_query_ex) ; ici on borne aussi le `limit` explicite du client à 10000 (une page de graphe).
fn ds_row_cap(requested: Option<i64>) -> i64 {
    requested.filter(|&n| n > 0).unwrap_or(10_000).min(10_000)
}

// ================================================================================================
// LEVIER 1 — GXQL-over-HTTP-JSON (Grafana Infinity / JSON datasource)
// ================================================================================================

/// CŒUR TESTABLE du levier GXQL-HTTP : compile le GXQL via le chemin MASQUÉ du rôle (choke-point unique #45)
/// puis exécute en lecture seule. `masks` VIDE -> STRICTEMENT identique à /api/query mode 0. C'est la fonction
/// exacte que le handler appelle avec l'AuthUser résolu -> la preuve d'héritage du masque tient ICI.
pub(crate) fn ds_soql_exec(
    db_path: &str,
    role: &str,
    tenant: &str,
    env: Option<&str>,
    soql: &str,
    from: i64,
    to: i64,
    limit: Option<i64>,
    budget_ms: u64,
) -> Result<Value, String> {
    // FIELD FILTERS (#45) : masques du RÔLE/TENANT/ENV de l'appelant, injectés DANS le SQL avant agrégation.
    let masks = effective_masks(db_path, role, tenant, env);
    let base = soql_to_sql_masked_x(soql, from, to, env, &masks)?;
    // pagination/plafond par WRAP (marche même si {base} a déjà un LIMIT : l'inner cape, l'outer borne).
    let cap = ds_row_cap(limit);
    let sql = format!("SELECT * FROM ({base}) LIMIT {cap}");
    run_query_ex(db_path, &sql, budget_ms, None)
}

/// Sérialise le résultat run_query_ex selon `format` :
///   - "records" (défaut) : `[{col:val, ...}, ...]` (le plus consommable par Grafana Infinity) ;
///   - "table"            : `{columns, rows}` (colonnes + lignes brutes).
/// Les valeurs sont DÉJÀ caviardées (masque émis dans le SQL) -> jamais de clair non masqué.
fn ds_shape(v: &Value, format: &str) -> Value {
    if format == "table" {
        json!({ "columns": v.get("columns").cloned().unwrap_or(json!([])), "rows": v.get("rows").cloned().unwrap_or(json!([])) })
    } else {
        result_to_json_records(v)
    }
}

/// Extrait (soql, from, to, limit, format) d'une map de params (GET query OU champs JSON).
fn ds_soql_params(get: impl Fn(&str) -> Option<String>) -> (String, i64, i64, Option<i64>, String) {
    let soql = get("soql").or_else(|| get("query")).unwrap_or_default();
    let from = get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let to = get("to").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let limit = get("limit").and_then(|s| s.parse::<i64>().ok());
    let format = get("format").unwrap_or_else(|| "records".into()).to_ascii_lowercase();
    (soql, from, to, limit, format)
}

async fn ds_soql_run(st: AppState, au: AuthUser, soql: String, from: i64, to: i64, limit: Option<i64>, format: String) -> Response {
    if soql.trim().is_empty() {
        return bad_req("soql requis (champ `soql` ou `query`)");
    }
    // backpressure : MÊME sémaphore que /api/query (borne les déchiffrements concurrents ; anti-OOM).
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    let db_path = req_db_path(&st, &au);
    let role = au.role.clone();
    let tenant = au.tenant.clone();
    let env = au.env_filter().map(|s| s.to_string());
    // budget AUTO (5 s) : borne une requête externe folle (pas le budget interactif 60 s de l'UI).
    let budget = query_budget_ms();
    let res = tokio::task::spawn_blocking(move || {
        ds_soql_exec(&db_path, &role, &tenant, env.as_deref(), &soql, from, to, limit, budget)
    })
    .await;
    match res {
        Ok(Ok(v)) => Json(ds_shape(&v, &format)).into_response(),
        Ok(Err(e)) => bad_req(e),
        Err(_) => server_err("exécution échouée"),
    }
}

/// GET /api/ds/query?soql=...&from=..&to=..&limit=..&format=records|table
pub(crate) async fn ds_query_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    let (soql, from, to, limit, format) = ds_soql_params(|k| q.get(k).cloned());
    ds_soql_run(st, au, soql, from, to, limit, format).await
}

/// POST /api/ds/query {soql|query, from?, to?, limit?, format?}
pub(crate) async fn ds_query_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let (soql, from, to, limit, format) = ds_soql_params(|k| b.get(k).and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string()))));
    ds_soql_run(st, au, soql, from, to, limit, format).await
}

// ================================================================================================
// LEVIER 2 — Prometheus-compatible read (sous-ensemble honnête)
// ================================================================================================

/// Réponse d'erreur au format Prometheus (`{status:error,errorType,error}`), HTTP 400.
fn prom_err(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "errorType": "bad_data", "error": msg.into() }))).into_response()
}
fn prom_ok(data: Value) -> Response {
    Json(json!({ "status": "success", "data": data })).into_response()
}

/// Un nom de métrique Prometheus valide (alnum + `_` + `:`), non vide.
fn prom_name_ok(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':')
}
/// Une clé de label valide (alnum + `_`), non vide.
fn prom_label_ok(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
/// Échappe une valeur pour une string littérale SQLite (double les apostrophes) — anti-injection.
fn sql_esc(v: &str) -> String {
    v.replace('\'', "''")
}

/// Parse un sélecteur PromQL MINIMAL : `name`, `name{l="v",...}` ou `{__name__="name",l="v"}`. SEUL l'opérateur
/// `=` (égalité) est supporté (miroir honnête : `!=`, `=~`, `!~` = suite documentée -> Err clair). Renvoie
/// (name, matchers) où matchers EXCLUT `__name__` (déjà résolu en name). Rejette tout ce qui n'est PAS un
/// sélecteur de série (fonctions/opérateurs PromQL -> le nom échoue la validation).
pub(crate) fn prom_parse_selector(sel: &str) -> Result<(String, Vec<(String, String)>), String> {
    let s = sel.trim();
    if s.is_empty() {
        return Err("query requise".into());
    }
    let (name_part, inner) = match s.find('{') {
        Some(b) => {
            if !s.ends_with('}') {
                return Err("sélecteur mal formé (attendu name{...})".into());
            }
            (s[..b].trim(), &s[b + 1..s.len() - 1])
        }
        None => (s, ""),
    };
    let mut matchers: Vec<(String, String)> = Vec::new();
    let mut name = name_part.to_string();
    // parse `k="v", k2="v2"` en respectant les guillemets.
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let ks = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b'!' && bytes[i] != b'~' && bytes[i] != b' ' {
            i += 1;
        }
        let key = inner[ks..i].trim().to_string();
        // opérateur : on n'accepte QUE `=` immédiatement suivi d'un guillemet (pas `==`, `!=`, `=~`, `!~`).
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return Err(format!("matcher non supporté pour '{key}' (seul l'opérateur = est supporté ; =~/!=/!~ = suite documentée)"));
        }
        i += 1;
        if i < bytes.len() && (bytes[i] == b'~' || bytes[i] == b'=') {
            return Err(format!("matcher non supporté pour '{key}' (seul l'opérateur = est supporté ; =~/!=/!~ = suite documentée)"));
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            return Err(format!("valeur de matcher attendue entre guillemets pour '{key}'"));
        }
        i += 1;
        let mut val = String::new();
        while i < bytes.len() && bytes[i] != b'"' {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 1;
                val.push(match bytes[i] {
                    b'n' => '\n',
                    b'"' => '"',
                    b'\\' => '\\',
                    o => o as char,
                });
            } else {
                val.push(bytes[i] as char);
            }
            i += 1;
        }
        i += 1; // guillemet fermant
        if key == "__name__" {
            name = val;
        } else {
            if !prom_label_ok(&key) {
                return Err(format!("clé de label invalide : {key}"));
            }
            matchers.push((key, val));
        }
    }
    if !prom_name_ok(&name) {
        return Err(format!("nom de métrique invalide ou expression PromQL non supportée : {name}"));
    }
    Ok((name, matchers))
}

/// GARDE MASQUE (#45) : un matcher sur un champ MASQUÉ pour l'appelant est un ORACLE (chaque filtre renvoyant
/// N lignes fuit l'existence de la valeur) -> REJET, comme search_mask_guard. `host` -> colonne `host` ; toute
/// autre clé -> clé de label (probe une clé JSON masquée). Renvoie Err(champ) au 1er matcher interdit.
pub(crate) fn prom_matcher_guard(matchers: &[(String, String)], masks: &FieldMaskSet) -> Result<(), String> {
    if masks.is_empty() {
        return Ok(());
    }
    for (k, _) in matchers {
        let col = if k == "host" { "host" } else { k.as_str() };
        if masks.get(col).is_some() {
            return Err(k.clone());
        }
    }
    Ok(())
}

/// Construit le SELECT read-only injection-SÛR sur la table `metric` (nom + labels validés, valeurs échappées).
/// run_query_ex refuse DE TOUTE FAÇON tout non-SELECT (défense en profondeur).
pub(crate) fn prom_metric_sql(name: &str, matchers: &[(String, String)], from: i64, to: i64) -> Result<String, String> {
    if !prom_name_ok(name) {
        return Err(format!("nom de métrique invalide : {name}"));
    }
    let mut conds = vec![format!("name='{}'", sql_esc(name))];
    for (k, v) in matchers {
        if k == "host" {
            conds.push(format!("host='{}'", sql_esc(v)));
        } else if prom_label_ok(k) {
            conds.push(format!("json_extract(labels,'$.{}')='{}'", k, sql_esc(v)));
        } else {
            return Err(format!("clé de label invalide : {k}"));
        }
    }
    if from > 0 {
        conds.push(format!("ts >= {from}"));
    }
    if to > 0 {
        conds.push(format!("ts <= {to}"));
    }
    let where_c = conds.join(" AND ");
    Ok(format!("SELECT ts,name,labels,host,value FROM metric WHERE {where_c} ORDER BY ts"))
}

/// Formate une valeur numérique en string Prometheus (les échantillons Prometheus sont des strings).
fn prom_val(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::Null => "NaN".into(),
        other => other.to_string(),
    }
}

/// Groupe les lignes {ts,name,labels,host,value} de run_query_ex en SÉRIES Prometheus, en APPLIQUANT le masque
/// de l'appelant aux valeurs de labels/host (mask_named_row) -> une série masquée n'expose jamais la valeur en
/// clair. Renvoie Vec<(label_map_json, Vec<(ts, val_string)>)> dans l'ordre d'apparition des séries.
pub(crate) fn prom_rows_to_series(v: &Value, db_path: &str, name: &str, masks: &FieldMaskSet) -> Vec<(serde_json::Map<String, Value>, Vec<(i64, String)>)> {
    let empty: Vec<Value> = Vec::new();
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);
    // ordre stable des séries + index par clé.
    let mut order: Vec<String> = Vec::new();
    let mut series: HashMap<String, (serde_json::Map<String, Value>, Vec<(i64, String)>)> = HashMap::new();
    for row in rows {
        let arr = match row.as_array() {
            Some(a) if a.len() >= 5 => a,
            _ => continue,
        };
        let ts = arr[0].as_i64().unwrap_or(0);
        let labels_raw = arr[2].as_str().unwrap_or("{}");
        let host = arr[3].clone();
        let val = prom_val(&arr[4]);
        // label map = __name__ + labels JSON + host (colonne dénormalisée si absente des labels).
        let mut m = serde_json::Map::new();
        m.insert("__name__".into(), Value::String(name.to_string()));
        if let Ok(Value::Object(lbls)) = serde_json::from_str::<Value>(labels_raw) {
            for (k, val) in lbls {
                m.insert(k, val);
            }
        }
        if !m.contains_key("host") {
            if let Value::String(h) = &host {
                if !h.is_empty() {
                    m.insert("host".into(), host.clone());
                }
            }
        }
        // MASQUE (#45) : caviarde en place toute valeur de label dont la clé est masquée pour l'appelant.
        let _ = mask_named_row(db_path, masks, &mut m);
        let key = Value::Object(m.clone()).to_string();
        let entry = series.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (m, Vec::new())
        });
        entry.1.push((ts, val));
    }
    order.into_iter().filter_map(|k| series.remove(&k)).collect()
}

/// Extraction commune du sélecteur + fenêtre + exécution masquée. `instant` -> ne garde que le DERNIER
/// échantillon (<= to) par série (vecteur) ; sinon toute la fenêtre (matrice).
async fn prom_run(st: AppState, au: AuthUser, query: String, from: i64, to: i64) -> Result<Vec<(serde_json::Map<String, Value>, Vec<(i64, String)>)>, Response> {
    let (name, matchers) = prom_parse_selector(&query).map_err(prom_err)?;
    let masks = caller_masks(&st, &au);
    if let Err(field) = prom_matcher_guard(&matchers, &masks) {
        return Err(prom_err(format!("filtre interdit sur un champ masqué : {field}")));
    }
    let sql = prom_metric_sql(&name, &matchers, from, to).map_err(prom_err)?;
    let _permit = st.query_sem.clone().acquire_owned().await.map_err(|_| err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"))?;
    let db_path = req_db_path(&st, &au);
    let dbp = db_path.clone();
    let budget = query_budget_ms();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &sql, budget, None)).await;
    let v = match res {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(prom_err(e)),
        Err(_) => return Err(prom_err("exécution échouée")),
    };
    Ok(prom_rows_to_series(&v, &db_path, &name, &masks))
}

/// Parse un timestamp Prometheus (secondes unix, float ou int). Défaut = `now()`.
fn prom_time(q: &HashMap<String, String>, key: &str, default: i64) -> i64 {
    q.get(key).and_then(|s| s.parse::<f64>().ok()).map(|f| f as i64).unwrap_or(default)
}

/// GET/POST /api/v1/query — requête INSTANTANÉE : dernier échantillon (<= time) par série (resultType=vector).
pub(crate) async fn prom_query(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    let query = q.get("query").cloned().unwrap_or_default();
    let time = prom_time(&q, "time", now());
    // fenêtre de lookback bornée pour retrouver le dernier point (évite un full-scan) : 1 h par défaut.
    let lookback: i64 = std::env::var("PLUME_PROM_LOOKBACK_S").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0).unwrap_or(3600);
    let series = match prom_run(st, au, query, time - lookback, time).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let result: Vec<Value> = series
        .into_iter()
        .filter_map(|(metric, mut pts)| {
            pts.sort_by_key(|(ts, _)| *ts);
            pts.last().map(|(ts, val)| json!({ "metric": metric, "value": [*ts, val] }))
        })
        .collect();
    prom_ok(json!({ "resultType": "vector", "result": result }))
}

/// GET/POST /api/v1/query_range — plage : tous les échantillons de [start,end] par série (resultType=matrix).
/// HONNÊTETÉ : `step` n'est PAS ré-échantillonné (échantillons BRUTS renvoyés ; Grafana fait son downsampling).
pub(crate) async fn prom_query_range(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    let query = q.get("query").cloned().unwrap_or_default();
    let end = prom_time(&q, "end", now());
    let start = prom_time(&q, "start", end - 3600);
    let series = match prom_run(st, au, query, start, end).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let result: Vec<Value> = series
        .into_iter()
        .map(|(metric, mut pts)| {
            pts.sort_by_key(|(ts, _)| *ts);
            let values: Vec<Value> = pts.into_iter().map(|(ts, val)| json!([ts, val])).collect();
            json!({ "metric": metric, "values": values })
        })
        .collect();
    prom_ok(json!({ "resultType": "matrix", "result": result }))
}

/// GET /api/v1/label/:name/values — valeurs distinctes d'un label. `__name__` -> noms de métriques distincts.
/// Un label MASQUÉ pour l'appelant -> 400 (miroir #45 : pas d'énumération d'un champ masqué).
pub(crate) async fn prom_label_values(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(label): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let masks = caller_masks(&st, &au);
    let db_path = req_db_path(&st, &au);
    if label == "__name__" {
        let sql = "SELECT DISTINCT name FROM metric ORDER BY name LIMIT 5000".to_string();
        return prom_distinct_col(&st, &db_path, &sql).await;
    }
    if !prom_label_ok(&label) {
        return prom_err("nom de label invalide");
    }
    // fail-closed : label masqué -> refus (pas d'oracle par énumération).
    let col_key = if label == "host" { "host" } else { label.as_str() };
    if masks.get(col_key).is_some() {
        return prom_err(format!("label masqué : {label}"));
    }
    let _ = q;
    let sql = if label == "host" {
        "SELECT DISTINCT host AS v FROM metric WHERE host IS NOT NULL AND host<>'' ORDER BY v LIMIT 5000".to_string()
    } else {
        format!("SELECT DISTINCT json_extract(labels,'$.{label}') AS v FROM metric WHERE v IS NOT NULL ORDER BY v LIMIT 5000")
    };
    prom_distinct_col(&st, &db_path, &sql).await
}

/// Exécute un SELECT d'UNE colonne et renvoie `{status:success,data:[...]}` (valeurs string).
async fn prom_distinct_col(st: &AppState, db_path: &str, sql: &str) -> Response {
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    let dbp = db_path.to_string();
    let sql = sql.to_string();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &sql, query_budget_ms(), None)).await;
    match res {
        Ok(Ok(v)) => {
            let empty: Vec<Value> = Vec::new();
            let data: Vec<Value> = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty).iter().filter_map(|row| row.as_array().and_then(|a| a.first()).cloned()).filter(|x| !x.is_null()).collect();
            prom_ok(json!(data))
        }
        Ok(Err(e)) => prom_err(e),
        Err(_) => prom_err("exécution échouée"),
    }
}

/// GET /api/v1/labels — clés de labels connues (bornées) : `__name__`, `host`, + clés JSON échantillonnées,
/// MOINS les clés masquées pour l'appelant (une clé masquée n'apparaît pas dans le browser de labels).
pub(crate) async fn prom_labels(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    let masks = caller_masks(&st, &au);
    let db_path = req_db_path(&st, &au);
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    let dbp = db_path.clone();
    // échantillon borné des blobs de labels récents -> union des clés.
    let sql = "SELECT DISTINCT labels FROM metric ORDER BY ts DESC LIMIT 2000".to_string();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &sql, query_budget_ms(), None)).await;
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    keys.insert("__name__".into());
    keys.insert("host".into());
    if let Ok(Ok(v)) = res {
        let empty: Vec<Value> = Vec::new();
        for row in v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty) {
            if let Some(blob) = row.as_array().and_then(|a| a.first()).and_then(|x| x.as_str()) {
                if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(blob) {
                    for k in m.keys() {
                        keys.insert(k.clone());
                    }
                }
            }
        }
    }
    // retire les clés masquées pour l'appelant (fail-closed : jamais exposer un champ masqué comme label).
    let data: Vec<Value> = keys.into_iter().filter(|k| k == "__name__" || masks.get(if k == "host" { "host" } else { k.as_str() }).is_none()).map(Value::String).collect();
    prom_ok(json!(data))
}

/// GET/POST /api/v1/series?match[]=selector — jeux de labels des séries correspondantes (masqués).
pub(crate) async fn prom_series(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    // Grafana envoie match[]=... ; on accepte match[] OU match.
    let query = q.get("match[]").or_else(|| q.get("match")).cloned().unwrap_or_default();
    if query.trim().is_empty() {
        return prom_err("paramètre match[] requis");
    }
    let end = prom_time(&q, "end", now());
    let start = prom_time(&q, "start", end - 3600);
    let series = match prom_run(st, au, query, start, end).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let data: Vec<Value> = series.into_iter().map(|(metric, _)| Value::Object(metric)).collect();
    prom_ok(json!(data))
}

// ================================================================================================
// LEVIER 3 — Loki-query (LogQL) : STUB + couture de config. Conception dans docs/DATASOURCE.md.
// ================================================================================================

/// Couture de config : `PLUME_LOKI_QUERY=1` activera (à terme) la surface de lecture LogQL. DÉFAUT off.
fn loki_query_enabled() -> bool {
    std::env::var("PLUME_LOKI_QUERY").ok().map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// GET/POST /loki/api/v1/query_range — STUB HONNÊTE (501). La lecture LogQL réutilisera le MÊME chemin masqué
/// (soql_to_sql_masked_x sur `event`) ; conception + mapping LogQL->GXQL décrits dans docs/DATASOURCE.md.
pub(crate) async fn loki_query_range(Extension(_au): Extension<AuthUser>) -> Response {
    let msg = if loki_query_enabled() {
        "lecture LogQL non encore implémentée (conception : docs/DATASOURCE.md ; réutilisera le chemin masqué event)"
    } else {
        "lecture LogQL désactivée (couture PLUME_LOKI_QUERY ; non implémentée — voir docs/DATASOURCE.md)"
    };
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "status": "error", "errorType": "not_implemented", "error": msg }))).into_response()
}
