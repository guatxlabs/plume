//! Récepteurs OBS (data-plane) : ingestion métriques Prometheus (format d'exposition + remote_write
//! protobuf/snappy) et logs Loki push (JSON + protobuf/snappy Alloy). Structs prost (`PromWrite`/
//! `LokiPush`…), parsing (`parse_prom`/`loki_labels`), handlers (`metrics_prom`/`metrics_write`/
//! `loki_push`) et garde-fous DoS (`ingest_decompress_capped`, caps INGEST_MAX_*). Statics/consts
//! avec accesseurs. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- OBS-1 : ingestion métriques au format d'exposition Prometheus ----------
// Parse les labels `k="v",k2="v2"` (guillemets respectés, déséchappement) -> JSON.
fn prom_labels_json(inner: &str) -> String {
    let b = inner.as_bytes();
    let mut map = serde_json::Map::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b',') { i += 1; }
        let ks = i;
        while i < b.len() && b[i] != b'=' { i += 1; }
        if i >= b.len() { break; }
        let key = inner[ks..i].trim().to_string();
        i += 1;
        if i >= b.len() || b[i] != b'"' { break; }
        i += 1;
        let mut val = String::new();
        while i < b.len() && b[i] != b'"' {
            if b[i] == b'\\' && i + 1 < b.len() {
                i += 1;
                val.push(match b[i] { b'n' => '\n', b'"' => '"', b'\\' => '\\', o => o as char });
            } else {
                val.push(b[i] as char);
            }
            i += 1;
        }
        i += 1;
        if !key.is_empty() { map.insert(key, Value::String(val)); }
    }
    Value::Object(map).to_string()
}
// (name, labels_json, value) pour chaque ligne valide (ignore #HELP/#TYPE, NaN/Inf, noms invalides).
fn parse_prom(body: &str) -> Vec<(String, String, f64)> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (series, rest) = if let Some(close) = line.rfind('}') {
            (&line[..=close], line[close + 1..].trim())
        } else if let Some(sp) = line.find(char::is_whitespace) {
            (&line[..sp], line[sp..].trim())
        } else { continue };
        let value: f64 = match rest.split_whitespace().next().and_then(|t| t.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        if !value.is_finite() { continue; }
        let (name, labels) = match series.find('{') {
            Some(p) => (series[..p].trim().to_string(), prom_labels_json(&series[p + 1..series.len() - 1])),
            None => (series.trim().to_string(), "{}".to_string()),
        };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':') {
            continue;
        }
        out.push((name, labels, value));
    }
    out
}
// POST /api/metrics/prom (text/plain) : ingère un scrape Prometheus dans la table metric.
pub(crate) async fn metrics_prom(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>, body: String) -> Response {
    let series = parse_prom(&body);
    if series.is_empty() {
        return bad_req("aucune métrique Prometheus valide");
    }
    let ts = q.get("ts").and_then(|s| s.parse::<i64>().ok()).filter(|t| *t > 0).unwrap_or_else(now); // ?ts= : backfill/import
    let host = q.get("host").cloned();
    let n = series.len();
    with_write(&st, &au, |conn| {
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    {
        if let Ok(mut stmt) = conn.prepare(store().metric_insert_sql()) {
            for (name, labels, value) in &series {
                let _ = stmt.execute(params![ts, name, labels, value, host]);
            }
        }
    }
    let _ = conn.execute_batch("COMMIT");
    Json(json!({ "ingested": n })).into_response()
    })
}

// GARDE-FOUS DoS des récepteurs remote_write / loki push :
//  - INGEST_MAX_DECOMPRESS : plafond de la taille DÉCOMPRESSÉE (anti-bombe snappy : un corps ≤8 Mio — cf.
//    DefaultBodyLimit — pouvait se décompresser en centaines de Mio -> OOM du pod 2 Gio). Au-delà -> 413.
//  - INGEST_MAX_SAMPLES / INGEST_MAX_ENTRIES : plafond du nombre de samples/entrées matérialisés PAR requête.
//    Volontairement TRÈS haut (bien au-delà d'un batch Alloy/Prometheus légitime, borné de fait par le cap de
//    décompression) -> ne tronque JAMAIS la collecte légitime ; ne coupe qu'un payload pathologique (413).
pub(crate) const INGEST_MAX_DECOMPRESS: usize = 64 * 1024 * 1024; // 64 Mio décompressés max
const INGEST_MAX_SAMPLES: usize = 500_000;             // remote_write : lignes metric/req
const INGEST_MAX_ENTRIES: usize = 200_000;             // loki push : lignes event/req

/// Décompresse un corps snappy en BORNANT la taille de sortie (anti-amplification). Renvoie Err si la taille
/// décompressée annoncée dépasse le cap. Corps NON-snappy (decompress_len échoue) -> renvoyé tel quel (déjà
/// borné par DefaultBodyLimit). MIROIR EXACT du décodage historique (`decompress_vec(...).unwrap_or(body)`),
/// avec seulement le plafond ajouté en amont.
pub(crate) fn ingest_decompress_capped(body: &[u8]) -> Result<Vec<u8>, ()> {
    match snap::raw::decompress_len(body) {
        Ok(len) if len > INGEST_MAX_DECOMPRESS => Err(()),
        Ok(_) => Ok(snap::raw::Decoder::new().decompress_vec(body).unwrap_or_else(|_| body.to_vec())),
        Err(_) => Ok(body.to_vec()), // pas du snappy -> corps brut (borné par la limite de corps HTTP)
    }
}

// ---------- OBS (métriques) : récepteur protocole remote_write (Alloy/Prometheus/Mimir...) ----------
// Endpoint neutre /api/metrics/write : protobuf+snappy (WriteRequest). __name__ = nom de la métrique.
#[derive(prost::Message)]
struct PromWrite {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<PromTs>,
}
#[derive(prost::Message)]
struct PromTs {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<PromLabel>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<PromSample>,
}
#[derive(prost::Message)]
struct PromLabel {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}
#[derive(prost::Message)]
struct PromSample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}
pub(crate) async fn metrics_write(State(st): State<AppState>, Extension(au): Extension<AuthUser>, body: axum::body::Bytes) -> Response {
    use prost::Message;
    // M5 : cap de décompression (anti-bombe snappy) AVANT toute allocation.
    let raw = match ingest_decompress_capped(body.as_ref()) {
        Ok(r) => r,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "corps décompressé trop volumineux").into_response(),
    };
    let wr = match PromWrite::decode(raw.as_slice()) {
        Ok(w) => w,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("remote_write invalide: {e}")).into_response(),
    };
    // M5 : labels partagés via Arc<str> -> plus de clone O(labels)×O(samples) (le vrai moteur d'OOM) ; chaque
    // sample ne bump qu'un refcount. name aussi partagé (Arc) pour la même raison.
    let mut rows: Vec<(i64, Arc<str>, Arc<str>, Option<Arc<str>>, f64)> = Vec::new();
    for ts in &wr.timeseries {
        let mut name = String::new();
        let mut host: Option<String> = None;
        let mut map = serde_json::Map::new();
        for l in &ts.labels {
            match l.name.as_str() {
                "__name__" => name = l.value.clone(),
                "instance" | "host" | "node" | "nodename" if host.is_none() => {
                    host = Some(l.value.clone());
                    map.insert(l.name.clone(), Value::String(l.value.clone()));
                }
                _ => {
                    map.insert(l.name.clone(), Value::String(l.value.clone()));
                }
            }
        }
        if name.is_empty() {
            continue;
        }
        let name: Arc<str> = Arc::from(name.as_str());
        let labels: Arc<str> = Arc::from(Value::Object(map).to_string().as_str());
        let host: Option<Arc<str>> = host.map(|h| Arc::from(h.as_str()));
        for s in &ts.samples {
            if s.value.is_finite() {
                // M5 : plafond dur du nombre de samples matérialisés (garde-fou ultime anti-OOM ; jamais atteint
                // par un batch légitime — cf. cap de décompression). Au-delà -> 413 (batch pathologique refusé).
                if rows.len() >= INGEST_MAX_SAMPLES {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "trop de samples dans une seule requête").into_response();
                }
                rows.push((s.timestamp / 1000, name.clone(), labels.clone(), host.clone(), s.value));
            }
        }
    }
    if rows.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    with_write(&st, &au, |conn| {
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    if let Ok(mut stmt) = conn.prepare(store().metric_insert_sql()) {
        for (ts, name, labels, host, value) in &rows {
            let _ = stmt.execute(params![ts, name.as_ref(), labels.as_ref(), value, host.as_deref()]);
        }
    }
    let _ = conn.execute_batch("COMMIT");
    StatusCode::NO_CONTENT.into_response()
    })
}

// ---------- OBS-3 : ingestion logs compatible Loki push (JSON ou protobuf+snappy d'Alloy) ----------
#[derive(prost::Message)]
struct LokiPush {
    #[prost(message, repeated, tag = "1")]
    streams: Vec<LokiStream>,
}
#[derive(prost::Message)]
struct LokiStream {
    #[prost(string, tag = "1")]
    labels: String, // string LogQL : {k="v",...}
    #[prost(message, repeated, tag = "2")]
    entries: Vec<LokiEntry>,
}
#[derive(prost::Message)]
struct LokiEntry {
    #[prost(message, optional, tag = "1")]
    timestamp: Option<PbTs>,
    #[prost(string, tag = "2")]
    line: String,
}
#[derive(prost::Message)]
struct PbTs {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}
fn loki_labels(s: &str) -> serde_json::Map<String, Value> {
    let inner = s.trim().trim_start_matches('{').trim_end_matches('}');
    match serde_json::from_str::<Value>(&prom_labels_json(inner)) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    }
}
/// Métadonnées CONSTANTES d'un stream Loki (identiques pour TOUTES ses entrées) : source normalisée (M1),
/// sévérité, host, et labels sérialisés UNE SEULE fois. Partagées via Arc -> M5 : élimine la re-sérialisation
/// `Value::Object(labels.clone()).to_string()` + le clone de la map à CHAQUE entrée (coût quadratique et
/// moteur d'OOM sur un gros stream). Chaque entrée ne bump plus qu'un refcount.
fn loki_stream_meta(labels: &serde_json::Map<String, Value>) -> (Arc<str>, i64, Option<Arc<str>>, Arc<str>) {
    let pick = |keys: &[&str]| keys.iter().find_map(|k| labels.get(*k).and_then(|v| v.as_str()).map(|s| s.to_string()));
    // M1 : la source dérivée des labels (job/service/…) est de la donnée agent -> namespace `plume-*` réservé.
    let source = ext_ingest_source(&pick(&["job", "service_name", "service", "unit", "container", "app", "filename"]).unwrap_or_else(|| "loki".into()));
    let host = pick(&["host", "hostname", "instance", "node", "nodename"]);
    let sev = pick(&["level", "severity", "detected_level"]).and_then(|l| sev_num(&l)).unwrap_or(0);
    let fields: Arc<str> = Arc::from(Value::Object(labels.clone()).to_string().as_str());
    (Arc::from(source.as_str()), sev, host.map(|h| Arc::from(h.as_str())), fields)
}
pub(crate) async fn loki_push(State(st): State<AppState>, Extension(au): Extension<AuthUser>, headers: axum::http::HeaderMap, body: axum::body::Bytes) -> Response {
    use prost::Message;
    let ce = headers.get(axum::http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let now_ts = now();
    // M2 : host LIÉ au token de l'agent (role='agent', name=host du token). Some -> ÉCRASE le host des labels
    // (loki_push insère en DIRECT, pas de spool) -> un agent ne peut pas usurper l'hôte d'un autre. Les
    // collecteurs centraux Basic (editor/admin) multiplexent légitimement plusieurs hôtes -> None -> inchangé.
    let bind_host: Option<String> = if au.role == "agent" && host_marker_ok(&au.name) { Some(au.name.clone()) } else { None };
    let mut rows: Vec<(i64, Arc<str>, i64, Option<Arc<str>>, String, Arc<str>)> = Vec::new();
    // M5 : garde-fou dur du nombre d'entrées matérialisées (jamais atteint par un push légitime).
    macro_rules! push_capped { ($row:expr) => {{
        if rows.len() >= INGEST_MAX_ENTRIES {
            return (StatusCode::PAYLOAD_TOO_LARGE, "trop d'entrées dans une seule requête").into_response();
        }
        rows.push($row);
    }}; }
    if ce.contains("snappy") || ct.contains("protobuf") {
        // M5 : cap de décompression (anti-bombe snappy) AVANT toute allocation.
        let raw = match ingest_decompress_capped(body.as_ref()) {
            Ok(r) => r,
            Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "corps décompressé trop volumineux").into_response(),
        };
        let push = match LokiPush::decode(raw.as_slice()) {
            Ok(p) => p,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("loki protobuf invalide: {e}")).into_response(),
        };
        for s in &push.streams {
            let labels = loki_labels(&s.labels);
            let (source, sev, host, fields) = loki_stream_meta(&labels);
            for e in &s.entries {
                let ts = e.timestamp.as_ref().map(|t| t.seconds).filter(|s| *s > 0).unwrap_or(now_ts);
                push_capped!((ts, source.clone(), sev, host.clone(), e.line.clone(), fields.clone()));
            }
        }
    } else {
        let v: Value = match serde_json::from_slice(body.as_ref()) {
            Ok(v) => v,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("loki json invalide: {e}")).into_response(),
        };
        for s in v.get("streams").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let labels = s.get("stream").and_then(|x| x.as_object()).cloned().unwrap_or_default();
            let (source, sev, host, fields) = loki_stream_meta(&labels);
            for val in s.get("values").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
                let arr = match val.as_array() {
                    Some(a) if a.len() >= 2 => a,
                    _ => continue,
                };
                let ts = arr[0].as_str().and_then(|s| s.parse::<i64>().ok()).map(|ns| ns / 1_000_000_000).unwrap_or(now_ts);
                push_capped!((ts, source.clone(), sev, host.clone(), arr[1].as_str().unwrap_or("").to_string(), fields.clone()));
            }
        }
    }
    if rows.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    crate::req_conn!(st, au, conn);
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    // NB : écriture data-plane SUR LE CHEMIN DIRECT (exception documentée dans l'en-tête STORE SPI,
    // non encore derrière `store().insert_event` — migration différée : 7 col vs 14 col `OR IGNORE`).
    if let Ok(mut stmt) = conn.prepare("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,?2,'log',?3,?4,?5,?6)") {
        for (ts, source, sev, host, line, fields) in &rows {
            // M2 : host lié à l'agent GAGNE sur le host des labels.
            let eff_host = bind_host.as_deref().or_else(|| host.as_deref());
            let _ = stmt.execute(params![ts, source.as_ref(), sev, eff_host, line, fields.as_ref()]);
        }
    }
    let _ = conn.execute_batch("COMMIT");
    StatusCode::NO_CONTENT.into_response()
}
