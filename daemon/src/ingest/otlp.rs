//! OTLP — récepteur d'ingest OpenTelemetry TRACES (#41, bring-your-own-observability, vendor-agnostic).
//!
//! OBJECTIF (sur-ensemble / souverain) : n'IMPORTE quel SDK OpenTelemetry ou OTel Collector existant peut
//! exporter ses traces distribuées vers plume SANS nouvel agent, via le protocole STANDARD OTLP/HTTP
//! (`POST /v1/traces`). Chaque `span` est mappé à une ligne CIM (`category=trace`) et ingéré par le MÊME
//! chemin que tout autre event (`ingest_events_batch` via le spool) -> masquage (#45), rollups et détection
//! s'appliquent UNIFORMÉMENT. Les spans deviennent donc requêtables en GXQL (`search category=trace ...`)
//! et CORRÉLABLES aux logs par `trace_id` (un log qui porte le même `trace_id` joint le même trace).
//!
//! INERTE PAR DÉFAUT (mode 0 byte-identique) : le récepteur est OFF tant que `PLUME_OTLP_TRACES=1` n'est
//! pas posé -> le handler renvoie 404 (surface absente). Aucune requête existante n'est touchée (route neuve).
//!
//! AUTH : `/v1/traces` est un chemin d'INGEST authentifié (agent_bearer_path + route_min_role=Ingest) —
//! `Authorization: Bearer <token>` résout une identité `agent` host-bound, ingest-only (JAMAIS UI/admin).
//! AUCUNE surface d'ingest non-authentifiée n'est ajoutée.
//!
//! DÉCODEUR = NOUVELLE SURFACE D'ATTAQUE : bornes DoS dures (cf. consts OTLP_MAX_*) — nombre de spans/req,
//! attributs/span, profondeur de valeur, et cap de DÉCOMPRESSION gzip (anti-bombe) AVANT toute allocation.
//! JSON malformé -> 400 sans panic. Les attributs de span traversent le MÊME chemin CIM->event->GXQL masqué
//! que tout champ ingéré (jamais de SQL construit à partir de la donnée de span).
//!
//! PORTÉE : OTLP/HTTP signal `traces`, encodage JSON (+ gzip). gRPC (OTLP/gRPC) et les signaux metrics/logs
//! OTLP sont DIFFÉRÉS (cf. docs/OTLP-TRACES.md). Le protobuf binaire OTLP est différé (JSON couvre les SDK/
//! collectors qui savent parler OTLP/JSON ; évite une dépendance protobuf lourde).
use crate::*;

/// Le récepteur OTLP traces est-il activé ? OFF par défaut (`PLUME_OTLP_TRACES` != "1") -> handler 404,
/// mode 0 byte-identique. Lu par requête (pas un chemin chaud ; comme `hec_sourcetype_overrides`).
pub(crate) fn otlp_traces_enabled() -> bool {
    std::env::var("PLUME_OTLP_TRACES").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Plafond DUR de spans matérialisés PAR requête (garde-fou anti-OOM). Bien au-delà d'un batch OTLP légitime
/// (borné de fait par la limite de corps 8 Mio + le cap de décompression). Au-delà -> 413 (batch pathologique
/// refusé, jamais une troncature muette). Combiné avec `ingest_max_events` (le plus petit gagne).
const OTLP_MAX_SPANS: usize = 50_000;
/// Plafond d'attributs FLATTENÉS retenus par span (resource + scope + span). Au-delà -> ignorés (borne le
/// travail par span ; un span légitime en a une poignée). Anti-cardinalité (explosion de clés attaquant).
const OTLP_MAX_ATTRS_PER_SPAN: usize = 256;
/// Profondeur MAX de conversion d'une `AnyValue` (array/kvlist imbriqués). Au-delà -> Null (borne la
/// récursion sur une valeur d'attribut construite par l'attaquant ; serde_json borne déjà le PARSE à 128).
const OTLP_MAX_VALUE_DEPTH: usize = 6;

/// Cap de DÉCOMPRESSION gzip SPÉCIFIQUE au chemin OTLP (défaut 16 Mio), volontairement PLUS PETIT que le
/// cap d'ingest PARTAGÉ `INGEST_MAX_DECOMPRESS` (64 Mio, metrics/loki). RAISON (anti-DoS) : OTLP/JSON
/// n'a AUCUN decode protobuf structuré pour amortir le coût — `serde_json::from_slice` MATÉRIALISE l'arbre
/// `Value` ENTIER (plusieurs× la taille texte en heap) AVANT que les caps span/attr/depth ne s'appliquent.
/// Un corps gzip ≤8 Mio (DefaultBodyLimit) NON-OTLP (ex. array plat géant) pouvait gonfler jusqu'à 64 Mio
/// puis exploser le heap du pod 2 Gio. On borne donc le gonflement OTLP plus tôt. Env-override (>=1 octet) :
/// `PLUME_OTLP_MAX_DECOMPRESS`. Ne touche PAS le cap 64 Mio de metrics/loki (decode protobuf borné, hors scope).
const OTLP_MAX_DECOMPRESS_DEFAULT: usize = 16 * 1024 * 1024;

/// Cap de décompression OTLP effectif (const par défaut, env `PLUME_OTLP_MAX_DECOMPRESS` si valide et >0).
pub(crate) fn otlp_max_decompress() -> usize {
    std::env::var("PLUME_OTLP_MAX_DECOMPRESS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(OTLP_MAX_DECOMPRESS_DEFAULT)
}

/// LAYER 2 (défense en profondeur, PAS l'unique garde) — vérif de FORME O(scan) AVANT le parse complet.
/// Un `ExportTraceServiceRequest` OTLP/JSON valide (1) commence par `{` (après whitespace) et (2) contient
/// la clé `"resourceSpans"` (SEULE clé de premier niveau de la requête -> présente dès le début). Un corps
/// qui échoue ces deux tests (array plat `[0,0,..]`, objet `{"x":[...]}` sans resourceSpans, scalaire) est
/// REJETÉ 400 pour un coût quasi nul, AVANT que `serde_json::from_slice` n'alloue l'arbre `Value` complet —
/// ce qui tue le vecteur "JSON non-OTLP qui gonfle jusqu'au cap". Le scan est borné (buffer déjà ≤ cap OTLP).
pub(crate) fn otlp_looks_like_traces(raw: &[u8]) -> bool {
    // (1) premier octet NON-blanc doit être `{` (une requête OTLP est un objet JSON).
    match raw.iter().copied().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') => {}
        _ => return false,
    }
    // (2) la clé `"resourceSpans"` doit apparaître dans le buffer (scan borné par le cap OTLP en amont).
    const NEEDLE: &[u8] = b"\"resourceSpans\"";
    raw.len() >= NEEDLE.len() && raw.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

/// Convertit une OTLP `AnyValue` (`{stringValue|boolValue|intValue|doubleValue|arrayValue|kvlistValue|
/// bytesValue}`) en `serde_json::Value` SCALAIRE/structuré, profondeur BORNÉE. `intValue` arrive en STRING
/// (mapping proto3-JSON de int64) -> reparsé en nombre si possible. Inconnu/au-delà de la profondeur -> Null.
pub(crate) fn otlp_any_value(v: &Value, depth: usize) -> Value {
    if depth == 0 {
        return Value::Null;
    }
    let obj = match v.as_object() {
        Some(o) => o,
        None => return Value::Null,
    };
    if let Some(s) = obj.get("stringValue").and_then(|x| x.as_str()) {
        return Value::String(s.to_string());
    }
    if let Some(b) = obj.get("boolValue").and_then(|x| x.as_bool()) {
        return Value::Bool(b);
    }
    if let Some(iv) = obj.get("intValue") {
        // proto3-JSON : int64 -> string ("200") ; certains émetteurs mettent un nombre. Les deux tolérés.
        if let Some(s) = iv.as_str() {
            if let Ok(n) = s.parse::<i64>() {
                return Value::Number(n.into());
            }
            return Value::String(s.to_string());
        }
        if iv.is_number() {
            return iv.clone();
        }
    }
    if let Some(d) = obj.get("doubleValue") {
        if let Some(f) = d.as_f64() {
            if f.is_finite() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    return Value::Number(n);
                }
            }
        }
    }
    if let Some(bytes) = obj.get("bytesValue").and_then(|x| x.as_str()) {
        // bytes -> base64 déjà (proto3-JSON) : on garde la string telle quelle (opaque, bornée).
        return Value::String(bytes.to_string());
    }
    if let Some(arr) = obj.get("arrayValue").and_then(|a| a.get("values")).and_then(|x| x.as_array()) {
        let out: Vec<Value> = arr.iter().map(|e| otlp_any_value(e, depth - 1)).collect();
        return Value::Array(out);
    }
    if let Some(kv) = obj.get("kvlistValue").and_then(|a| a.get("values")).and_then(|x| x.as_array()) {
        let mut m = serde_json::Map::new();
        for pair in kv {
            if let Some(k) = pair.get("key").and_then(|x| x.as_str()) {
                m.insert(k.to_string(), otlp_any_value(pair.get("value").unwrap_or(&Value::Null), depth - 1));
            }
        }
        return Value::Object(m);
    }
    Value::Null
}

/// Aplati une liste OTLP `KeyValue[]` (`[{key,value:AnyValue}]`) dans `into`, préfixe `prefix` sur la clé
/// (ex. `otel.` pour les attributs resource/scope). BORNE : s'arrête à `OTLP_MAX_ATTRS_PER_SPAN` clés au
/// total dans `into` (anti-cardinalité). `or_insert` : ne réécrit pas une clé déjà posée (précédence stable).
pub(crate) fn otlp_flatten_attrs(attrs: &Value, prefix: &str, into: &mut serde_json::Map<String, Value>) {
    let list = match attrs.as_array() {
        Some(l) => l,
        None => return,
    };
    for kv in list {
        if into.len() >= OTLP_MAX_ATTRS_PER_SPAN {
            break;
        }
        let key = match kv.get("key").and_then(|x| x.as_str()) {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };
        let val = otlp_any_value(kv.get("value").unwrap_or(&Value::Null), OTLP_MAX_VALUE_DEPTH);
        if val.is_null() {
            continue;
        }
        into.entry(format!("{prefix}{key}")).or_insert(val);
    }
}

/// `span.kind` (numérique 0..5 OU string `SPAN_KIND_SERVER`) -> verbe NEUTRE. Inconnu -> "unspecified".
pub(crate) fn otlp_span_kind(v: Option<&Value>) -> &'static str {
    match v {
        Some(Value::Number(n)) => match n.as_i64().unwrap_or(0) {
            1 => "internal",
            2 => "server",
            3 => "client",
            4 => "producer",
            5 => "consumer",
            _ => "unspecified",
        },
        Some(Value::String(s)) => match s.as_str() {
            "SPAN_KIND_INTERNAL" => "internal",
            "SPAN_KIND_SERVER" => "server",
            "SPAN_KIND_CLIENT" => "client",
            "SPAN_KIND_PRODUCER" => "producer",
            "SPAN_KIND_CONSUMER" => "consumer",
            _ => "unspecified",
        },
        _ => "unspecified",
    }
}

/// `span.status` (`{code, message}`) -> (status NEUTRE `ok|error|unset`, sévérité CIM, message optionnel).
/// code : 0/UNSET, 1/OK, 2/ERROR (numérique ou string proto). Un status ERROR mappe severity=3 (error CIM) —
/// ENRICH candidat (le collecteur ne fournit pas de severity ici) ; sinon 0 (info). Jamais un drop.
pub(crate) fn otlp_status(status: Option<&Value>) -> (&'static str, i64, Option<String>) {
    let msg = status
        .and_then(|s| s.get("message"))
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let code = status.and_then(|s| s.get("code"));
    let (label, sev) = match code {
        Some(Value::Number(n)) => match n.as_i64().unwrap_or(0) {
            1 => ("ok", 0),
            2 => ("error", 3),
            _ => ("unset", 0),
        },
        Some(Value::String(s)) => match s.as_str() {
            "STATUS_CODE_OK" => ("ok", 0),
            "STATUS_CODE_ERROR" => ("error", 3),
            _ => ("unset", 0),
        },
        _ => ("unset", 0),
    };
    (label, sev, msg)
}

/// Normalise un identifiant OTLP (traceId/spanId) en HEX minuscule. OTLP/JSON encode ces `bytes` en HEX
/// (exception spec) ; par robustesse, si l'entrée n'est pas de l'hex pur on tente un décodage base64 ->
/// hex. Vide/tout-zéro/invalide -> None (un parentSpanId absent est un span racine — légitime).
pub(crate) fn otlp_id_hex(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    let is_hex = s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit());
    let hex = if is_hex {
        s.to_ascii_lowercase()
    } else {
        // repli base64 (standard) -> hex.
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(s) {
            Ok(bytes) if !bytes.is_empty() => bytes.iter().map(|b| format!("{b:02x}")).collect(),
            _ => return None,
        }
    };
    // rejette l'identifiant tout-zéro (OTLP : trace/span id nul = invalide).
    if hex.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(hex)
}

/// `*UnixNano` (string proto3-JSON d'un uint64, ou nombre) -> nanos bruts (i128). None si absent/invalide.
pub(crate) fn otlp_nano_i128(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::String(s) => s.trim().parse::<i128>().ok(),
        Value::Number(n) => n.as_i64().map(|x| x as i128),
        _ => None,
    }
}

/// `*UnixNano` -> epoch SECONDES (i64). None si absent/invalide/<=0.
pub(crate) fn otlp_nano_to_secs(v: Option<&Value>) -> Option<i64> {
    let nanos = otlp_nano_i128(v)?;
    if nanos <= 0 {
        return None;
    }
    Some((nanos / 1_000_000_000) as i64)
}

/// Un span OTLP + les attributs resource/scope déjà aplatis -> event Plume (`{ts,source,category,severity,
/// message,host,dedup,fields}`) consommable par `ingest_events_batch` (schéma d'ingest EXISTANT). Category
/// FIXE = `trace`. `source` dérivée de `service.name` (namespace `plume-*` réservé par `ext_ingest_source`
/// à l'ingest). `host` = attribut resource `host.name`/`k8s.node.name`/… si présent. `dedup` = `otel-<trace>-
/// <span>` (idempotent : un ré-export du même span ne duplique pas). `message` = nom du span (opération).
/// None si le span n'a ni traceId ni spanId (inexploitable — jamais une ligne vide).
pub(crate) fn otlp_span_to_event(
    span: &Value,
    resource_attrs: &serde_json::Map<String, Value>,
    service: Option<&str>,
    scope_name: Option<&str>,
    scope_version: Option<&str>,
) -> Option<Value> {
    let trace_id = otlp_id_hex(span.get("traceId"))?;
    let span_id = otlp_id_hex(span.get("spanId"))?;
    let name = span.get("name").and_then(|x| x.as_str()).unwrap_or("");
    let kind = otlp_span_kind(span.get("kind"));
    let (status, sev, status_msg) = otlp_status(span.get("status"));
    let start_s = otlp_nano_to_secs(span.get("startTimeUnixNano"));

    // fields : d'abord les attributs resource (partagés, précédence la plus basse), puis scope, puis span
    // (les plus spécifiques gagnent via or_insert appliqué dans l'ordre inverse ci-dessous).
    let mut fields = serde_json::Map::new();
    // attributs du SPAN (précédence haute) en premier -> or_insert protège des clés resource homonymes.
    otlp_flatten_attrs(span.get("attributes").unwrap_or(&Value::Null), "otel.", &mut fields);
    // puis resource (déjà aplatis) sans écraser.
    for (k, v) in resource_attrs {
        if fields.len() >= OTLP_MAX_ATTRS_PER_SPAN {
            break;
        }
        fields.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Champs de trace de PREMIÈRE CLASSE (searchable/corrélables) — posés APRÈS pour être autoritatifs.
    fields.insert("trace_id".to_string(), json!(trace_id));
    fields.insert("span_id".to_string(), json!(span_id));
    if let Some(psid) = otlp_id_hex(span.get("parentSpanId")) {
        fields.insert("parent_span_id".to_string(), json!(psid));
    }
    if !name.is_empty() {
        fields.insert("span_name".to_string(), json!(name));
    }
    fields.insert("span_kind".to_string(), json!(kind));
    fields.insert("trace_status".to_string(), json!(status));
    if let Some(m) = &status_msg {
        fields.insert("status_message".to_string(), json!(m));
    }
    if let Some(svc) = service.filter(|s| !s.is_empty()) {
        fields.insert("service".to_string(), json!(svc));
    }
    if let Some(sn) = scope_name.filter(|s| !s.is_empty()) {
        fields.insert("scope_name".to_string(), json!(sn));
    }
    if let Some(sv) = scope_version.filter(|s| !s.is_empty()) {
        fields.insert("scope_version".to_string(), json!(sv));
    }
    // durée en millisecondes (dérivée des bornes nano brutes) -> métrique de latence requêtable.
    if let (Some(s), Some(e)) = (otlp_nano_i128(span.get("startTimeUnixNano")), otlp_nano_i128(span.get("endTimeUnixNano"))) {
        let dur_ms = ((e - s).max(0)) as f64 / 1_000_000.0;
        if let Some(n) = serde_json::Number::from_f64(dur_ms) {
            fields.insert("duration_ms".to_string(), Value::Number(n));
        }
    }

    // host : attribut resource d'infrastructure si présent (autoritatif = resource, pas forgé par span).
    // Les clés resource sont aplaties AVEC le préfixe `otel.` (cf. otlp_flatten_attrs) -> on cherche prefixé.
    let host = ["otel.host.name", "otel.k8s.node.name", "otel.host.id", "otel.container.name"]
        .iter()
        .find_map(|k| resource_attrs.get(*k).and_then(|v| v.as_str()).map(|s| s.to_string()));

    let source = ext_ingest_source(service.filter(|s| !s.is_empty()).unwrap_or("otlp"));

    let mut ev = serde_json::Map::new();
    if let Some(ts) = start_s {
        ev.insert("ts".to_string(), json!(ts));
    }
    ev.insert("source".to_string(), json!(source));
    ev.insert("category".to_string(), json!("trace"));
    if sev != 0 {
        ev.insert("severity".to_string(), json!(sev));
    }
    ev.insert("message".to_string(), json!(name));
    if let Some(h) = host {
        ev.insert("host".to_string(), json!(h));
    }
    ev.insert("dedup".to_string(), json!(format!("otel-{trace_id}-{span_id}")));
    ev.insert("fields".to_string(), Value::Object(fields));
    Some(Value::Object(ev))
}

/// Parse un `ExportTraceServiceRequest` OTLP/JSON -> Vec d'events CIM. Itère `resourceSpans[] ->
/// scopeSpans[] -> spans[]`, aplatit les attributs resource UNE fois par resource (partagés). BORNE DURE :
/// s'arrête à `max_spans` (renvoie `Err(nombre_atteint)` -> l'appelant renvoie 413). Best-effort : un span
/// inexploitable (sans id) est ignoré, pas un échec global.
pub(crate) fn otlp_request_to_events(root: &Value, max_spans: usize) -> Result<Vec<Value>, usize> {
    let mut out: Vec<Value> = Vec::new();
    let resource_spans = root.get("resourceSpans").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
    for rs in resource_spans {
        // attributs resource aplatis une seule fois (partagés par tous les spans de ce resource).
        let mut resource_attrs = serde_json::Map::new();
        let resource = rs.get("resource");
        if let Some(res) = resource {
            otlp_flatten_attrs(res.get("attributes").unwrap_or(&Value::Null), "otel.", &mut resource_attrs);
        }
        // service.name : clé de routage `source`. OTLP l'expose comme attribut resource `service.name`.
        let service = resource_attrs.get("otel.service.name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let scope_spans = rs.get("scopeSpans").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
        for ss in scope_spans {
            let scope_name = ss.get("scope").and_then(|s| s.get("name")).and_then(|x| x.as_str()).map(|s| s.to_string());
            let scope_version = ss.get("scope").and_then(|s| s.get("version")).and_then(|x| x.as_str()).map(|s| s.to_string());
            let spans = ss.get("spans").and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
            for span in spans {
                if out.len() >= max_spans {
                    return Err(out.len());
                }
                if let Some(ev) = otlp_span_to_event(
                    span,
                    &resource_attrs,
                    service.as_deref(),
                    scope_name.as_deref(),
                    scope_version.as_deref(),
                ) {
                    out.push(ev);
                }
            }
        }
    }
    Ok(out)
}

/// Décompresse un corps gzip en BORNANT la taille de sortie (anti-bombe : un corps ≤8 Mio peut se
/// décompresser en centaines de Mio -> OOM du pod 2 Gio). Lit par tranches jusqu'au cap ; au-delà -> Err.
/// Corps NON-gzip -> renvoyé tel quel. `flate2` est DÉJÀ dans l'arbre (transitif via tower-http) : aucune
/// crate compilée nouvelle.
pub(crate) fn otlp_gunzip_capped(body: &[u8], cap: usize) -> Result<Vec<u8>, ()> {
    use std::io::Read;
    let mut dec = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    // +1 pour DÉTECTER le dépassement (on lit cap+1 et on refuse si on atteint cap+1).
    let mut buf = [0u8; 64 * 1024];
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > cap {
                    return Err(());
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(_) => return Err(()),
        }
    }
    Ok(out)
}

/// Réponse OTLP/HTTP de SUCCÈS : `ExportTraceServiceResponse` (corps `{}` = zéro rejet ; ou `partialSuccess`
/// si des spans ont été refusés). Les clients OTLP acceptent le 200 + JSON.
fn otlp_ok(rejected: i64) -> Response {
    let body = if rejected > 0 {
        json!({ "partialSuccess": { "rejectedSpans": rejected, "errorMessage": "spans over per-request cap were rejected" } })
    } else {
        json!({})
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// POST /v1/traces — récepteur OTLP/HTTP TRACES (JSON, + gzip). Auth (Bearer -> agent host-bound) déjà
/// appliquée par auth_guard (agent_bearer_path + route_min_role=Ingest). INERTE si `PLUME_OTLP_TRACES` != 1
/// (404). Parse -> mappe chaque span vers un event CIM `category=trace` -> écrit l'enveloppe `{kind:events}`
/// dans le spool (atomique, RÉUTILISE `ingest_events_batch` via la boucle de fond) -> masquage/rollups/
/// détection UNIFORMES. PAS de host-marker : un collector OTel relaie LÉGITIMEMENT plusieurs services/hôtes
/// (host autoritatif = attribut resource par span). NE fait AUCUN travail DB sur le worker tokio.
pub(crate) async fn otlp_traces_post(
    State(st): State<AppState>,
    Extension(au): Extension<AuthUser>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // INERTE par défaut : endpoint absent tant que non activé (mode 0). 404 = comme si la route n'existait pas.
    if !otlp_traces_enabled() {
        return (StatusCode::NOT_FOUND, "OTLP traces receiver disabled (set PLUME_OTLP_TRACES=1)").into_response();
    }
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }
    // L1 — GARDE DISQUE : 503 explicite en pré-saturation (le client OTLP rejoue). Avant toute allocation.
    if ingest_disk_guard(&st).is_some() {
        return (StatusCode::SERVICE_UNAVAILABLE, "server busy (disk pressure)").into_response();
    }
    // LAYER 3 — BORNE DE CONCURRENCE : on prend un permit d'ingest décompression-lourde AVANT la
    // décompression + le parse, et on le TIENT jusqu'à la fin (décompress, arbre Value, Vec d'events). Ainsi
    // N requêtes OTLP concurrentes ne matérialisent JAMAIS plus de `ingest_sem` arbres Value simultanément ->
    // le pic mémoire par-requête (≤ un arbre issu d'un corps OTLP_MAX_DECOMPRESS) ne se MULTIPLIE pas. Saturé
    // -> 503 (le client OTLP rejoue) plutôt qu'une file d'attente non bornée qui accumulerait des corps.
    let _ingest_permit = match st.ingest_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "server busy (ingest concurrency)").into_response(),
    };
    // gzip (Content-Encoding: gzip) avec cap de décompression (anti-bombe) AVANT le parse. LAYER 1 — cap
    // OTLP-spécifique (16 Mio défaut) PLUS PETIT que le cap partagé metrics/loki : OTLP/JSON n'amortit pas
    // le coût par un decode protobuf structuré (l'arbre Value est matérialisé entier avant les caps span).
    let ce = headers.get(axum::http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let raw: Vec<u8> = if ce.contains("gzip") {
        match otlp_gunzip_capped(body.as_ref(), otlp_max_decompress()) {
            Ok(r) => r,
            Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "decompressed body too large").into_response(),
        }
    } else {
        // corps non-gzip : borné par DefaultBodyLimit (8 Mio) < cap OTLP, mais on applique le cap par cohérence.
        if body.len() > otlp_max_decompress() {
            return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
        }
        body.to_vec()
    };
    // OTLP/protobuf binaire différé : on ne sert QUE JSON. Un Content-Type protobuf -> 415 explicite.
    let ct = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if ct.contains("x-protobuf") || ct.contains("protobuf") {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "OTLP protobuf not supported — use OTLP/JSON (application/json)").into_response();
    }
    // LAYER 2 — VÉRIF DE FORME O(scan) AVANT le parse coûteux : rejette 400 tout corps qui ne ressemble pas
    // structurellement à une requête OTLP traces (pas d'objet racine, ou pas de clé `"resourceSpans"`). Tue
    // le vecteur "JSON non-OTLP valide qui gonfle jusqu'au cap" (array plat, objet arbitraire) pour ~0 coût,
    // AVANT que serde_json n'alloue l'arbre Value entier. Défense en profondeur (pas l'unique garde).
    if !otlp_looks_like_traces(&raw) {
        return (StatusCode::BAD_REQUEST, "not an OTLP trace payload (missing resourceSpans)").into_response();
    }
    // Parse JSON SANS panic -> 400 sur corps malformé (surface d'attaque du décodeur).
    let root: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid OTLP JSON: {e}")).into_response(),
    };
    let cap = OTLP_MAX_SPANS.min(st.ingest_max_events);
    let events = match otlp_request_to_events(&root, cap) {
        Ok(ev) => ev,
        // PLAFOND DUR de cardinalité : refus 413 (le client scinde et réémet) — jamais de troncature muette.
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "too many spans in one request — split and resend").into_response(),
    };
    if events.is_empty() {
        // rien d'exploitable (aucun span valide) -> succès OTLP vide (le client ne rejoue pas inutilement).
        return otlp_ok(0);
    }
    let env = json!({ "ts": now(), "host": host_self(), "kind": "events", "events": events });
    let body_out = match serde_json::to_string(&env) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "serialize failed").into_response(),
    };
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker(&st, &au); // R8 : tenant du token encodé dans le nom -> routé à la relecture
    // P5.2-a : ce chemin n'avait pas de marqueur d'hôte au motif qu'« un collector OTel relaie plusieurs
    // services/hôtes ». Vrai d'un RELAIS, faux d'une MACHINE. `spool_host_marker` n'émet QUE pour un jeton
    // LIÉ : un collector (jeton non lié) garde le comportement d'avant — l'attribut resource `host.name`
    // reste autoritatif. La distinction est le liage du jeton, plus une décision par route.
    let hk = spool_host_marker(&au);
    let tmp = format!("{}/.otlp-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/otlp-{}-{}{}{}.json", st.spool, now(), n, mk, hk);
    if std::fs::write(&tmp, body_out.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return (StatusCode::INTERNAL_SERVER_ERROR, "spool write failed").into_response();
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return (StatusCode::INTERNAL_SERVER_ERROR, "spool publish failed").into_response();
    }
    otlp_ok(0)
}
