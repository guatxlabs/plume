//! Connecteur generique http_pull (bring-your-own-vendor) — split #35 de connectors.rs (byte-identique).
use crate::*;

// ================================================================================================
// #20/#22 — CONNECTEUR GÉNÉRIQUE `http_pull` (bring-your-own-vendor). N'IMPORTE QUELLE API REST/JSON
// devient une source d'events par CONFIG SEULE (zéro code par-vendeur). PRINCIPE (directive vendor-
// agnostic / sur-ensemble) : AUCUN vendeur codé en dur — CrowdStrike Falcon, SentinelOne, un REST maison
// s'expriment tous via la même `config_json`. ADDITIF : ajouté À CÔTÉ des arms `defender`/`taxii2`
// (intacts, live+testés). MÊMES INVARIANTS que Defender : `fetch` injectable (testable offline, aucun
// socket), 429/Retry-After respectés (watermark non régressé), le credential (colonne `secret`) ne fuit
// dans AUCUN message/erreur/log. INERTE tant qu'aucun connecteur http_pull n'est configuré (table vide).
//
// SÉCURITÉ EXTRACTION : le field-mapping s'appuie sur un SOUS-ENSEMBLE JSONPath SÛR (`json_extract_path`)
// — chemins pointés + index de tableau + `[*]` — PURE indexation clé/index, ZÉRO eval, injection-safe.
// INGEST : chemin d'ingestion EXISTANT (store().insert_event, INSERT OR IGNORE sur `dedup` -> idempotent,
// env_id par-connecteur porté) — IDENTIQUE à l'arm Defender. CIM : sourcetype -> category via le mapping
// existant `hec_category` (gate `cim_category_ok`), extensible par ENV `PLUME_HEC_SOURCETYPE_MAP` + un
// `sourcetype_map` inline dans la config (bring-your-own, sans rebuild ni ENV).
// ================================================================================================

/// Segment d'un JSONPath (sous-ensemble sûr) : clé d'objet, index de tableau, ou wildcard (`*`/`[*]`).
#[derive(Debug, Clone)]
enum JsonPathSeg {
    Key(String),
    Index(usize),
    Wild,
}

/// Parse un JSONPath du SOUS-ENSEMBLE SÛR : `a.b.c`, `a.0.b`, `a[0].b`, `items[*].name`, `a.*.b`. Découpe
/// sur `.` et gère les groupes `[...]`. Un segment tout-chiffres est un INDEX de tableau (dot-notation
/// courante). AUCUN opérateur d'expression / filtre / eval -> injection-safe (indexation pure).
fn parse_json_path(path: &str) -> Vec<JsonPathSeg> {
    let mut segs: Vec<JsonPathSeg> = Vec::new();
    let push_name = |segs: &mut Vec<JsonPathSeg>, name: &str| {
        if name == "*" {
            segs.push(JsonPathSeg::Wild);
        } else if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = name.parse::<usize>() { segs.push(JsonPathSeg::Index(n)); }
        } else if !name.is_empty() {
            segs.push(JsonPathSeg::Key(name.to_string()));
        }
    };
    for part in path.split('.') {
        if part.is_empty() { continue; }
        let mut name = String::new();
        let mut brk = String::new();
        let mut in_bracket = false;
        for ch in part.chars() {
            match ch {
                '[' => {
                    if !name.is_empty() { push_name(&mut segs, &name); name.clear(); }
                    in_bracket = true;
                    brk.clear();
                }
                ']' => {
                    if in_bracket {
                        if brk == "*" { segs.push(JsonPathSeg::Wild); }
                        else if let Ok(n) = brk.parse::<usize>() { segs.push(JsonPathSeg::Index(n)); }
                        in_bracket = false;
                    }
                }
                _ => { if in_bracket { brk.push(ch); } else { name.push(ch); } }
            }
        }
        if !name.is_empty() { push_name(&mut segs, &name); }
    }
    segs
}

/// TOUTES les valeurs atteignables par `path` (sous-ensemble sûr) depuis `root`. Chemin vide -> `[root]`.
/// `[*]`/`*` expanse tableaux (éléments) et objets (valeurs). Pure indexation (jamais d'eval).
pub(crate) fn json_extract_all<'a>(root: &'a Value, path: &str) -> Vec<&'a Value> {
    let segs = parse_json_path(path);
    let mut cur: Vec<&Value> = vec![root];
    for seg in &segs {
        let mut next: Vec<&Value> = Vec::new();
        for node in cur {
            match seg {
                JsonPathSeg::Key(k) => { if let Some(v) = node.get(k) { next.push(v); } }
                JsonPathSeg::Index(i) => { if let Some(v) = node.get(*i) { next.push(v); } }
                JsonPathSeg::Wild => match node {
                    Value::Array(a) => next.extend(a.iter()),
                    Value::Object(o) => next.extend(o.values()),
                    _ => {}
                },
            }
        }
        cur = next;
    }
    cur
}

/// PREMIÈRE valeur atteignable par `path` (helper `json_extract_path` demandé : chemin pointé + index +
/// `[*]`). None si le chemin ne résout rien (-> le champ est OMIS, jamais un drop de l'event).
pub(crate) fn json_extract_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    json_extract_all(root, path).into_iter().next()
}

/// Le TABLEAU d'enregistrements pointé par `records_path`. Si le chemin résout un unique tableau ->
/// ses éléments ; sinon les nœuds résolus (ex. `data.items[*]`). Chemin vide + racine tableau -> ses éléments.
pub(crate) fn httppull_records(root: &Value, records_path: &str) -> Vec<Value> {
    let nodes = json_extract_all(root, records_path);
    if nodes.len() == 1 {
        if let Value::Array(a) = nodes[0] { return a.clone(); }
    }
    nodes.into_iter().cloned().collect()
}

/// Auth d'un connecteur générique. Le credential est TOUJOURS dans la colonne `secret` (jamais la config).
/// `client_id`/`token_url`/`scope` (oauth2) sont des identifiants NON-secrets -> config (comme Defender).
struct HttpAuth {
    kind: String,        // none|basic|token|bearer|header|oauth2_client_credentials
    header_name: String, // header/token : nom d'en-tête (défaut Authorization)
    prefix: String,      // header/token : préfixe de valeur (ex. "ApiToken ")
    token_url: String,   // oauth2 : endpoint token (client-credentials)
    client_id: String,   // oauth2 : client_id (non-secret)
    scope: String,       // oauth2 : scope (optionnel)
}
/// Pagination d'un connecteur générique (5 formes couvrant les API REST courantes).
struct HttpPage {
    kind: String,        // none|offset|page|cursor|link_header
    param: String,       // nom du param portant offset/page/cursor
    size: i64,           // taille de page
    size_param: String,  // nom du param de taille (ex. limit/top/page_size)
    start: i64,          // offset/page de départ (défaut 0 offset, 1 page)
    cursor_path: String, // JSONPath du curseur suivant (kind=cursor)
    next_path: String,   // JSONPath de l'URL suivante dans le corps (kind=link_header, fallback)
}
/// Watermark incrémental d'un connecteur générique.
struct HttpWatermark {
    field_path: String,  // JSONPath (dans CHAQUE record) de la valeur watermark
    param: String,       // param de requête envoyé au serveur (optionnel : sinon dedup seul)
    format: String,      // epoch | iso8601 (règle de comparaison monotone)
    template: String,    // gabarit optionnel "{value}" (ex. FQL `last_behavior:>'{value}'`)
    lookback_days: i64,  // cold-start
}
/// Config décodée d'un connecteur `http_pull` (depuis `connector.config_json`). Le secret N'EST PAS ici.
pub(crate) struct HttpPullCfg {
    method: String,      // GET (défaut) | POST
    url: String,         // URL complète (ou api_root+path recomposé à la construction)
    body: String,        // corps optionnel (POST) — statique
    records_path: String,
    source: String,      // libellé source par défaut (sinon http:{id})
    sourcetype: String,  // sourcetype constant (fallback si field_map.sourcetype absent)
    field_map: Value,    // objet { champ_event: <path|=const> }
    st_overrides: HashMap<String, String>, // sourcetype_map inline + ENV (merge)
    auth: HttpAuth,
    page: HttpPage,
    watermark: Option<HttpWatermark>,
}
impl HttpPullCfg {
    /// JSONPath du tableau d'enregistrements (P-HEC : le récepteur push l'utilise pour APLATIR une enveloppe
    /// CloudTrail `{"Records":[...]}` via `httppull_records`, exactement comme la voie poll). Champ sinon privé.
    pub(crate) fn records_path(&self) -> &str { &self.records_path }
    pub(crate) fn from_json(v: &Value) -> HttpPullCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        // url : explicite, sinon api_root (slash final normalisé) + path.
        let url = {
            let direct = s("url");
            if !direct.is_empty() {
                direct
            } else {
                let root = s("api_root");
                let path = s("path");
                if root.is_empty() { String::new() } else { format!("{}{}", root.trim_end_matches('/'), path) }
            }
        };
        let method = { let m = s("method").to_ascii_uppercase(); if m == "POST" { m } else { "GET".to_string() } };
        let av = v.get("auth").cloned().unwrap_or_else(|| json!({}));
        let asv = |k: &str| av.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let auth = HttpAuth {
            kind: { let k = asv("kind").to_ascii_lowercase(); if k.is_empty() { "none".to_string() } else { k } },
            header_name: { let h = asv("header_name"); if h.is_empty() { "Authorization".to_string() } else { h } },
            prefix: av.get("prefix").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            token_url: asv("token_url"),
            client_id: asv("client_id"),
            scope: asv("scope"),
        };
        let pv = v.get("pagination").cloned().unwrap_or_else(|| json!({}));
        let psv = |k: &str| pv.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let pkind = { let k = psv("kind").to_ascii_lowercase(); if matches!(k.as_str(), "offset" | "page" | "cursor" | "link_header") { k } else { "none".to_string() } };
        let page = HttpPage {
            start: pv.get("start").and_then(|x| x.as_i64()).unwrap_or(if pkind == "page" { 1 } else { 0 }),
            kind: pkind,
            param: psv("param"),
            size: pv.get("size").and_then(|x| x.as_i64()).filter(|&n| n > 0 && n <= 100_000).unwrap_or(100),
            size_param: psv("size_param"),
            cursor_path: psv("cursor_path"),
            next_path: psv("next_path"),
        };
        let watermark = v.get("watermark").filter(|w| w.is_object()).map(|w| {
            let ws = |k: &str| w.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            HttpWatermark {
                field_path: ws("field_path"),
                param: ws("param"),
                format: { let f = ws("format").to_ascii_lowercase(); if f == "epoch" { f } else { "iso8601".to_string() } },
                template: w.get("template").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                lookback_days: w.get("lookback_days").and_then(|x| x.as_i64()).filter(|&n| n > 0 && n <= 3650).unwrap_or(7),
            }
        });
        // sourcetype_map inline (bring-your-own CIM sans ENV) MERGÉ avec l'override ENV (ENV gagne).
        let mut st_overrides = HashMap::new();
        if let Some(obj) = v.get("sourcetype_map").and_then(|x| x.as_object()) {
            for (k, val) in obj {
                if let Some(cat) = val.as_str() {
                    let (k, cat) = (k.trim().to_ascii_lowercase(), cat.trim().to_string());
                    if !k.is_empty() && !cat.is_empty() { st_overrides.insert(k, cat); }
                }
            }
        }
        for (k, val) in hec_sourcetype_overrides() { st_overrides.insert(k, val); }
        HttpPullCfg {
            method,
            url,
            body: v.get("body").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            records_path: s("records_path"),
            source: s("source"),
            sourcetype: s("sourcetype"),
            field_map: v.get("field_map").cloned().unwrap_or_else(|| json!({})),
            st_overrides,
            auth,
            page,
            watermark,
        }
    }
}

/// Résultat d'un pull générique : events NORMALISÉS (schéma d'ingest `event`, prêts pour store().insert_event
/// / preview UI) + watermark avancé (monotone). Aucun secret n'y transite (produit à partir de la seule
/// réponse HTTP).
#[derive(Debug)]
pub(crate) struct HttpPullOutcome {
    pub(crate) events: Vec<Value>,
    pub(crate) watermark: Option<String>,
}

/// Résout une SPEC de field_map -> valeur : `"=const"` (littéral), `{ "const": .. }`, sinon un JSONPath
/// dans le record. None si le chemin ne résout rien (champ omis).
fn httppull_resolve(rec: &Value, spec: &Value) -> Option<Value> {
    match spec {
        Value::String(s) => {
            if let Some(c) = s.strip_prefix('=') { Some(Value::String(c.to_string())) }
            else { json_extract_path(rec, s).cloned() }
        }
        Value::Object(o) => o.get("const").cloned(),
        _ => None,
    }
}

/// Valeur JSON -> String d'affichage (scalaire) : String tel quel, Number/Bool -> forme compacte, sinon
/// JSON compact ; None si Null. Sert message/host/ip/url et le rendu générique.
fn httppull_as_str(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}

/// Coercition ts -> epoch secondes. Number/num-string -> epoch (ms toléré, cf. hec_epoch) ; string ISO8601
/// -> minio_to_epoch. Fallback now() (jamais un event sans ts).
fn httppull_ts(v: &Value) -> i64 {
    match v {
        Value::Number(_) => hec_epoch(Some(v)).unwrap_or_else(now),
        Value::String(s) => {
            let sv = Value::String(s.clone());
            hec_epoch(Some(&sv)).unwrap_or_else(|| minio_to_epoch(Some(s)))
        }
        _ => now(),
    }
}

/// Coercition severity -> i64 (borne 0..=4). Number direct ; string -> `sev_num` (low/medium/high/critical)
/// sinon parse numérique. Défaut 0.
fn httppull_sev(v: &Value) -> i64 {
    let raw = match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.round() as i64)).unwrap_or(0),
        Value::String(s) => sev_num(s).or_else(|| s.trim().parse::<i64>().ok()).unwrap_or(0),
        _ => 0,
    };
    raw.clamp(0, 4)
}

/// Hash court (16 hex de SHA-256) d'une clé de dedup composite — fallback quand aucun `id`/`dedup` n'est
/// mappé (idempotence sur record identique : même entrée -> même dedup).
fn httppull_hash(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts { h.update(p.as_bytes()); h.update([0u8]); }
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// MAPPE un record vendeur -> event Plume (schéma d'ingest). `field_map` (obligatoire) mappe chaque champ
/// via un JSONPath OU une constante `=`. `fields.*` -> objet `fields` (contexte structuré, searchable en
/// SOQL). category : explicite (field_map.category) sinon dérivée du sourcetype via `hec_category` (gate
/// CIM). source : field_map.source sinon config.source sinon `http:{id}`. dedup : field_map.dedup sinon
/// `http-{id}-{field_map.id|hash}` (idempotent). Skip (None) uniquement si le record n'est pas un objet.
pub(crate) fn httppull_map_record(rec: &Value, cfg: &HttpPullCfg, connector_id: i64) -> Option<Value> {
    let fm = cfg.field_map.as_object()?;
    if !rec.is_object() { return None; }
    let getf = |key: &str| -> Option<Value> { fm.get(key).and_then(|spec| httppull_resolve(rec, spec)) };
    let getstr = |key: &str| -> Option<String> { getf(key).as_ref().and_then(httppull_as_str) };

    let ts = getf("ts").map(|v| httppull_ts(&v)).unwrap_or_else(now);
    let severity = getf("severity").map(|v| httppull_sev(&v)).unwrap_or(0);
    let message = getstr("message").unwrap_or_default();
    let src_ip = getstr("src_ip");
    let dst_ip = getstr("dst_ip");
    let url = getstr("url");
    let host = getstr("host");

    // fields.* -> objet fields ; entity -> fields.entity.
    let mut fields = serde_json::Map::new();
    for (k, spec) in fm {
        if let Some(suffix) = k.strip_prefix("fields.") {
            if let Some(val) = httppull_resolve(rec, spec) {
                if !val.is_null() && !suffix.is_empty() { fields.insert(suffix.to_string(), val); }
            }
        }
    }
    if let Some(ent) = getstr("entity") { fields.insert("entity".to_string(), json!(ent)); }

    // category : explicite sinon dérivée du sourcetype (record ou constant) via le mapping CIM existant.
    let category = match getstr("category") {
        Some(c) => Some(c),
        None => {
            let st = getstr("sourcetype").or_else(|| (!cfg.sourcetype.is_empty()).then(|| cfg.sourcetype.clone()));
            if let Some(st) = st {
                fields.entry("sourcetype".to_string()).or_insert_with(|| json!(st));
                hec_category(&st, &cfg.st_overrides)
            } else {
                None
            }
        }
    };

    let source = getstr("source").unwrap_or_else(|| {
        if cfg.source.is_empty() { format!("http:{connector_id}") } else { cfg.source.clone() }
    });
    let dedup = getstr("dedup").unwrap_or_else(|| {
        let idv = getstr("id").unwrap_or_else(|| httppull_hash(&[&ts.to_string(), &message, src_ip.as_deref().unwrap_or("")]));
        format!("http-{connector_id}-{idv}")
    });

    // Event schéma d'ingest — n'inclut que les clés présentes (comme hec_record_to_event).
    let mut ev = serde_json::Map::new();
    ev.insert("ts".to_string(), json!(ts));
    ev.insert("source".to_string(), json!(source));
    if let Some(c) = category { ev.insert("category".to_string(), json!(c)); }
    ev.insert("severity".to_string(), json!(severity));
    ev.insert("message".to_string(), json!(message));
    if let Some(h) = host { ev.insert("host".to_string(), json!(h)); }
    if let Some(ip) = src_ip { ev.insert("src_ip".to_string(), json!(ip)); }
    if let Some(ip) = dst_ip { ev.insert("dst_ip".to_string(), json!(ip)); }
    if let Some(u) = url { ev.insert("url".to_string(), json!(u)); }
    ev.insert("dedup".to_string(), json!(dedup));
    if !fields.is_empty() { ev.insert("fields".to_string(), Value::Object(fields)); }
    Some(Value::Object(ev))
}

/// Avance monotone d'un watermark string (epoch = comparaison numérique, iso8601 = comparaison lexicale
/// — les deux formats sont ordonnés). Ne régresse jamais.
pub(crate) fn httppull_wm_advance(cur: Option<String>, cand: &str, format: &str) -> Option<String> {
    if cand.is_empty() { return cur; }
    match cur {
        Some(c) => {
            let keep = if format == "epoch" {
                c.parse::<f64>().unwrap_or(f64::MIN) >= cand.parse::<f64>().unwrap_or(f64::MIN)
            } else {
                c.as_str() >= cand
            };
            if keep { Some(c) } else { Some(cand.to_string()) }
        }
        None => Some(cand.to_string()),
    }
}

/// ING-2 : `a < b` selon le format (epoch = numérique, iso8601 = lexical — les deux sont ordonnés, comme
/// `httppull_wm_advance`). Sert à détecter un flux NON ASCENDANT (une valeur PLUS PETITE que la précédente),
/// ce qui rend l'avance du watermark au MAX global d'un lot TRONQUÉ non sûre.
pub(crate) fn httppull_wm_lt(a: &str, b: &str, format: &str) -> bool {
    if format == "epoch" {
        a.parse::<f64>().unwrap_or(f64::MIN) < b.parse::<f64>().unwrap_or(f64::MIN)
    } else {
        a < b
    }
}

/// Valeur watermark envoyée au serveur (param, valeur) — cold-start = now - lookback (format epoch/iso).
/// `template` optionnel encadre la valeur (ex. FQL). None si aucun `param` configuré (-> pas de filtrage
/// côté serveur ; l'incrément repose alors sur le dedup, qui absorbe les recouvrements).
fn httppull_wm_request(cfg: &HttpPullCfg, watermark: Option<&str>) -> Option<(String, String)> {
    let w = cfg.watermark.as_ref()?;
    if w.param.is_empty() { return None; }
    let raw = match watermark {
        Some(x) if !x.is_empty() => x.to_string(),
        _ => {
            let cold = now() - w.lookback_days * 86400;
            if w.format == "epoch" { cold.to_string() } else { epoch_to_iso8601(cold) }
        }
    };
    let val = if w.template.is_empty() { raw } else { w.template.replace("{value}", &raw) };
    Some((w.param.clone(), val))
}

/// Ajoute `k=v` (percent-encodés) à une URL (`?` ou `&` selon présence d'un query-string).
fn httppull_append_query(url: &str, k: &str, v: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{}={}", url_encode(k), url_encode(v))
}

/// Construit l'URL d'UNE page : base + param watermark (si configuré) + params de pagination (taille +
/// offset/page/cursor selon la forme). Le kind `link_header` n'utilise cette fonction QUE pour la 1re page
/// (les suivantes viennent de l'en-tête `Link`/`next_path` de la réponse, absolues).
pub(crate) fn httppull_page_url(cfg: &HttpPullCfg, watermark: Option<&str>, off: Option<i64>, page: Option<i64>, cursor: Option<&str>) -> String {
    let mut u = cfg.url.clone();
    if let Some((p, val)) = httppull_wm_request(cfg, watermark) {
        u = httppull_append_query(&u, &p, &val);
    }
    if !cfg.page.size_param.is_empty() && cfg.page.size > 0 && cfg.page.kind != "none" {
        u = httppull_append_query(&u, &cfg.page.size_param, &cfg.page.size.to_string());
    }
    match cfg.page.kind.as_str() {
        "offset" if !cfg.page.param.is_empty() => u = httppull_append_query(&u, &cfg.page.param, &off.unwrap_or(cfg.page.start).to_string()),
        "page" if !cfg.page.param.is_empty() => u = httppull_append_query(&u, &cfg.page.param, &page.unwrap_or(cfg.page.start).to_string()),
        "cursor" if !cfg.page.param.is_empty() => { if let Some(c) = cursor { u = httppull_append_query(&u, &cfg.page.param, c); } }
        _ => {}
    }
    u
}

/// Extrait l'URL `rel="next"` d'un en-tête HTTP `Link` (RFC 5988) — pagination `link_header`.
fn httppull_link_next(h: &str) -> Option<String> {
    for part in h.split(',') {
        let low = part.to_ascii_lowercase();
        if low.contains("rel=\"next\"") || low.contains("rel=next") {
            let a = part.find('<')?;
            let b = part[a + 1..].find('>')? + a + 1;
            let u = part[a + 1..b].trim();
            if !u.is_empty() { return Some(u.to_string()); }
        }
    }
    None
}

/// OAuth2 client-credentials générique -> access_token (modèle `defender_token`). POST form-urlencoded
/// (client_id/client_secret[/scope]) sur `auth.token_url`. Le secret ne transite QUE dans le corps (mémoire,
/// jamais loggé) ; non-2xx -> Err (statut seul, jamais le corps).
fn httppull_oauth_token<F>(cfg: &HttpPullCfg, secret: &str, fetch: &F) -> Result<String, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    if cfg.auth.token_url.is_empty() {
        return Err("config http_pull incomplète (auth.token_url requis pour oauth2)".into());
    }
    let mut body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        url_encode(&cfg.auth.client_id), url_encode(secret)
    );
    if !cfg.auth.scope.is_empty() {
        body.push_str(&format!("&scope={}", url_encode(&cfg.auth.scope)));
    }
    let resp = fetch("POST", &cfg.auth.token_url, &[("Content-Type", "application/x-www-form-urlencoded")], Some(body.as_bytes()))?;
    if resp.status == 429 || resp.status == 503 {
        return Err(rate_limit_msg(&resp));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {} (auth)", resp.status)); // jamais le corps (ni le secret)
    }
    let v: Value = serde_json::from_slice(&resp.body).map_err(|_| "réponse token non-JSON".to_string())?;
    v.get("access_token").and_then(|t| t.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string())
        .ok_or_else(|| "access_token absent de la réponse".to_string())
}

/// En-têtes d'auth (le secret ne transite QUE dans ces en-têtes / le corps token — jamais loggé). Pour
/// oauth2 : fetch le token d'abord (client-credentials), puis Authorization: Bearer.
pub(crate) fn httppull_auth_headers<F>(cfg: &HttpPullCfg, secret: &str, fetch: &F) -> Result<Vec<(String, String)>, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    use base64::Engine as _;
    match cfg.auth.kind.as_str() {
        "none" => Ok(vec![]),
        "basic" => Ok(vec![("Authorization".to_string(), format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(secret)))]),
        "bearer" => Ok(vec![("Authorization".to_string(), format!("Bearer {secret}"))]),
        "token" | "header" => Ok(vec![(cfg.auth.header_name.clone(), format!("{}{}", cfg.auth.prefix, secret))]),
        "oauth2_client_credentials" => {
            let token = httppull_oauth_token(cfg, secret, fetch)?;
            Ok(vec![("Authorization".to_string(), format!("Bearer {token}"))])
        }
        other => Err(format!("auth.kind non supporté : {other}")),
    }
}

/// Borne dure de pages http_pull par tick (budget mémoire/CPU) — le reste repris au tick suivant.
pub(crate) fn httppull_max_pages() -> u64 {
    std::env::var("PLUME_HTTP_PULL_MAX_PAGES").ok().and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(20)
}

/// PULL GÉNÉRIQUE : auth -> GET/POST paginé (borné `max_pages`) -> extraction `records_path` -> mapping
/// `field_map` -> events (schéma d'ingest). N'INGÈRE PAS (l'appelant écrit sous le lock writer, comme
/// Defender). Watermark = max de `watermark.field_path` (MONOTONE, jamais régressé). 429/503 -> Err rate-
/// limit (watermark non régressé). `fetch` injectable -> testable offline. Aucun credential dans le mapping.
pub(crate) fn poll_http_pull<F>(cfg: &HttpPullCfg, secret: &str, watermark: Option<&str>,
                     connector_id: i64, fetch: F, max_pages: u64) -> Result<HttpPullOutcome, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    if cfg.url.is_empty() {
        return Err("config http_pull incomplète (url ou api_root+path requis)".into());
    }
    if !cfg.field_map.is_object() || cfg.field_map.as_object().map_or(true, |o| o.is_empty()) {
        return Err("config http_pull incomplète (field_map requis)".into());
    }
    let auth = httppull_auth_headers(cfg, secret, &fetch)?;
    let (wm_path, wm_fmt) = cfg.watermark.as_ref()
        .map(|w| (w.field_path.clone(), w.format.clone()))
        .unwrap_or_default();
    let mut events: Vec<Value> = Vec::new();
    let mut new_wm: Option<String> = watermark.filter(|s| !s.is_empty()).map(|s| s.to_string());
    // ING-2 — SÉCURITÉ WATERMARK SUR TRONCATURE. Si la récupération est COUPÉE à `max_pages` alors qu'il
    // reste des pages, avancer `new_wm` au MAX global du lot TRONQUÉ SAUTERAIT DÉFINITIVEMENT les
    // enregistrements plus vieux-mais-encore-neufs d'une API NON triée (backlog > max_pages*size). On observe
    // donc l'ORDRE réel du flux : `ascending` reste vrai tant que chaque valeur de watermark est >= la
    // précédente. Sur troncature d'un flux ASCENDANT (cf. presets : sort ascendant), le max global == borne de
    // la dernière page et le reste non-fetché est >= ce max -> re-fetché au tick suivant SANS saut -> on avance
    // (progrès conservé). Sur troncature d'un flux NON ascendant, on NE PAS avance (on garde le watermark
    // ENTRANT) : le reste est rejoué au tick suivant (jamais de perte silencieuse). Fetch COMPLET (non tronqué)
    // -> on avance au max (tout a été vu), comportement byte-identique à l'historique.
    let mut ascending = true;
    let mut prev_wv: Option<String> = None;
    let mut truncated = false;
    let mut off = cfg.page.start;
    let mut pageno = cfg.page.start;
    let mut url = httppull_page_url(cfg, watermark, Some(off), Some(pageno), None);
    let mut pages = 0u64;
    loop {
        pages += 1;
        if pages > max_pages { truncated = true; break; } // borne dure -> repris au tick suivant (ING-2)
        let headers: Vec<(&str, &str)> = auth.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let body: Option<&[u8]> = if cfg.method == "POST" && !cfg.body.is_empty() { Some(cfg.body.as_bytes()) } else { None };
        let resp = fetch(&cfg.method, &url, &headers, body)?;
        if resp.status == 429 || resp.status == 503 {
            return Err(rate_limit_msg(&resp)); // abandon propre, watermark non régressé
        }
        if !(200..300).contains(&resp.status) {
            return Err(format!("HTTP {} (http_pull)", resp.status)); // jamais le corps
        }
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| "réponse non-JSON".to_string())?;
        let records = httppull_records(&v, &cfg.records_path);
        let n = records.len();
        for rec in &records {
            if !wm_path.is_empty() {
                if let Some(node) = json_extract_path(rec, &wm_path) {
                    let wv = node.as_str().map(|s| s.to_string())
                        .or_else(|| node.as_i64().map(|i| i.to_string()))
                        .or_else(|| node.as_f64().map(|f| f.to_string()));
                    if let Some(wv) = wv {
                        // ING-2 : ordre observé — une valeur PLUS PETITE que la précédente marque le flux NON
                        // ascendant (-> avance prudente sur troncature ; cf. bloc ci-dessous).
                        if let Some(p) = &prev_wv {
                            if httppull_wm_lt(&wv, p, &wm_fmt) { ascending = false; }
                        }
                        prev_wv = Some(wv.clone());
                        new_wm = httppull_wm_advance(new_wm, &wv, &wm_fmt);
                    }
                }
            }
            if let Some(ev) = httppull_map_record(rec, cfg, connector_id) { events.push(ev); }
        }
        // Pagination : avance selon la forme (fin -> break).
        match cfg.page.kind.as_str() {
            "offset" => {
                if n == 0 || (cfg.page.size > 0 && (n as i64) < cfg.page.size) { break; }
                off += if cfg.page.size > 0 { cfg.page.size } else { n as i64 };
                url = httppull_page_url(cfg, watermark, Some(off), None, None);
            }
            "page" => {
                if n == 0 { break; }
                pageno += 1;
                url = httppull_page_url(cfg, watermark, None, Some(pageno), None);
            }
            "cursor" => {
                match json_extract_path(&v, &cfg.page.cursor_path).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    Some(c) => { let c = c.to_string(); url = httppull_page_url(cfg, watermark, None, None, Some(&c)); }
                    None => break,
                }
            }
            "link_header" => {
                let next = resp.header("link").and_then(httppull_link_next)
                    .or_else(|| json_extract_path(&v, &cfg.page.next_path).and_then(|x| x.as_str()).map(|s| s.to_string()));
                match next.filter(|s| !s.is_empty()) {
                    Some(nu) => url = nu,
                    None => break,
                }
            }
            _ => break, // none : une seule page
        }
    }
    // ING-2 : sur troncature d'un flux NON ascendant, ne PAS s'engager sur le max global (saut d'anciens
    // enregistrements non triés) -> on garde le watermark ENTRANT pour re-fetcher le reste au tick suivant.
    // Tout autre cas (fetch complet, ou flux ascendant même tronqué) -> max global (byte-identique historique).
    let final_wm = if truncated && !ascending {
        watermark.filter(|s| !s.is_empty()).map(|s| s.to_string())
    } else {
        new_wm
    };
    Ok(HttpPullOutcome { events, watermark: final_wm })
}
