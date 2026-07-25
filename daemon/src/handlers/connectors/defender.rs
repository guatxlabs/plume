//! Connecteur Defender (Microsoft Graph Security) — split #35 de connectors.rs (byte-identique).
use crate::*;

// ================================================================================================
// #3a — FRAMEWORK CONNECTEURS DE SOURCES EXTERNES + CONNECTEUR DEFENDER (Microsoft Graph Security).
//
// Un ADMIN configure une source externe en UI (table `connector` PAR-TENANT, migration v68). Le daemon
// PULL périodiquement les alertes (poll loop via for_each_active_tenant), les NORMALISE au schéma `event`
// (source=defender), les INGÈRE dans la base du tenant (INSERT OR IGNORE sur dedup) et AVANCE le watermark.
//
// INVARIANT ABSOLU : sans connecteur configuré (état prod actuel), la table est VIDE -> le select des
// « dus » ne renvoie rien -> le poll est un NO-OP STRICT (aucun réseau, aucune écriture). FAIL-SAFE : un
// connecteur cassé/injoignable est loggé (connector.last_error) et n'arrête NI l'ingest, NI les autres
// connecteurs, NI les autres tenants. RATE-LIMITÉ : 429/Retry-After Graph respectés (abandon propre du tick,
// watermark non régressé). SÉCU : le client_secret ne fuit JAMAIS (logs/erreurs/réponses API ; authorizer).
// TESTABILITÉ : poll_defender prend une closure `fetch` -> l'OAuth/Graph se mockent offline (pas de socket).
// ================================================================================================

/// Config d'un connecteur Defender (décodée depuis `connector.config_json`). Le secret N'EST PAS ici
/// (colonne dédiée `connector.secret`) : la config ne voit jamais le credential.
pub(crate) struct DefenderCfg {
    azure_tenant: String,   // GUID du tenant Azure AD (segment de l'URL token)
    client_id: String,      // GUID de l'app enregistrée (client-credentials)
    resource: String,       // "alerts" (alerts_v2) | "incidents"
    graph_host: String,     // défaut graph.microsoft.com
    login_host: String,     // défaut login.microsoftonline.com
    lookback_days: i64,     // cold-start : fenêtre initiale (défaut 7, borné 1..3650)
}
impl DefenderCfg {
    pub(crate) fn from_json(v: &Value) -> DefenderCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let host = |k: &str, d: &str| {
            let x = s(k);
            if x.is_empty() { d.to_string() } else { x }
        };
        DefenderCfg {
            azure_tenant: s("azure_tenant"),
            client_id: s("client_id"),
            resource: { let r = s("resource"); if r == "incidents" { r } else { "alerts".to_string() } },
            graph_host: host("graph_host", "graph.microsoft.com"),
            login_host: host("login_host", "login.microsoftonline.com"),
            lookback_days: v.get("lookback_days").and_then(|x| x.as_i64()).filter(|&n| n > 0 && n <= 3650).unwrap_or(7),
        }
    }
}

/// Un event normalisé prêt à ingérer (schéma `event`). Aucun secret n'y transite (produit à partir de la
/// seule réponse Graph).
#[derive(Debug)]
pub(crate) struct NormEvent {
    pub(crate) ts: i64,
    pub(crate) category: String,
    pub(crate) severity: i64,
    pub(crate) message: String,
    pub(crate) host: Option<String>,
    pub(crate) fields_json: String,
    pub(crate) dedup: String,
    /// `lastUpdateDateTime` (chaîne ISO) de l'alerte -> sert à avancer le watermark (max, monotone).
    pub(crate) last_update: String,
}

/// Résultat d'un pull : events normalisés + watermark avancé (max lastUpdateDateTime, monotone).
#[derive(Debug)]
pub(crate) struct DefenderOutcome {
    pub(crate) events: Vec<NormEvent>,
    pub(crate) watermark: Option<String>,
}

/// epoch (s, UTC) -> ISO8601 `YYYY-MM-DDTHH:MM:SSZ` (civil_from_days de Howard Hinnant, inverse de
/// minio_to_epoch). Sert la borne cold-start du $filter (now - lookback_days). Comparable lex. au watermark.
pub(crate) fn epoch_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, se) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

/// Hôte porté par une alerte Defender : 1er `deviceDnsName` non vide des evidences (device evidence).
pub(crate) fn defender_device_host(a: &Value) -> Option<String> {
    a.get("evidence").and_then(|e| e.as_array()).and_then(|arr| {
        arr.iter().find_map(|e| {
            e.get("deviceDnsName").and_then(|d| d.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string())
        })
    })
}

/// Normalise une alerte Graph `alerts_v2` (ou incident) -> event Plume. `resource` distingue le préfixe de
/// dedup (`defender-{cid}-{id}` pour les alertes, `defender-inc-{cid}-{id}` pour les incidents). Réutilise
/// `sev_num` (+ informational->0, fallback 2) et `minio_to_epoch` (RFC3339 UTC -> epoch). AUCUN secret.
pub(crate) fn normalize_defender_alert(a: &Value, connector_id: i64, resource: &str) -> NormEvent {
    let sev_str = a.get("severity").and_then(|x| x.as_str()).unwrap_or("");
    let severity = if sev_str.eq_ignore_ascii_case("informational") { 0 } else { sev_num(sev_str).unwrap_or(2) };
    let category = a.get("category").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let message = a.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let last_update = a.get("lastUpdateDateTime").and_then(|x| x.as_str())
        .or_else(|| a.get("createdDateTime").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let ts = minio_to_epoch(if last_update.is_empty() { None } else { Some(last_update.as_str()) });
    let host = defender_device_host(a);
    let id = a.get("id").and_then(|x| x.as_str()).unwrap_or("");
    let dedup = if resource == "incidents" {
        format!("defender-inc-{connector_id}-{id}")
    } else {
        format!("defender-{connector_id}-{id}")
    };
    // fields : contexte structuré exploitable en SOQL / drilldown (mitreTechniques -> couverture détection).
    let mut f = serde_json::Map::new();
    for k in ["id", "incidentId", "status", "determination", "serviceSource", "detectionSource", "description"] {
        if let Some(val) = a.get(k) {
            if !val.is_null() { f.insert(k.to_string(), val.clone()); }
        }
    }
    if let Some(mt) = a.get("mitreTechniques") {
        if !mt.is_null() { f.insert("mitreTechniques".to_string(), mt.clone()); }
    }
    if let Some(ev) = a.get("evidence") {
        if !ev.is_null() { f.insert("evidence".to_string(), ev.clone()); }
    }
    NormEvent {
        ts, category, severity, message, host,
        fields_json: Value::Object(f).to_string(),
        dedup, last_update,
    }
}

/// 429/503 Graph -> message d'erreur RATE-LIMIT (statut + Retry-After) SANS corps. Le poll pose ce message
/// en `last_error`, ne régresse PAS le watermark, et réessaie au prochain tick (>= interval_s).
pub(crate) fn rate_limit_msg(resp: &HttpResp) -> String {
    let ra = resp.header("retry-after").unwrap_or("");
    if ra.is_empty() {
        format!("HTTP {} Graph rate-limit (retry au prochain tick)", resp.status)
    } else {
        format!("HTTP {} Graph rate-limit, retry après {ra}s", resp.status)
    }
}

/// OAuth2 client-credentials -> access_token. POST form-urlencoded (client_id/client_secret/scope). Le
/// token reste EN MÉMOIRE LOCALE (jamais persisté, jamais loggé) ; le corps (qui porte le secret) n'apparaît
/// dans AUCUNE erreur. Fail-closed : non-2xx -> Err (statut seul, jamais le corps).
pub(crate) fn defender_token<F>(cfg: &DefenderCfg, secret: &str, fetch: F) -> Result<String, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    if cfg.azure_tenant.is_empty() || cfg.client_id.is_empty() {
        return Err("config Defender incomplète (azure_tenant/client_id)".into());
    }
    let url = format!("https://{}/{}/oauth2/v2.0/token", cfg.login_host, cfg.azure_tenant);
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
        url_encode(&cfg.client_id), url_encode(secret)
    );
    let resp = fetch("POST", &url, &[("Content-Type", "application/x-www-form-urlencoded")], Some(body.as_bytes()))?;
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

/// URL Graph du 1er page (borne watermark). Cold-start (watermark None) -> now - lookback_days. La valeur du
/// $filter est percent-encodée (espaces/`:` -> pas de request-line cassée) ; les pages suivantes réutilisent
/// `@odata.nextLink` tel quel.
pub(crate) fn graph_first_url(cfg: &DefenderCfg, watermark: Option<&str>) -> String {
    let resource_path = if cfg.resource == "incidents" { "incidents" } else { "alerts_v2" };
    let wm = match watermark {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => epoch_to_iso8601(now() - cfg.lookback_days * 86400),
    };
    let filter = format!("lastUpdateDateTime gt {wm}");
    format!(
        "https://{}/v1.0/security/{resource_path}?$filter={}&$orderby=lastUpdateDateTime&$top=100",
        cfg.graph_host, url_encode(&filter)
    )
}

/// Borne dure de pages par tick (budget mémoire/CPU) — le reste est repris au tick suivant (watermark avancé).
pub(crate) fn defender_max_pages() -> u64 {
    std::env::var("PLUME_DEFENDER_MAX_PAGES").ok().and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(20)
}

/// PULL Defender : OAuth -> GET Graph (pagination @odata.nextLink, bornée `max_pages`) -> normalisation.
/// N'INGÈRE PAS (l'ingest est fait par l'appelant, sous le lock writer). Le watermark renvoyé = max
/// lastUpdateDateTime observé (MONOTONE : initialisé à l'ancien watermark, jamais régressé). Sur 429/503 :
/// Err rate-limit (watermark NON régressé côté appelant car on ne renvoie pas d'Outcome). `fetch` est
/// injectable -> testable offline (mock OAuth/Graph). Aucun credential ne transite par la normalisation.
pub(crate) fn poll_defender<F>(cfg: &DefenderCfg, secret: &str, watermark: Option<&str>,
                    connector_id: i64, fetch: F, max_pages: u64) -> Result<DefenderOutcome, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    let token = defender_token(cfg, secret, &fetch)?;
    let auth = format!("Bearer {token}");
    let mut url = graph_first_url(cfg, watermark);
    let mut events: Vec<NormEvent> = Vec::new();
    let mut new_wm: Option<String> = watermark.filter(|s| !s.is_empty()).map(|s| s.to_string());
    let mut pages = 0u64;
    loop {
        pages += 1;
        if pages > max_pages { break; } // borne dure -> repris au tick suivant
        let resp = fetch("GET", &url, &[("Authorization", auth.as_str())], None)?;
        if resp.status == 429 || resp.status == 503 {
            return Err(rate_limit_msg(&resp)); // abandon propre du tick, watermark non régressé
        }
        if !(200..300).contains(&resp.status) {
            return Err(format!("HTTP {} (graph)", resp.status)); // jamais le corps
        }
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| "réponse Graph non-JSON".to_string())?;
        if let Some(arr) = v.get("value").and_then(|x| x.as_array()) {
            for a in arr {
                let ne = normalize_defender_alert(a, connector_id, &cfg.resource);
                // watermark MONOTONE : n'avance que si la borne dépasse strictement l'actuelle (chaîne ISO).
                if !ne.last_update.is_empty() && new_wm.as_deref().map_or(true, |cur| ne.last_update.as_str() > cur) {
                    new_wm = Some(ne.last_update.clone());
                }
                events.push(ne);
            }
        }
        match v.get("@odata.nextLink").and_then(|x| x.as_str()) {
            Some(next) if !next.is_empty() => url = next.to_string(),
            _ => break,
        }
    }
    Ok(DefenderOutcome { events, watermark: new_wm })
}

