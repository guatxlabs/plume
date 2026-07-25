//! Connecteur TAXII 2.1 — split #35 de connectors.rs (byte-identique).
use crate::*;

// ================================================================================================
// #23 — CONNECTEUR TAXII 2.1 (couche RÉSEAU du flux threat-intel). Un ADMIN configure une COLLECTION TAXII
// (type='taxii2') ; le daemon PULL périodiquement les objets STIX de la collection, les TRADUIT en IOC via
// guatx_core::ti::stix_bundle_to_iocs (PUR, injection-safe), et les UPSERT dans le magasin `ioc` du tenant.
// Le poll est INCRÉMENTAL (watermark = date_added TAXII du dernier objet -> `added_after` au tick suivant) et
// BORNÉ (max_pages/tick, repris ensuite). Idempotent (ioc_upsert = UPSERT sur UNIQUE) -> un recouvrement de
// watermark n'ajoute AUCUN doublon (une imprécision de watermark est donc SANS danger). Mêmes invariants que
// Defender : `fetch` injectable (testable offline), 429/Retry-After respectés (watermark non régressé), le
// credential ne fuit dans AUCUN message. INERTE tant qu'aucune collection n'est configurée (table vide).
// ================================================================================================

/// Config d'un connecteur TAXII 2.1 (décodée depuis `connector.config_json`). Le credential (Basic/Bearer)
/// N'EST PAS ici (colonne dédiée `connector.secret`).
pub(crate) struct TaxiiCfg {
    api_root: String,       // URL de l'API root TAXII (…/taxii2/apiX/ ; slash final normalisé)
    collection_id: String,  // identifiant (UUID) de la collection
    auth_type: String,      // "basic" | "bearer" | "none" (défaut heuristique : basic si secret ':' , bearer si non vide, none sinon)
    lookback_days: i64,     // cold-start : `added_after` initial (défaut 30, borné 1..3650)
    page_limit: i64,        // ?limit= par page (défaut 100, borné 1..1000)
    accept: String,         // Accept (défaut application/taxii+json;version=2.1)
}
impl TaxiiCfg {
    pub(crate) fn from_json(v: &Value) -> TaxiiCfg {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let accept = { let a = s("accept"); if a.is_empty() { "application/taxii+json;version=2.1".to_string() } else { a } };
        let auth_type = { let a = s("auth_type").to_ascii_lowercase(); if matches!(a.as_str(), "basic" | "bearer" | "none") { a } else { String::new() } };
        TaxiiCfg {
            api_root: s("api_root"),
            collection_id: s("collection_id"),
            auth_type,
            lookback_days: v.get("lookback_days").and_then(|x| x.as_i64()).filter(|&n| n > 0 && n <= 3650).unwrap_or(30),
            page_limit: v.get("page_limit").and_then(|x| x.as_i64()).filter(|&n| n > 0 && n <= 1000).unwrap_or(100),
            accept,
        }
    }
    /// Type d'auth EFFECTIF (résout l'heuristique si `auth_type` non forcé). Le secret décide : contient ':'
    /// -> Basic (user:pass) ; non vide -> Bearer (token) ; vide -> none (collection publique).
    fn effective_auth<'a>(&'a self, secret: &str) -> &'a str {
        if !self.auth_type.is_empty() {
            return &self.auth_type;
        }
        if secret.is_empty() { "none" } else if secret.contains(':') { "basic" } else { "bearer" }
    }
}

/// En-tête Authorization pour TAXII (ou None si collection publique). Basic = base64(user:pass) ; Bearer =
/// token brut. Le secret ne transite QUE dans cet en-tête (jamais loggé, jamais dans une erreur).
pub(crate) fn taxii_auth_header(cfg: &TaxiiCfg, secret: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    match cfg.effective_auth(secret) {
        "basic" => Some(("Authorization".to_string(), format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(secret)))),
        "bearer" => Some(("Authorization".to_string(), format!("Bearer {secret}"))),
        _ => None,
    }
}

/// URL des objets d'une collection TAXII 2.1. Page initiale : `?added_after={watermark|cold-start}&limit=N`.
/// Page suivante : ajoute `&next={cursor}` (le serveur encode l'état de pagination dans `next`). `added_after`
/// filtre par date_added (temps d'ajout côté serveur) -> incrémental. La valeur est percent-encodée.
pub(crate) fn taxii_objects_url(cfg: &TaxiiCfg, watermark: Option<&str>, next: Option<&str>) -> String {
    let root = cfg.api_root.trim_end_matches('/');
    let added_after = match watermark {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => epoch_to_iso8601(now() - cfg.lookback_days * 86400),
    };
    let mut url = format!(
        "{root}/collections/{}/objects/?added_after={}&limit={}",
        cfg.collection_id, url_encode(&added_after), cfg.page_limit
    );
    if let Some(n) = next {
        if !n.is_empty() {
            url.push_str(&format!("&next={}", url_encode(n)));
        }
    }
    url
}

/// Max lexical d'une chaîne ISO8601 (watermark monotone) — TAXII `date_added` et STIX `modified/created` sont
/// tous ISO8601 UTC, donc comparables lexicographiquement. Renvoie la plus grande de `cur` et `cand`.
fn iso_max(cur: Option<String>, cand: &str) -> Option<String> {
    if cand.is_empty() {
        return cur;
    }
    match cur {
        Some(c) if c.as_str() >= cand => Some(c),
        _ => Some(cand.to_string()),
    }
}

/// Résultat d'un pull TAXII : IOC traduits (à upserter par l'appelant sous le lock writer), nombre d'objets
/// non traduisibles (skip-with-reason, cf. guatx_core::ti), et watermark avancé (date_added max, monotone).
#[derive(Debug)]
pub(crate) struct TaxiiOutcome {
    pub(crate) iocs: Vec<guatx_core::ti::Ioc>,
    pub(crate) skipped: usize,
    pub(crate) watermark: Option<String>,
}

/// PULL TAXII 2.1 : GET paginé de l'enveloppe `/collections/{id}/objects/` (borné `max_pages`), traduction
/// PURE STIX->IOC. N'UPSERT PAS (l'appelant le fait sous le lock writer). Watermark = date_added TAXII du
/// dernier objet (en-tête `X-TAXII-Date-Added-Last`), fallback max STIX `modified`/`created`. Sur 429/503 :
/// Err rate-limit (watermark non régressé). `fetch` injectable -> testable offline. Aucun credential ne
/// transite par la traduction (objets STIX = données publiques de renseignement).
pub(crate) fn poll_taxii<F>(cfg: &TaxiiCfg, secret: &str, watermark: Option<&str>, fetch: F, max_pages: u64) -> Result<TaxiiOutcome, String>
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    if cfg.api_root.is_empty() || cfg.collection_id.is_empty() {
        return Err("config TAXII incomplète (api_root/collection_id)".into());
    }
    let auth = taxii_auth_header(cfg, secret);
    let mut url = taxii_objects_url(cfg, watermark, None);
    let mut iocs: Vec<guatx_core::ti::Ioc> = Vec::new();
    let mut skipped = 0usize;
    let mut new_wm: Option<String> = watermark.filter(|s| !s.is_empty()).map(|s| s.to_string());
    let mut pages = 0u64;
    loop {
        pages += 1;
        if pages > max_pages {
            break; // borne dure -> repris au tick suivant (watermark avancé)
        }
        let mut headers: Vec<(&str, &str)> = vec![("Accept", cfg.accept.as_str())];
        if let Some((k, v)) = &auth {
            headers.push((k.as_str(), v.as_str()));
        }
        let resp = fetch("GET", &url, &headers, None)?;
        if resp.status == 429 || resp.status == 503 {
            return Err(rate_limit_msg(&resp)); // abandon propre, watermark non régressé
        }
        if !(200..300).contains(&resp.status) {
            return Err(format!("HTTP {} (taxii)", resp.status)); // jamais le corps
        }
        // Watermark autoritatif : date_added du DERNIER objet de la page (en-tête TAXII 2.1).
        if let Some(last) = resp.header("x-taxii-date-added-last") {
            new_wm = iso_max(new_wm, last);
        }
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| "réponse TAXII non-JSON".to_string())?;
        // Enveloppe TAXII 2.1 : { objects: [ ...STIX SDOs... ], more, next }. stix_bundle_to_iocs accepte un
        // tableau d'objets (comme un bundle). Fallback watermark : si pas d'en-tête, max STIX modified/created.
        if let Some(objs) = v.get("objects") {
            if resp.header("x-taxii-date-added-last").is_none() {
                if let Some(arr) = objs.as_array() {
                    for o in arr {
                        for k in ["modified", "created"] {
                            if let Some(ts) = o.get(k).and_then(|x| x.as_str()) {
                                new_wm = iso_max(new_wm, ts);
                            }
                        }
                    }
                }
            }
            let imp = guatx_core::ti::stix_bundle_to_iocs(objs);
            skipped += imp.skipped.len();
            iocs.extend(imp.iocs);
        }
        // Pagination TAXII 2.1 : `more:true` + `next` (cursor). Sinon fin.
        let more = v.get("more").and_then(|x| x.as_bool()).unwrap_or(false);
        let next = v.get("next").and_then(|x| x.as_str()).unwrap_or("");
        if more && !next.is_empty() {
            url = taxii_objects_url(cfg, watermark, Some(next));
        } else {
            break;
        }
    }
    Ok(TaxiiOutcome { iocs, skipped, watermark: new_wm })
}

/// UPSERT d'un lot d'IOC TAXII sous le lock writer (mêmes règles que l'import STIX manuel : valid_until ->
/// expires ; sévérité dérivée de la confiance si absente). Renvoie le nombre d'IOC écrits/mis à jour.
pub(crate) fn taxii_upsert_iocs(conn: &Connection, iocs: &[guatx_core::ti::Ioc], source: &str, env_id: &str, now_ts: i64) -> i64 {
    let mut n = 0i64;
    for ioc in iocs {
        let expires = ioc.valid_until.as_deref().map(|s| minio_to_epoch(Some(s))).filter(|&e| e > 0);
        let confidence = ioc.confidence.unwrap_or(50).clamp(0, 100);
        let severity = if confidence >= 80 { 3 } else { 2 };
        if ioc_upsert(conn, &ioc.kind, &ioc.value, source, confidence, severity, expires, ioc.stix_id.as_deref(), env_id, now_ts) {
            n += 1;
        }
    }
    n
}

/// Borne dure de pages TAXII par tick (idem Defender) — le reste est repris au tick suivant.
pub(crate) fn taxii_max_pages() -> u64 {
    std::env::var("PLUME_TAXII_MAX_PAGES").ok().and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(20)
}
