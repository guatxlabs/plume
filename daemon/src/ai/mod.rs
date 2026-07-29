//! Couche IA CONSEIL (advisory) — Phase 1, côté daemon (#16). Feature `ai` OFF par défaut. Ce module
//! porte : (1) la porte de feature `require_feature()` (miroir EXACT du stub LDAP/SAML « non compilé »
//! -> 501) ; (2) la classification CLOUD/LOCAL de l'endpoint (réutilise la garde SSRF) ; (3) le budget
//! d'appels ; (4) — DERRIÈRE `#[cfg(feature="ai")]` — l'impl HTTP OpenAI-compatible / Ollama-natif /
//! Anthropic du trait `guatx_core::ai::AiProvider`, dont l'ÉGRESS passe VERBATIM par `ssrf_guard` +
//! le client HTTP interne `http_call` (AUCUNE nouvelle crate réseau).
//!
//! INVARIANT CARDINAL (cf. core::ai) : l'IA propose du TEXTE GXQL, le compilo FERMÉ (`soql_to_sql_x`)
//! dispose. Le daemon n'exécute JAMAIS le texte généré. RAM-neutre : inférence DISTANTE ; ce module ne
//! fait que sérialiser du JSON, appeler dehors, parser du JSON. Aucun modèle/tokenizer/vecteur.
mod presets;
pub(crate) use presets::*;

use crate::*;

/// Feature `ai` compilée ? OFF -> `Err("… non compilé …")` -> les handlers renvoient 501 (miroir strict de
/// `ldap_authenticate`/`saml_*`). ON -> `Ok(())`. C'est le stub 501 de TOUS les endpoints IA.
#[cfg(not(feature = "ai"))]
pub(crate) fn require_feature() -> Result<(), String> {
    Err("support IA non compilé (recompiler avec --features ai)".into())
}
#[cfg(feature = "ai")]
pub(crate) fn require_feature() -> Result<(), String> {
    Ok(())
}

/// Runtime : la couche IA est-elle ARMÉE ? Feature compilée ET `PLUME_AI_ENABLE` posé. Sans ça, aucun
/// endpoint IA n'agit (inertie mode-0, comme un provider IdP absent). NB : indépendant de l'existence
/// d'un provider en base (vérifiée séparément par `active_provider`).
pub(crate) fn runtime_enabled() -> bool {
    require_feature().is_ok() && env_flag("PLUME_AI_ENABLE")
}

/// Le drapeau cloud est-il autorisé ? `PLUME_AI_ALLOW_CLOUD` in {1,true,yes,on}. Défaut OFF —
/// équivalent IA de `PLUME_SSRF_BLOCK_PRIVATE`.
pub(crate) fn cloud_allowed() -> bool {
    env_flag("PLUME_AI_ALLOW_CLOUD")
}

fn env_flag(k: &str) -> bool {
    matches!(std::env::var(k).unwrap_or_default().trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Borne dure de tokens par appel (`PLUME_AI_MAX_TOKENS`, défaut 512, clampé 1..=4096).
pub(crate) fn max_tokens_cap() -> u32 {
    std::env::var("PLUME_AI_MAX_TOKENS").ok().and_then(|v| v.parse().ok()).unwrap_or(512u32).clamp(1, 4096)
}

// ============================ CLASSIFICATION CLOUD / LOCAL (réutilise SSRF) ============================

/// Extrait (host, port) d'un endpoint `http(s)://host[:port]`. port défaut 80/443.
fn endpoint_host_port(endpoint: &str) -> Option<(String, u16)> {
    let (https, rest) = if let Some(r) = endpoint.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = endpoint.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

/// L'endpoint est-il CLOUD (public/non-RFC1918) ? Réutilise la classification SSRF : une IP est LOCALE
/// si `ssrf_blocked_policy(ip, true)` (loopback/link-local/unspecified/RFC1918/ULA). CLOUD ssi AU MOINS
/// une IP résolue est publique. Échec de résolution / schéma invalide -> CLOUD (fail-closed : exige le
/// drapeau). Ollama sur localhost:11434 -> LOCAL. api.openai.com -> CLOUD.
pub(crate) fn endpoint_is_cloud(endpoint: &str) -> bool {
    let Some((host, port)) = endpoint_host_port(endpoint) else {
        return true; // pas d'URL exploitable -> traiter comme cloud (conservateur)
    };
    // littéral IP ?
    if let Some(ip) = ssrf_norm_ip(&host) {
        return !ssrf_blocked_policy(ip, true);
    }
    use std::net::ToSocketAddrs;
    match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => {
            let mut any = false;
            for a in addrs {
                any = true;
                if !ssrf_blocked_policy(a.ip(), true) {
                    return true; // une IP publique -> cloud
                }
            }
            !any // aucune IP résolue -> cloud (fail-closed)
        }
        Err(_) => true, // résolution impossible -> cloud (fail-closed)
    }
}

/// Un provider est-il CLOUD ? Endpoint public OU `requires_cloud` déclaré (preset). Défense en profondeur.
pub(crate) fn provider_is_cloud(endpoint: &str, requires_cloud: bool) -> bool {
    requires_cloud || endpoint_is_cloud(endpoint)
}

/// La GARDE CLOUD : un provider cloud n'est instanciable/appelable QUE si `PLUME_AI_ALLOW_CLOUD`. LOCAL
/// toujours OK. Enforced à la CRÉATION *et* à l'APPEL (defense in depth). Renvoie Err(message) si refusé.
pub(crate) fn cloud_gate(endpoint: &str, requires_cloud: bool) -> Result<(), String> {
    if provider_is_cloud(endpoint, requires_cloud) && !cloud_allowed() {
        return Err("provider IA CLOUD refusé (endpoint public ou requires_cloud) — poser PLUME_AI_ALLOW_CLOUD=1 pour autoriser l'inférence hors du réseau local".into());
    }
    Ok(())
}

// ================================ BUDGET D'APPELS (fenêtre glissante) ================================

/// Compteur d'appels IA par tenant sur une fenêtre glissante de 60 s (miroir du rate-limiter `rl`).
/// AppState INCHANGÉE (static autonome) -> mode 0 byte-identique. `PLUME_AI_MAX_CALLS_PER_MIN` (défaut 30).
static AI_BUDGET: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>> =
    std::sync::OnceLock::new();

fn ai_calls_per_min() -> u32 {
    std::env::var("PLUME_AI_MAX_CALLS_PER_MIN").ok().and_then(|v| v.parse().ok()).filter(|&n: &u32| n > 0).unwrap_or(30)
}

/// Consomme un jeton de budget pour `tenant`. Err si la fenêtre est saturée. NL→GXQL = 1 appel/question,
/// jamais par-event.
pub(crate) fn budget_take(tenant: &str) -> Result<(), String> {
    let cap = ai_calls_per_min();
    let cell = AI_BUDGET.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    let mut map = cell.lock();
    let now = std::time::Instant::now();
    let e = map.entry(tenant.to_string()).or_insert((now, 0));
    if now.duration_since(e.0).as_secs() >= 60 {
        *e = (now, 0); // reset de fenêtre
    }
    if e.1 >= cap {
        return Err(format!("budget IA dépassé ({cap} appels/min) — réessayez dans un instant"));
    }
    e.1 += 1;
    Ok(())
}

// ============================== IMPL PROVIDER HTTP (feature-gated) ==============================

/// Exécute NL→GXQL de bout en bout. DEUX bras : `ai` (impl réelle) / non-`ai` (stub 501 « non compilé »).
/// `compile` = couture du compilo FERMÉ (en prod `soql_to_sql_x`). Renvoie l'outcome pur (core) ou une
/// erreur (dont la variante « non compilé » -> 501). AUCUNE exécution du SQL.
#[cfg(not(feature = "ai"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_nl2soql(
    _endpoint: &str, _api_shape: &str, _model: &str, _key: &str, _temperature: f64, _num_ctx: u32,
    _nl: &str, _fields: &[String], _categories: &[&str], _policy: &guatx_core::ai::RedactionPolicy,
    _max_tokens: u32, _compile: &dyn Fn(&str) -> Result<String, String>,
) -> Result<guatx_core::ai::Nl2SoqlOutcome, String> {
    Err("support IA non compilé (recompiler avec --features ai)".into())
}

#[cfg(feature = "ai")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_nl2soql(
    endpoint: &str, api_shape: &str, model: &str, key: &str, temperature: f64, num_ctx: u32,
    nl: &str, fields: &[String], categories: &[&str], policy: &guatx_core::ai::RedactionPolicy,
    max_tokens: u32, compile: &dyn Fn(&str) -> Result<String, String>,
) -> Result<guatx_core::ai::Nl2SoqlOutcome, String> {
    let prov = OpenAiCompatProvider {
        id: format!("{api_shape}:{model}"),
        api_shape: api_shape.to_string(),
        endpoint: endpoint.trim_end_matches('/').to_string(),
        model: model.to_string(),
        key: key.to_string(),
        temperature,
        num_ctx,
    };
    guatx_core::ai::nl2soql_pipeline(&prov, nl, fields, categories, policy, max_tokens, compile)
        .map_err(|e| e.to_string())
}

/// Provider HTTP unique derrière `guatx_core::ai::AiProvider`, multi-`api_shape`. RAM-neutre : sérialise,
/// appelle dehors (ssrf_guard + http_call), parse. La clé n'est JAMAIS loggée ni mise dans une erreur.
#[cfg(feature = "ai")]
pub(crate) struct OpenAiCompatProvider {
    pub id: String,
    pub api_shape: String, // openai | ollama-native | anthropic
    pub endpoint: String,
    pub model: String,
    pub key: String,
    pub temperature: f64,
    pub num_ctx: u32,
}

#[cfg(feature = "ai")]
impl guatx_core::ai::AiProvider for OpenAiCompatProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn complete(&self, req: &guatx_core::ai::AiRequest) -> Result<guatx_core::ai::AiResponse, guatx_core::ai::AiError> {
        use guatx_core::ai::AiError;
        let (url, body, headers_owned): (String, serde_json::Value, Vec<(String, String)>) = match self.api_shape.as_str() {
            "ollama-native" => (
                format!("{}/api/chat", self.endpoint),
                json!({
                    "model": self.model,
                    "stream": false,
                    "messages": [
                        {"role":"system","content": req.system},
                        {"role":"user","content": req.user},
                    ],
                    "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "num_predict": req.max_tokens},
                }),
                vec![("Content-Type".into(), "application/json".into())],
            ),
            "anthropic" => (
                format!("{}/v1/messages", self.endpoint),
                json!({
                    "model": self.model,
                    "max_tokens": req.max_tokens,
                    "temperature": self.temperature,
                    "system": req.system,
                    "messages": [{"role":"user","content": req.user}],
                }),
                vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("x-api-key".into(), self.key.clone()),
                    ("anthropic-version".into(), "2023-06-01".into()),
                ],
            ),
            // openai + tout gateway compatible /v1/chat/completions (vLLM, LocalAI, Azure-OpenAI, Ollama /v1).
            _ => (
                format!("{}/v1/chat/completions", self.endpoint),
                json!({
                    "model": self.model,
                    "max_tokens": req.max_tokens,
                    "temperature": self.temperature,
                    "messages": [
                        {"role":"system","content": req.system},
                        {"role":"user","content": req.user},
                    ],
                }),
                {
                    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
                    if !self.key.is_empty() {
                        h.push(("Authorization".to_string(), format!("Bearer {}", self.key)));
                    }
                    h
                },
            ),
        };

        // ÉGRESS : garde SSRF VERBATIM (même choke-point que connecteurs/idp/notifiers) PUIS client interne.
        ssrf_guard(&url).map_err(AiError::Backend)?;
        let body_bytes = body.to_string().into_bytes();
        let headers: Vec<(&str, &str)> = headers_owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let resp = http_call("POST", &url, &headers, Some(&body_bytes)).map_err(AiError::Backend)?;
        if !(200..300).contains(&resp.status) {
            return Err(AiError::Backend(format!("HTTP {}", resp.status))); // JAMAIS le corps, JAMAIS la clé
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|_| AiError::BadResponse("corps non-JSON".into()))?;
        let (text, pt, ct) = match self.api_shape.as_str() {
            "ollama-native" => (
                v.get("message").and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap_or("").to_string(),
                v.get("prompt_eval_count").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                v.get("eval_count").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            ),
            "anthropic" => (
                v.get("content").and_then(|c| c.get(0)).and_then(|b| b.get("text")).and_then(|t| t.as_str()).unwrap_or("").to_string(),
                v.get("usage").and_then(|u| u.get("input_tokens")).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                v.get("usage").and_then(|u| u.get("output_tokens")).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            ),
            _ => (
                v.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|t| t.as_str()).unwrap_or("").to_string(),
                v.get("usage").and_then(|u| u.get("prompt_tokens")).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                v.get("usage").and_then(|u| u.get("completion_tokens")).and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            ),
        };
        if text.trim().is_empty() {
            return Err(AiError::BadResponse("complétion vide".into()));
        }
        Ok(guatx_core::ai::AiResponse { text, prompt_tokens: pt, completion_tokens: ct })
    }
}

#[cfg(test)]
mod ai_unit_tests {
    // Tests unitaires du module daemon (classification cloud/local, budget) — TOUS gated `ai` pour que le
    // build/test DÉFAUT reste inchangé (miroir saml.rs). Voir aussi daemon/src/tests/ai.rs (handlers).
    #[cfg(feature = "ai")]
    #[test]
    fn cloud_local_classification() {
        use super::endpoint_is_cloud;
        assert!(!endpoint_is_cloud("http://127.0.0.1:11434"), "loopback = local");
        assert!(!endpoint_is_cloud("http://localhost:11434"), "localhost = local");
        assert!(!endpoint_is_cloud("http://10.0.0.5:8000"), "RFC1918 = local");
        assert!(!endpoint_is_cloud("http://192.168.1.20:1234"), "RFC1918 = local");
        assert!(endpoint_is_cloud("https://1.1.1.1"), "IP publique = cloud");
        assert!(endpoint_is_cloud("ftp://whatever"), "schéma invalide -> cloud (fail-closed)");
    }

    #[cfg(feature = "ai")]
    #[test]
    fn budget_saturates_then_errors() {
        std::env::set_var("PLUME_AI_MAX_CALLS_PER_MIN", "3");
        let t = "tenant-budget-test";
        assert!(super::budget_take(t).is_ok());
        assert!(super::budget_take(t).is_ok());
        assert!(super::budget_take(t).is_ok());
        assert!(super::budget_take(t).is_err(), "4e appel doit être refusé");
        std::env::remove_var("PLUME_AI_MAX_CALLS_PER_MIN");
    }
}
