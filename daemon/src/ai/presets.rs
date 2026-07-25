//! Bibliothèque de presets IA (secret-free), EMBARQUÉS via `include_str!` (même patron que
//! `handlers/connectors/presets.rs`). Servis en lecture à l'admin (`GET /api/ai/presets`) et
//! instanciés en 1 clic (`POST /api/ai/from-preset` -> délègue à provider-create, `enabled:false`
//! forcé, garde CLOUD appliquée). AUCUN secret : la clé API reste saisie à la main à l'instanciation.
//! `requires_cloud` + `api_shape` sont des DÉCISIONS CURÉES (dans la constante, pas dérivées du JSON).
use crate::*;

pub(crate) struct AiPreset {
    pub id: &'static str,
    pub vendor: &'static str,
    pub label: &'static str,
    /// openai | ollama-native | anthropic — la forme d'API du backend.
    pub api_shape: &'static str,
    /// true => provider CLOUD par nature (gate `PLUME_AI_ALLOW_CLOUD`) même si l'endpoint semble local.
    pub requires_cloud: bool,
    /// Descriptor JSON brut (endpoint/model/config template + `_comment`), secret-free.
    pub raw: &'static str,
}

/// CATALOGUE EMBARQUÉ (6 presets = `docs/ai-presets/*.json`). LOCAL (ollama/vllm/générique) d'abord,
/// CLOUD (azure/anthropic/openai) ensuite. L'ordre = ordre d'affichage.
pub(crate) static AI_PRESETS: &[AiPreset] = &[
    AiPreset {
        id: "ollama-local", vendor: "Ollama", label: "Ollama (local) — API native /api/chat",
        api_shape: "ollama-native", requires_cloud: false,
        raw: include_str!("../../../docs/ai-presets/ollama-local.json"),
    },
    AiPreset {
        id: "vllm-local", vendor: "vLLM", label: "vLLM (local) — OpenAI-compatible /v1",
        api_shape: "openai", requires_cloud: false,
        raw: include_str!("../../../docs/ai-presets/vllm-local.json"),
    },
    AiPreset {
        id: "openai-compatible-generic", vendor: "Générique", label: "OpenAI-compatible (bring-your-own gateway)",
        api_shape: "openai", requires_cloud: false,
        raw: include_str!("../../../docs/ai-presets/openai-compatible-generic.json"),
    },
    AiPreset {
        id: "azure-openai", vendor: "Microsoft", label: "Azure OpenAI (cloud)",
        api_shape: "openai", requires_cloud: true,
        raw: include_str!("../../../docs/ai-presets/azure-openai.json"),
    },
    AiPreset {
        id: "anthropic", vendor: "Anthropic", label: "Anthropic Messages API (cloud)",
        api_shape: "anthropic", requires_cloud: true,
        raw: include_str!("../../../docs/ai-presets/anthropic.json"),
    },
    AiPreset {
        id: "openai", vendor: "OpenAI", label: "OpenAI (cloud)",
        api_shape: "openai", requires_cloud: true,
        raw: include_str!("../../../docs/ai-presets/openai.json"),
    },
];

pub(crate) fn ai_preset_by_id(id: &str) -> Option<&'static AiPreset> {
    AI_PRESETS.iter().find(|p| p.id == id)
}

/// Collecte les placeholders `{ident}` (à remplir par l'admin) présents dans les feuilles chaîne d'un Value.
fn collect_needs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let b = s.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'{' {
                    let mut j = i + 1;
                    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'}' && j > i + 1 {
                        let key = s[i + 1..j].to_string();
                        if !out.contains(&key) {
                            out.push(key);
                        }
                        i = j + 1;
                        continue;
                    }
                }
                i += 1;
            }
        }
        Value::Array(a) => a.iter().for_each(|c| collect_needs(c, out)),
        Value::Object(o) => o.values().for_each(|c| collect_needs(c, out)),
        _ => {}
    }
}

/// Objet public d'un preset servi à l'UI : métadonnée + template (endpoint/model/config), SANS secret.
pub(crate) fn ai_preset_public(p: &AiPreset) -> Value {
    let raw: Value = serde_json::from_str(p.raw).unwrap_or_else(|_| json!({}));
    let description = raw.get("_comment").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let endpoint = raw.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let model = raw.get("model").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let config = raw.get("config").cloned().unwrap_or_else(|| json!({}));
    let mut needs: Vec<String> = Vec::new();
    collect_needs(&raw, &mut needs);
    json!({
        "id": p.id,
        "vendor": p.vendor,
        "label": p.label,
        "api_shape": p.api_shape,
        "requires_cloud": p.requires_cloud,
        "endpoint": endpoint,
        "model": model,
        "config": config,
        "description": description,
        "needs": needs,
        // indice UI : ce preset serait-il refusé dans l'état courant (cloud sans le drapeau) ?
        "cloud_blocked": p.requires_cloud && !crate::ai::cloud_allowed(),
    })
}
