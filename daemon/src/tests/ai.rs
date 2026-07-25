// Tests de la couche IA CONSEIL (#16). TOUS gated `#[cfg(feature = "ai")]` -> le build/test DÉFAUT reste
// à 600 tests (byte-identique, aucune dep IA). Sous `--features ai` : garde cloud, instanciation preset +
// garde à la création, redaction du secret en CRUD, inertie runtime, mapping 501, no-leak du ledger.
// Le CŒUR (invariant cardinal « compilo fermé dispose », zéro-exécution, redaction, rebond) est prouvé en
// pur dans core/src/ai.rs (mock provider, sans réseau). Ici on prouve le CÂBLAGE daemon, hors réseau.

#[cfg(feature = "ai")]
static AI_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

// ---- (c) GARDE CLOUD : classification + PLUME_AI_ALLOW_CLOUD (pur, hors réseau) ----
#[cfg(feature = "ai")]
#[test]
fn ai_cloud_gate_local_vs_cloud() {
    let _g = AI_ENV_LOCK.lock();
    // classification pure (IP littérales -> pas de DNS) : RFC1918/loopback = local, publique = cloud.
    assert!(!crate::ai::endpoint_is_cloud("http://10.0.0.5:8000"), "RFC1918 = local");
    assert!(!crate::ai::endpoint_is_cloud("http://192.168.1.10:11434"), "RFC1918 = local");
    assert!(!crate::ai::endpoint_is_cloud("http://127.0.0.1:11434"), "loopback = local");
    assert!(crate::ai::endpoint_is_cloud("https://1.1.1.1"), "IP publique = cloud");

    std::env::remove_var("PLUME_AI_ALLOW_CLOUD");
    // drapeau OFF : provider CLOUD refusé (endpoint public OU requires_cloud), LOCAL toujours autorisé.
    assert!(crate::ai::cloud_gate("https://1.1.1.1", false).is_err(), "cloud refusé sans le drapeau");
    assert!(crate::ai::cloud_gate("http://10.0.0.5:8000", true).is_err(), "requires_cloud refusé sans le drapeau (même endpoint local)");
    assert!(crate::ai::cloud_gate("http://10.0.0.5:8000", false).is_ok(), "local toujours autorisé");
    assert!(crate::ai::cloud_gate("http://127.0.0.1:11434", false).is_ok(), "loopback local toujours autorisé (garde cloud) ");

    std::env::set_var("PLUME_AI_ALLOW_CLOUD", "1");
    assert!(crate::ai::cloud_gate("https://1.1.1.1", false).is_ok(), "cloud autorisé avec le drapeau");
    assert!(crate::ai::cloud_gate("http://10.0.0.5:8000", true).is_ok(), "requires_cloud autorisé avec le drapeau");
    std::env::remove_var("PLUME_AI_ALLOW_CLOUD");
}

// ---- (c) instanciation preset : garde cloud à la CRÉATION (offline, aucun egress) ----
#[cfg(feature = "ai")]
#[tokio::test]
async fn ai_from_preset_cloud_gate_and_local_ok() {
    let _g = AI_ENV_LOCK.lock();
    std::env::remove_var("PLUME_AI_ALLOW_CLOUD");
    let st = sso_test_state("plume-admin", "plume-editor", "admins");

    // preset CLOUD (openai, requires_cloud) refusé sans le drapeau -> 403.
    let (code, _v) = tok_resp_json(ai_from_preset(
        State(st.clone()), Extension(ergo_au("admin")),
        Json(json!({ "preset_id": "openai", "values": { "model": "gpt-4o-mini" }, "secret": "env:OPENAI_KEY" })),
    ).await).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "preset cloud refusé sans PLUME_AI_ALLOW_CLOUD");

    // preset LOCAL (générique, endpoint RFC1918 explicite) instancié, enabled:false FORCÉ.
    let (code, v) = tok_resp_json(ai_from_preset(
        State(st.clone()), Extension(ergo_au("admin")),
        Json(json!({ "preset_id": "openai-compatible-generic", "name": "local-gw",
            "values": { "endpoint": "http://10.0.0.5:8000", "model": "qwen2.5-coder" } })),
    ).await).await;
    assert_eq!(code, StatusCode::OK, "preset local instancié : {v}");
    assert_eq!(v["enabled"], json!(false), "enabled:false FORCÉ à l'instanciation");

    // la liste montre le provider, enabled=false, has_secret=false (pas de secret fourni).
    let (_c, list) = tok_resp_json(ai_providers_list(State(st.clone()), Extension(ergo_au("admin"))).await).await;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["enabled"], json!(false));
    assert_eq!(arr[0]["has_secret"], json!(false));
    assert_eq!(arr[0]["cloud"], json!(false), "endpoint RFC1918 -> local");

    // viewer NE PEUT PAS instancier (admin-only).
    let (code, _v) = tok_resp_json(ai_from_preset(
        State(st.clone()), Extension(ergo_au("viewer")),
        Json(json!({ "preset_id": "openai-compatible-generic", "values": { "endpoint": "http://10.0.0.5:8000", "model": "m" } })),
    ).await).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "from-preset réservé admin");
}

// ---- CRUD : le secret n'est JAMAIS projeté (write-only + redaction) ----
#[cfg(feature = "ai")]
#[tokio::test]
async fn ai_provider_crud_redacts_secret() {
    let st = sso_test_state("plume-admin", "plume-editor", "admins");
    let (code, v) = tok_resp_json(ai_provider_create(
        State(st.clone()), Extension(ergo_au("admin")),
        Json(json!({ "name": "p1", "vendor": "vLLM", "api_shape": "openai",
            "endpoint": "http://10.0.0.5:8000", "secret": "env:SUPER_SECRET_AI_KEY",
            "config": { "model": "m" } })),
    ).await).await;
    assert_eq!(code, StatusCode::OK, "create : {v}");

    let (_c, list) = tok_resp_json(ai_providers_list(State(st.clone()), Extension(ergo_au("admin"))).await).await;
    let s = list.to_string();
    assert!(!s.contains("SUPER_SECRET_AI_KEY"), "le secret NE DOIT PAS être projeté : {s}");
    assert_eq!(list[0]["has_secret"], json!(true), "has_secret=true sans révéler la valeur");

    // viewer ne peut pas lister (admin-only).
    let (code, _v) = tok_resp_json(ai_providers_list(State(st.clone()), Extension(ergo_au("viewer"))).await).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "list réservé admin");
}

// ---- inertie runtime : sans PLUME_AI_ENABLE / sans provider actif, NL→SOQL n'agit pas (aucun egress) ----
#[cfg(feature = "ai")]
#[tokio::test]
async fn ai_nl2soql_inert_without_enable_or_provider() {
    let _g = AI_ENV_LOCK.lock();
    let st = sso_test_state("plume-admin", "plume-editor", "admins");

    std::env::remove_var("PLUME_AI_ENABLE");
    let (code, _v) = tok_resp_json(ai_nl2soql(
        State(st.clone()), Extension(ergo_au("viewer")), Json(json!({ "nl": "erreurs auth" })),
    ).await).await;
    assert_eq!(code, StatusCode::CONFLICT, "NL→SOQL inerte sans PLUME_AI_ENABLE");

    // ENABLE posé mais AUCUN provider actif -> 409 (jamais d'egress).
    std::env::set_var("PLUME_AI_ENABLE", "1");
    let (code, _v) = tok_resp_json(ai_nl2soql(
        State(st.clone()), Extension(ergo_au("viewer")), Json(json!({ "nl": "erreurs auth" })),
    ).await).await;
    assert_eq!(code, StatusCode::CONFLICT, "409 sans provider actif (aucun appel réseau)");

    // status reflète l'inertie (enabled=false : pas de provider).
    let (_c, s) = tok_resp_json(ai_status(State(st.clone()), Extension(ergo_au("viewer"))).await).await;
    assert_eq!(s["enabled"], json!(false));
    assert_eq!(s["has_provider"], json!(false));
    std::env::remove_var("PLUME_AI_ENABLE");
}

// ---- (f) mapping 501 : « non compilé » -> 501 (stub feature-off) ; autre erreur -> 500 ----
#[cfg(feature = "ai")]
#[test]
fn ai_worker_err_maps_501_and_500() {
    use axum::response::IntoResponse;
    assert_eq!(ai_worker_err("support IA non compilé (recompiler avec --features ai)".into()).into_response().status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(ai_worker_err("backend HTTP 500".into()).into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
    // require_feature() est Ok quand la feature est compilée (le bras non-compilé renvoie le sentinel « non compilé »).
    assert!(crate::ai::require_feature().is_ok());
}

// ---- (e) no-leak du ledger : le détail `ai.call` porte le HASH du prompt, JAMAIS la matière ni la clé ----
#[cfg(feature = "ai")]
#[test]
fn ai_call_ledger_detail_has_hash_never_prompt_or_key() {
    let policy = guatx_core::ai::default_redaction_policy();
    let mut fields: Vec<String> = guatx_core::cim::CIM_CORE_FIELDS.iter().map(|s| s.to_string()).collect();
    fields.push("api_key".into()); // doit être rédigé
    let fields = guatx_core::ai::redact_fields(&fields, &policy);
    let nl = "trouve les connexions de alice avec le mot de passe hunter2";
    let (sys_p, usr_p) = guatx_core::ai::build_nl2soql_prompt(&fields, guatx_core::cim::CIM_CATEGORIES, nl);
    let prompt_sha = sha256_hex(format!("{sys_p}\n{usr_p}").as_bytes());

    let detail = ai_call_ledger_detail(7, "ollama-native", false, 42, 13, policy.version, &prompt_sha, true, false, "alice-analyst");
    // porte : le HASH, la version de politique, les compteurs — PAS la matière du prompt.
    assert!(detail.contains(&prompt_sha), "le hash du prompt doit être présent");
    assert!(detail.contains("prompt_sha256") && detail.contains("redaction_policy_version"));
    assert!(!detail.contains("hunter2"), "la question NL (secret) NE DOIT PAS fuiter");
    assert!(!detail.contains("mot de passe"), "la matière du prompt NE DOIT PAS fuiter");
    assert!(!detail.contains("api_key"), "aucun nom de champ rédigé ne doit apparaître");
    // le hash NE DOIT PAS être inversible en la question (juste une empreinte).
    assert_ne!(prompt_sha, nl);
}
