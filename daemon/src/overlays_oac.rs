//! #55 OBSERVABILITY-AS-CODE — overlays config.d pour les OBJETS DE CONFIG du SOC (au-delà du CONTENU de
//! détection rules/parsers/sigma déjà couvert par `overlays.rs`). MÊME contrat que `overlays.rs` :
//!   - chargé au boot APRÈS les seed_*, dans `load_overlays_dir` (un overlay GAGNE sur un seed du même nom) ;
//!   - chaque objet posé avec `managed=1` (source git) -> verrouillé en UI + prunable (#26) ;
//!   - IDEMPOTENT, keyé par `name` : re-jouer donne le MÊME état ;
//!   - VALIDÉ-OU-IGNORÉ : un objet invalide (JSON cassé, requête qui ne compile pas, type hors allowlist,
//!     matcher hors allowlist) -> WARN + skip, JAMAIS un crash du boot ;
//!   - OVERRIDE-SAFE : un overlay NE clobber JAMAIS un objet `managed=2` (ad-hoc UI) du même nom (SKIP+WARN) ;
//!     réciproquement l'UI refuse de muter/supprimer un `managed=1` (delete_managed_row_tx).
//!
//! RISQUE CLÉ — SECRETS EN GIT : un notifier/connecteur/destination porte de l'AUTH. Un overlay committé NE
//! DOIT JAMAIS contenir un secret EN CLAIR. Le secret est RÉFÉRENCÉ indirectement (`env:`/`file:`/`vault:`)
//! et RÉSOLU ICI, au chargement. Une valeur EN CLAIR dans une clé-secret -> l'objet est REJETÉ (fail-closed).
use crate::*;

// =====================================================================================================
// RÉFÉRENCES DE SECRET (indirection) — un secret n'est JAMAIS committé en clair : il est référencé.
// =====================================================================================================

/// `true` si `s` est une RÉFÉRENCE de secret résoluble (et non un secret en clair).
pub(crate) fn is_secret_ref(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("env:") || s.starts_with("file:") || s.starts_with("vault:")
}

/// Résout une référence de secret AU CHARGEMENT (fail-closed) :
///   `env:NOM`      -> variable d'environnement `NOM` (injectée hors-git : sidecar / Secret k8s).
///   `file:/chemin` -> contenu du fichier (Secret k8s monté / rendu Vault-Agent), trimmé.
///   `vault:CHEMIN` -> secret Vault SURFACÉ au loader par Vault-Agent sous la variable d'env de nom dérivé
///                     (CHEMIN sanitizé, MAJUSCULES, non-alnum -> '_') — MÊME canal que le reste de plume
///                     consomme Vault (le loader n'ouvre PAS de session Vault au boot ; cf. docs).
/// Vide -> `Ok("")` (pas de secret). Toute autre forme = SECRET EN CLAIR -> `Err` (rejet fail-closed).
pub(crate) fn resolve_secret_ref(s: &str) -> Result<String, String> {
    // PHASE 2 — dispatch via la grammaire `SecretRef` UNIFIÉE, mais SÉMANTIQUE PROPRE À L'OVERLAY (caller-4)
    // STRICTEMENT PRÉSERVÉE, VOLONTAIREMENT DIFFÉRENTE des callers 1/2/3 (NE PAS homogénéiser) :
    //   - `env:` = `env::var` BRUT (PAS de filter-vide : une var posée à "" -> `Ok("")` ; absente -> `Err`) ;
    //   - `file:` = lecture TRIMMÉE (`.trim()`), tolérante au vide (`Ok("")`) ; absent/illisible -> `Err` ;
    //   - `vault:` = ENV-PROJECTION Vault-Agent (nom d'env DÉRIVÉ du chemin), forme DISTINCTE et toujours
    //     atteignable, séparée du `vault:` HTTP (db-key/tenant/{KEY}_REF) ;
    //   - tout le reste (chemin nu / `literal:` / cleartext) -> `Err` (secret EN CLAIR interdit en git).
    // On réutilise `SecretRef` UNIQUEMENT pour classer le schéma ; les providers PURS du cœur (verbatim /
    // filter-vide) ne conviennent PAS ici (leur sémantique diffère) — on garde donc la lecture inline.
    use guatx_core::secret::SecretRef;
    let s = s.trim();
    if s.is_empty() {
        return Ok(String::new());
    }
    let r = SecretRef::parse(s);
    match r.scheme() {
        "env" => {
            let n = r.rest().trim();
            std::env::var(n)
                .map_err(|_| format!("référence secret env:{n} — variable absente de l'environnement"))
        }
        "file" => {
            let p = r.rest().trim();
            std::fs::read_to_string(p)
                .map(|t| t.trim().to_string()) // TRIM — spécifique caller-4 (PAS verbatim)
                .map_err(|e| format!("référence secret file:{p} — {e}"))
        }
        "vault" => {
            let path = r.rest().trim();
            let var: String = path
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
                .collect();
            std::env::var(&var).map_err(|_| {
                format!("référence secret vault:{path} — attendue projetée par Vault-Agent sous l'env {var}, absente")
            })
        }
        // Unscheme (chemin nu / cleartext) OU `literal:` (non géré en overlay) -> REJET fail-closed.
        _ => Err("valeur de secret EN CLAIR interdite dans un overlay config.d (committé en git) — référencez-la via env:/file:/vault:".into()),
    }
}

/// `true` si le NOM de clé désigne un slot porteur de SECRET (heuristique conservatrice : les clés-URL
/// `*_url`/`*_uri`/`*_endpoint` sont EXCLUES — `token_url` est un endpoint OAuth non-secret, pas un token).
pub(crate) fn oac_key_is_secretish(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    // Clés-secrets EXACTES connues (union connecteur/notifier/destination + génériques prudents).
    const EXACT: &[&str] = &[
        "secret", "secret_ref", "token", "password", "passwd", "pass", "api_key", "apikey",
        "auth_header", "routing_key", "webhook_url", "hec_token", "client_secret", "private_key",
        "bearer", "authorization",
    ];
    if EXACT.contains(&k.as_str()) {
        return true;
    }
    // Les endpoints ne sont JAMAIS des secrets (évite un faux positif sur token_url/secret_uri).
    if k.ends_with("_url") || k.ends_with("_uri") || k.ends_with("_endpoint") {
        return false;
    }
    k.ends_with("_secret")
        || k.ends_with("_token")
        || k.ends_with("_password")
        || k.ends_with("_passwd")
        || k.ends_with("_key")
        || k.ends_with("_apikey")
}

/// Parcourt (au 1er niveau) un objet de config d'overlay : toute clé-secret non vide DOIT être une RÉFÉRENCE
/// (`env:`/`file:`/`vault:`) -> résolue EN PLACE ; une valeur EN CLAIR -> `Err` (l'objet entier est REJETÉ,
/// fail-closed). Les clés non-secrètes sont laissées telles quelles.
pub(crate) fn scrub_config_secrets(cfg: &mut Value) -> Result<(), String> {
    let obj = match cfg.as_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };
    for (k, v) in obj.iter_mut() {
        if !oac_key_is_secretish(k) {
            continue;
        }
        if let Some(s) = v.as_str() {
            if s.trim().is_empty() {
                continue;
            }
            if is_secret_ref(s) {
                let resolved = resolve_secret_ref(s)?;
                *v = Value::String(resolved);
            } else {
                return Err(format!(
                    "clé secret '{k}' contient un secret EN CLAIR — référencez-la via env:/file:/vault: (jamais de secret committé en git)"
                ));
            }
        }
    }
    Ok(())
}

// =====================================================================================================
// PLAN D'UPSERT override-safe (mirroir de la discipline `managed` de overlays.rs).
// =====================================================================================================

pub(crate) enum UpsertPlan {
    Insert,
    Update(i64),
    /// ligne `managed=2` (ad-hoc UI) du même nom -> on NE clobber PAS l'objet utilisateur.
    SkipUser,
}

/// Décide de l'action pour un objet overlay keyé par `name`. `table` est un littéral fixe de l'appelant
/// (aucune injection). aucune ligne -> Insert ; managed 0/1 -> Update (l'overlay possède) ; managed 2 -> Skip.
pub(crate) fn plan_upsert(conn: &Connection, table: &str, name: &str) -> UpsertPlan {
    match conn.query_row(
        &format!("SELECT id, managed FROM {table} WHERE name=?1"),
        params![name],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok((id, managed)) => {
            if managed == 2 {
                UpsertPlan::SkipUser
            } else {
                UpsertPlan::Update(id)
            }
        }
        Err(_) => UpsertPlan::Insert,
    }
}

/// Nom d'overlay (champ `name` trimmé, non vide) ou None (WARN émis par l'appelant).
fn overlay_name(v: &Value) -> Option<String> {
    let n = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if n.is_empty() { None } else { Some(n) }
}

// =====================================================================================================
// LOADERS par type d'objet. Chacun : lit config.d/<sous-dossier>/*.json, valide (MÊMES validateurs que
// l'API), UPSERT override-safe managed=1. Renvoie le nombre d'objets posés.
// =====================================================================================================

/// NOTIFIERS (canaux d'alerte). Secret dans `config` (token/pass/webhook_url/routing_key/auth_header) ->
/// référencé indirectement. `url`/`url_ref` : l'endpoint (peut porter un token pour un webhook -> `url_ref`).
pub(crate) fn load_overlay_notifiers(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    const KINDS: &[&str] = &["ntfy", "webhook", "email", "slack", "pagerduty", "generic", "lookup"];
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN notifier {} sans 'name' — ignoré", path.display()); continue } };
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("ntfy").trim().to_string();
        if !KINDS.contains(&kind.as_str()) {
            eprintln!("[oac] WARN notifier '{name}' : kind '{kind}' hors allowlist — ignoré");
            continue;
        }
        // url : `url_ref` (résolu) l'emporte sur `url`. Validation `safe_url` comme notifier_create.
        let url = match v.get("url_ref").and_then(|x| x.as_str()) {
            Some(r) => match resolve_secret_ref(r) { Ok(u) => u, Err(e) => { eprintln!("[oac] WARN notifier '{name}' : url_ref — {e} — ignoré"); continue } },
            None => v.get("url").and_then(|x| x.as_str()).unwrap_or("").trim().to_string(),
        };
        if notifier_kind_needs_url(&kind) {
            if !safe_url(&url) { eprintln!("[oac] WARN notifier '{name}' : url requise/invalide pour kind '{kind}' — ignoré"); continue; }
        } else if !url.is_empty() && !safe_url(&url) {
            eprintln!("[oac] WARN notifier '{name}' : url invalide — ignoré");
            continue;
        }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = scrub_config_secrets(&mut config) {
            eprintln!("[oac] WARN notifier '{name}' : {e} — REJETÉ");
            continue;
        }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let min_sev = v.get("min_severity").and_then(|x| x.as_i64()).unwrap_or(2).clamp(0, 4);
        let config_s = config.to_string();
        match plan_upsert(conn, "notifier", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN notifier '{name}' : un canal UI (managed=2) du même nom existe — overlay ignoré (renommez l'un des deux)"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE notifier SET kind=?1, enabled=?2, url=?3, min_severity=?4, config=?5, managed=1 WHERE id=?6", params![kind, enabled, url, min_sev, config_s, id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO notifier(name,kind,enabled,url,min_severity,config,managed) VALUES(?1,?2,?3,?4,?5,?6,1)", params![name, kind, enabled, url, min_sev, config_s]); }
        }
        n += 1;
    }
    n
}

/// DESTINATIONS (#50 forward vers sink externe). Secret dans `config` (hec_token/auth_header) -> référencé.
/// `endpoint`/`endpoint_ref` non-secret (validé schéma+anti-metadata). `filter` = sélecteur allowlisté.
pub(crate) fn load_overlay_destinations(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN destination {} sans 'name' — ignorée", path.display()); continue } };
        let dtype = v.get("type").and_then(|x| x.as_str()).unwrap_or("webhook").trim().to_string();
        if !dest_type_ok(&dtype) { eprintln!("[oac] WARN destination '{name}' : type '{dtype}' hors allowlist — ignorée"); continue; }
        let endpoint = match v.get("endpoint_ref").and_then(|x| x.as_str()) {
            Some(r) => match resolve_secret_ref(r) { Ok(u) => u, Err(e) => { eprintln!("[oac] WARN destination '{name}' : endpoint_ref — {e} — ignorée"); continue } },
            None => v.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").trim().to_string(),
        };
        if !dest_endpoint_ok(&dtype, &endpoint) { eprintln!("[oac] WARN destination '{name}' : endpoint invalide pour type '{dtype}' — ignorée"); continue; }
        let filter_v = v.get("filter").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = DestFilter::from_json(&filter_v).validate() { eprintln!("[oac] WARN destination '{name}' : filtre invalide ({e}) — ignorée"); continue; }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = scrub_config_secrets(&mut config) { eprintln!("[oac] WARN destination '{name}' : {e} — REJETÉE"); continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let batch_max = v.get("batch_max").and_then(|x| x.as_i64()).unwrap_or(500).clamp(1, 10000);
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(30).max(5);
        let (config_s, filter_s) = (config.to_string(), filter_v.to_string());
        match plan_upsert(conn, "destination", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN destination '{name}' : une destination UI (managed=2) du même nom existe — overlay ignoré"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE destination SET type=?1, enabled=?2, endpoint=?3, config=?4, filter=?5, batch_max=?6, interval_s=?7, managed=1 WHERE id=?8", params![dtype, enabled, endpoint, config_s, filter_s, batch_max, interval_s, id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,managed,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9)", params![dtype, name, enabled, endpoint, config_s, filter_s, batch_max, interval_s, now()]); }
        }
        n += 1;
    }
    n
}

/// CONNECTEURS (#3a sources externes). Credential = colonne `secret` (JAMAIS dans `config_json`) référencée
/// via `secret_ref`. `config_json` = identifiants NON-secrets (client_id/api_root/...) validés par type.
pub(crate) fn load_overlay_connectors(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    const TYPES: &[&str] = &["defender", "taxii2", "http_pull"];
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN connecteur {} sans 'name' — ignoré", path.display()); continue } };
        let ctype = v.get("type").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if !TYPES.contains(&ctype.as_str()) { eprintln!("[oac] WARN connecteur '{name}' : type '{ctype}' hors allowlist (defender|taxii2|http_pull) — ignoré"); continue; }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        // Validation de forme PAR TYPE (miroir de connector_create).
        let cfg_ok = match ctype.as_str() {
            "http_pull" => {
                let has_url = config.get("url").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                    || config.get("api_root").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                let has_path = config.get("records_path").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                let has_map = config.get("field_map").and_then(|x| x.as_object()).map(|o| !o.is_empty()).unwrap_or(false);
                has_url && has_path && has_map
            }
            "taxii2" => config.get("api_root").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && config.get("collection_id").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            "defender" => config.get("azure_tenant").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && config.get("client_id").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            _ => false,
        };
        if !cfg_ok { eprintln!("[oac] WARN connecteur '{name}' : config invalide/incomplète pour type '{ctype}' — ignoré"); continue; }
        // Le secret NE vit QUE dans la colonne `secret`, via `secret_ref`. Un `secret` en clair top-level -> rejet.
        if v.get("secret").map(|s| !s.is_null()).unwrap_or(false) {
            eprintln!("[oac] WARN connecteur '{name}' : champ 'secret' en clair interdit — utilisez 'secret_ref' (env:/file:/vault:) — REJETÉ");
            continue;
        }
        let secret = match resolve_secret_ref(v.get("secret_ref").and_then(|x| x.as_str()).unwrap_or("")) {
            Ok(s) => s,
            Err(e) => { eprintln!("[oac] WARN connecteur '{name}' : secret_ref — {e} — REJETÉ"); continue; }
        };
        // Défense en profondeur : le config_json ne DOIT pas porter de secret (le split est structurel).
        if let Err(e) = scrub_config_secrets(&mut config) { eprintln!("[oac] WARN connecteur '{name}' : {e} — REJETÉ"); continue; }
        let env_id = v.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").trim().to_string();
        if !env_slug_ok(&env_id) { eprintln!("[oac] WARN connecteur '{name}' : env_id '{env_id}' invalide — ignoré"); continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(300).max(60);
        let config_s = config.to_string();
        match plan_upsert(conn, "connector", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN connecteur '{name}' : un connecteur UI (managed=2) du même nom existe — overlay ignoré"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE connector SET type=?1, enabled=?2, config_json=?3, secret=?4, interval_s=?5, env_id=?6, managed=1 WHERE id=?7", params![ctype, enabled, config_s, secret, interval_s, env_id, id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,managed,created) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)", params![ctype, name, enabled, config_s, secret, interval_s, env_id, now()]); }
        }
        n += 1;
    }
    n
}

/// INDEX-POLICIES (#49). Aucun secret. name = un env_id (env_id_ok) ; rétention clampée [7,3650] si > 0.
pub(crate) fn load_overlay_index_policies(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN index-policy {} sans 'name' — ignorée", path.display()); continue } };
        if !env_id_ok(&name) { eprintln!("[oac] WARN index-policy '{name}' : nom hors allowlist env_id — ignorée"); continue; }
        let rdays = v.get("retention_days").and_then(|x| x.as_i64()).unwrap_or(0);
        let max_rows = v.get("max_rows").and_then(|x| x.as_i64()).unwrap_or(0);
        let max_bytes = v.get("max_bytes").and_then(|x| x.as_i64()).unwrap_or(0);
        if rdays < 0 || max_rows < 0 || max_bytes < 0 { eprintln!("[oac] WARN index-policy '{name}' : valeurs négatives interdites — ignorée"); continue; }
        let rd = if rdays > 0 { rdays.clamp(7, 3650) } else { 0 };
        let description = v.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        match plan_upsert(conn, "index_policy", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN index-policy '{name}' : une policy UI (managed=2) du même nom existe — overlay ignorée"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE index_policy SET retention_days=?1, max_rows=?2, max_bytes=?3, description=?4, enabled=?5, managed=1, updated=?6, updated_by='config.d' WHERE id=?7", params![rd, max_rows, max_bytes, description, enabled, now(), id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description,enabled,managed,created,updated,updated_by) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7,'config.d')", params![name, rd, max_rows, max_bytes, description, enabled, now()]); }
        }
        n += 1;
    }
    n
}

/// FIELD-FILTERS (#45 masquage par champ). Aucun secret. field/action/role validés comme field_filter_create.
pub(crate) fn load_overlay_field_filters(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    const ACTIONS: &[&str] = &["mask", "partial", "hash", "redact", "deny"];
    const ROLES: &[&str] = &["", "viewer", "editor", "admin"];
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN field-filter {} sans 'name' — ignoré", path.display()); continue } };
        let field = match validate_field(v.get("field").and_then(|x| x.as_str()).unwrap_or("")) {
            Ok(f) => f,
            Err(e) => { eprintln!("[oac] WARN field-filter '{name}' : champ invalide ({e}) — ignoré"); continue; }
        };
        let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("mask").to_ascii_lowercase();
        if !ACTIONS.contains(&action.as_str()) { eprintln!("[oac] WARN field-filter '{name}' : action '{action}' hors allowlist — ignoré"); continue; }
        let role = v.get("role").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if !ROLES.contains(&role.as_str()) { eprintln!("[oac] WARN field-filter '{name}' : rôle '{role}' hors allowlist — ignoré"); continue; }
        let tenant = v.get("tenant").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let env = v.get("env").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if !env.is_empty() && !env_id_ok(&env) { eprintln!("[oac] WARN field-filter '{name}' : env '{env}' invalide — ignoré"); continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let ord = v.get("ord").and_then(|x| x.as_i64()).unwrap_or(0);
        match plan_upsert(conn, "field_filter", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN field-filter '{name}' : un filtre UI (managed=2) du même nom existe — overlay ignoré"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE field_filter SET field=?1, action=?2, role=?3, tenant=?4, env=?5, enabled=?6, ord=?7, managed=1, updated=?8 WHERE id=?9", params![field, action, role, tenant, env, enabled, ord, now(), id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,managed,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?9)", params![name, field, action, role, tenant, env, enabled, ord, now()]); }
        }
        n += 1;
    }
    n
}

/// LE SQL BRUT D'UN OVERLAY DE PANNEAU — frontière ÉTABLIE, plus seulement constatée (P7.9-a).
///
/// Le CRUD HTTP des panneaux garde le SQL brut derrière `raw_sql_allowed` (admin, et pas de
/// permission `raw_sql` retirée) — `dash_ergonomics.rs` à l'INSERT comme à l'UPDATE. Ce chemin-ci
/// n'y passe pas, et c'est ASSUMÉ : établi par lecture le 2026-08-03, il n'est atteignable que par
/// `main() -> run() -> open_and_migrate_db -> load_overlays`, c'est-à-dire AU DÉMARRAGE. Aucune
/// route HTTP, aucune commande CLI, aucun job de fond n'y mène — donc aucun utilisateur
/// authentifié, quel que soit son rôle, ne peut le déclencher. La source est le répertoire
/// `PLUME_CONFIG_DIR`, baké dans l'image (`chmod a+rX`, process `USER soc` non-propriétaire) ou
/// monté en ConfigMap, sous `readOnlyRootFilesystem`/`read_only`. Écrire là, c'est être opérateur :
/// l'auteur d'un overlay est déjà équivalent-admin, et lui redemander un rôle n'a pas de sens.
///
/// CE QUI MANQUAIT VRAIMENT. Le chemin JUMEAU des règles/playbooks REFUSE le SQL brut au
/// chargement (`overlays.rs`), et sa raison écrite est double : « contournerait le gate admin
/// `raw_sql_allowed` ET LE LEDGER D'AUDIT plume (seul un commit git la tracerait) ». Le premier
/// motif ne vaut pas ici (pas d'utilisateur), mais LE SECOND SI : un panneau en SQL brut arrivait
/// sans laisser la moindre trace côté plume. On ne renverse donc pas la décision — on la DÉCLARE
/// et on la TRACE, comme le fait déjà son jumeau de son côté.
fn tracer_panneau_sql_brut(conn: &Connection, kind: &str, name: &str) {
    let _ = audit_config_change(
        conn,
        "config.overlay.raw_sql",
        &format!("{kind} overlay '{name}' posé en SQL brut (auteur d'overlay = équivalent-admin)"),
        3,
        &format!("overlay config.d : {kind} '{name}' en SQL brut accepté au chargement (hors gate raw_sql_allowed, tracé ici)"),
        &json!({ "op": "accept", "kind": kind, "name": name, "reason": "raw-sql-overlay-operator-authored" }).to_string(),
    );
}

/// LIBRARY-PANELS (#54 panneaux réutilisables). Aucun secret. Requête validée par compile_panel_sql.
pub(crate) fn load_overlay_library_panels(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN library-panel {} sans 'name' — ignoré", path.display()); continue } };
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("Panneau").to_string();
        let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let is_soql = v.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
        if let Err(e) = compile_panel_sql(&query, is_soql, 0, 0, None) { eprintln!("[oac] WARN library-panel '{name}' : requête invalide ({e}) — ignoré"); continue; }
        if !is_soql { tracer_panneau_sql_brut(conn, "library-panel", &name); }
        let viz = v.get("viz").and_then(|x| x.as_str()).unwrap_or("table").to_string();
        let drill = v.get("drill").and_then(|x| x.as_str()).unwrap_or("").to_string();
        match plan_upsert(conn, "library_panel", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN library-panel '{name}' : un panneau UI (managed=2) du même nom existe — overlay ignoré"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE library_panel SET title=?1, query=?2, is_soql=?3, viz=?4, drill=?5, managed=1, updated=?6 WHERE id=?7", params![title, query, is_soql as i64, viz, drill, now(), id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO library_panel(name,title,query,is_soql,viz,drill,visibility,managed,created,updated) VALUES(?1,?2,?3,?4,?5,?6,'shared',1,?7,?7)", params![name, title, query, is_soql as i64, viz, drill, now()]); }
        }
        n += 1;
    }
    n
}

/// NOTIFICATION-POLICIES (routage des alertes vers des canaux). Aucun secret. matchers validés (allowlist de
/// champs) ; contact_points = ids de notifiers (CSV, existence NON vérifiée, comme policy_create).
pub(crate) fn load_overlay_notification_policies(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN notification-policy {} sans 'name' — ignorée", path.display()); continue } };
        let matchers_v = v.get("matchers").cloned().unwrap_or_else(|| json!({}));
        let matchers = match parse_matchers(&matchers_v) { Ok(m) => m, Err(e) => { eprintln!("[oac] WARN notification-policy '{name}' : matchers invalides ({e}) — ignorée"); continue; } };
        let matchers_s = matchers_to_json(&matchers);
        let cps: Vec<i64> = v.get("contact_points").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|e| e.as_i64()).collect()).unwrap_or_default();
        if cps.is_empty() || cps.len() > 32 { eprintln!("[oac] WARN notification-policy '{name}' : contact_points (ids de canaux) vide ou > 32 — ignorée"); continue; }
        let cps_s = cps.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let cont = v.get("continue").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        match plan_upsert(conn, "notification_policy", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN notification-policy '{name}' : une policy UI (managed=2) du même nom existe — overlay ignorée"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE notification_policy SET matchers=?1, contact_points=?2, continue_=?3, enabled=?4, managed=1 WHERE id=?5", params![matchers_s, cps_s, cont, enabled, id]); }
            UpsertPlan::Insert => { let _ = conn.execute("INSERT INTO notification_policy(name,matchers,contact_points,continue_,enabled,managed,created,created_by) VALUES(?1,?2,?3,?4,?5,1,?6,'config.d')", params![name, matchers_s, cps_s, cont, enabled, now()]); }
        }
        n += 1;
    }
    n
}

/// DASHBOARDS (+ leurs PANNEAUX). Aucun secret. Chaque panneau validé par compile_panel_sql. Le jeu de
/// panneaux managed=1 d'un dashboard managed est REMPLACÉ à l'identique du fichier (idempotent).
pub(crate) fn load_overlay_dashboards(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN dashboard {} sans 'name' — ignoré", path.display()); continue } };
        // Valider TOUS les panneaux AVANT toute écriture (tout-ou-rien : un panneau cassé -> dashboard ignoré).
        let panels = v.get("panels").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        let mut compiled: Vec<(String, String, i64, String, i64, String)> = Vec::new(); // title,query,is_soql,viz,window_s,drill
        let mut bad = false;
        for p in &panels {
            let query = p.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let is_soql = p.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
            if let Err(e) = compile_panel_sql(&query, is_soql, 0, 0, None) { eprintln!("[oac] WARN dashboard '{name}' : panneau invalide ({e}) — dashboard ignoré"); bad = true; break; }
            compiled.push((
                p.get("title").and_then(|x| x.as_str()).unwrap_or("Panneau").to_string(),
                query,
                is_soql as i64,
                p.get("viz").and_then(|x| x.as_str()).unwrap_or("table").to_string(),
                p.get("window_s").and_then(|x| x.as_i64()).unwrap_or(0),
                p.get("drill").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            ));
        }
        if bad { continue; }
        // Même frontière que les library-panels : un panneau de dashboard overlay en SQL brut est
        // opérateur-authoré, donc accepté — mais TRACÉ (cf. `tracer_panneau_sql_brut`).
        if compiled.iter().any(|(_, _, is_soql, _, _, _)| *is_soql == 0) {
            tracer_panneau_sql_brut(conn, "dashboard-panel", &name);
        }
        let did = match plan_upsert(conn, "dashboard", &name) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN dashboard '{name}' : un dashboard UI (managed=2) du même nom existe — overlay ignoré"); continue; }
            UpsertPlan::Update(id) => { let _ = conn.execute("UPDATE dashboard SET managed=1 WHERE id=?1", params![id]); id }
            UpsertPlan::Insert => {
                let _ = conn.execute("INSERT INTO dashboard(name,created,managed) VALUES(?1,?2,1)", params![name, now()]);
                conn.last_insert_rowid()
            }
        };
        // Synchronise les panneaux managed=1 de CE dashboard sur le fichier (remplace intégralement).
        let _ = conn.execute("DELETE FROM panel WHERE dashboard_id=?1 AND managed=1", params![did]);
        for (i, (title, query, is_soql, viz, window_s, drill)) in compiled.iter().enumerate() {
            let _ = conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,window_s,position,drill,managed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",
                params![did, title, query, is_soql, viz, window_s, i as i64, drill],
            );
        }
        n += 1;
    }
    n
}

/// Applique TOUS les overlays d'objets de config d'un `config.d` (sous-dossiers dédiés). Racine absente ->
/// no-op. Appelé DANS `load_overlays_dir` (overlays.rs) APRÈS le contenu de détection.
pub(crate) fn load_oac_overlays_dir(conn: &Connection, root: &std::path::Path) {
    if !root.is_dir() {
        return;
    }
    let nn = load_overlay_notifiers(conn, &root.join("notifiers"));
    let nd = load_overlay_destinations(conn, &root.join("destinations"));
    let nc = load_overlay_connectors(conn, &root.join("connectors"));
    let ni = load_overlay_index_policies(conn, &root.join("index-policies"));
    let nf = load_overlay_field_filters(conn, &root.join("field-filters"));
    let nl = load_overlay_library_panels(conn, &root.join("library-panels"));
    let np = load_overlay_notification_policies(conn, &root.join("notification-policies"));
    let nb = load_overlay_dashboards(conn, &root.join("dashboards"));
    if nn + nd + nc + ni + nf + nl + np + nb > 0 {
        eprintln!("[oac] config.d objets appliqués : {nn} notifier(s), {nd} destination(s), {nc} connecteur(s), {ni} index-policy, {nf} field-filter(s), {nl} library-panel(s), {np} notification-policy, {nb} dashboard(s) — managed=1 (source git)");
    }
}

// =====================================================================================================
// #26 — PRUNE des objets de config OAC orphelins (managed=1 sans fichier adossé). Ne touche JAMAIS
// managed=0/2. Miroir de prune_orphan_overlays (overlays.rs) pour les tables OAC.
// =====================================================================================================

#[derive(Default, Debug, PartialEq)]
pub(crate) struct OacPruneCounts {
    pub(crate) notifier: i64,
    pub(crate) destination: i64,
    pub(crate) connector: i64,
    pub(crate) index_policy: i64,
    pub(crate) field_filter: i64,
    pub(crate) library_panel: i64,
    pub(crate) notification_policy: i64,
    pub(crate) dashboard: i64,
    pub(crate) panel: i64,
}

/// Noms adossés à un fichier pour une table donnée (le `name` de chaque overlay JSON du sous-dossier).
fn backed_names(root: &std::path::Path, sub: &str) -> std::collections::HashSet<String> {
    let mut s = std::collections::HashSet::new();
    for path in overlay_files(&root.join(sub)) {
        if let Some(v) = overlay_read_json(&path) {
            if let Some(n) = overlay_name(&v) {
                s.insert(n);
            }
        }
    }
    s
}

/// Supprime les lignes managed=1 dont le `name` n'est plus adossé. `table` littéral fixe (aucune injection).
fn prune_by_name(conn: &Connection, table: &str, keep: &std::collections::HashSet<String>) -> rusqlite::Result<i64> {
    let orphan_ids: Vec<i64> = {
        let mut st = conn.prepare(&format!("SELECT id,name FROM {table} WHERE managed=1"))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        rows.flatten().filter(|(_, n)| !keep.contains(n)).map(|(id, _)| id).collect()
    };
    let mut n = 0i64;
    for id in &orphan_ids {
        n += conn.execute(&format!("DELETE FROM {table} WHERE id=?1 AND managed=1"), params![id])? as i64;
    }
    Ok(n)
}

/// PRUNE des objets OAC orphelins contre l'état COURANT des fichiers de `root`. Idempotent. Renvoie les
/// comptes par table. Les panneaux managed=1 d'un dashboard pruné (ou dont le dashboard n'existe plus) sont
/// élagués derrière (FK logique).
pub(crate) fn prune_oac_orphans(conn: &Connection, root: &std::path::Path) -> rusqlite::Result<OacPruneCounts> {
    let mut c = OacPruneCounts {
        notifier: prune_by_name(conn, "notifier", &backed_names(root, "notifiers"))?,
        destination: prune_by_name(conn, "destination", &backed_names(root, "destinations"))?,
        connector: prune_by_name(conn, "connector", &backed_names(root, "connectors"))?,
        index_policy: prune_by_name(conn, "index_policy", &backed_names(root, "index-policies"))?,
        field_filter: prune_by_name(conn, "field_filter", &backed_names(root, "field-filters"))?,
        library_panel: prune_by_name(conn, "library_panel", &backed_names(root, "library-panels"))?,
        notification_policy: prune_by_name(conn, "notification_policy", &backed_names(root, "notification-policies"))?,
        dashboard: prune_by_name(conn, "dashboard", &backed_names(root, "dashboards"))?,
        panel: 0,
    };
    // Panneaux managed=1 orphelins (dashboard managed pruné/absent) — jamais les panneaux managed=2 (UI).
    c.panel = conn.execute(
        "DELETE FROM panel WHERE managed=1 AND dashboard_id NOT IN (SELECT id FROM dashboard)",
        [],
    )? as i64;
    Ok(c)
}
