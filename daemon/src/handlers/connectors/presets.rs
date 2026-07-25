//! Bibliothèque de presets connecteurs (P1 — le PONT preset -> connecteur live). Chantier
//! « connecteurs actifs » : les descriptors `docs/connector-presets/*.json` sont EMBARQUÉS dans le
//! binaire (`include_str!`, même source que la CI `cloud_presets_parse_load_and_are_secret_free`),
//! servis en lecture-seule à l'UI (`GET /api/connectors/presets`, admin-only) et instanciés en 1 clic
//! (`POST /api/connectors/from-preset`, admin-only).
//!
//! PRINCIPE DE RÉUTILISATION (aucune nouvelle surface de secret / SSRF) : `connector_from_preset`
//! NE FAIT QUE pré-remplir le corps d'un create http_pull puis DÉLÈGUE à `connector_create` — le
//! MÊME chemin CRUD (validation url/records_path/field_map, colonne `secret` chiffrée at-rest,
//! `enabled:false` par défaut, audit fail-closed). Le poll/test qui en découle traverse le MÊME
//! `ssrf_guard` au point d'égress (`run_due_connectors`/`connector_test`) — le preset ne crée AUCUN
//! chemin réseau ni credential neuf. La bibliothèque servie ne lit JAMAIS la table `connector` et ne
//! contient AUCUN secret (les descriptors sont secret-free, garanti par la CI existante ; le credential
//! reste saisi à la main par l'admin à l'instanciation -> colonne `secret`).
//!
//! PÉRIMÈTRE AUTH (P1) : seuls les presets dont l'auth est SUPPORTÉE par le moteur `http_pull` actuel
//! (`none`/`basic`/`bearer`/`token`/`header`/`oauth2_client_credentials`) sont INSTANCIABLES. AWS
//! (SigV4) et GCP/Workspace-SA-JWT sont livrés en métadonnée `instantiable:false` (voie push->HEC /
//! phase ultérieure) — le pull-direct de leur API native n'est pas encore construit.
use crate::*;

/// Un preset embarqué : métadonnée d'affichage (curée) + le descriptor JSON brut (`include_str!`).
/// L'`auth_kind`, les `needs` (placeholders à remplir) et le template `config` sont DÉRIVÉS du JSON —
/// zéro duplication. `instantiable`/`note` encodent la décision de périmètre P1 (auth supportée ?).
pub(crate) struct EmbeddedPreset {
    pub id: &'static str,
    pub vendor: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    /// P1 : le moteur sait poller ce preset tel quel (auth supportée) et il n'est pas réservé à une
    /// phase ultérieure. `false` => servi pour information mais REFUSÉ à l'instanciation.
    pub instantiable: bool,
    /// Explication quand `instantiable=false` (voie de livraison alternative). `""` sinon.
    pub note: &'static str,
    /// P-HEC : ce preset est instanciable en SOURCE PUSH (`POST /api/connectors/push-source`) — l'API native
    /// signe (SigV4 / SA-JWT) mais le field_map->CIM est réutilisé sur la voie PUSH. Distinct de `instantiable`
    /// (voie poll http_pull, inchangée). `true` pour aws-cloudtrail/aws-guardduty (Firehose) + gcp-audit (Pub/Sub).
    /// Le TYPE de connecteur/transport minté est dérivé par `preset_push_conn_type` (aws_firehose | gcp_pubsub).
    pub push_source: bool,
    /// Le descriptor JSON brut (config http_pull déclarative, secret-free).
    pub raw: &'static str,
}

/// CATALOGUE EMBARQUÉ (11 presets = `docs/connector-presets/*.json`, même liste que la CI). L'ordre =
/// ordre d'affichage. `instantiable` reflète le support d'auth du moteur ACTUEL (design §3) :
///  - Okta (SSWS header), Entra/M365 (oauth2), Cloudflare (bearer), CrowdStrike (oauth2),
///    SentinelOne (ApiToken header), Google Workspace (bearer court), REST générique (bearer) -> OUI ;
///  - AWS CloudTrail/GuardDuty (SigV4), GCP Cloud Audit (SA-JWT) -> NON en P1 (voie push->HEC).
pub(crate) static PRESETS: &[EmbeddedPreset] = &[
    EmbeddedPreset {
        id: "okta", vendor: "Okta", label: "Okta — System Log", category: "auth",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/okta.json"),
    },
    EmbeddedPreset {
        id: "m365-entra-signin", vendor: "Microsoft", label: "Entra ID — Sign-in logs", category: "auth",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/m365-entra-signin.json"),
    },
    EmbeddedPreset {
        id: "m365-entra-audit", vendor: "Microsoft", label: "Entra ID / M365 — Directory audit", category: "audit",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/m365-entra-audit.json"),
    },
    EmbeddedPreset {
        id: "cloudflare-audit", vendor: "Cloudflare", label: "Cloudflare — Audit Logs", category: "audit",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/cloudflare-audit.json"),
    },
    EmbeddedPreset {
        id: "crowdstrike-falcon", vendor: "CrowdStrike", label: "Falcon — Alerts v2 (EDR)", category: "malware",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/crowdstrike-falcon.json"),
    },
    EmbeddedPreset {
        id: "sentinelone", vendor: "SentinelOne", label: "Singularity — Threats v2.1 (EDR)", category: "malware",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/sentinelone.json"),
    },
    EmbeddedPreset {
        id: "google-workspace", vendor: "Google", label: "Workspace — Admin Reports (login)", category: "auth",
        instantiable: true, push_source: false,
        note: "Le champ secret attend un access_token OAuth2 COURT (kind=bearer) à rafraîchir (sidecar / workload-identity). La signature SA-JWT native arrive dans une phase ultérieure.",
        raw: include_str!("../../../../docs/connector-presets/google-workspace.json"),
    },
    EmbeddedPreset {
        id: "generic-rest", vendor: "Générique", label: "REST/JSON paginée (bring-your-own)", category: "",
        instantiable: true, note: "", push_source: false,
        raw: include_str!("../../../../docs/connector-presets/generic-rest.json"),
    },
    // --- NON instanciables en P1 : auth (SigV4 / SA-JWT) non construite dans le moteur. ---
    EmbeddedPreset {
        id: "aws-cloudtrail", vendor: "AWS", label: "CloudTrail", category: "audit",
        instantiable: false, push_source: true,
        note: "Livraison PUSH (P-HEC) : créez une source push (AWS Kinesis Firehose -> endpoint HTTP de Plume). L'API native signe en SigV4 (non pollable) ; le field_map -> CIM est réutilisé tel quel sur la voie push. Plume ne détient AUCUNE clé AWS.",
        raw: include_str!("../../../../docs/connector-presets/aws-cloudtrail.json"),
    },
    EmbeddedPreset {
        id: "aws-guardduty", vendor: "AWS", label: "GuardDuty", category: "malware",
        instantiable: false, push_source: true,
        note: "Livraison PUSH (P-HEC) : créez une source push (EventBridge `GuardDuty Finding` -> Kinesis Firehose -> endpoint HTTP de Plume). Le field_map -> CIM du finding est réutilisé tel quel. Plume ne détient AUCUNE clé AWS.",
        raw: include_str!("../../../../docs/connector-presets/aws-guardduty.json"),
    },
    EmbeddedPreset {
        id: "gcp-audit", vendor: "GCP", label: "Cloud Audit Logs", category: "audit",
        instantiable: false, push_source: true,
        note: "Livraison PUSH (P-HEC) : créez une source push (log sink -> Pub/Sub -> abonnement push -> endpoint HTTP de Plume `/api/ingest/pubsub?token=…`). L'API native signe en SA-JWT (non pollable) ; le field_map -> CIM de la LogEntry est réutilisé tel quel sur la voie push. Plume ne détient AUCUNE clé GCP.",
        raw: include_str!("../../../../docs/connector-presets/gcp-audit.json"),
    },
];

pub(crate) fn preset_by_id(id: &str) -> Option<&'static EmbeddedPreset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// Scanne une CHAÎNE et collecte ses tokens placeholder (tous ASCII) :
///  - forme accolade `{ident}` (alnum + `_`) -> clé = `ident` ;
///  - forme `REPLACE_[A-Z0-9_]+` (jeton nu, ex. `REPLACE_WITH_APP_CLIENT_ID`) -> clé = le token entier.
/// Ordre préservé, déduplication en place. Les frontières sont ASCII -> le slicing reste UTF-8-valide.
fn scan_placeholders(s: &str, out: &mut Vec<String>) {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        // forme accolade {ident}
        if b[i] == b'{' {
            let mut j = i + 1;
            while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'_') { j += 1; }
            if j < n && b[j] == b'}' && j > i + 1 {
                let key = s[i + 1..j].to_string();
                if !out.contains(&key) { out.push(key); }
                i = j + 1;
                continue;
            }
        }
        // forme REPLACE_...
        if b[i..].starts_with(b"REPLACE_") {
            let mut j = i + "REPLACE_".len();
            while j < n && (b[j].is_ascii_uppercase() || b[j].is_ascii_digit() || b[j] == b'_') { j += 1; }
            if j > i + "REPLACE_".len() {
                let token = s[i..j].to_string();
                if !out.contains(&token) { out.push(token); }
            }
            i = j;
            continue;
        }
        i += 1;
    }
}

/// Marche récursive : collecte tous les placeholders présents dans les FEUILLES chaîne d'un `Value`.
fn collect_placeholders(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => scan_placeholders(s, out),
        Value::Array(a) => a.iter().for_each(|c| collect_placeholders(c, out)),
        Value::Object(o) => o.values().for_each(|c| collect_placeholders(c, out)),
        _ => {}
    }
}

/// Substitue les placeholders dans chaque feuille chaîne. `{key}` (accolade) et le token nu `REPLACE_*`
/// sont remplacés par la valeur admin. Opère sur l'ARBRE (jamais sur le JSON sérialisé) -> aucun risque
/// d'échappement / injection JSON quel que soit le contenu de la valeur admin.
fn substitute(v: &Value, values: &serde_json::Map<String, Value>) -> Value {
    match v {
        Value::String(s) => {
            let mut out = s.clone();
            for (k, val) in values {
                let rep = val.as_str().unwrap_or("");
                out = out.replace(&format!("{{{k}}}"), rep); // forme accolade
                if k.starts_with("REPLACE_") {
                    out = out.replace(k.as_str(), rep); // forme jeton nu
                }
            }
            Value::String(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|c| substitute(c, values)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, c)| (k.clone(), substitute(c, values))).collect()),
        _ => v.clone(),
    }
}

/// Le template `config` servi/instancié = le descriptor SANS la clé de prose `_comment` (déplacée en
/// `description`). Rien d'autre n'est retiré ni ajouté.
fn config_template(raw_val: &Value) -> Value {
    let mut c = raw_val.clone();
    if let Some(o) = c.as_object_mut() {
        o.remove("_comment");
    }
    c
}

/// L'objet public d'un preset servi à l'UI : métadonnée + template `config` (SANS secret). Ne lit
/// JAMAIS la base — 100 % dérivé de la constante embarquée.
pub(crate) fn preset_public(p: &EmbeddedPreset) -> Value {
    let raw_val: Value = serde_json::from_str(p.raw).unwrap_or_else(|_| json!({}));
    let description = raw_val.get("_comment").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let auth_kind = raw_val.get("auth").and_then(|a| a.get("kind")).and_then(|k| k.as_str()).unwrap_or("none").to_string();
    let cfg = config_template(&raw_val);
    let mut needs: Vec<String> = Vec::new();
    collect_placeholders(&cfg, &mut needs);
    json!({
        "id": p.id,
        "vendor": p.vendor,
        "label": p.label,
        "category": p.category,
        "description": description,
        "auth_kind": auth_kind,
        "instantiable": p.instantiable,
        "push_source": p.push_source,   // P-HEC : instanciable en source PUSH (AWS Firehose -> plume)
        "note": p.note,
        "type": "http_pull",
        "requires_secret": auth_kind != "none",
        "needs": needs,          // placeholders (URL/token_url/client_id…) que l'admin doit remplir
        "config": cfg,            // template éditable — AUCUN secret (secret saisi à l'instanciation)
    })
}

/// GET /api/connectors/presets (ADMIN-ONLY) — sert la bibliothèque embarquée (métadonnée + templates,
/// AUCUN secret, AUCUNE lecture de la table `connector`). Read-only pur sur des constantes du binaire.
pub(crate) async fn connector_presets_list(Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let list: Vec<Value> = PRESETS.iter().map(preset_public).collect();
    Json(json!({ "presets": list })).into_response()
}

/// POST /api/connectors/from-preset (ADMIN-ONLY) — instancie un connecteur À PARTIR d'un preset.
/// Corps : { preset_id, name?, values?:{placeholder->valeur}, secret?, env_id?, interval_s? }.
/// N'EFFECTUE AUCUNE écriture ni validation propre : pré-remplit le `config` (template + substitutions)
/// puis DÉLÈGUE à `connector_create` (même validation, même colonne `secret`, même `enabled:false`,
/// même audit). Le secret reste saisi à la main par l'admin et va dans la colonne chiffrée.
pub(crate) async fn connector_from_preset(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let preset_id = b.get("preset_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let preset = match preset_by_id(&preset_id) {
        Some(p) => p,
        None => return bad_req("preset_id inconnu"),
    };
    if !preset.instantiable {
        // AWS/GCP : auth (SigV4/SA-JWT) non construite -> refus explicite (voie push->HEC / phase suivante).
        return bad_req("preset non instanciable en P1 (auth SigV4/SA-JWT non supportée — voir 'note' : voie push->HEC)");
    }
    let raw_val: Value = serde_json::from_str(preset.raw).unwrap_or_else(|_| json!({}));
    let template = config_template(&raw_val);
    // Substitution des placeholders avec les valeurs fournies par l'admin (map vide acceptée).
    let empty = serde_json::Map::new();
    let values = b.get("values").and_then(|x| x.as_object()).unwrap_or(&empty);
    let config = substitute(&template, values);
    // REFUS si un placeholder subsiste (URL/token_url/client_id non renseigné) — miroir de la garde UI.
    let mut remaining: Vec<String> = Vec::new();
    collect_placeholders(&config, &mut remaining);
    if !remaining.is_empty() {
        return bad_req(format!("placeholders non renseignés : {}", remaining.join(", ")));
    }
    // Corps de create pré-rempli. enabled:false (l'admin teste puis active). Tout le reste — validation
    // http_pull, secret -> colonne chiffrée, audit fail-closed — est assuré PAR connector_create.
    let name = b.get("name").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string()).unwrap_or_else(|| preset.label.to_string());
    let mut body = json!({
        "type": "http_pull",
        "name": name,
        "config": config,
        "enabled": false,
    });
    // secret / env_id / interval_s : repassés tels quels au create (secret jamais logué par create).
    if let Some(s) = b.get("secret") { body["secret"] = s.clone(); }
    if let Some(e) = b.get("env_id") { body["env_id"] = e.clone(); }
    if let Some(iv) = b.get("interval_s") { body["interval_s"] = iv.clone(); }
    // DÉLÉGATION — aucun nouveau chemin d'écriture/secret/SSRF : c'est LE create manuel.
    connector_create(State(st), Extension(au), Json(body)).await
}

/// P-HEC — TYPE de connecteur push minté pour un preset `push_source`, et donc son transport de livraison :
///  - GCP (`gcp-audit`) -> `gcp_pubsub` (abonnement Pub/Sub push, auth query `?token=`, endpoint /api/ingest/pubsub) ;
///  - AWS (`aws-cloudtrail`/`aws-guardduty`) -> `aws_firehose` (Kinesis Firehose, header X-Amz-Firehose-Access-Key,
///    endpoint /api/ingest/firehose).
/// "" si le preset n'est PAS une source push. Keyé sur l'`id` (stable, curé dans la constante embarquée).
fn preset_push_conn_type(p: &EmbeddedPreset) -> &'static str {
    if !p.push_source {
        ""
    } else if p.id.starts_with("gcp") {
        "gcp_pubsub"
    } else {
        "aws_firehose"
    }
}

/// Extrait de `raw` (descriptor preset) la config PUSH minimale : SEULS les champs de MAPPING (field_map,
/// records_path, source, sourcetype, sourcetype_map) — url/auth/pagination/watermark (voie poll, avec placeholders)
/// sont ÉCARTÉS (une source push ne poll jamais). Garantit une config sans placeholder REPLACE_* et sans faux `url`.
fn push_config_from_preset(raw: &str) -> Value {
    let v: Value = serde_json::from_str(raw).unwrap_or_else(|_| json!({}));
    let mut cfg = serde_json::Map::new();
    for k in ["field_map", "records_path", "source", "sourcetype", "sourcetype_map"] {
        if let Some(val) = v.get(k) {
            cfg.insert(k.to_string(), val.clone());
        }
    }
    Value::Object(cfg)
}

/// POST /api/connectors/push-source (ADMIN-ONLY, P-HEC) — instancie une SOURCE PUSH AWS (Firehose) à partir d'un
/// preset `push_source` (aws-cloudtrail / aws-guardduty) et MINTE sa clé de livraison (show-once). Corps :
/// `{ preset_id, name?, env_id? }`. CRÉE ATOMIQUEMENT (une seule transaction) : (1) un connecteur `type=aws_firehose`
/// portant le field_map->CIM du preset + env_id (il ne POLL jamais : run_due_connectors exclut ce type) ; (2) une
/// clé de livraison — CSPRNG hex, dont SEUL le SHA-256 est stocké (`token.kind='firehose'`, `connector_id` lié) —
/// jamais le clair (montré UNE fois). Renvoie `{ connector_id, delivery_key (once), endpoint_path, instructions }`.
/// Aucune clé cloud n'est stockée. Fail-closed : si l'audit/insert échoue -> ROLLBACK, la clé renvoyée ne
/// correspondrait à rien -> on ne la renvoie PAS. Mode 1 (control-plane) refusé (comme le provisioning de jetons UI).
pub(crate) async fn connector_push_source(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "source push réservée au mode mono-tenant (clé de livraison via control-plane non supportée)");
    }
    let preset_id = b.get("preset_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let preset = match preset_by_id(&preset_id) {
        Some(p) => p,
        None => return bad_req("preset_id inconnu"),
    };
    if !preset.push_source {
        return bad_req("preset non instanciable en source push (P-HEC : aws-cloudtrail / aws-guardduty / gcp-audit)");
    }
    // TYPE de connecteur push + kind de clé + endpoint DÉRIVÉS du preset (AWS Firehose vs GCP Pub/Sub).
    let conn_type = preset_push_conn_type(preset);
    let (token_kind, endpoint_path): (&str, &str) = if conn_type == "gcp_pubsub" {
        ("gcp_pubsub", "/api/ingest/pubsub")
    } else {
        ("firehose", "/api/ingest/firehose")
    };
    let env_id = b.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").to_string();
    if !env_slug_ok(&env_id) {
        return bad_req("env_id invalide (alnum + _/-)");
    }
    let name = b.get("name").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string()).unwrap_or_else(|| format!("{} (push)", preset.label));
    let mut config = push_config_from_preset(preset.raw);
    if conn_type == "gcp_pubsub" {
        // Pub/Sub push livre UNE LogEntry par message (pas une enveloppe `{"entries":[…]}` — ce records_path est
        // pour la voie poll gateway). records_path="" -> `firehose_decode_record_data` renvoie [LogEntry] (ou
        // splitte un array/ND-JSON défensif). Sans cet override, records_path="entries" mapperait 0 event.
        if let Some(o) = config.as_object_mut() {
            o.insert("records_path".to_string(), json!(""));
        }
    }
    // CSPRNG AVANT la transaction (entropie noyau ; jamais de secret faible). SEUL son SHA-256 sera stocké.
    let Some(delivery_key) = token_rand_hex() else {
        return server_err("entropie noyau indisponible — source push NON créée");
    };
    let hash = sha256_hex(delivery_key.as_bytes());
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    // Connecteur + clé + audit ATOMIQUES fail-closed : la clé renvoyée correspond TOUJOURS à un binding persisté.
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,created) \
             VALUES(?1,?2,1,?3,'',300,?4,?5)",
            params![conn_type, name, config.to_string(), env_id, now()],
        )?;
        let cid = conn.last_insert_rowid();
        // clé de livraison : SHA-256 stocké (jamais le clair), kind=token_kind ('firehose'|'gcp_pubsub' — isolée
        // du seam agent/HEC ET de l'autre voie push), connector_id lié (-> field_map/env_id). token_hash UNIQUE.
        conn.execute(
            "INSERT INTO token(name,token_hash,created,kind,connector_id) VALUES(?1,?2,?3,?4,?5)",
            params![format!("{token_kind}-{cid}"), hash, now(), token_kind, cid],
        )?;
        audit_config_change(
            &conn,
            "config.connector.push_source.create",
            &format!("source push '{name}' ({preset_id}) créée par {} + clé de livraison mintée", au.name),
            3,
            &format!("source push '{name}' ({preset_id}, type={conn_type}, env={env_id}) créée par {} — clé de livraison mintée (SHA-256 stocké)", au.name),
            &json!({ "connector_id": cid, "preset_id": preset_id, "env_id": env_id, "kind": token_kind, "type": conn_type, "actor": au.name }).to_string(),
        )?;
        Ok(cid)
    })();
    match outcome {
        Ok(cid) => {
            let _ = conn.execute_batch("COMMIT");
            // SHOW-ONCE : la clé de livraison n'est renvoyée QU'ICI (jamais re-dérivable ; la lecture connecteur
            // n'expose que has_secret/has_key). Réponse SELON le transport (Firehose header vs Pub/Sub query).
            if conn_type == "gcp_pubsub" {
                // GCP Pub/Sub : le token voyage en QUERY (`?token=`). L'UI compose l'URL push complète (endpoint +
                // ?token=<delivery_token>) à afficher UNE fois ; on NE l'incruste PAS dans `instructions` (le secret
                // ne vit que dans le champ structuré `delivery_token`). Forme DISTINCTE de la réponse Firehose
                // (delivery_token/transport) -> l'UI branche dessus ; la réponse Firehose reste inchangée.
                Json(json!({
                    "connector_id": cid,
                    "delivery_token": delivery_key,
                    "endpoint_path": endpoint_path,
                    "transport": "query_token",
                    "instructions": "Configurez un abonnement Pub/Sub « push » qui POSTe vers <votre-URL-Plume>/api/ingest/pubsub?token=<clé-de-livraison>. Un log sink route vos Cloud Audit Logs vers ce topic Pub/Sub ; chaque message push encapsule une LogEntry, mappée en CIM par le field_map du preset. Aucune clé GCP n'est partagée avec Plume.",
                })).into_response()
            } else {
                // AWS Firehose : réponse INCHANGÉE (delivery_key + header X-Amz-Firehose-Access-Key).
                Json(json!({
                    "connector_id": cid,
                    "delivery_key": delivery_key,
                    "endpoint_path": endpoint_path,
                    "auth_header": "X-Amz-Firehose-Access-Key",
                    "instructions": "Configurez votre delivery stream Kinesis Firehose (destination « HTTP endpoint ») sur <votre-URL-Plume>/api/ingest/firehose, avec l'access key ci-dessus dans le champ « Access key » (envoyée en header X-Amz-Firehose-Access-Key). Aucune clé AWS n'est partagée avec Plume.",
                })).into_response()
            }
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction (aucune source push créée, aucune clé mintée): {e}"))
        }
    }
}
