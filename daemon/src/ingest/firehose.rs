//! P-HEC — récepteur d'ingest PUSH AWS Kinesis Data Firehose (CloudTrail / GuardDuty), vendor-agnostic.
//!
//! OBJECTIF (sur-ensemble / zéro-credential-cloud) : un client AWS branche un stream Firehose « HTTP endpoint »
//! sur `POST /api/ingest/firehose` et POUSSE ses logs CloudTrail/GuardDuty vers plume — plume ne détient AUCUNE
//! clé AWS (aucun SigV4, aucun rôle IAM partagé). L'auth est une CLÉ DE LIVRAISON (`X-Amz-Firehose-Access-Key`)
//! mintée par plume à la création de la source push, LIÉE à un connecteur push (-> son `field_map`/`env_id`).
//!
//! RÉUTILISATION MAXIMALE (aucune nouvelle primitive crypto / d'ingest / de mapping) :
//!   - AUTH : `firehose_token_lookup` = `sha256_hex(clé)` + SELECT sur la colonne INDEXÉE `token_hash`
//!     (state.rs) — la MÊME primitive que le HEC/agent (jamais le clair ; la comparaison porte sur le hash).
//!   - MAPPING CIM : `httppull_map_record` (sous-ensemble JSONPath SÛR, injection-safe) + `httppull_records`
//!     (aplatissement d'enveloppe) — le field_map des presets `aws-cloudtrail`/`aws-guardduty` est TRANSPORT-
//!     INDÉPENDANT et réutilisé tel quel.
//!   - SPOOL / INGEST : enveloppe `{kind:events, env_id, events:[…]}` -> spool atomique 0600 -> la boucle de
//!     fond `ingest_events_batch(_env)` (parsers, extracteur, threat-intel, RBA, masquage) — IDENTIQUE au HEC.
//!   - BORNES DoS : `ingest_disk_guard`, permis `ingest_sem`, cap de décompression `otlp_gunzip_capped`,
//!     `ingest_max_events`, + limite de corps `PLUME_INGEST_MAX_BODY_MB` (défaut 8 Mio, couche `limite_corps`) + rate_limit (layer).
//!
//! AUTH HORS auth_guard (comme /services/collector/health) : la route est EXEMPTÉE du choke-point auth_guard et
//! s'AUTO-AUTHENTIFIE ICI (clé -> tenant + connecteur). Une clé absente/mauvaise -> 403 IMMÉDIAT, AVANT tout
//! parse/décompression/spool. Autorité INGEST-ONLY par construction : le handler n'écrit qu'un fichier spool
//! events — aucune autre capacité (jamais UI/admin/agent-responder). Mode 0 byte-identique (route neuve, INERTE
//! tant qu'aucune source push n'existe : firehose_token_lookup -> None).
use crate::*;

/// Plafond DUR d'enregistrements Firehose par requête (un batch Firehose légitime en porte quelques milliers ;
/// buffer ≤ 5 Mo / 128 Mo). Au-delà -> 413 (le stream réduit son buffer et rejoue) : jamais de troncature muette.
const FIREHOSE_MAX_RECORDS: usize = 10_000;
/// Plafond DUR d'events matérialisés par requête (une enveloppe CloudTrail `{"Records":[…]}` peut multiplier).
/// Combiné avec `st.ingest_max_events` (le plus petit gagne) -> 413 au-delà. Miroir de `HEC_MAX_EVENTS`.
pub(crate) const FIREHOSE_MAX_EVENTS: usize = 50_000;
/// Cap de DÉCOMPRESSION gzip du corps Firehose (défaut 16 Mio) — anti-bombe : un corps sous le plafond de `limite_corps` (défaut 8 Mio)
/// peut se décompresser en centaines de Mio -> OOM du pod 2 Gio. MÊME borne prudente que le récepteur OTLP
/// (JSON matérialisé entier avant les caps records/events). Env-override `PLUME_FIREHOSE_MAX_DECOMPRESS` (>=1).
const FIREHOSE_MAX_DECOMPRESS_DEFAULT: usize = 16 * 1024 * 1024;

/// Cap de décompression Firehose effectif (const par défaut, env `PLUME_FIREHOSE_MAX_DECOMPRESS` si valide >0).
pub(crate) fn firehose_max_decompress() -> usize {
    std::env::var("PLUME_FIREHOSE_MAX_DECOMPRESS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(FIREHOSE_MAX_DECOMPRESS_DEFAULT)
}

/// Timestamp Firehose en MILLISECONDES (le contrat HTTP-endpoint attend des ms dans l'ACK/l'erreur).
fn now_ms() -> i64 {
    now().saturating_mul(1000)
}

/// ACK Firehose de SUCCÈS : HTTP 200 `{"requestId":<echo>,"timestamp":<ms>}`. Un non-200 fait REJOUER le stream
/// (puis dumpe dans le bucket S3 d'erreur) -> on ne renvoie 200 QUE si la donnée est spoolée (ou vide-mais-acceptée).
///
/// `S31` (temps 1) — ET « SPOOLÉE » NE VEUT PAS DIRE « DURABLE ». Le fichier est écrit puis renommé, jamais
/// synchronisé : après une coupure d'alimentation, son entrée de répertoire peut manquer. Firehose, lui, a
/// pris ce 200 pour un acquittement définitif et ne rejouera pas. Le corps n'est pas étendu : sa forme est
/// le contrat AWS de l'endpoint HTTP, et un champ inconnu y serait un changement de protocole. La limite est
/// écrite dans `docs/AGENTS-PROTOCOLE.md` et dans le bandeau de `ingest/mod.rs`.
fn firehose_ok(request_id: &str) -> Response {
    (StatusCode::OK, Json(json!({ "requestId": request_id, "timestamp": now_ms() }))).into_response()
}

/// Erreur Firehose : HTTP 4xx/5xx `{"requestId":<echo>,"timestamp":<ms>,"errorMessage":…}` (le stream rejoue).
/// `errorMessage` ne contient JAMAIS de secret (statut/motif générique seul).
fn firehose_err(http: StatusCode, request_id: &str, msg: &str) -> Response {
    (http, Json(json!({ "requestId": request_id, "timestamp": now_ms(), "errorMessage": msg }))).into_response()
}

/// Décode le champ `data` (base64) d'UN record Firehose -> liste d'enregistrements CIM-mappables. Le blob décodé
/// peut être : un objet JSON unique, des objets JSON CONCATÉNÉS `{…}{…}`, du ND-JSON, un array top-level (couverts
/// par `hec_parse_body`), OU une enveloppe CloudTrail `{"Records":[…]}` (aplatie par `httppull_records` selon le
/// `records_path` du connecteur : `Records` pour CloudTrail, `""` pour un événement GuardDuty unique). PURE (aucun
/// I/O) -> testable offline. Blob non-base64 / non-UTF8 / non-JSON -> `[]` (ignoré, jamais un panic).
pub(crate) fn firehose_decode_record_data(data_b64: &str, records_path: &str) -> Vec<Value> {
    use base64::Engine;
    let raw = match base64::engine::general_purpose::STANDARD.decode(data_b64.trim().as_bytes()) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let text = match std::str::from_utf8(&raw) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    // hec_parse_body : objet unique / concaténés / ND-JSON / array top-level -> Vec<Value> (RÉUTILISE le parseur HEC).
    let mut out = Vec::new();
    for item in hec_parse_body(text) {
        // Enveloppe CloudTrail `{"Records":[…]}` -> éléments ; événement GuardDuty (records_path="") -> [item].
        out.extend(httppull_records(&item, records_path));
    }
    out
}

/// POST /api/ingest/firehose — récepteur PUSH AWS Kinesis Firehose (contrat HTTP-endpoint). EXEMPTÉ d'auth_guard :
/// s'auto-authentifie par la clé de livraison `X-Amz-Firehose-Access-Key` (-> tenant + connecteur push lié).
/// Contrat : corps `{"requestId":…,"timestamp":<ms>,"records":[{"data":"<base64>"},…]}` ; succès -> 200
/// `{"requestId":<echo>,"timestamp":<ms>}` ; échec -> 4xx/5xx `{…,"errorMessage":…}` (le stream rejoue).
/// gzip optionnel (`Content-Encoding: gzip`, cap anti-bombe). NE fait AUCUN travail DB sur le worker tokio (spool).
pub(crate) async fn firehose_ingest_post(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1) AUTH EN PREMIER : clé de livraison -> tenant + connecteur lié, AVANT tout travail COÛTEUX (inflate gzip,
    //    parse JSON, décodage base64, spool). LOW#1 (précision) : l'extracteur `Bytes` d'axum a DÉJÀ bufferisé le
    //    corps (borné par `limite_corps`, défaut 8 Mio, + rate_limit en amont) avant cette vérification in-handler ; ce
    //    qui est GARDÉ derrière l'auth n'est pas la lecture du corps mais son TRAITEMENT coûteux. Clé absente/
    //    mauvaise/hors mode 0 -> 403 IMMÉDIAT, avant tout parse/décompression/spool.
    let key = headers.get("x-amz-firehose-access-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let ident = match firehose_token_lookup(&st, key) {
        Some(i) => i,
        None => return firehose_err(StatusCode::FORBIDDEN, "", "invalid or missing X-Amz-Firehose-Access-Key"),
    };
    // request-id d'écho : header standard Firehose (sinon relu du corps après parse).
    let hdr_request_id = headers.get("x-amz-firehose-request-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    // 2) GARDE DISQUE : 503 en pré-saturation (le stream rejoue) — avant toute allocation de corps.
    if ingest_disk_guard(&st).is_some() {
        return firehose_err(StatusCode::SERVICE_UNAVAILABLE, &hdr_request_id, "server busy (disk pressure)");
    }
    // 3) BORNE DE CONCURRENCE : un permis d'ingest décompression-lourde, TENU jusqu'à la fin (décompress + parse
    //    + arbre Value + Vec d'events). N requêtes concurrentes ne matérialisent jamais > `ingest_sem` arbres.
    let _permit = match st.ingest_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return firehose_err(StatusCode::SERVICE_UNAVAILABLE, &hdr_request_id, "server busy (ingest concurrency)"),
    };
    // 4) gzip optionnel (cap anti-bombe AVANT le parse). Corps NON-gzip : borné par `limite_corps` (défaut 8 Mio) mais
    //    on applique le cap par cohérence. RÉUTILISE `otlp_gunzip_capped` (flate2 déjà dans l'arbre).
    let ce = headers.get(axum::http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let raw: Vec<u8> = if ce.contains("gzip") {
        match otlp_gunzip_capped(body.as_ref(), firehose_max_decompress()) {
            Ok(r) => r,
            Err(_) => return firehose_err(StatusCode::PAYLOAD_TOO_LARGE, &hdr_request_id, "decompressed body too large"),
        }
    } else {
        if body.len() > firehose_max_decompress() {
            return firehose_err(StatusCode::PAYLOAD_TOO_LARGE, &hdr_request_id, "body too large");
        }
        body.to_vec()
    };
    // 5) parse l'enveloppe Firehose (SANS panic -> 400).
    let root: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return firehose_err(StatusCode::BAD_REQUEST, &hdr_request_id, "invalid JSON body"),
    };
    let request_id = root.get("requestId").and_then(|x| x.as_str()).filter(|s| !s.is_empty())
        .map(|s| s.to_string()).unwrap_or(hdr_request_id);
    let records = match root.get("records").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return firehose_err(StatusCode::BAD_REQUEST, &request_id, "missing records[]"),
    };
    if records.len() > FIREHOSE_MAX_RECORDS {
        return firehose_err(StatusCode::PAYLOAD_TOO_LARGE, &request_id, "too many records — reduce Firehose buffer and resend");
    }
    // 6) charge le connecteur push LIÉ (field_map + env_id + type) depuis la base du tenant (mode 0 = st.db).
    //    RE-VÉRIFIE type='aws_firehose' : une clé ne peut être honorée que si son binding pointe une source push
    //    VIVANTE (connecteur supprimé / mauvais type -> 403, jamais un mapping arbitraire).
    let handle = st.tenants.handle_for(&ident.tenant).unwrap_or_else(|| st.db.clone());
    let (ctype, cfg_json, env_id): (String, String, String) = {
        let conn = handle.lock();
        match conn.query_row(
            "SELECT type,config_json,env_id FROM connector WHERE id=?1",
            params![ident.connector_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        ) {
            Ok(x) => x,
            Err(_) => return firehose_err(StatusCode::FORBIDDEN, &request_id, "delivery key not bound to a live push source"),
        }
    };
    if ctype != "aws_firehose" {
        return firehose_err(StatusCode::FORBIDDEN, &request_id, "delivery key not bound to a push source");
    }
    let cfg = HttpPullCfg::from_json(&serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})));
    let records_path = cfg.records_path().to_string();
    // 7) décode chaque record (base64 -> JSON/ND-JSON/enveloppe) -> mappe CIM via le field_map réutilisé. Plafond
    //    DUR d'events -> 413 (jamais de troncature muette). `dedup` du field_map (eventID/Id) absorbe le redelivery.
    let max_events = FIREHOSE_MAX_EVENTS.min(st.ingest_max_events);
    let mut events: Vec<Value> = Vec::new();
    for rec in records {
        let data = rec.get("data").and_then(|x| x.as_str()).unwrap_or("");
        if data.is_empty() {
            continue;
        }
        for decoded in firehose_decode_record_data(data, &records_path) {
            if let Some(ev) = httppull_map_record(&decoded, &cfg, ident.connector_id) {
                events.push(ev);
                // NB (P4.1-p, survol du 2026-08-09) : ce refus ne nomme AUCUN levier, et c'est
                // volontairement laissé tel quel — contrairement à MinIO, il ne peut pas mentir sur le
                // remède puisqu'il n'en propose pas. Il ne peut pas non plus chiffrer ce qu'il a reçu :
                // la boucle s'ARRÊTE au plafond (pour ne pas mapper au-delà), donc `events.len()` vaut
                // le plafond + 1, pas le total émis. Le verdict « qui lie » est en revanche mesuré et
                // verrouillé par `le_plafond_qui_lie_est_mesure_sur_les_cinq_routes_d_ingestion`.
                if events.len() > max_events {
                    return firehose_err(StatusCode::PAYLOAD_TOO_LARGE, &request_id, "too many events in one request — reduce Firehose buffer and resend");
                }
            }
        }
    }
    if events.is_empty() {
        // aucun record exploitable -> ACK 200 (rien à écrire ; le stream ne rejoue pas inutilement). LOW#2 :
        // COMPTE ce batch mappé-à-zéro (misconfig field_map/records_path OBSERVABLE au lieu d'un 200 silencieux).
        PUSH_ZERO_MAP_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return firehose_ok(&request_id);
    }
    // 8) spool enveloppe events + `env_id` (routage environnement du connecteur, cf. ingest_once) + marqueur tenant
    //    (R8 ; mode 0 = "") -> ingéré par la boucle de fond (parsers/extracteur/threat-intel/masquage UNIFORMES).
    let env = json!({ "ts": now(), "host": host_self(), "kind": "events", "env_id": env_id, "events": events });
    let body_out = match serde_json::to_string(&env) {
        Ok(s) => s,
        Err(_) => return firehose_err(StatusCode::INTERNAL_SERVER_ERROR, &request_id, "serialize failed"),
    };
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker_for(&st, &ident.tenant);
    let tmp = format!("{}/.fh-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/fh-{}-{}{}.json", st.spool, now(), n, mk);
    if std::fs::write(&tmp, body_out.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return firehose_err(StatusCode::INTERNAL_SERVER_ERROR, &request_id, "spool write failed");
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return firehose_err(StatusCode::INTERNAL_SERVER_ERROR, &request_id, "spool publish failed");
    }
    firehose_ok(&request_id)
}
