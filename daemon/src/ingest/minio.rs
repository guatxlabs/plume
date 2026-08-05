//! Ingestion MinIO audit_webhook natif + endpoints d'ingest génériques. Parseur MinIO (buckets/apis/
//! sévérité/`minio_record_to_event`) reproduisant le relais Python, handler `ingest_minio_post`,
//! endpoint agent générique `ingest_post` (spool), et pont mail (`mail_token_ok`/`mail_body`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ====================================================================================================
// MinIO audit_webhook — PARSEUR NATIF (Option C, étape 1, PASSIF).
// ----------------------------------------------------------------------------------------------------
// OBJECTIF (cf. en-tête de plume/collectors/minio-audit-relay.py) : à terme MinIO postera son
// audit_webhook DIRECTEMENT au daemon (mTLS) sur `POST /api/ingest/minio`, au lieu de transiter par le
// relais Python `minio-audit-relay.py`. Ce parseur reproduit EXACTEMENT la transformation du relais
// (mêmes champs + même sévérité + même filtre de bruit + même scope buckets), CÔTÉ daemon.
//
// ADDITIF / réversible : l'endpoint `/api/ingest` existant et le relais Python restent INCHANGÉS (le
// relais continue de poster `{kind:events,events:[...]}` sur `/api/ingest`). Tant que MinIO n'est pas
// basculé sur `/api/ingest/minio`, ce chemin est purement dormant.
//
// FORMAT NATIF accepté (audit_webhook MinIO, batch_size=1 -> 1 objet JSON/POST ; on tolère aussi un
// array JSON et du ND-JSON) :
//   { "time":"2026-06-28T05:46:28.007Z",
//     "api":{ "name":"DeleteObject","bucket":"backups","object":"<key>","status":"OK","statusCode":204 },
//     "remotehost":"10.42.0.5", "requestID":"18BD28870CA90E93", "userAgent":"MinIO ...",
//     "requestQuery":{ "versionId":"<uuid>" }, "accessKey":"backup-svc" }
//
// EVENT Plume PRODUIT : source=minio-audit, category=data. fields = { bucket, object, api, accessKey,
//   src_ip, status, statusCode, request_id, user_agent, version_delete("1" si suppression de version) }.
//   severity : Delete*/version-delete = 4 ; GetObject = 3 ; Put/Copy/Multipart = 2 ; sinon 1.
//   dedup = requestID (idempotence si MinIO rejoue via queue_dir). Filtre de bruit List*/Head*/GetBucket*/
//   StatObject IGNORÉ ; scope = buckets de sauvegarde (backups,cluster-backups) par défaut.
//
// CONFIG (lue depuis l'ENV, mêmes noms que le relais — vide => "tous") :
//   PLUME_MINIO_AUDIT_BUCKETS   (défaut "backups,cluster-backups" — noms GÉNÉRIQUES : à aligner sur
//                                les buckets réels du déploiement ; les règles livrées filtrent `*backups`)
//   PLUME_MINIO_AUDIT_DROP_APIS (défaut = liste List*/Head*/GetBucket*/GetObjectTagging/StatObject)
// AUTH : MÊME garde que l'ingest agent (Bearer token + mTLS attendu via la route plume-ingest) — ce
//   path est ajouté à l'allowlist Bearer de `auth_guard` à côté de `/api/ingest`.
const MINIO_MAX_EVENTS: usize = 500; // garde-fou evts/req (= PLUME_MINIO_AUDIT_MAXEVENTS du relais)

fn minio_is_delete_api(api: &str) -> bool {
    matches!(api,
        "DeleteObject" | "DeleteObjects" | "DeleteMultipleObjects" | "DeleteObjectVersion"
        | "DeleteObjectTagging" | "DeleteBucket" | "DeleteBucketTagging")
}
fn minio_is_put_api(api: &str) -> bool {
    matches!(api,
        "PutObject" | "CopyObject" | "CompleteMultipartUpload" | "NewMultipartUpload"
        | "PutObjectTagging" | "PutObjectRetention" | "PutObjectLegalHold" | "PostPolicyBucket")
}
fn minio_sev(api: &str, version_delete: bool) -> i64 {
    if version_delete || minio_is_delete_api(api) { 4 }
    else if api == "GetObject" { 3 }
    else if minio_is_put_api(api) { 2 }
    else { 1 }
}
/// Buckets remontés (CSV ENV, vide => TOUS). Défaut = buckets de sauvegarde (scope haute-valeur, faible
/// volume). Noms GÉNÉRIQUES : à aligner par déploiement via `PLUME_MINIO_AUDIT_BUCKETS`.
pub(crate) fn minio_buckets() -> std::collections::HashSet<String> {
    let v = std::env::var("PLUME_MINIO_AUDIT_BUCKETS")
        .unwrap_or_else(|_| "backups,cluster-backups".to_string());
    v.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
}
/// Ops "bruit" (metadata/list/head) ignorées par défaut (un agent de sauvegarde cluster liste ses buckets
/// en boucle -> volume inutile).
/// Mettre PLUME_MINIO_AUDIT_DROP_APIS="" pour TOUT capturer.
pub(crate) fn minio_drop_apis() -> std::collections::HashSet<String> {
    let default = "ListObjects,ListObjectsV2,ListObjectVersions,ListBuckets,ListMultipartUploads,\
HeadObject,HeadBucket,GetBucketLocation,GetBucketObjectLockConfig,GetBucketVersioning,GetBucketPolicy,\
GetBucketTagging,GetBucketLifecycle,GetBucketReplication,GetBucketEncryption,GetBucketNotification,\
GetBucketCors,GetObjectTagging,StatObject";
    let v = std::env::var("PLUME_MINIO_AUDIT_DROP_APIS").unwrap_or_else(|_| default.to_string());
    v.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
}
/// MinIO émet `time` en ISO8601 UTC (`2026-06-28T05:46:28.007Z`). Parse les composantes UTC (fractions
/// + offset ignorés : MinIO poste en Z) -> epoch ; fallback now() si absent/non parsable (= le relais).
pub(crate) fn minio_to_epoch(s: Option<&str>) -> i64 {
    let s = match s { Some(s) if !s.is_empty() => s, _ => return now() };
    let parse = || -> Option<i64> {
        if s.len() < 19 { return None; }
        let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
        let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) { return None; }
        // days-from-civil (Howard Hinnant), UTC : jours depuis 1970-01-01.
        let y2 = if mo <= 2 { y - 1 } else { y };
        let era = (if y2 >= 0 { y2 } else { y2 - 399 }) / 400;
        let yoe = y2 - era * 400;
        let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Some(days * 86400 + h * 3600 + mi * 60 + se)
    };
    parse().unwrap_or_else(now)
}
/// Tolère : 1 objet JSON, un array JSON, ou du ND-JSON (1 objet/ligne) — cf. parse_body du relais.
pub(crate) fn minio_parse_body(raw: &str) -> Vec<Value> {
    let raw = raw.trim();
    if raw.is_empty() { return Vec::new(); }
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        return match v { Value::Array(a) => a, other => vec![other] };
    }
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Ok(v) = serde_json::from_str::<Value>(line) { out.push(v); }
    }
    out
}
/// Un record d'audit MinIO natif -> event Plume (source=minio-audit). None = hors scope/bruit/sans bucket.
/// Reproduit `record_to_event` du relais (mêmes champs, sévérité, message, dedup, filtres).
pub(crate) fn minio_record_to_event(rec: &Value, buckets: &std::collections::HashSet<String>,
                         drop_apis: &std::collections::HashSet<String>) -> Option<Value> {
    let api_o = rec.get("api");
    let getstr = |o: Option<&Value>, k: &str| -> String {
        o.and_then(|v| v.get(k)).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };
    let api = getstr(api_o, "name");
    let bucket = getstr(api_o, "bucket");
    let obj = getstr(api_o, "object");
    let status = getstr(api_o, "status");
    // statusCode : numérique côté MinIO (204) ; on le rend en string comme le relais (str(code)).
    let code = api_o.and_then(|a| a.get("statusCode")).map(|v| match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }).unwrap_or_default();
    // remotehost : [::1] -> ::1 (strip des crochets, comme Python strip("[]")).
    let src = rec.str_field("remotehost")
        .trim_matches(|c| c == '[' || c == ']').to_string();
    let reqid = rec.str_field("requestID").to_string();
    let ak = rec.str_field("accessKey").to_string();
    let ua = rec.str_field("userAgent").to_string();
    // versionId présent ET api de suppression => suppression de VERSION (bool(versionId) du relais).
    let version_id_present = rec.get("requestQuery").and_then(|q| q.get("versionId")).map(|v| match v {
        Value::String(s) => !s.is_empty(),
        Value::Null => false,
        _ => true,
    }).unwrap_or(false);
    let version_delete = version_id_present && minio_is_delete_api(&api);
    // scope : buckets backups par défaut ; on ignore les events admin/sans bucket.
    if !buckets.is_empty() && !buckets.contains(&bucket) { return None; }
    if bucket.is_empty() { return None; }
    // bruit metadata/list/head (velero poll en boucle) ignoré par défaut.
    if drop_apis.contains(&api) { return None; }
    let sev = minio_sev(&api, version_delete);
    let vtag = if version_delete { " VERSION-DELETE" } else { "" };
    let msg = format!("minio-audit {api} {bucket}/{obj} status={status} code={code} ak={ak} src={src} req={reqid}{vtag}");
    let mut fields = serde_json::Map::new();
    fields.insert("bucket".into(), json!(bucket));
    fields.insert("object".into(), json!(obj));
    fields.insert("api".into(), json!(api));
    fields.insert("accessKey".into(), json!(ak));
    fields.insert("src_ip".into(), json!(src));
    fields.insert("status".into(), json!(status));
    fields.insert("statusCode".into(), json!(code));
    fields.insert("request_id".into(), json!(reqid));
    fields.insert("user_agent".into(), json!(ua));
    if version_delete { fields.insert("version_delete".into(), json!("1")); }
    let dedup = if !reqid.is_empty() { format!("minioaudit-{reqid}") }
                else { format!("minioaudit-{api}-{bucket}-{obj}") };
    let mut ev = json!({
        "ts": minio_to_epoch(rec.get("time").and_then(|v| v.as_str())),
        "source": "minio-audit", "category": "data", "severity": sev,
        "message": msg, "dedup": dedup, "fields": Value::Object(fields),
    });
    if !src.is_empty() { ev["src_ip"] = json!(src); }
    Some(ev)
}

/// Ingest NATIF MinIO audit_webhook (Option C, étape 1, PASSIF). Parse le format natif MinIO -> events
/// source=minio-audit (mêmes champs/sévérité que le relais Python), écrit l'enveloppe
/// `{kind:events,events:[...]}` dans le spool (atomique) -> ingérée par la boucle de fond (comme le
/// relais via /api/ingest). NE fait PAS le travail DB sur le worker tokio (parse JSON léger seulement).
/// ADDITIF : /api/ingest + le relais restent INCHANGÉS. Auth = Bearer + mTLS (allowlist auth_guard).
pub(crate) async fn ingest_minio_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, body: String) -> Response {
    if body.trim().is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    // L1 — GARDE DISQUE (avant écriture spool) : 503 explicite en pré-saturation, MinIO rejoue. Le plafond
    // events/req de ce chemin est DÉJÀ MINIO_MAX_EVENTS (miroir du relais), appliqué à la boucle ci-dessous.
    if let Some(resp) = ingest_disk_guard(&st) {
        return resp;
    }
    let buckets = minio_buckets();
    let drop_apis = minio_drop_apis();
    let mut events: Vec<Value> = Vec::new();
    for rec in minio_parse_body(&body) {
        if !rec.is_object() { continue; }
        if let Some(ev) = minio_record_to_event(&rec, &buckets, &drop_apis) {
            events.push(ev);
        }
    }
    // P4.1-p — REFUS EXPLICITE, PLUS DE TRONCATURE SILENCIEUSE.
    //
    // AVANT, cette boucle faisait `if events.len() >= MINIO_MAX_EVENTS { break; }` puis rendait
    // `202 {"queued": true, "events": events.len()}`. Ce n'était pas une troncature « silencieuse » :
    // c'était PIRE. La réponse portait un nombre qui RESSEMBLE à un total alors qu'il comptait ce qui
    // avait été RETENU. MinIO recevait un SUCCÈS, ne rejouait rien, et tout enregistrement au-delà du
    // 500ᵉ disparaissait sans compteur, sans journal, sans en-tête. Le cap mordait à ~265 Kio, soit
    // 31,6x AVANT le plafond de corps — donc en pratique TOUJOURS avant lui.
    //
    // Le chemin générique, vingt lignes plus bas, applique déjà la bonne doctrine, et son commentaire
    // l'énonce : « Refus 413 EXPLICITE (l'agent SCINDE et réémet) -> jamais une troncature
    // silencieuse. » Ce chemin-ci la contredisait en silence.
    //
    // La borne est désormais COMBINÉE avec `st.ingest_max_events` comme sur tous les autres chemins :
    // `PLUME_INGEST_MAX_EVENTS` n'avait AUCUN effet ici, ce qui rendait le levier documenté inopérant
    // sur cette route. Vérifié le 2026-08-05.
    let plafond = MINIO_MAX_EVENTS.min(st.ingest_max_events);
    if events.len() > plafond {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({
            "error": format!(
                "trop d'events dans une seule requête ({} > plafond {plafond}) — scindez le lot et \
                 réémettez, ou relevez PLUME_INGEST_MAX_EVENTS",
                events.len()
            )
        }))).into_response();
    }
    if events.is_empty() {
        // batch entièrement filtré (bruit/hors scope) : MinIO n'a rien à rejouer -> 204.
        return StatusCode::NO_CONTENT.into_response();
    }
    let env = json!({ "ts": now(), "host": host_self(), "kind": "events", "events": events });
    let body_out = match serde_json::to_string(&env) {
        Ok(s) => s,
        Err(_) => return server_err("sérialisation échouée"),
    };
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker(&st, &au); // R8 : tenant du token encodé dans le nom -> routé à la relecture
    // P5.2-a : uniformité des surfaces d'ingestion. Ce chemin déclare `host: host_self()` (le daemon), et
    // les records MinIO ne portent pas d'hôte propre -> avec un jeton NON lié la ligne est inchangée. Avec
    // un jeton LIÉ (le webhook MinIO provisionné pour SA machine), l'attribution devient attestée.
    let hk = spool_host_marker(&au);
    let tmp = format!("{}/.minio-audit-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/minio-audit-{}-{}{}{}.json", st.spool, now(), n, mk, hk);
    if std::fs::write(&tmp, body_out.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return server_err("écriture spool échouée");
    }
    // durcis le spool (0600) avant la publication atomique : umask 022 laissait les fichiers en 0644 (world-readable) -> dataacl.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return server_err("écriture spool échouée");
    }
    (StatusCode::ACCEPTED, Json(json!({ "queued": true, "events": events.len() }))).into_response()
}

/// Ingestion HTTP multi-OS : un agent (Windows/Mac/Linux/distant) pousse le même JSON
/// que les capteurs locaux (kind=events|metrics|firewall|controls…). Écrit dans le spool
/// (atomique) -> ingéré par la boucle. Authentifié + localhost comme le reste.
pub(crate) async fn ingest_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, body: String) -> Response {
    // L1 — GARDE DISQUE : refuse EXPLICITEMENT (503) si le volume du spool est en pré-saturation ->
    // l'agent réémet plus tard (jamais de perte silencieuse ni de disk-pressure qui évince le pod).
    if let Some(resp) = ingest_disk_guard(&st) {
        return resp;
    }
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return bad_req(format!("JSON invalide : {e}")),
    };
    if v.get("kind").and_then(|k| k.as_str()).is_none() {
        return bad_req("champ 'kind' requis (events|metrics|firewall|controls…)");
    }
    // L1 — PLAFOND DUR de cardinalité (events/req) : TRÈS au-dessus d'un batch légitime -> ne coupe qu'un flux
    // pathologique. Refus 413 EXPLICITE (l'agent SCINDE et réémet) -> jamais une troncature silencieuse.
    if ingest_events_over_cap(&v, st.ingest_max_events) {
        let n = v.get("events").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0);
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({
            "error": format!("trop d'events dans une seule requête ({n} > plafond {}) — scindez le batch et réémettez", st.ingest_max_events)
        }))).into_response();
    }
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker(&st, &au); // R8 : tenant du token encodé dans le nom -> routé à la relecture
    let hk = spool_host_marker(&au); // M2 : host LIÉ au token agent -> écrase event.host à la relecture (anti-forge)
    let tmp = format!("{}/.ingest-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/ingest-{}-{}{}{}.json", st.spool, now(), n, mk, hk);
    if std::fs::write(&tmp, body.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return server_err("écriture spool échouée");
    }
    // durcis le spool (0600) avant la publication atomique : umask 022 laissait les fichiers en 0644 (world-readable) -> dataacl.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return server_err("écriture spool échouée");
    }
    (StatusCode::ACCEPTED, Json(json!({ "queued": true }))).into_response()
}

/// Jeton sur : alphanum + qq ponctuations sures (email, id maildir, dossier). PAS d'espace,
/// PAS de `*`/`/`/meta-shell -> sur a passer en argument, y compris a travers `ssh <cmd> ...`.
fn mail_token_ok(s: &str) -> bool {
    !s.is_empty() && s.len() < 256 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:,=+-@".contains(c))
}

/// body-fetch GATE (role=admin) + AUDITE (ledger central + audit agent). Lit le corps COMPLET
/// d'un message via la commande configuree PLUME_MAIL_BODY_CMD (ex local : ".../plume-collector-mail body",
/// ex distant : "ssh agent .../plume-collector-mail body"). On ajoute account/id/folder EN ARGUMENTS
/// (jamais de shell) ; PLUME_ACTOR = qui demande. cf. ADR-0006/0008. Le rendu html se fait en
/// iframe sandbox + CSP cote web (anti-XSS / anti-tracking).
pub(crate) async fn mail_body(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("reserve a l'administrateur");
    }
    let account = b.str_field("account");
    let id = b.str_field("id");
    let folder = b.get("folder").and_then(|v| v.as_str()).unwrap_or("INBOX");
    if !mail_token_ok(account) || !mail_token_ok(id) || !mail_token_ok(folder) {
        return bad_req("account/id/folder requis et sans caracteres speciaux");
    }
    // Plume CANONICAL (PLUME_-only) : PLUME_MAIL_BODY_CMD uniquement.
    let cmd = std::env::var("PLUME_MAIL_BODY_CMD").unwrap_or_default();
    if cmd.trim().is_empty() {
        return err_json(StatusCode::NOT_IMPLEMENTED, "body-fetch non configure (PLUME_MAIL_BODY_CMD)");
    }
    let mut parts = cmd.split_whitespace();
    let prog = parts.next().unwrap_or("");
    let base: Vec<&str> = parts.collect();
    let out = std::process::Command::new(prog)
        .args(&base)
        .arg(account).arg(id).arg(folder)
        // Contrat sous-process : on POSE PLUME_ACTOR (qui demande), lu par le binaire externe PLUME_MAIL_BODY_CMD.
        .env("PLUME_ACTOR", &au.name)
        .output();
    // audit central tamper-evident (en plus de l'event mail-audit cote agent)
    ledger_append(&req_db(&st, &au).lock(), "mail.body.read", &format!("{account} {folder}/{id} by {}", au.name));
    match out {
        Ok(o) if o.status.success() => match serde_json::from_slice::<Value>(&o.stdout) {
            Ok(j) => Json(j).into_response(),
            Err(_) => err_json(StatusCode::BAD_GATEWAY, "sortie body invalide"),
        },
        Ok(o) => err_json(StatusCode::BAD_GATEWAY, format!("body-fetch a echoue : {}", String::from_utf8_lossy(&o.stderr).chars().take(300).collect::<String>())),
        Err(e) => server_err(format!("exec: {e}")),
    }
}
