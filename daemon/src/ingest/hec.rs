//! HEC — endpoint d'ingest WIRE-COMPATIBLE Splunk HTTP Event Collector (#16, bring-your-own-forwarder).
//!
//! OBJECTIF (sur-ensemble / vendor-agnostic) : n'IMPORTE quel forwarder Splunk existant, client HEC ou
//! exporteur OTel-splunk peut poster vers plume SANS nouvel agent. On expose la surface HEC standard :
//!   POST /services/collector          (+ /event)  -> ingest d'events
//!   GET  /services/collector/health              -> liveness (public, sans token, comme Splunk)
//! et on ACCEPTE le format HEC (objet unique, objets CONCATÉNÉS `{...}{...}`, ND-JSON, ou array JSON).
//!
//! ADDITIF / MODE 0 BYTE-IDENTIQUE : ces routes n'existent pas aujourd'hui -> aucune requête existante
//! n'est touchée. L'auth réutilise l'infra token existante (schéma HEC `Authorization: Splunk <tok>` OU
//! `?token=`) -> identité de rôle `agent`, INGEST-ONLY (jamais UI/admin). ATTENTION AU MOT « host-bound »,
//! qui figurait ici et était FAUX pour cette route : le liage d'hôte n'y était PAS appliqué (mesuré
//! usurpable le 2026-08-02 — cf. le bandeau de `hec_event_post`). Il l'est depuis, comme partout, et
//! UNIQUEMENT pour un jeton de MACHINE : un forwarder (jeton `--relais`) reste multi-hôtes.
//! Le mapping sourcetype->CIM
//! est extensible par ENV (PLUME_HEC_SOURCETYPE_MAP) -> zéro hardcode vendeur verrouillé. Le chemin de
//! stockage RÉUTILISE l'ingest existant (envelope `{kind:events}` -> spool -> `ingest_events_batch`).
use crate::*;

/// Garde-fou events/req du chemin HEC (miroir de la borne minio ; l'appelant renvoie 413 HEC au-delà).
const HEC_MAX_EVENTS: usize = 50_000;

/// Routes collector d'events (défaut FERMÉ) : SEULES ces routes acceptent le schéma d'auth HEC (Splunk/
/// token=). `/services/collector/health` en est EXCLU (public, sans token — cf. exemption auth_guard).
pub(crate) fn hec_collector_path(path: &str) -> bool {
    matches!(path, "/services/collector" | "/services/collector/event")
}

/// Extrait le token HEC : `Authorization: Splunk <tok>` (schéma standard, casse tolérée) OU `?token=<tok>`
/// (repli des clients qui posent le token en query). None si aucun. RÉUTILISE l'infra token (token_lookup).
pub(crate) fn hec_token(authz: &str, query: Option<&str>) -> Option<String> {
    if let Some(rest) = authz.strip_prefix("Splunk ").or_else(|| authz.strip_prefix("splunk ")) {
        let t = rest.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(qs) = query {
        for kv in qs.split('&') {
            if let Some(v) = kv.strip_prefix("token=") {
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Override ENV du mapping sourcetype->category : `PLUME_HEC_SOURCETYPE_MAP="st1=cat1,st2=cat2"`. Parsé
/// UNE fois par requête (comme minio_buckets). Clés en minuscule. Permet d'étendre/écraser SANS rebuild
/// (principe sur-ensemble / bring-your-own-vendor). Vide/absent -> map vide (built-in seul).
pub(crate) fn hec_sourcetype_overrides() -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(raw) = std::env::var("PLUME_HEC_SOURCETYPE_MAP") {
        for pair in raw.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().to_string();
                if !k.is_empty() && !v.is_empty() {
                    m.insert(k, v);
                }
            }
        }
    }
    m
}

/// sourcetype Splunk -> `category` CIM (vocabulaire NEUTRE). Override ENV prioritaire, sinon table
/// built-in des sourcetypes courants. GARDE-FOU : la catégorie résolue DOIT être dans la taxonomie CIM
/// (`cim_category_ok`) sinon None (jamais une category hors-contrat). None = pas de mapping -> l'event
/// est stocké AVEC category vide (JAMAIS un drop : un dparser déclaratif peut encore la remplir).
pub(crate) fn hec_category(sourcetype: &str, overrides: &HashMap<String, String>) -> Option<String> {
    let key = sourcetype.trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    // 1) override ENV (extensible, gagne sur le built-in).
    if let Some(cat) = overrides.get(&key) {
        return cim_category_ok(cat).then(|| cat.clone());
    }
    // 2) built-in : sourcetypes Splunk/OTel courants -> CIM. Guidance, pas une liste verrouillée
    //    (l'ENV override couvre tout le reste). Toute valeur ci-dessous est une category CIM valide.
    let cat = match key.as_str() {
        // Web / proxy
        "access_combined" | "access_common" | "access_combined_wcookie" | "apache:access"
        | "apache_access" | "nginx:access" | "nginx_access" | "iis" | "ms:iis" | "httpd" => "web",
        // Auth / secure
        "linux_secure" | "secure" | "auth" | "authpriv" | "pam" | "sshd" | "openssh" => "auth",
        "wineventlog:security" | "winsecurity" | "xmlwineventlog:security" => "auth",
        // Firewall / réseau périmètre
        "cisco:asa" | "cisco_asa" | "pan:traffic" | "pan:firewall" | "fortigate"
        | "fortinet" | "checkpoint" | "iptables" | "pf" | "ufw" => "firewall",
        // IDS/IPS
        "suricata" | "snort" | "bro:notice" | "zeek:notice" | "cisco:ips" => "ids",
        // DNS
        "dns" | "bro:dns" | "zeek:dns" | "named" | "bind" | "isc:bind:query" => "dns",
        // Mail
        "postfix_syslog" | "sendmail_syslog" | "cisco:esa" | "exchange" | "ms:exchange" => "mail",
        // Endpoint / OS
        "wineventlog:system" | "winsystem" => "system",
        "wineventlog:application" | "winapp" => "application",
        "wineventlog" | "sysmon" | "xmlwineventlog:microsoft-windows-sysmon/operational"
        | "linux:audit" | "auditd" | "osquery:results" => "endpoint",
        // Générique syslog / conteneurs
        "syslog" | "rfc5424" | "rfc3164" => "syslog",
        "docker" | "container" | "kube:container" => "container",
        "kube:apiserver" | "kubernetes" | "k8s" => "k8s",
        _ => return None,
    };
    cim_category_ok(cat).then(|| cat.to_string())
}

/// `time` HEC -> epoch SECONDES (i64). Accepte number (epoch s, fraction ms tolérée) ou string numérique.
/// Robustesse : une valeur > 1e12 est interprétée comme des MILLIsecondes (certains clients) -> /1000.
/// None si absent/non numérique -> l'appelant OMET `ts` (l'ingest retombe sur le ts d'enveloppe = now).
pub(crate) fn hec_epoch(v: Option<&Value>) -> Option<i64> {
    let secs = match v? {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !secs.is_finite() || secs <= 0.0 {
        return None;
    }
    let mut s = secs as i64;
    if s > 1_000_000_000_000 {
        s /= 1000; // millis -> secondes
    }
    Some(s)
}

/// Un record HEC -> event Plume (`{ts,source,category,message,host,fields}`) consommable par
/// `ingest_events_batch` (schéma d'ingest EXISTANT). `event` string -> `message` ; `event` objet ->
/// message = JSON compact + champs FUSIONNÉS dans `fields`. `fields` HEC -> colonne `fields`
/// (prioritaire sur les homonymes de l'event objet). sourcetype/index tracés dans `fields` (searchable).
/// None = record inexploitable (ni `event` ni `fields`) -> ignoré (pas de ligne vide).
pub(crate) fn hec_record_to_event(rec: &Value, overrides: &HashMap<String, String>) -> Option<Value> {
    if !rec.is_object() {
        return None;
    }
    let sourcetype = rec.get("sourcetype").and_then(|v| v.as_str()).unwrap_or("");
    let source = rec.get("source").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("hec");
    let host = rec.get("host").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let index = rec.get("index").and_then(|v| v.as_str()).unwrap_or("");

    // fields = `fields` HEC (indexés) d'abord (prioritaires), puis champs de l'event objet (or_insert).
    let mut fields = serde_json::Map::new();
    if let Some(Value::Object(fmap)) = rec.get("fields") {
        for (k, v) in fmap {
            fields.insert(k.clone(), v.clone());
        }
    }
    let message = match rec.get("event") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(obj)) => {
            for (k, v) in obj {
                fields.entry(k.clone()).or_insert_with(|| v.clone());
            }
            serde_json::to_string(&Value::Object(obj.clone())).unwrap_or_default()
        }
        Some(Value::Null) | None => {
            // pas d'`event` : accepté SEULEMENT si des `fields` sont présents (cas metrics HEC).
            if fields.is_empty() {
                return None;
            }
            String::new()
        }
        Some(other) => other.to_string(),
    };
    if !sourcetype.is_empty() {
        fields.entry("sourcetype".to_string()).or_insert_with(|| json!(sourcetype));
    }
    if !index.is_empty() {
        fields.entry("index".to_string()).or_insert_with(|| json!(index));
    }

    let mut ev = serde_json::Map::new();
    if let Some(ts) = hec_epoch(rec.get("time")) {
        ev.insert("ts".to_string(), json!(ts));
    }
    ev.insert("source".to_string(), json!(source));
    if let Some(cat) = hec_category(sourcetype, overrides) {
        ev.insert("category".to_string(), json!(cat));
    }
    ev.insert("message".to_string(), json!(message));
    if let Some(h) = host {
        ev.insert("host".to_string(), json!(h));
    }
    ev.insert("fields".to_string(), Value::Object(fields));
    Some(Value::Object(ev))
}

/// Parse un corps HEC : objet unique, objets CONCATÉNÉS `{...}{...}`, ND-JSON, OU array JSON. Le
/// StreamDeserializer de serde_json itère les valeurs JSON quel que soit le blanc/retour-ligne entre
/// elles (couvre concat + ND-JSON) ; un array top-level est APLATI.
///
/// ING-3 : SKIP-AND-CONTINUE (comme le parseur ligne-à-ligne de `minio_parse_body`). AVANT : `break` au 1er
/// fragment MALFORMÉ -> on ne renvoyait QUE les records AVANT lui, alors que l'appelant ACK succès -> perte
/// SILENCIEUSE partielle. MAINTENANT : sur un fragment invalide, on saute CE fragment (reprise au prochain
/// début de valeur JSON `{`/`[` après l'octet fautif) et on continue -> un corps `{good}{bad}{good}` ingère
/// les DEUX bons records. Les fragments sautés sont comptés/loggés (observabilité, pas de drop muet).
pub(crate) fn hec_parse_body(raw: &str) -> Vec<Value> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut skipped = 0usize;
    let mut pos = 0usize;
    while pos < raw.len() {
        // (re)crée un flux à partir du reliquat non consommé ; sur erreur on avance `pos` puis on RECOMMENCE.
        let mut stream = serde_json::Deserializer::from_str(&raw[pos..]).into_iter::<Value>();
        loop {
            match stream.next() {
                Some(Ok(Value::Array(a))) => out.extend(a),
                Some(Ok(v)) => out.push(v),
                Some(Err(_)) => {
                    skipped += 1;
                    // position absolue de l'octet fautif ; on cherche le prochain début de valeur (`{`/`[`)
                    // STRICTEMENT après lui (fail+1 garantit la progression -> pas de boucle infinie).
                    let fail = pos + stream.byte_offset();
                    let mut nxt = fail + 1;
                    while nxt < raw.len() && bytes[nxt] != b'{' && bytes[nxt] != b'[' { nxt += 1; }
                    pos = nxt;
                    break;
                }
                None => { pos = raw.len(); break; } // flux épuisé proprement
            }
        }
    }
    if skipped > 0 {
        eprintln!("[hec] {skipped} fragment(s) HEC malformé(s) ignoré(s) (skip-and-continue) — {} record(s) retenu(s)", out.len());
    }
    out
}

/// Réponse HEC de SUCCÈS (wire-compatible : les vrais clients HEC vérifient `code==0`).
fn hec_ok(events: usize) -> Response {
    (StatusCode::OK, Json(json!({ "text": "Success", "code": 0, "events": events }))).into_response()
}
/// Réponse HEC d'ERREUR (code HEC standard : 4=Invalid token, 5=No data, …). `code` HTTP + corps HEC.
fn hec_err(http: StatusCode, hec_code: i64, text: &str) -> Response {
    (http, Json(json!({ "text": text, "code": hec_code }))).into_response()
}

/// GET /services/collector/health — liveness HEC (PUBLIC, sans token : exempté dans auth_guard, comme
/// Splunk). Corps standard `{"text":"HEC is healthy","code":17}`.
pub(crate) async fn hec_health() -> Response {
    (StatusCode::OK, Json(json!({ "text": "HEC is healthy", "code": 17 }))).into_response()
}

/// POST /services/collector[/event] — ingest HEC wire-compatible. Auth (token HEC/agent) déjà appliquée
/// par auth_guard (route ingest-only). Parse -> mappe CIM -> écrit l'enveloppe `{kind:events}` dans le
/// spool (atomique, RÉUTILISE `ingest_events_batch` via la boucle de fond). NE fait AUCUN travail DB sur
/// le worker tokio.
///
/// P5.2-a — CE CHEMIN N'AVAIT PAS DE MARQUEUR D'HÔTE, et le justifiait par « un forwarder HEC relaie
/// LÉGITIMEMENT plusieurs hôtes ». C'est vrai d'un RELAIS, et faux d'une MACHINE : MESURÉ le 2026-08-02,
/// un jeton lié à `WS22-LAB` postant `{"event":…,"host":"HEC-USURPE"}` recevait 200 et l'événement était
/// stocké sous `HEC-USURPE`. Le marqueur ci-dessous est posé par `spool_host_marker`, qui n'émet QUE pour
/// un jeton LIÉ : un forwarder (jeton non lié) garde donc EXACTEMENT le comportement d'avant — le champ
/// `host` de chaque record HEC reste autoritatif. La distinction n'est plus une décision de route, c'est
/// le liage du jeton. (Le bandeau du module disait « identité agent host-bound » : c'était faux ICI.)
pub(crate) async fn hec_event_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, body: String) -> Response {
    if body.trim().is_empty() {
        return hec_err(StatusCode::BAD_REQUEST, 5, "No data");
    }
    // L1 — GARDE DISQUE : 503 explicite en pré-saturation (le client HEC rejoue). Réponse HEC serveur (8).
    if ingest_disk_guard(&st).is_some() {
        return hec_err(StatusCode::SERVICE_UNAVAILABLE, 8, "Server is busy");
    }
    let recs = hec_parse_body(&body);
    // PLAFOND DUR de cardinalité : refus 413 HEC (le client scinde et réémet) -> jamais de troncature muette.
    if recs.len() > HEC_MAX_EVENTS.min(st.ingest_max_events) {
        return hec_err(StatusCode::PAYLOAD_TOO_LARGE, 5, "Batch too large — split and resend");
    }
    let overrides = hec_sourcetype_overrides();
    let mut events: Vec<Value> = Vec::new();
    for rec in recs {
        if let Some(ev) = hec_record_to_event(&rec, &overrides) {
            events.push(ev);
        }
    }
    if events.is_empty() {
        return hec_err(StatusCode::BAD_REQUEST, 5, "No data");
    }
    let env = json!({ "ts": now(), "host": host_self(), "kind": "events", "events": events });
    let body_out = match serde_json::to_string(&env) {
        Ok(s) => s,
        Err(_) => return hec_err(StatusCode::INTERNAL_SERVER_ERROR, 8, "Internal server error"),
    };
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker(&st, &au); // R8 : tenant du token encodé dans le nom -> routé à la relecture
    let hk = spool_host_marker(&au); // P5.2-a : jeton LIÉ -> écrase le `host` HEC à la relecture ; relais -> vide
    let tmp = format!("{}/.hec-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/hec-{}-{}{}{}.json", st.spool, now(), n, mk, hk);
    if std::fs::write(&tmp, body_out.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return hec_err(StatusCode::INTERNAL_SERVER_ERROR, 8, "Internal server error");
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return hec_err(StatusCode::INTERNAL_SERVER_ERROR, 8, "Internal server error");
    }
    hec_ok(events.len())
}
