//! #50 — OUTPUTS / DESTINATIONS (forward des events normalisés vers un SINK EXTERNE).
//!
//! Plume ne faisait qu'INGÉRER ; ici il peut aussi SORTIR la donnée normalisée/filtrée vers une cible
//! externe -> il devient une couche de COLLECTE + NORMALISATION devant un autre SIEM (ou un archiveur
//! froid). Complète #40 (qui ROUTE en INTERNE par env_id) : #40 range, #50 exfiltre (explicitement,
//! admin-décidé). Miroir du modèle de confiance/secret du `notifier` webhook (l'admin décide OÙ part sa
//! donnée) et de la discipline curseur/watermark/last_error du connecteur (#3a, mais en SORTIE).
//!
//! SURFACE DE DATA-EXFIL — GARDE-FOUS (toutes appliquées ici) :
//!   - ADMIN-ONLY : CRUD gardé serveur (`au.is_admin()`) + route_min_role Admin (GET compris) — c'est de
//!     la donnée SOC qui QUITTE le périmètre.
//!   - SEND-ONLY / anti-SSRF : on POSTe/écrit vers un endpoint ADMIN-configuré (même trust que le notifier
//!     webhook) et on NE RENVOIE JAMAIS la réponse du sink à l'appelant (statut/motif seul en last_error,
//!     jamais le corps — invariant du client HTTP). Endpoint validé par la MÊME garde SSRF que les notifiers
//!     (`ssrf_guard`/`ssrf_check_host`) — À LA CRÉATION *et* AU POINT D'ÉGRESS : loopback/link-local=metadata/
//!     unspecified/IPv4-mapped-v6 REFUSÉS (RFC1918 opt-in), avec re-check DNS. Une destination interne ne
//!     peut ni être créée ni jamais égresser.
//!   - GOUVERNANCE : create/enable/delete d'une destination est LEDGERISÉ (audit_config_change,
//!     fail-closed transactionnel, source non-purgeable `plume-config`). La donnée qui sort = un événement
//!     d'audit tamper-evident, MÊME quand c'est un admin qui l'exporte.
//!   - SECRET : l'auth du sink (hec_token / auth_header webhook) vit dans le blob `config`, JAMAIS projeté
//!     (has_auth booléen seul, comme notifier.config) et NIÉ en lecture SQL brute par l'authorizer
//!     read-pool (#44/#45, `destination.config`).
//!   - FEED MACHINE (honnêteté) : une destination reçoit des events NORMALISÉS BRUTS (non masqués). Le
//!     masquage field-filter (#45) est un contrôle de LECTURE HUMAINE ; la destination est une infra
//!     explicitement configurée par l'admin -> c'est POURQUOI elle est admin-only + ledgerisée.
//!
//! WATERMARK / AT-LEAST-ONCE : `destination.watermark` = plus grand `event.id` DÉJÀ forwardé (curseur
//! monotone). Le forwarder lit un LOT BORNÉ d'events `id > watermark` matchant le filtre (ORDER BY id ASC
//! LIMIT batch_max), les envoie HORS lock writer, et n'avance le watermark QUE sur envoi RÉUSSI. Un sink
//! mort -> watermark gelé, last_error/error_count posés, re-tente au tick suivant (at-least-once, jamais de
//! trou) SANS jamais bloquer l'ingest (thread séparé ; l'ingest écrit `event` en append-only, ne touche
//! JAMAIS cette table). Sur succès, `id > watermark` exclut le lot -> jamais de ré-envoi infini.
//!
//! MODE 0 (byte-identique) : aucune destination -> `run_due_destinations` sélectionne 0 ligne -> no-op
//! strict (aucun réseau, aucune écriture, zéro coût sur l'ingest).
use crate::*;

// ===================================================================================================
// TYPES DE SINK. syslog | hec | webhook = FAITS. s3 | kafka = DESIGN/STUB (posent last_error explicite,
// n'avancent JAMAIS le watermark, ne crashent jamais).
// ===================================================================================================
pub(crate) fn dest_type_ok(t: &str) -> bool {
    matches!(t, "syslog" | "hec" | "webhook" | "s3" | "kafka")
}
/// Un type EFFECTIVEMENT implémenté (envoie réellement). Les stubs (s3/kafka) répondent explicitement.
pub(crate) fn dest_type_implemented(t: &str) -> bool {
    matches!(t, "syslog" | "hec" | "webhook")
}

/// Longueur max d'une valeur de filtre (borne, anti-abus).
pub(crate) const DEST_TOKEN_MAX: usize = 128;
/// Plafond DUR d'un lot forwardé par tick (borne la RAM + le débit réseau ; backpressure).
pub(crate) const DEST_BATCH_HARD_MAX: i64 = 5000;

/// Valeur de filtre allowlistée (category/source) : non vide, bornée, charset CIM (alnum + `._-:*`).
/// Jamais interpolée en SQL sans binding — c'est une garde de SURFACE, la sécurité vient des bound params.
fn dest_token_ok(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= DEST_TOKEN_MAX
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '*'))
}

// ===================================================================================================
// FILTRE ALLOWLISTÉ (quels events sortent). Réutilise la forme prédicat des politiques d'alerte #48 /
// du processeur #40 : un SÉLECTEUR STRUCTURÉ (jamais du SQL libre). Champs OPTIONNELS, TOUS bornés :
//   category    (eq, CIM)          env_id (eq, #49 env_id_ok)
//   source      (eq)               min_severity (>=, 0..=4)
// Compilé en clause WHERE à BOUND PARAMS -> injection-safe par construction.
// ===================================================================================================
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct DestFilter {
    pub category: Option<String>,
    pub source: Option<String>,
    pub env_id: Option<String>,
    pub min_severity: Option<i64>,
}

impl DestFilter {
    /// Parse un blob JSON de filtre (les clés absentes/vides -> None = pas de contrainte).
    pub(crate) fn from_json(v: &Value) -> DestFilter {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        DestFilter {
            category: s("category"),
            source: s("source"),
            env_id: s("env_id"),
            min_severity: v.get("min_severity").and_then(|x| x.as_i64()).filter(|n| *n != 0),
        }
    }
    /// Valide chaque champ AVANT persistance (fail-closed : un filtre invalide est REFUSÉ à la création,
    /// jamais silencieusement ignoré). env_id via la MÊME allowlist que #49/#40 (env_id_ok).
    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(c) = &self.category {
            if !dest_token_ok(c) { return Err("filter.category invalide (alnum + ._-:*)".into()); }
        }
        if let Some(s) = &self.source {
            if !dest_token_ok(s) { return Err("filter.source invalide (alnum + ._-:*)".into()); }
        }
        if let Some(e) = &self.env_id {
            if !env_id_ok(e) { return Err("filter.env_id invalide (alnum + ._- borné 64)".into()); }
        }
        if let Some(n) = self.min_severity {
            if !(0..=4).contains(&n) { return Err("filter.min_severity hors bornes (0..=4)".into()); }
        }
        Ok(())
    }
    /// Compile la clause WHERE ADDITIONNELLE (bound params) : ` AND category=?N AND ...`. Le premier param
    /// (?1) est TOUJOURS le watermark (curseur `id > ?1`) — construit par l'appelant ; ce compilateur
    /// démarre à ?2. Renvoie (clause, params) où params s'aligne EXACTEMENT sur les placeholders ajoutés.
    pub(crate) fn sql_where(&self, start_idx: usize) -> (String, Vec<rusqlite::types::Value>) {
        use rusqlite::types::Value as SV;
        let mut clause = String::new();
        let mut params: Vec<SV> = Vec::new();
        let mut idx = start_idx;
        if let Some(c) = &self.category {
            clause.push_str(&format!(" AND category = ?{idx}"));
            params.push(SV::Text(c.clone()));
            idx += 1;
        }
        if let Some(s) = &self.source {
            clause.push_str(&format!(" AND source = ?{idx}"));
            params.push(SV::Text(s.clone()));
            idx += 1;
        }
        if let Some(e) = &self.env_id {
            clause.push_str(&format!(" AND env_id = ?{idx}"));
            params.push(SV::Text(e.clone()));
            idx += 1;
        }
        if let Some(n) = self.min_severity {
            clause.push_str(&format!(" AND severity >= ?{idx}"));
            params.push(SV::Integer(n));
        }
        (clause, params)
    }
}

// ===================================================================================================
// VALIDATION D'ENDPOINT (send-only, anti-SSRF). webhook/hec -> http(s):// ; syslog -> tcp://. SEC-FIX #50 :
// la donnée SOC COMPLÈTE (non masquée) sort en continu vers cet endpoint admin-configuré -> on applique la
// MÊME garde SSRF que les notifiers (`ssrf_guard`/`ssrf_check_host` : loopback/link-local=metadata/unspecified/
// mapped-v6 REFUSÉS ; RFC1918 opt-in ; re-check DNS). Rejet À LA CRÉATION -> jamais d'égress vers une cible interne.
// ===================================================================================================
/// Endpoint valide pour ce type de sink ? Schéma correct ET garde SSRF (cible interne refusée à la création).
pub(crate) fn dest_endpoint_ok(dtype: &str, endpoint: &str) -> bool {
    let e = endpoint.trim();
    match dtype {
        "webhook" | "hec" => {
            let low = e.to_ascii_lowercase();
            if !(low.starts_with("http://") || low.starts_with("https://")) {
                return false;
            }
            // garde SSRF complète (host + résolution DNS) — même choke-point que egress_url_ok des notifiers.
            ssrf_guard(e).is_ok()
        }
        "syslog" => {
            let rest = match e.to_ascii_lowercase().strip_prefix("tcp://") {
                Some(_) => e.splitn(2, "://").nth(1).unwrap_or(""),
                None => return false,
            };
            let hostport = rest.split('/').next().unwrap_or("");
            match hostport.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(port) => !h.is_empty() && ssrf_check_host(h, port).is_ok(),
                    Err(_) => false,
                },
                None => false,
            }
        }
        // stubs : endpoint libre (jamais contacté) ; on exige juste non-vide pour l'UI.
        "s3" | "kafka" => !e.is_empty(),
        _ => false,
    }
}

// ===================================================================================================
// SÉRIALISATION D'UN EVENT (feed machine). Round-trip canonique : `fields` (blob JSON en base) reparsé
// en Value si valide, sinon conservé en chaîne. AUCUN masquage (feed machine, cf. en-tête du module).
// ===================================================================================================
#[derive(Debug, Clone)]
pub(crate) struct FwdEvent {
    pub id: i64,
    pub json: Value,
    pub ts: i64,
    pub host: String,
    pub source: String,
    pub category: String,
    pub severity: i64,
}

pub(crate) fn row_to_fwd(
    id: i64, ts: i64, source: String, category: String, severity: i64, message: String,
    host: Option<String>, src_ip: Option<String>, dst_ip: Option<String>, url: Option<String>,
    fields: Option<String>, env_id: String,
) -> FwdEvent {
    let fields_v: Value = fields.as_deref()
        .and_then(|f| serde_json::from_str::<Value>(f).ok())
        .unwrap_or_else(|| fields.clone().map(Value::String).unwrap_or(Value::Null));
    // `json!` MEUT ses feuilles -> on clone les champs RÉUTILISÉS ensuite dans FwdEvent (source/category/host).
    let source_s = source.clone();
    let category_s = category.clone();
    let host_s = host.clone().unwrap_or_default();
    let json = json!({
        "id": id, "ts": ts, "source": source, "category": category, "severity": severity,
        "message": message, "host": host, "src_ip": src_ip, "dst_ip": dst_ip, "url": url,
        "fields": fields_v, "env_id": env_id,
    });
    FwdEvent {
        id, json, ts,
        host: host_s,
        source: source_s, category: category_s, severity,
    }
}

// ===================================================================================================
// WIRE : forme réseau prête à émettre (construite HORS lock, testable sans socket). Le transport réel
// (`dest_transport`) OU un mock (tests) la consomme. Http renvoie un statut (2xx=ok) ; Tcp renvoie 0=ok.
// ===================================================================================================
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Wire {
    Http { method: String, url: String, headers: Vec<(String, String)>, body: Vec<u8> },
    Tcp { host: String, port: u16, body: Vec<u8> },
}

/// Sévérité Plume (0..4) -> sévérité syslog (0..7, RFC5424). Plus le chiffre est BAS, plus c'est grave.
fn syslog_severity(plume_sev: i64) -> i64 {
    match plume_sev { 4 => 2, 3 => 3, 2 => 4, 1 => 5, _ => 6 }
}
/// Neutralise CR/LF (framing syslog par ligne) — anti injection de message.
fn oneline_out(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// Construit une ligne RFC5424 : `<PRI>1 TS HOST plume - - - {json}`. PRI = facility(1=user)*8 + sev.
fn rfc5424_line(ev: &FwdEvent) -> String {
    let pri = 8 + syslog_severity(ev.severity);
    let ts = epoch_to_iso8601(ev.ts);
    let host = if ev.host.is_empty() { "-".to_string() } else { oneline_out(&ev.host) };
    // MSG = JSON compact de l'event (structured payload machine), neutralisé CR/LF pour le framing.
    let msg = oneline_out(&ev.json.to_string());
    format!("<{pri}>1 {ts} {host} plume - - - {msg}")
}

/// Construit la forme WIRE pour un lot d'events selon le type de sink. PURE (aucun socket) -> testable.
/// Lit le SECRET d'auth dans `config` (hec_token / auth_header). Erreur = config/endpoint invalide (jamais
/// le secret dans le message).
pub(crate) fn build_wire(dtype: &str, endpoint: &str, config: &Value, events: &[FwdEvent]) -> Result<Wire, String> {
    match dtype {
        // WEBHOOK : POST d'un tableau JSON d'events (feed machine). Auth optionnelle `config.auth_header`
        // (secret, ex `Authorization: Bearer x`), neutralisée CR/LF (anti-injection d'en-tête).
        "webhook" => {
            let arr: Vec<&Value> = events.iter().map(|e| &e.json).collect();
            let body = json!({ "events": arr }).to_string().into_bytes();
            let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
            let auth = config.get("auth_header").and_then(|x| x.as_str()).unwrap_or("").trim();
            if !auth.is_empty() {
                let (k, v) = match auth.split_once(':') {
                    Some((k, v)) => (oneline_out(k.trim()), oneline_out(v.trim())),
                    None => ("Authorization".to_string(), oneline_out(auth)),
                };
                headers.push((k, v));
            }
            Ok(Wire::Http { method: "POST".into(), url: endpoint.to_string(), headers, body })
        }
        // HEC-OUT : wire-compatible Splunk HTTP Event Collector. POST NDJSON d'enveloppes {time,host,
        // source,sourcetype,event} vers <endpoint>/services/collector/event, auth `Authorization: Splunk <tok>`.
        "hec" => {
            let token = config.get("hec_token").and_then(|x| x.as_str()).unwrap_or("").trim();
            if token.is_empty() {
                return Err("config.hec_token requis (HEC-out)".into());
            }
            let mut body = String::new();
            for e in events {
                let env = json!({
                    "time": e.ts, "host": e.host, "source": e.source,
                    "sourcetype": e.category, "event": e.json,
                });
                body.push_str(&env.to_string());
                body.push('\n');
            }
            let base = endpoint.trim_end_matches('/');
            let url = format!("{base}/services/collector/event");
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), format!("Splunk {}", oneline_out(token))),
            ];
            Ok(Wire::Http { method: "POST".into(), url, headers, body: body.into_bytes() })
        }
        // SYSLOG : RFC5424 sur TCP nu, 1 ligne \n par event (framing par ligne). Endpoint tcp://host:port.
        "syslog" => {
            let rest = endpoint.trim().splitn(2, "://").nth(1).unwrap_or("");
            let hostport = rest.split('/').next().unwrap_or("");
            let (host, port) = hostport.rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), p)))
                .ok_or_else(|| "endpoint syslog invalide (tcp://host:port)".to_string())?;
            let mut body = String::new();
            for e in events {
                body.push_str(&rfc5424_line(e));
                body.push('\n');
            }
            Ok(Wire::Tcp { host, port, body: body.into_bytes() })
        }
        other => Err(format!("type de sink non émissible: {other}")),
    }
}

/// TRANSPORT RÉEL (send-only). Http via le client minimal (jamais le corps de réponse en erreur) ;
/// Tcp via socket nu borné 10 s. À appeler HORS lock writer (le réseau ne bloque JAMAIS l'ingest).
pub(crate) fn dest_transport(w: &Wire) -> Result<u16, String> {
    match w {
        Wire::Http { method, url, headers, body } => {
            // SEC-FIX #50 : garde SSRF AU POINT D'ÉGRESS (choke-point non contournable, y compris si la ligne
            // a été insérée hors du chemin create/update). Cible interne -> Err (last_error, watermark gelé).
            ssrf_guard(url)?;
            let hdr: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            // http_call ne met JAMAIS le corps dans une erreur (invariant #3a) -> statut/motif seul remonte.
            let resp = http_call(method, url, &hdr, Some(body))?;
            Ok(resp.status)
        }
        Wire::Tcp { host, port, body } => {
            use std::io::Write;
            // SEC-FIX #50 : même garde SSRF pour le syslog tcp:// (never-egress interne refusé au point d'envoi).
            ssrf_check_host(host, *port)?;
            let mut sock = std::net::TcpStream::connect((host.as_str(), *port))
                .map_err(|e| format!("connexion syslog {host}:{port} : {e}"))?;
            let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
            sock.write_all(body).map_err(|e| format!("écriture syslog : {e}"))?;
            Ok(0) // succès TCP (pas de statut applicatif)
        }
    }
}

/// Un envoi est-il un SUCCÈS ? Tcp -> 0 ; Http -> 2xx. Tout autre statut = échec (watermark non avancé).
fn transport_ok(status: u16) -> bool {
    status == 0 || (200..300).contains(&status)
}

// ===================================================================================================
// FORWARDER (cœur). Miroir SORTIE de poll_one_connector : lit un lot borné, envoie HORS lock, avance le
// watermark UNIQUEMENT sur succès. FAIL-SAFE : ne remonte jamais (toute erreur -> last_error).
// ===================================================================================================
/// Forwarde UN lot pour la destination `id`. `transport` injectable (mock en test, `dest_transport` en
/// prod). `now_ts` figé par l'appelant. Ne panique jamais (l'appelant l'enrobe en catch_unwind malgré tout).
///
/// REND SON BILAN (`P4.1-r`) : `Illisible` si le lot d'événements n'a pas pu être lu — la destination n'a
/// rien transmis ce tick, son `last_error` le dit désormais aussi ; `Lue(n)` sinon, où `n` compte un
/// événement du lot que la base n'a pas su décoder. Un tel événement ne part PAS et le lot est refusé
/// (filigrane gelé, `last_error` nomme l'identifiant) : avant, `.flatten()` le sautait et le filigrane
/// passait dessus — un événement JAMAIS transmis au SOC, sans aucune trace.
pub(crate) fn forward_one_destination<T>(
    db: &Arc<Mutex<Connection>>, id: i64, dtype: &str, endpoint: &str,
    config_json: &str, filter_json: &str, batch_max: i64, watermark: i64, now_ts: i64, transport: T,
) -> crate::bilan_de_tick::BilanDeTick
where
    T: Fn(&Wire) -> Result<u16, String>,
{
    use crate::mesure_environnement::Mesure;
    // STUBS s3/kafka : jamais de réseau, watermark JAMAIS avancé, last_error explicite (non-silence).
    if !dest_type_implemented(dtype) {
        let conn = db.lock();
        let _ = conn.execute(
            "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
            params![now_ts, format!("type '{dtype}' = design/stub (non implémenté ; aucun forward)"), id],
        );
        return Mesure::Lue(0);
    }
    let filt = DestFilter::from_json(&serde_json::from_str::<Value>(filter_json).unwrap_or_else(|_| json!({})));
    let batch = batch_max.clamp(1, DEST_BATCH_HARD_MAX);

    // 1) LOT BORNÉ d'events NEUFS matchant le filtre (curseur id > watermark). Bound params : ?1=watermark,
    //    puis le filtre. Lecture SOUS lock writer, BORNÉE (LIMIT) -> brève ; RELÂCHÉE avant le réseau.
    let (clause, fparams) = filt.sql_where(2);
    let sql = format!(
        "SELECT id,ts,source,category,severity,message,host,src_ip,dst_ip,url,fields,env_id \
         FROM event WHERE id > ?1{clause} ORDER BY id ASC LIMIT {batch}"
    );
    let events: Vec<FwdEvent> = {
        let conn = db.lock();
        let mut all: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(watermark)];
        all.extend(fparams);
        // Le lot qu'on ne sait pas LIRE : la destination ne transmet rien ce tick, et elle le DIT
        // (`last_error`, `error_count`) au lieu de rendre la main comme si rien n'était dû.
        let refus = |conn: &Connection, e: &rusqlite::Error| {
            let _ = conn.execute(
                "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                params![now_ts, format!("lecture du lot d'événements refusée : {e}"), id],
            );
            crate::bilan_de_tick::tick_aveugle(&format!("destination {id}"), e)
        };
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => return refus(&conn, &e),
        };
        let rows = match stmt.query_map(rusqlite::params_from_iter(all.iter()), |r| {
            Ok(row_to_fwd(
                r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,
                r.get::<_, Option<String>>(6)?, r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?, r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?, r.get::<_, String>(11)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return refus(&conn, &e),
        };
        let mut lus: Vec<FwdEvent> = Vec::new();
        for r in rows {
            match r {
                Ok(ev) => lus.push(ev),
                Err(e) => {
                    // Un événement indécodable ne part pas, et le lot NON PLUS : le filigrane reste en
                    // deçà, la cause est nommée, et le compte remonte au planificateur.
                    let _ = conn.execute(
                        "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                        params![now_ts, format!("un événement du lot (après id {watermark}) est indécodable, lot non transmis : {e}"), id],
                    );
                    return Mesure::Lue(1);
                }
            }
        }
        lus
    };
    if events.is_empty() {
        // Rien de neuf : on pose last_run (anti-martèlement) SANS toucher au watermark ni compter d'erreur.
        let conn = db.lock();
        let _ = conn.execute("UPDATE destination SET last_run=?1 WHERE id=?2", params![now_ts, id]);
        return Mesure::Lue(0);
    }
    let max_id = events.iter().map(|e| e.id).max().unwrap_or(watermark);
    let count = events.len() as i64;

    // 2) Construction WIRE (HORS lock). Config invalide (ex hec_token manquant) -> last_error, pas d'avance.
    let config: Value = serde_json::from_str(config_json).unwrap_or_else(|_| json!({}));
    let wire = match build_wire(dtype, endpoint, &config, &events) {
        Ok(w) => w,
        Err(e) => {
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                params![now_ts, e, id],
            );
            return Mesure::Lue(1); // le lot de CETTE destination est abandonné : porté par `last_error` ET compté
        }
    };

    // 3) ENVOI (HORS lock writer — le réseau ne bloque JAMAIS l'ingest). Send-only : la réponse du sink
    //    n'est JAMAIS renvoyée à un appelant (seul le statut sert à décider succès/échec).
    match transport(&wire) {
        Ok(status) if transport_ok(status) => {
            // SUCCÈS -> avance le watermark au dernier id du lot (at-least-once : `id > watermark` exclut
            // désormais ce lot -> jamais de ré-envoi infini ; un crash avant ce COMMIT re-enverra le lot).
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE destination SET watermark=?1, last_run=?2, last_ok=?2, last_error=NULL, last_count=?3 WHERE id=?4",
                params![max_id, now_ts, count, id],
            );
        }
        Ok(status) => {
            // Statut non-2xx : ÉCHEC. Watermark GELÉ (rejouable), last_error = statut seul (jamais le corps).
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                params![now_ts, format!("sink HTTP {status}"), id],
            );
        }
        Err(e) => {
            // Erreur transport (réseau/TLS/DNS) : watermark GELÉ, last_error = motif (jamais un secret/corps).
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                params![now_ts, e, id],
            );
        }
    }
    Mesure::Lue(0)
}

/// TICK FORWARDER (thread dédié, PAR TENANT). Sélectionne les destinations DUES (enabled + intervalle
/// écoulé) -> forward un lot chacune. INERTE si table vide (mode 0 : 0 ligne -> no-op strict, aucun réseau).
/// FAIL-SAFE : chaque destination isolée par catch_unwind (une panne ne stoppe jamais les autres).
///
/// REND SON BILAN (`P4.1-r`) : `Illisible` si la liste des destinations dues n'a pas pu être lue (aucun
/// forward, et rien ne le disait), `Lue(n)` = abandons cumulés des destinations traitées.
pub(crate) fn run_due_destinations(db: &Arc<Mutex<Connection>>, _db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
    let due: Vec<(i64, String, String, String, String, i64, i64)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id,type,endpoint,config,filter,batch_max,watermark FROM destination \
             WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("destinations", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("destinations", &e),
        };
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(x) => due.push(x),
                Err(_) => bilan.absorber(crate::mesure_environnement::Mesure::Lue(1)), // ligne indécodable : une destination non servie, comptée
            }
        }
        due
    };
    for (id, dtype, endpoint, config_json, filter_json, batch_max, watermark) in due {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            forward_one_destination(db, id, &dtype, &endpoint, &config_json, &filter_json, batch_max, watermark, now_ts, dest_transport)
        }));
        match res {
            Ok(b) => bilan.absorber(b),
            Err(_) => {
                bilan.absorber(crate::mesure_environnement::Mesure::Lue(1));
                let conn = db.lock();
                let _ = conn.execute(
                    "UPDATE destination SET last_run=?1, last_error=?2, error_count=error_count+1 WHERE id=?3",
                    params![now_ts, "panic interne du forwarder (capturé)", id],
                );
            }
        }
    }
    bilan.bilan_de_tick()
}

// ===================================================================================================
// CRUD ADMIN (admin-only serveur + route_min_role Admin + par-tenant req_db). Le blob `config` (secret
// d'auth) n'est JAMAIS projeté (has_auth seul) ni loggé. Create/enable/delete LEDGERISÉ (fail-closed).
// ===================================================================================================
pub(crate) async fn destinations_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    crate::req_conn!(st, au, conn);
    // `config` (secret) JAMAIS projeté -> has_auth booléen (hec_token/auth_header non vide). `filter`
    // (non secret) est renvoyé (l'UI l'affiche/édite). watermark + error_count = observabilité du lag.
    let list: Vec<Value> = match conn.prepare(
        "SELECT id,type,name,enabled,endpoint,config,filter,batch_max,interval_s,watermark,last_run,last_ok,last_error,last_count,error_count \
         FROM destination ORDER BY id",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                let cfg: String = r.get(5)?;
                let has_auth = serde_json::from_str::<Value>(&cfg).ok()
                    .map(|v| ["hec_token", "auth_header"].iter().any(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)))
                    .unwrap_or(false);
                let filter: String = r.get(6)?;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "type": r.get::<_, String>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "enabled": r.get::<_, i64>(3)? != 0,
                    "endpoint": r.get::<_, String>(4)?,
                    "filter": serde_json::from_str::<Value>(&filter).unwrap_or_else(|_| json!({})),
                    "batch_max": r.get::<_, i64>(7)?,
                    "interval_s": r.get::<_, i64>(8)?,
                    "watermark": r.get::<_, i64>(9)?,
                    "last_run": r.get::<_, Option<i64>>(10)?,
                    "last_ok": r.get::<_, Option<i64>>(11)?,
                    "last_error": r.get::<_, Option<String>>(12)?,
                    "last_count": r.get::<_, i64>(13)?,
                    "error_count": r.get::<_, i64>(14)?,
                    "has_auth": has_auth,
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(Value::Array(list)).into_response()
}

pub(crate) async fn destination_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let dtype = b.get("type").and_then(|x| x.as_str()).unwrap_or("webhook").to_string();
    if !dest_type_ok(&dtype) {
        return bad_req("type non supporté (syslog | hec | webhook | s3 | kafka)");
    }
    let endpoint = b.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if !dest_endpoint_ok(&dtype, &endpoint) {
        return bad_req("endpoint invalide (webhook/hec: http(s):// ; syslog: tcp://host:port ; cible métadonnées interdite)");
    }
    // FILTRE : valide AVANT persistance (fail-closed). Vide -> {} = tous les events (feed complet).
    let filter_v = b.get("filter").cloned().unwrap_or_else(|| json!({}));
    let filt = DestFilter::from_json(&filter_v);
    if let Err(e) = filt.validate() {
        return bad_req(e);
    }
    let name = b.get("name").and_then(|x| x.as_str()).unwrap_or("Destination").to_string();
    // enabled:false par défaut (l'admin CONFIGURE avant d'ouvrir la vanne d'exfil).
    let enabled = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
    let interval_s = b.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(30).max(5);
    let batch_max = b.get("batch_max").and_then(|x| x.as_i64()).unwrap_or(500).clamp(1, DEST_BATCH_HARD_MAX);
    // config = blob secret (auth). Accepte un objet OU une chaîne JSON (comme notifier).
    let config = match b.get("config") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "{}".to_string(),
    };
    crate::req_conn!(st, au, conn);
    // GOUVERNANCE : création + audit fail-closed (data-exfil surface). Le blob `config` (secret d'auth) n'est
    // JAMAIS logué : l'audit ne porte que type/name/enabled/endpoint + un booléen has_auth.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let has_auth = serde_json::from_str::<Value>(&config).ok()
        .map(|v| ["hec_token", "auth_header"].iter().any(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)))
        .unwrap_or(false);
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,created) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![dtype, name, enabled, endpoint, config, filter_v.to_string(), batch_max, interval_s, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn,
            "config.destination.create",
            &format!("destination de sortie '{name}' ({dtype} -> {endpoint}) créée par {}", au.name),
            3,
            &format!("SORTIE de données : destination '{name}' ({dtype}, enabled={}, endpoint={endpoint}) créée par {} — la donnée SOC peut désormais quitter le périmètre vers ce sink", enabled != 0, au.name),
            &json!({ "id": id, "type": dtype, "enabled": enabled != 0, "endpoint": endpoint, "has_auth": has_auth, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "enabled": enabled != 0 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn destination_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    // Valide AVANT écriture : type/endpoint/filtre cohérents si fournis. On a besoin du type EFFECTIF
    // (fourni ou existant) pour valider l'endpoint.
    crate::req_conn!(st, au, conn);
    let cur_type: String = match conn.query_row("SELECT type FROM destination WHERE id=?1", params![id], |r| r.get(0)) {
        Ok(t) => t,
        Err(_) => return not_found("destination introuvable"),
    };
    let eff_type = b.get("type").and_then(|x| x.as_str()).unwrap_or(&cur_type).to_string();
    if b.get("type").is_some() && !dest_type_ok(&eff_type) {
        return bad_req("type non supporté");
    }
    if let Some(ep) = b.get("endpoint").and_then(|x| x.as_str()) {
        if !dest_endpoint_ok(&eff_type, ep.trim()) {
            return bad_req("endpoint invalide pour ce type de sink");
        }
    }
    if let Some(f) = b.get("filter") {
        if let Err(e) = DestFilter::from_json(f).validate() {
            return bad_req(e);
        }
    }
    // GOUVERNANCE : mutation + audit fail-closed. Le blob `config` (secret) n'est JAMAIS logué -> l'audit
    // note un booléen `secret_set` + les NOMS des champs modifiés (jamais leurs valeurs).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) {
            conn.execute("UPDATE destination SET name=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("type").and_then(|x| x.as_str()) {
            conn.execute("UPDATE destination SET type=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("endpoint").and_then(|x| x.as_str()) {
            conn.execute("UPDATE destination SET endpoint=?1 WHERE id=?2", params![v.trim(), id])?;
        }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE destination SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) {
            conn.execute("UPDATE destination SET interval_s=?1 WHERE id=?2", params![v.max(5), id])?;
        }
        if let Some(v) = b.get("batch_max").and_then(|x| x.as_i64()) {
            conn.execute("UPDATE destination SET batch_max=?1 WHERE id=?2", params![v.clamp(1, DEST_BATCH_HARD_MAX), id])?;
        }
        if let Some(v) = b.get("filter") {
            conn.execute("UPDATE destination SET filter=?1 WHERE id=?2", params![v.to_string(), id])?;
        }
        // CONFIG (secret d'auth) : mise à jour UNIQUEMENT si fournie ET non vide/`{}` -> config omise = conserver
        // l'existant (jamais d'écrasement par vide). Jamais renvoyée, jamais loggée.
        let mut secret_set = false;
        if let Some(cv) = b.get("config") {
            let cs = match cv { Value::String(s) => s.clone(), Value::Null => String::new(), v => v.to_string() };
            let trimmed = cs.trim();
            if !trimmed.is_empty() && trimmed != "{}" {
                conn.execute("UPDATE destination SET config=?1 WHERE id=?2", params![cs, id])?;
                secret_set = true;
            }
        }
        let changed: Vec<&str> = ["name", "type", "endpoint", "enabled", "interval_s", "batch_max", "filter"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn,
            "config.destination.update",
            &format!("destination #{id} modifiée ({}{}) par {}", changed.join(","), if secret_set { ",config" } else { "" }, au.name),
            3,
            &format!("destination de sortie #{id} modifiée (champs: {}{}) par {}", changed.join(","), if secret_set { ", auth rotatée" } else { "" }, au.name),
            &json!({ "id": id, "changed": changed, "secret_set": secret_set, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn destination_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM destination WHERE id=?1", params![id])?;
        audit_config_change(
            &conn,
            "config.destination.delete",
            &format!("destination #{id} supprimée par {}", au.name),
            3,
            &format!("destination de sortie #{id} supprimée par {}", au.name),
            &json!({ "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

/// FLUSH MANUEL : déclenche UN forward+avance IMMÉDIAT (admin-only + fail-safe). RÉUTILISE le chemin de
/// prod `forward_one_destination` (parité stricte). N'ingère rien, ne renvoie NI la réponse du sink NI le
/// secret — seulement { ok, forwarded, last_error } lu APRÈS coup dans la table. spawn_blocking : le réseau
/// n'occupe pas un worker async.
pub(crate) async fn destination_flush(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let __rc = req_db(&st, &au);
    let row = {
        let conn = __rc.lock();
        conn.query_row(
            "SELECT type,endpoint,config,filter,batch_max,watermark FROM destination WHERE id=?1 AND enabled=1",
            params![id],
            |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?,
            )),
        ).ok()
    };
    let (dtype, endpoint, config_json, filter_json, batch_max, watermark) = match row {
        Some(x) => x,
        None => return not_found("destination introuvable ou désactivée"),
    };
    let db = __rc.clone();
    let now_ts = now();
    let _ = tokio::task::spawn_blocking(move || {
        forward_one_destination(&db, id, &dtype, &endpoint, &config_json, &filter_json, batch_max, watermark, now_ts, dest_transport);
    }).await;
    // Relit l'état APRÈS coup (jamais la réponse du sink).
    let conn = __rc.lock();
    let (wm, lc, le): (i64, i64, Option<String>) = conn.query_row(
        "SELECT watermark,last_count,last_error FROM destination WHERE id=?1",
        params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).unwrap_or((watermark, 0, None));
    Json(json!({ "ok": le.is_none(), "forwarded": lc, "watermark": wm, "last_error": le })).into_response()
}
