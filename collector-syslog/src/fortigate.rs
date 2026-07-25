//! Parser vendeur FortiGate (FortiOS) — PREMIER de la famille pluggable.
//!
//! FortiGate emet du syslog `key=value` (parfois quote). Le message part typiquement en
//! `<PRI>date=... time=... devname=... type=... subtype=... ...` : la couche `framing` renvoie donc
//! tout le kv dans `frame.msg`, que ce parser tokenise.
//!
//! TAXONOMIE source->category (le coeur de la composition inter-vendeur) :
//!   source   = "fortigate"                (identite du vendeur)
//!   category = firewall|malware|ids|web|dns|application|vpn|auth|mail|dlp|endpoint|system|utm|network
//!              (semantique NEUTRE : une regle `category=malware` matche FortiGate ET n'importe quel
//!               futur vendeur qui mappe ses menaces sur `malware`).
//!   fields.log_type / fields.subtype conservent le `type`/`subtype` FortiGate BRUTS (drilldown).
//!   fields.action = action normalisee (dimension de rollup CIM du daemon).
//!
//! ROBUSTESSE : tout manque/surplus/quote est tolere ; une ligne sans aucune cle FortiGate -> event de
//! repli (`fields.parse_status="unparsed"`) : jamais un panic, jamais un drop.

use crate::framing::{sanitize_key, SyslogFrame};
use crate::parser::{
    add_syslog_provenance, cap_val, fold_sd, parse_kv, syslog_sev_to_plume, VendorParser, MAX_FIELDS,
    MAX_MSG,
};
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

pub struct FortiGate;

/// Offset tz PAR DEFAUT (secondes) applique quand une ligne FortiGate porte `date`/`time` mais PAS de
/// champ `tz` (dependant de la version/config FortiOS). `date`/`time` sont en heure LOCALE du device :
/// sans indication, l'interpreter en UTC decale l'horodatage de l'offset du device. `PLUME_SYSLOG_TZ`
/// (ex. `+0100`) rend cette hypothese EXPLICITE et configurable. Non pose -> `None` -> UTC (documente).
static DEFAULT_TZ_OFFSET: OnceLock<Option<i64>> = OnceLock::new();

/// Fixe (une fois, au boot) l'offset tz par defaut a partir de `PLUME_SYSLOG_TZ`. No-op si deja fixe.
pub fn set_default_tz(tz: Option<&str>) {
    let _ = DEFAULT_TZ_OFFSET.set(tz.and_then(parse_tz_offset));
}
fn default_tz_offset() -> Option<i64> {
    DEFAULT_TZ_OFFSET.get().copied().flatten()
}

impl VendorParser for FortiGate {
    fn name(&self) -> &'static str {
        "fortigate"
    }

    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value {
        let kv = parse_kv(&frame.msg);
        // repli sur si RIEN de FortiGate (ligne tronquee/corrompue) : event SAFE, pas de drop.
        if kv.is_empty() || !has_fortigate_marker(&kv) {
            return fallback_event(frame, source, host, default_ts);
        }

        let get = |k: &str| -> Option<&str> {
            kv.iter().find(|(kk, _)| kk.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
        };

        let log_type = get("type").unwrap_or("").to_ascii_lowercase();
        let subtype = get("subtype").unwrap_or("").to_ascii_lowercase();
        let category = fgt_category(&log_type, &subtype);
        let action = get("action").unwrap_or("").to_ascii_lowercase();
        let level = get("level").unwrap_or("");

        // severite : niveau FortiGate -> Plume, avec PLANCHER menace (une menace loggee est deja un signal).
        let mut severity = level_to_sev(level, frame.severity);
        match category {
            "malware" => severity = severity.max(3),
            "ids" => severity = severity.max(2),
            _ => {}
        }

        let ts = fgt_epoch(&get, default_ts);

        // --- fields : TOUT le kv (cles FortiGate brutes) + alias canoniques Plume ---
        let mut fields = Map::new();
        fields.insert("vendor".into(), json!("fortigate"));
        fields.insert("product".into(), json!("fortigate"));
        for (k, v) in &kv {
            if fields.len() >= MAX_FIELDS {
                break;
            }
            let key = sanitize_key(k);
            fields.entry(key).or_insert_with(|| json!(cap_val(v)));
        }
        // alias canoniques (queryables/rollup) — n'ecrasent pas si deja poses
        if !log_type.is_empty() {
            fields.insert("log_type".into(), json!(log_type.clone()));
        }
        if !subtype.is_empty() {
            fields.insert("subtype".into(), json!(subtype.clone()));
        }
        if !action.is_empty() {
            // fields.action = dimension de rollup CIM (json_extract(fields,'$.action') cote daemon)
            fields.insert("action".into(), json!(action.clone()));
        }
        let src_ip = get("srcip").filter(|s| !s.is_empty()).map(|s| s.to_string());
        let dst_ip = get("dstip").filter(|s| !s.is_empty()).map(|s| s.to_string());
        if let Some(ip) = &src_ip {
            fields.insert("src_ip".into(), json!(ip));
        }
        if let Some(ip) = &dst_ip {
            fields.insert("dst_ip".into(), json!(ip));
        }
        if let Some(p) = get("srcport").filter(|s| !s.is_empty()) {
            fields.insert("src_port".into(), json!(p));
        }
        if let Some(p) = get("dstport").filter(|s| !s.is_empty()) {
            fields.insert("dst_port".into(), json!(p));
        }
        if let Some(pr) = get("proto").filter(|s| !s.is_empty()) {
            if let Some(name) = proto_name(pr) {
                fields.insert("proto".into(), json!(name));
            }
        }
        // url pour promotion colonne (fields_url cote daemon) : url explicite OU hostname UTM.
        let url = get("url")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| get("hostname").filter(|s| !s.is_empty()).map(|s| s.to_string()));
        if let Some(u) = &url {
            fields.insert("url".into(), json!(cap_val(u)));
        }
        // provenance device (multi-firewall) : `observer` = identite NEUTRE de l'appareil emetteur
        // (devname > devid > hostname d'entete syslog). Permet `stats ... by observer` inter-vendeur
        // meme quand plusieurs FortiGate pointent le MEME collecteur (host = collecteur, cf. finding).
        let observer = get("devname")
            .filter(|s| !s.is_empty())
            .or_else(|| get("devid").filter(|s| !s.is_empty()))
            .map(|s| s.to_string())
            .or_else(|| frame.hostname.as_deref().filter(|s| !s.is_empty()).map(|s| s.to_string()));
        if let Some(dev) = &observer {
            fields.insert("observer".into(), json!(cap_val(dev)));
        }
        add_syslog_provenance(&mut fields, frame);
        fold_sd(&mut fields, frame);

        let message = build_message(&subtype, &log_type, &get, &action, src_ip.as_deref(), dst_ip.as_deref());

        // event : src_ip/dst_ip/url en TOP-LEVEL -> promus en colonnes indexees par ingest_events_batch.
        let mut ev = Map::new();
        ev.insert("ts".into(), json!(ts));
        ev.insert("source".into(), json!(source));
        ev.insert("category".into(), json!(category));
        ev.insert("severity".into(), json!(severity));
        ev.insert("message".into(), json!(message));
        ev.insert("host".into(), json!(host));
        if let Some(ip) = src_ip {
            ev.insert("src_ip".into(), json!(ip));
        }
        if let Some(ip) = dst_ip {
            ev.insert("dst_ip".into(), json!(ip));
        }
        if let Some(u) = url {
            ev.insert("url".into(), json!(cap_val(&u)));
        }
        // dedup best-effort : idempotence sur re-ship SANS collision inter-events (finding dedup).
        //  - N'EMET UN dedup QUE si `eventtime` est present : sinon la cle `fgt-{logid}--{srcip}` (sans
        //    composante temps) est PREDICTIBLE et collapse tous les paquets d'une meme IP/logid en UNE
        //    ligne (INSERT OR IGNORE). Pas de dedup -> le daemon insere (dedup NULL = distinct).
        //  - Ajoute un DISCRIMINATEUR par-event (sessionid, sinon 5-uple src_port:dst_ip:dst_port:proto)
        //    -> deux paquets refuses distincts (scan horizontal : dst_port varie) ne se collapsent plus.
        if let (Some(logid), Some(et)) = (
            get("logid").filter(|s| !s.is_empty()),
            get("eventtime").filter(|s| !s.is_empty()),
        ) {
            let si = fields.get("src_ip").and_then(|v| v.as_str()).unwrap_or("");
            let disc = get("sessionid").filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_else(|| {
                let sp = get("srcport").unwrap_or("");
                let di = fields.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("");
                let dp = get("dstport").unwrap_or("");
                let pr = get("proto").unwrap_or("");
                format!("{sp}:{di}:{dp}:{pr}")
            });
            ev.insert("dedup".into(), json!(format!("fgt-{logid}-{et}-{si}-{disc}")));
        }
        ev.insert("fields".into(), Value::Object(fields));
        Value::Object(ev)
    }
}

/// Une paire kv ressemble-t-elle a du FortiGate ? (au moins un marqueur d'identite/schema).
fn has_fortigate_marker(kv: &[(String, String)]) -> bool {
    kv.iter().any(|(k, _)| {
        let k = k.to_ascii_lowercase();
        matches!(k.as_str(), "devid" | "logid" | "type" | "devname" | "eventtime" | "vd")
    })
}

/// TAXONOMIE FortiGate `type`/`subtype` -> category Plume NEUTRE (composition inter-vendeur).
pub fn fgt_category(log_type: &str, subtype: &str) -> &'static str {
    match log_type {
        "traffic" => "firewall",
        "utm" => match subtype {
            "virus" | "antivirus" => "malware",
            "ips" => "ids",
            "anomaly" => "ids",
            "webfilter" | "urlfilter" | "web" => "web",
            "waf" => "web",
            "app-ctrl" | "app" | "application" => "application",
            "dns" | "dns-query" => "dns",
            "emailfilter" | "spamfilter" | "spam" => "mail",
            "dlp" | "file-filter" | "dlp-archive" => "dlp",
            "ssl" | "ssh" | "voip" => "network",
            _ => "utm",
        },
        "event" => match subtype {
            "vpn" => "vpn",
            "user" => "auth",
            "system" | "ha" | "config" => "system",
            "router" | "wireless" | "wad" => "network",
            "endpoint" | "ems" | "connector" => "endpoint",
            _ => "system",
        },
        "anomaly" => "ids",
        "virus" | "antivirus" => "malware",
        "webfilter" | "urlfilter" => "web",
        "ips" => "ids",
        "app-ctrl" | "application" => "application",
        // pas de `type=` du tout : semantique DELIBEREE conservee -> firewall (le cas FortiGate historique).
        "" => "firewall",
        // `type=` PRESENT mais inconnu (futur FortiOS / valeur inattendue) : bucket NEUTRE plutot que de
        // diluer `firewall` (sur lequel composent les regles inter-vendeur). cf. finding taxonomie.
        _ => "network",
    }
}

/// Niveau FortiGate -> severite Plume (0..4). Repli sur la severite syslog si `level` inconnu/absent.
fn level_to_sev(level: &str, syslog_sev: Option<u8>) -> i64 {
    match level.to_ascii_lowercase().as_str() {
        "emergency" | "alert" | "critical" => 4,
        "error" => 3,
        "warning" => 2,
        "notice" => 1,
        "information" | "informational" | "debug" => 0,
        "" => syslog_sev_to_plume(syslog_sev),
        _ => syslog_sev_to_plume(syslog_sev),
    }
}

/// Horodatage : PREFERE `eventtime` (epoch, ns/ms/s auto-detecte), sinon `date`+`time` (+`tz`),
/// sinon l'epoch de reception. Jamais de panic.
fn fgt_epoch<'a>(get: &dyn Fn(&str) -> Option<&'a str>, default_ts: i64) -> i64 {
    if let Some(et) = get("eventtime").filter(|s| !s.is_empty()) {
        if let Ok(v) = et.trim().parse::<i128>() {
            let secs = if v >= 1_000_000_000_000_000 {
                v / 1_000_000_000 // nanosecondes (FortiOS recent)
            } else if v >= 1_000_000_000_000 {
                v / 1000 // millisecondes
            } else {
                v // secondes
            };
            if (0..=i64::MAX as i128).contains(&secs) {
                return secs as i64;
            }
        }
    }
    if let (Some(date), Some(time)) = (get("date"), get("time")) {
        if let Some(secs) = civil_to_epoch(date, time, get("tz"), default_tz_offset()) {
            return secs;
        }
    }
    default_ts
}

/// `YYYY-MM-DD` + `HH:MM:SS` (+ tz `+HHMM`/`-HHMM`) -> epoch UTC. `days_from_civil` (Howard Hinnant).
/// `default_off` = offset tz applique quand la ligne ne porte PAS de champ `tz` (cf. PLUME_SYSLOG_TZ).
fn civil_to_epoch(date: &str, time: &str, tz: Option<&str>, default_off: Option<i64>) -> Option<i64> {
    let mut d = date.splitn(3, '-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    // Borne l'annee : une `date=` forcee enorme (ex. 9223372036854775800) deborderait l'arithmetique
    // i64 ci-dessous (panic en build debug, wrap silencieux en release) -> repli propre sur default_ts.
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let mut t = time.splitn(3, ':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    let ss: i64 = t.next().unwrap_or("0").parse().ok()?;
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let mut secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    // tz du device -> ramene en UTC (heure locale - offset). Priorite : champ `tz` de la ligne, sinon
    // l'offset par defaut configure (PLUME_SYSLOG_TZ). A defaut des deux : interprete en UTC (documente).
    if let Some(off) = tz.and_then(parse_tz_offset).or(default_off) {
        secs -= off;
    }
    Some(secs)
}

/// `+HHMM` / `-HHMM` / `+HH:MM` -> offset en secondes.
fn parse_tz_offset(tz: &str) -> Option<i64> {
    let tz = tz.trim();
    let (sign, rest) = match tz.strip_prefix('-') {
        Some(r) => (-1i64, r),
        None => (1i64, tz.strip_prefix('+').unwrap_or(tz)),
    };
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 2 {
        return None;
    }
    let hh: i64 = digits[..2].parse().ok()?;
    let mm: i64 = if digits.len() >= 4 { digits[2..4].parse().ok()? } else { 0 };
    Some(sign * (hh * 3600 + mm * 60))
}

/// Numero de protocole IP -> nom (les plus courants ; sinon on garde le numero brut ailleurs).
fn proto_name(p: &str) -> Option<&'static str> {
    match p.trim() {
        "1" => Some("icmp"),
        "6" => Some("tcp"),
        "17" => Some("udp"),
        "47" => Some("gre"),
        "50" => Some("esp"),
        "58" => Some("icmpv6"),
        "89" => Some("ospf"),
        "132" => Some("sctp"),
        _ => None,
    }
}

/// Message lisible (inclut action + dport pour que les regles message-regex marchent aussi).
fn build_message<'a>(
    subtype: &str,
    log_type: &str,
    get: &dyn Fn(&str) -> Option<&'a str>,
    action: &str,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
) -> String {
    let sub = if !subtype.is_empty() {
        subtype
    } else if !log_type.is_empty() {
        log_type
    } else {
        "log"
    };
    let sp = get("srcport").unwrap_or("");
    let dp = get("dstport").unwrap_or("");
    let svc = get("service").unwrap_or("");
    let src = src_ip.unwrap_or("-");
    let dst = dst_ip.unwrap_or("-");
    // detail specifique menace (virus/attaque/url) si present
    let detail = get("virus")
        .or_else(|| get("attack"))
        .or_else(|| get("filename"))
        .or_else(|| get("msg"))
        .unwrap_or("");
    let mut m = format!("fortigate {sub}: {src}:{sp} -> {dst}:{dp}");
    if !action.is_empty() {
        m.push_str(&format!(" action={action}"));
    }
    if !svc.is_empty() {
        m.push_str(&format!(" service={svc}"));
    }
    if !detail.is_empty() {
        m.push_str(&format!(" [{detail}]"));
    }
    m.chars().take(MAX_MSG).collect()
}

/// Event de REPLI : ligne FortiGate illisible -> on emet quand meme (source correcte, categorie NEUTRE,
/// message = brut tronque, marqueur `parse_status=unparsed`). JAMAIS de drop silencieux.
///
/// category = `network` (PAS `firewall`) : une ligne non parsee n'est PAS du trafic firewall confirme ;
/// la classer `firewall` diluerait la category sur laquelle composent les regles inter-vendeur.
fn fallback_event(frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value {
    let mut fields = Map::new();
    fields.insert("vendor".into(), json!("fortigate"));
    fields.insert("product".into(), json!("fortigate"));
    fields.insert("parse_status".into(), json!("unparsed"));
    add_syslog_provenance(&mut fields, frame);
    // provenance device (multi-firewall) : hostname d'entete syslog si present.
    if let Some(h) = frame.hostname.as_deref().filter(|s| !s.is_empty()) {
        fields.insert("observer".into(), json!(cap_val(h)));
    }
    let msg: String = if frame.msg.is_empty() {
        "(ligne fortigate illisible / vide)".to_string()
    } else {
        frame.msg.chars().take(MAX_MSG).collect()
    };
    json!({
        "ts": default_ts,
        "source": source,
        "category": "network",
        "severity": syslog_sev_to_plume(frame.severity),
        "message": msg,
        "host": host,
        "fields": Value::Object(fields),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::parse_syslog;

    const TRAFFIC: &str = "<189>date=2019-05-13 time=15:00:00 devname=\"FGT\" devid=\"FG100D\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" eventtime=1557756000 srcip=192.168.1.10 srcport=44000 srcintf=\"internal\" dstip=8.8.8.8 dstport=443 dstintf=\"wan1\" proto=6 action=\"accept\" policyid=1 service=\"HTTPS\" sentbyte=1200 rcvdbyte=3400 duration=12";

    const UTM_VIRUS: &str = "<184>date=2019-05-13 time=15:05:00 devname=\"FGT\" devid=\"FG100D\" logid=\"0211008192\" type=\"utm\" subtype=\"virus\" eventtype=\"infected\" level=\"warning\" vd=\"root\" eventtime=1557756300 srcip=192.168.1.20 srcport=51000 dstip=93.184.216.34 dstport=80 proto=6 action=\"blocked\" service=\"HTTP\" hostname=\"malware.test\" url=\"http://malware.test/eicar.com\" virus=\"EICAR_TEST_FILE\" filename=\"eicar.com\"";

    // ligne malformee : PRI + charabia sans aucune cle FortiGate.
    const MALFORMED: &str = "<190>%%% not a fortigate line at all, no kv here !!!";

    fn parse(line: &str) -> Value {
        let f = parse_syslog(line);
        FortiGate.parse(&f, "fortigate", "collector-1", 999)
    }

    #[test]
    fn traffic_line() {
        let ev = parse(TRAFFIC);
        assert_eq!(ev["source"], "fortigate");
        assert_eq!(ev["category"], "firewall");
        assert_eq!(ev["severity"], 1); // notice
        assert_eq!(ev["ts"], 1557756000); // eventtime (secondes)
        assert_eq!(ev["src_ip"], "192.168.1.10"); // promu top-level
        assert_eq!(ev["dst_ip"], "8.8.8.8");
        assert_eq!(ev["fields"]["action"], "accept");
        assert_eq!(ev["fields"]["dst_port"], "443");
        assert_eq!(ev["fields"]["proto"], "tcp");
        assert_eq!(ev["fields"]["vendor"], "fortigate");
        assert_eq!(ev["fields"]["log_type"], "traffic");
        assert!(ev["message"].as_str().unwrap().contains("action=accept"));
    }

    #[test]
    fn utm_virus_line() {
        let ev = parse(UTM_VIRUS);
        assert_eq!(ev["category"], "malware");
        assert_eq!(ev["fields"]["action"], "blocked");
        // level=warning -> 2, plancher menace malware -> 3
        assert_eq!(ev["severity"], 3);
        assert_eq!(ev["ts"], 1557756300);
        assert_eq!(ev["dst_ip"], "93.184.216.34");
        assert_eq!(ev["url"], "http://malware.test/eicar.com"); // promu top-level
        assert_eq!(ev["fields"]["virus"], "EICAR_TEST_FILE");
        assert!(ev["dedup"].as_str().unwrap().starts_with("fgt-0211008192-"));
    }

    #[test]
    fn malformed_line_safe_fallback() {
        let ev = parse(MALFORMED);
        // ne panique pas ; event de repli exploitable
        assert_eq!(ev["source"], "fortigate");
        // category NEUTRE (pas `firewall`) pour une ligne non parsee -> ne dilue pas la category firewall.
        assert_eq!(ev["category"], "network");
        assert_eq!(ev["fields"]["parse_status"], "unparsed");
        assert!(ev["message"].as_str().unwrap().contains("not a fortigate"));
        assert!(ev["ts"].is_i64());
        assert!(ev["severity"].is_i64());
    }

    #[test]
    fn eventtime_nanoseconds_auto_scaled() {
        let f = parse_syslog(
            "<189>type=\"traffic\" devid=\"X\" subtype=\"forward\" eventtime=1557756000123456789 action=\"deny\"",
        );
        let ev = FortiGate.parse(&f, "fortigate", "c1", 1);
        assert_eq!(ev["ts"], 1557756000); // ns -> s
    }

    #[test]
    fn date_time_tz_fallback() {
        // pas d'eventtime -> date/time + tz. 2019-05-13 15:00:00 UTC = 1557759600 ; tz +0100 -> -3600.
        let f = parse_syslog(
            "<189>date=2019-05-13 time=15:00:00 tz=\"+0100\" devid=\"X\" type=\"traffic\" subtype=\"forward\" action=\"accept\"",
        );
        let ev = FortiGate.parse(&f, "fortigate", "c1", 42);
        assert_eq!(ev["ts"], 1557759600 - 3600);
    }

    #[test]
    fn taxonomy_mapping() {
        assert_eq!(fgt_category("traffic", "forward"), "firewall");
        assert_eq!(fgt_category("utm", "virus"), "malware");
        assert_eq!(fgt_category("utm", "ips"), "ids");
        assert_eq!(fgt_category("utm", "webfilter"), "web");
        assert_eq!(fgt_category("utm", "app-ctrl"), "application");
        assert_eq!(fgt_category("utm", "dns"), "dns");
        assert_eq!(fgt_category("utm", "emailfilter"), "mail");
        assert_eq!(fgt_category("event", "vpn"), "vpn");
        assert_eq!(fgt_category("event", "user"), "auth");
        assert_eq!(fgt_category("event", "system"), "system");
        assert_eq!(fgt_category("anomaly", ""), "ids");
        assert_eq!(fgt_category("", ""), "firewall"); // type absent -> firewall (semantique deliberee)
        assert_eq!(fgt_category("wibble", ""), "network"); // type present mais inconnu -> bucket neutre
    }

    #[test]
    fn year_overflow_falls_back_to_default_ts() {
        // `date=` avec une annee enorme deborderait l'arithmetique i64 -> repli propre sur default_ts.
        let f = parse_syslog(
            "<189>date=9223372036854775800-01-01 time=00:00:00 type=\"traffic\" devid=\"X\" subtype=\"forward\" action=\"deny\"",
        );
        let ev = FortiGate.parse(&f, "fortigate", "c1", 4242);
        assert_eq!(ev["ts"], 4242); // pas de panic, pas de ts aberrant : on retombe sur l'epoch de reception
    }

    #[test]
    fn tz_absent_uses_configured_default() {
        // Champ `tz` absent : sans default, interprete en UTC ; avec default_off, applique l'offset.
        let utc = civil_to_epoch("2026-07-03", "09:00:00", None, None).unwrap();
        let plus2 = civil_to_epoch("2026-07-03", "09:00:00", None, parse_tz_offset("+0200")).unwrap();
        assert_eq!(plus2, utc - 7200); // heure locale +02:00 -> UTC = -2h
        // le champ `tz` de la ligne PRIME sur le default configure.
        let field_wins = civil_to_epoch("2026-07-03", "09:00:00", Some("+0100"), parse_tz_offset("+0200")).unwrap();
        assert_eq!(field_wins, utc - 3600);
    }

    #[test]
    fn dedup_omitted_without_eventtime() {
        // Sans eventtime : PAS de dedup (evite la cle predictible `fgt-{logid}--{srcip}` qui collapse).
        let f = parse_syslog(
            "<189>date=2019-05-13 time=15:00:00 logid=\"0000000013\" type=\"traffic\" devid=\"X\" subtype=\"forward\" srcip=203.0.113.5 dstip=10.0.0.1 dstport=22 action=\"deny\"",
        );
        let ev = FortiGate.parse(&f, "fortigate", "c1", 1);
        assert!(ev.get("dedup").is_none(), "pas de dedup sans eventtime -> daemon insere (NULL distinct)");
    }

    #[test]
    fn dedup_distinct_per_destination_port() {
        // Scan horizontal (memes logid/eventtime/srcip, dst_port varie) -> dedup DISTINCTS (pas de collapse).
        let mk = |dport: u16| {
            let line = format!(
                "<189>logid=\"0000000013\" type=\"traffic\" devid=\"X\" subtype=\"forward\" eventtime=1557756000 srcip=203.0.113.5 dstip=10.0.0.1 dstport={dport} proto=6 action=\"deny\""
            );
            let f = parse_syslog(&line);
            FortiGate.parse(&f, "fortigate", "c1", 1)["dedup"].as_str().unwrap().to_string()
        };
        assert_ne!(mk(22), mk(23), "des dst_port distincts -> des dedup distincts");
    }

    #[test]
    fn observer_carries_device_identity() {
        let ev = parse(TRAFFIC); // devname="FGT"
        assert_eq!(ev["fields"]["observer"], "FGT");
    }

    #[test]
    fn no_panic_on_torn_kv() {
        // valeurs manquantes, guillemet non ferme, cles en trop -> jamais de panic.
        for line in [
            "<189>type=\"traffic",
            "<189>srcip= dstip= action= type=traffic devid=x",
            "<189>type=utm subtype= level= eventtime= devid=x",
            "<189>devid=x proto=999 srcport= dstport=",
        ] {
            let f = parse_syslog(line);
            let ev = FortiGate.parse(&f, "fortigate", "c1", 7);
            assert_eq!(ev["source"], "fortigate");
            assert!(ev["fields"].is_object());
        }
    }
}
