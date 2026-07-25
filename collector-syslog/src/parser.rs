//! Famille de parsers vendeur PLUGGABLE (config-selectable via `PLUME_SYSLOG_PARSER`).
//!
//! Un parser transforme un `SyslogFrame` (charge utile + entete) en UN event Plume normalise
//! (objet JSON pret pour l'enveloppe `kind=events`). Contrat :
//!   - source = identite du VENDEUR (`fortigate`), category = SEMANTIQUE inter-vendeur (`firewall`,
//!     `malware`, `ids`, `web`, ...) -> les regles de detection composent PAR category, pas par vendeur.
//!   - `src_ip`/`dst_ip` en top-level (promus en colonnes indexees par le daemon), `action` dans
//!     `fields.action` (dimension de rollup CIM), tout le reste dans `fields`.
//!   - NE PANIQUE JAMAIS : une ligne malformee -> un event de repli sur (jamais un drop silencieux).
//!
//! Ajouter un vendeur = implementer `VendorParser` + l'enregistrer dans `select()`. C'est tout.

use crate::framing::SyslogFrame;
use serde_json::{json, Map, Value};

/// Nombre max de champs `fields` par event (borne la cardinalite -> budget index/RAM du daemon).
pub const MAX_FIELDS: usize = 64;
/// Longueur max d'une valeur de champ.
pub const MAX_VAL: usize = 1024;
/// Longueur max du message.
pub const MAX_MSG: usize = 512;

pub trait VendorParser: Send + Sync {
    fn name(&self) -> &'static str;
    /// Normalise `frame` en UN event Plume. `source`/`host` sont la config du collecteur,
    /// `default_ts` l'epoch de reception (fallback quand le vendeur ne fournit pas d'horodatage).
    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value;
}

/// Selection du parser par nom (config `PLUME_SYSLOG_PARSER`). Defaut sur inconnu = generic (jamais un
/// panic ni un drop). `auto` sniffe le vendeur par message.
pub fn select(name: &str) -> Box<dyn VendorParser> {
    match name.trim().to_ascii_lowercase().as_str() {
        "fortigate" | "fortios" | "fortinet" => Box::new(crate::fortigate::FortiGate),
        "auto" => Box::new(Auto),
        _ => Box::new(Generic),
    }
}

/// Source canonique par defaut associee au parser (surchargeable par `PLUME_SYSLOG_SOURCE`).
pub fn default_source(name: &str) -> &'static str {
    match name.trim().to_ascii_lowercase().as_str() {
        "fortigate" | "fortios" | "fortinet" => "fortigate",
        _ => "syslog",
    }
}

// ---------------------------------------------------------------------------------------
//  Helpers PARTAGES par tous les parsers vendeur.
// ---------------------------------------------------------------------------------------

/// severite syslog (0..7, RFC5424 §6.2.1) -> severite Plume (0..4).
/// emerg/alert/crit -> 4 ; err -> 3 ; warn -> 2 ; notice -> 1 ; info/debug -> 0.
pub fn syslog_sev_to_plume(sev: Option<u8>) -> i64 {
    match sev {
        Some(0) | Some(1) | Some(2) => 4,
        Some(3) => 3,
        Some(4) => 2,
        Some(5) => 1,
        Some(6) | Some(7) => 0,
        _ => 1, // pas de PRI : neutre-bas
    }
}

/// Tronque une valeur de champ (protege le budget cardinalite / taille de spool).
pub fn cap_val(s: &str) -> String {
    if s.len() <= MAX_VAL {
        s.to_string()
    } else {
        s.chars().take(MAX_VAL).collect()
    }
}

/// Tokeniseur `key=value` tolerant (format FortiGate/CEF-like). Gere :
///   - valeurs entre guillemets avec espaces (`msg="a b c"`) et guillemets echappes (`\"`),
///   - valeurs nues (`srcip=1.2.3.4`), valeurs vides (`user=`),
///   - jetons parasites sans `=` (ignores), espaces multiples.
/// Ne panique jamais. Retourne les paires DANS L'ORDRE d'apparition.
pub fn parse_kv(s: &str) -> Vec<(String, String)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' && b[i] != b' ' {
            i += 1;
        }
        if i >= b.len() || b[i] == b' ' {
            // jeton sans '=' -> parasite, on saute
            continue;
        }
        let key = &s[ks..i];
        i += 1; // '='
        let val = if i < b.len() && b[i] == b'"' {
            i += 1;
            let vs = i;
            let mut esc = false;
            while i < b.len() {
                if esc {
                    esc = false;
                    i += 1;
                    continue;
                }
                match b[i] {
                    b'\\' => {
                        esc = true;
                        i += 1;
                    }
                    b'"' => break,
                    _ => i += 1,
                }
            }
            let v = unescape(&s[vs..i]);
            if i < b.len() {
                i += 1; // guillemet fermant
            }
            v
        } else {
            let vs = i;
            while i < b.len() && b[i] != b' ' {
                i += 1;
            }
            s[vs..i].to_string()
        };
        if !key.is_empty() {
            out.push((key.to_string(), val));
        }
    }
    out
}

fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    if esc {
        out.push('\\');
    }
    out
}

/// Injecte les paires SD de l'entete (provenance) dans `fields`, sans depasser `MAX_FIELDS`.
pub fn fold_sd(fields: &mut Map<String, Value>, frame: &SyslogFrame) {
    for (k, v) in &frame.sd {
        if fields.len() >= MAX_FIELDS {
            break;
        }
        fields.entry(k.clone()).or_insert_with(|| json!(cap_val(v)));
    }
}

/// Ajoute la provenance transport (facility/severity syslog + host/ts d'entete) dans `fields`.
pub fn add_syslog_provenance(fields: &mut Map<String, Value>, frame: &SyslogFrame) {
    if let Some(fac) = frame.facility {
        fields.insert("syslog_facility".into(), json!(fac));
    }
    if let Some(sev) = frame.severity {
        fields.insert("syslog_severity".into(), json!(sev));
    }
    if let Some(h) = &frame.hostname {
        fields.insert("syslog_host".into(), json!(cap_val(h)));
    }
    if let Some(ts) = &frame.timestamp {
        fields.insert("syslog_ts".into(), json!(cap_val(ts)));
    }
}

// ---------------------------------------------------------------------------------------
//  Parser GENERIC (repli inter-vendeur : n'importe quel appareil syslog).
// ---------------------------------------------------------------------------------------

pub struct Generic;

impl VendorParser for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }
    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value {
        let mut fields = Map::new();
        // provenance device (multi-appareil) : `observer` = hostname d'entete syslog de l'emetteur.
        // `host` reste le collecteur ; `observer` distingue les appareils qui pointent le meme collecteur.
        if let Some(h) = frame.hostname.as_deref().filter(|s| !s.is_empty()) {
            fields.insert("observer".into(), json!(cap_val(h)));
        }
        add_syslog_provenance(&mut fields, frame);
        fold_sd(&mut fields, frame);
        if let Some(app) = &frame.app_name {
            fields.insert("app".into(), json!(cap_val(app)));
        }
        let msg: String = if frame.msg.is_empty() {
            "(message syslog vide)".to_string()
        } else {
            frame.msg.chars().take(MAX_MSG).collect()
        };
        json!({
            "ts": default_ts,
            "source": source,
            "category": "syslog",
            "severity": syslog_sev_to_plume(frame.severity),
            "message": msg,
            "host": host,
            "fields": Value::Object(fields),
        })
    }
}

// ---------------------------------------------------------------------------------------
//  Parser AUTO : sniffe le vendeur par message, delegue. Attribution de source par vendeur detecte.
// ---------------------------------------------------------------------------------------

pub struct Auto;

/// Signature FortiGate : `devid=` OU `logid=` OU (`type=` && `subtype=` && `eventtime=`).
fn sniff_fortigate(msg: &str) -> bool {
    msg.contains("devid=")
        || msg.contains("logid=")
        || (msg.contains("type=") && msg.contains("subtype=") && msg.contains("eventtime="))
}

impl VendorParser for Auto {
    fn name(&self) -> &'static str {
        "auto"
    }
    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value {
        if sniff_fortigate(&frame.msg) {
            // attribution correcte meme si la source configuree est generique
            crate::fortigate::FortiGate.parse(frame, "fortigate", host, default_ts)
        } else {
            Generic.parse(frame, source, host, default_ts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::parse_syslog;

    #[test]
    fn sev_mapping() {
        assert_eq!(syslog_sev_to_plume(Some(0)), 4);
        assert_eq!(syslog_sev_to_plume(Some(2)), 4);
        assert_eq!(syslog_sev_to_plume(Some(3)), 3);
        assert_eq!(syslog_sev_to_plume(Some(4)), 2);
        assert_eq!(syslog_sev_to_plume(Some(5)), 1);
        assert_eq!(syslog_sev_to_plume(Some(7)), 0);
        assert_eq!(syslog_sev_to_plume(None), 1);
    }

    #[test]
    fn kv_quoted_unquoted_empty() {
        let kv = parse_kv(r#"a=1 b="two words" c= d="with \"quote\"" bareflag e=5"#);
        let get = |k: &str| kv.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("a"), Some("1"));
        assert_eq!(get("b"), Some("two words"));
        assert_eq!(get("c"), Some(""));
        assert_eq!(get("d"), Some(r#"with "quote""#));
        assert_eq!(get("e"), Some("5"));
        assert!(get("bareflag").is_none()); // jeton sans '=' ignore
    }

    #[test]
    fn kv_never_panics_on_garbage() {
        for junk in ["", "=", "===", "\"", "a=\"unterminated", "   ", "k=", "=v"] {
            let _ = parse_kv(junk); // ne doit pas paniquer
        }
    }

    #[test]
    fn generic_builds_event() {
        let f = parse_syslog("<34>Oct 11 22:14:15 host sshd: failed login");
        let ev = Generic.parse(&f, "syslog", "collector-1", 1000);
        assert_eq!(ev["source"], "syslog");
        assert_eq!(ev["category"], "syslog");
        assert_eq!(ev["severity"], 4); // crit (sev 2)
        assert_eq!(ev["fields"]["syslog_facility"], 4);
        assert!(ev["message"].as_str().unwrap().contains("sshd"));
    }

    #[test]
    fn auto_routes_fortigate() {
        let f = parse_syslog(
            "<189>date=2019-05-13 time=15:00:00 devid=\"FG100D\" type=\"traffic\" subtype=\"forward\" eventtime=1557756000 action=\"accept\"",
        );
        let ev = Auto.parse(&f, "syslog", "c1", 1);
        assert_eq!(ev["source"], "fortigate"); // sniff -> attribution vendeur
        assert_eq!(ev["category"], "firewall");
    }

    #[test]
    fn auto_falls_back_generic() {
        let f = parse_syslog("<34>Oct 11 22:14:15 host random: not a firewall");
        let ev = Auto.parse(&f, "syslog", "c1", 1);
        assert_eq!(ev["source"], "syslog");
        assert_eq!(ev["category"], "syslog");
    }
}
