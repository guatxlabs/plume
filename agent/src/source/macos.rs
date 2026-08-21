//! Lecteur macOS unified log — IMPLÉMENTÉ (sous-processus `log`, miroir de la stratégie journald).
//!
//! Stratégie : à chaque `next_batch`, sous-processus `log show --style ndjson` (1 objet JSON/ligne,
//! macOS 11+) borné par le curseur. Reprise par timestamp : `--start '<ts>'` reprend au dernier
//! `timestamp` consommé (au 1er démarrage : `--last <since>`), un prédicat optionnel filtre les
//! subsystems/process. On lit AU PLUS `max` lignes, on tue l'enfant (borne le lot), et on avance le
//! curseur au dernier `timestamp`. La borne `--start` est INCLUSIVE -> l'event pivot est relu au tour
//! suivant ; la déduplication côté daemon (`dedup`) absorbe le doublon (sémantique at-least-once).
//!
//! Champs `log` utiles : `timestamp`, `eventMessage`, `subsystem`, `category`, `processImagePath`,
//! `processID`, `messageType` (Default/Info/Debug/Error/Fault), `traceID`.
//!
//! Fil : `Wire::Events` -> enveloppe `kind:events` sur `/api/ingest`. Le mapping ndjson -> `Event`
//! (`oslog_to_event`) est PUR -> testé sur Linux ; seul le spawn de `log` est `cfg(target_os="macos")`.
//!
//! Validation runtime : nécessite un hôte macOS (`log` absent ailleurs).
//! Cross-compile depuis Linux : `cargo zigbuild --target aarch64-apple-darwin` (ou `osxcross`).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use super::{Cursor, Event, NativeRecord, SourceReader, Wire};
use crate::config::OsLogCfg;
use serde_json::Value;

pub struct OsLogReader {
    cfg: OsLogCfg,
    host: String,
    /// Curseur = dernier `timestamp` consommé -> `log show --start <ts>`.
    cursor: Option<String>,
}

impl OsLogReader {
    pub fn new(cfg: OsLogCfg, host: String) -> Self {
        Self { cfg, host, cursor: None }
    }

    /// Ligne de commande `log show` pour la position courante (pure -> testable sans exécuter).
    /// `log` n'accepte pas la partie fractionnaire dans `--start` : on tronque à la seconde.
    fn args(&self) -> Vec<String> {
        let mut a = vec![
            "show".to_string(),
            "--style".to_string(),
            "ndjson".to_string(),
            "--info".to_string(),
        ];
        match &self.cursor {
            Some(ts) => {
                a.push("--start".to_string());
                a.push(start_arg(ts));
            }
            None => {
                a.push("--last".to_string());
                a.push(self.cfg.since.clone());
            }
        }
        if let Some(p) = &self.cfg.predicate {
            if !p.trim().is_empty() {
                a.push("--predicate".to_string());
                a.push(p.clone());
            }
        }
        a
    }
}

/// Normalise un timestamp `log` (`2026-06-28 12:34:56.789012-0700`) en argument `--start` accepté
/// (`"2026-06-28 12:34:56"`), en retirant la partie fractionnaire et le fuseau.
fn start_arg(ts: &str) -> String {
    // garde `YYYY-MM-DD HH:MM:SS` : retire la partie fractionnaire, puis le fuseau (`Z` ou `±HH:MM`).
    let no_frac = ts.split('.').next().unwrap_or(ts);
    let mut out = String::new();
    let mut colons = 0;
    for c in no_frac.chars() {
        if c == 'Z' || c == 'z' {
            break; // fuseau UTC collé aux secondes
        }
        if c == ':' {
            colons += 1;
        }
        // arrête au fuseau `+`/`-` APRÈS l'heure (après au moins un ':')
        if (c == '+' || c == '-') && colons >= 1 {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

impl SourceReader for OsLogReader {
    fn source_id(&self) -> &str {
        &self.cfg.id
    }

    fn wire(&self) -> Wire {
        Wire::Events
    }

    fn open(&mut self, cursor: Cursor) {
        self.cursor = cursor.0;
    }

    /// `S36` — MÊME FIGURE QUE LE LECTEUR JOURNALD, MÊME REMÈDE. `log show` absent ou refusé, flux
    /// coupé en cours de lot, code de retour jeté : trois chemins vers le lot vide, c'est-à-dire vers
    /// « cet hôte n'a rien à dire ». Le statut n'est consulté que si le plafond du lot n'a PAS été
    /// atteint (sinon c'est notre propre signal qu'on lirait comme un échec de la source).
    fn next_batch(&mut self, max: usize) -> crate::lisibilite::Releve {
        use crate::lisibilite::Releve;
        if max == 0 {
            return Releve::rien_a_faire();
        }
        #[cfg(target_os = "macos")]
        {
            use crate::lisibilite::{cause_io, CAUSE_SOURCE_ILLISIBLE, RAISON_DEPENDANCE_ABSENTE, RAISON_SOURCE_ABSENTE};
            use std::io::{BufRead, BufReader};
            use std::process::{Command, Stdio};

            let mut child = match Command::new("log")
                .args(self.args())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    return Releve::illisible(
                        RAISON_DEPENDANCE_ABSENTE,
                        cause_io(&e),
                        format!("[oslog:{}] exécution de `log` impossible : {e}", self.cfg.id),
                    )
                }
            };
            let mut out = Vec::with_capacity(max.min(1024));
            let mut interrompu: Option<String> = None;
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for ligne in reader.lines() {
                    let line = match ligne {
                        Ok(l) => l.trim().to_string(),
                        Err(e) => {
                            interrompu = Some(format!(
                                "[oslog:{}] flux de `log` interrompu après {} ligne(s) : {e}",
                                self.cfg.id,
                                out.len()
                            ));
                            break;
                        }
                    };
                    // `log show --style ndjson` peut préfixer/suffixer avec `[` / `]` selon la version.
                    if line.is_empty() || line == "[" || line == "]" {
                        continue;
                    }
                    let line = line.trim_end_matches(',').to_string();
                    let cursor = ndjson_timestamp(&line);
                    out.push(NativeRecord { raw: line, cursor });
                    if out.len() >= max {
                        break;
                    }
                }
            }
            let plafond_atteint = out.len() >= max;
            let _ = child.kill();
            let statut = child.wait();
            if let Some(last) = out.iter().rev().find_map(|r| r.cursor.clone()) {
                self.cursor = Some(last);
            }
            if let Some(detail) = interrompu {
                return Releve::partiel(out, RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ILLISIBLE, detail);
            }
            if !plafond_atteint {
                if let Ok(st) = statut {
                    if !st.success() {
                        return Releve::partiel(
                            out,
                            RAISON_SOURCE_ABSENTE,
                            CAUSE_SOURCE_ILLISIBLE,
                            format!(
                                "[oslog:{}] `log show` a terminé en échec ({st}) — prédicat refusé, \
                                 borne de reprise invalide ou accès interdit ; un lot vide ne veut alors \
                                 pas dire que le journal l'est",
                                self.cfg.id
                            ),
                        );
                    }
                }
            }
            Releve::lu(out)
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Ce lecteur n'est construit QUE sur macOS ; ailleurs c'est `UnsupportedReader` qui répond
            // et qui avoue. Ce bras n'existe que pour la compilation croisée, et il ne prétend pas
            // avoir lu.
            Releve::illisible(
                crate::lisibilite::RAISON_SOUS_SYSTEME_ABSENT,
                crate::lisibilite::CAUSE_SOURCE_ABSENTE,
                "l'unified log n'existe que sur macOS",
            )
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor(self.cursor.clone())
    }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        oslog_to_event(&rec.raw, &self.host)
    }
}

/// Extrait `timestamp` d'une ligne ndjson `log` (chemin curseur, sans désérialiser tout l'objet inutilement).
fn ndjson_timestamp(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    v.get("timestamp").and_then(|t| t.as_str()).map(|s| s.to_string())
}

/// Basename d'un chemin de processus (`/usr/sbin/sshd` -> `sshd`).
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Ligne ndjson `log` -> `Event` (contrat Plume, mapping CIM). Pur -> testé sur Linux.
pub fn oslog_to_event(line: &str, host: &str) -> Option<Event> {
    let v: Value = serde_json::from_str(line).ok()?;
    let subsystem = v.get("subsystem").and_then(|x| x.as_str()).unwrap_or("");
    let os_category = v.get("category").and_then(|x| x.as_str()).unwrap_or("");
    let process_path = v.get("processImagePath").and_then(|x| x.as_str()).unwrap_or("");
    let process = basename(process_path);
    let message = v.get("eventMessage").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let msg_type = v.get("messageType").and_then(|x| x.as_str()).unwrap_or("Default");
    let ts = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .and_then(super::parse_epoch)
        .unwrap_or_else(super::now_secs);

    // Sévérité : Fault/Error -> 3 ; sinon 0. Recoupe aussi les mots-clés d'échec (parité journald).
    let ml = message.to_ascii_lowercase();
    let severity = if matches!(msg_type, "Error" | "Fault")
        || ml.contains("fail")
        || ml.contains("denied")
        || ml.contains("invalid")
    {
        3
    } else {
        0
    };

    // Catégorie CIM : auth pour les process/subsystems d'authentification ; réseau pour les subsystems
    // réseau ; sinon vide (le dparser côté daemon tranche). Vocabulaire aligné sur le daemon.
    let sub_l = subsystem.to_ascii_lowercase();
    let category = if is_auth(process) || sub_l.contains("auth") || sub_l.contains("ssh") {
        "auth"
    } else if sub_l.contains("network") || sub_l.contains("nehelper") || sub_l.contains("firewall") {
        "network"
    } else {
        ""
    };

    let source = if !subsystem.is_empty() {
        subsystem.to_string()
    } else if !process.is_empty() {
        process.to_string()
    } else {
        "oslog".to_string()
    };

    let dedup = v
        .get("traceID")
        .and_then(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_i64().map(|n| n.to_string())))
        .map(|t| format!("mac-{t}"))
        .unwrap_or_else(|| format!("mac-{ts}-{:x}", fnv1a(&message)));

    let fields = serde_json::json!({
        "subsystem": subsystem,
        "os_category": os_category,
        "process": process,
        "pid": v.get("processID"),
        "messageType": msg_type,
    });

    Some(Event {
        ts,
        host: host.to_string(),
        source,
        category: category.to_string(),
        severity,
        message,
        fields,
        dedup: Some(dedup),
    })
}

fn is_auth(process: &str) -> bool {
    matches!(
        process,
        "sshd" | "sudo" | "su" | "login" | "authd" | "opendirectoryd" | "loginwindow" | "securityd"
    )
}

/// Petit hash FNV-1a 64 bits pour le repli de `dedup` (quand `traceID` absent). Pur/déterministe.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OsLogCfg;

    const LINE_SSH_FAIL: &str = r#"{"timestamp":"2026-06-28 12:34:56.789012-0700","eventMessage":"Failed password for invalid user root","subsystem":"com.openssh.sshd","category":"","processImagePath":"/usr/sbin/sshd","processID":501,"messageType":"Error","traceID":123456789}"#;
    const LINE_INFO: &str = r#"{"timestamp":"2026-06-28 00:00:01Z","eventMessage":"routine housekeeping","subsystem":"com.apple.something","category":"general","processImagePath":"/usr/libexec/foo","processID":42,"messageType":"Default","traceID":"abc"}"#;

    #[test]
    fn maps_ssh_failure_to_auth_sev3() {
        let e = oslog_to_event(LINE_SSH_FAIL, "mac01").expect("event");
        assert_eq!(e.category, "auth", "sshd -> auth");
        assert_eq!(e.severity, 3, "messageType Error -> 3");
        assert_eq!(e.source, "com.openssh.sshd");
        assert_eq!(e.fields["process"], "sshd");
        assert_eq!(e.fields["pid"], 501);
        assert_eq!(e.dedup.as_deref(), Some("mac-123456789"));
        // 12:34:56 -0700 -> 19:34:56 UTC
        assert_eq!(e.ts, 1_782_650_096 + 7 * 3600);
    }

    #[test]
    fn benign_info_is_empty_category_sev0() {
        let e = oslog_to_event(LINE_INFO, "mac01").unwrap();
        assert_eq!(e.category, "");
        assert_eq!(e.severity, 0);
        assert_eq!(e.dedup.as_deref(), Some("mac-abc"));
        // 2026-06-28 00:00:01Z (minuit + 1s) = 1782604801.
        assert_eq!(e.ts, 1_782_604_801);
    }

    #[test]
    fn dedup_falls_back_to_hash_without_traceid() {
        let line = r#"{"timestamp":"2026-06-28 00:00:01Z","eventMessage":"m","subsystem":"s","processImagePath":"/x/p","processID":1,"messageType":"Default"}"#;
        let d = oslog_to_event(line, "h").unwrap().dedup.unwrap();
        assert!(d.starts_with("mac-"), "repli hash déterministe : {d}");
    }

    #[test]
    fn bad_json_is_none() {
        assert!(oslog_to_event("not json", "h").is_none());
    }

    #[test]
    fn args_use_last_then_start() {
        let mut r = OsLogReader::new(
            OsLogCfg { id: "oslog".into(), predicate: Some("subsystem == \"com.apple.foo\"".into()), since: "15m".into() },
            "h".into(),
        );
        let a = r.args();
        assert!(a.contains(&"--last".to_string()));
        assert!(a.contains(&"15m".to_string()));
        assert!(a.contains(&"--predicate".to_string()));
        // après ouverture sur un curseur -> --start (tronqué à la seconde)
        r.open(Cursor(Some("2026-06-28 12:34:56.789012-0700".into())));
        let a2 = r.args();
        assert!(a2.contains(&"--start".to_string()));
        assert!(a2.contains(&"2026-06-28 12:34:56".to_string()), "start tronqué : {a2:?}");
        assert!(!a2.iter().any(|x| x == "--last"));
    }

    #[test]
    fn start_arg_strips_fraction_and_tz() {
        assert_eq!(start_arg("2026-06-28 12:34:56.789012-0700"), "2026-06-28 12:34:56");
        assert_eq!(start_arg("2026-06-28 12:34:56Z"), "2026-06-28 12:34:56");
        assert_eq!(start_arg("2026-06-28 12:34:56"), "2026-06-28 12:34:56");
    }

    #[test]
    fn cursor_roundtrips() {
        let mut r = OsLogReader::new(
            OsLogCfg { id: "oslog".into(), predicate: None, since: "15m".into() },
            "h".into(),
        );
        assert_eq!(r.wire(), Wire::Events);
        assert_eq!(r.cursor(), Cursor(None));
        r.open(Cursor(Some("2026-06-28 12:00:00Z".into())));
        assert_eq!(r.cursor(), Cursor(Some("2026-06-28 12:00:00Z".into())));
        #[cfg(not(target_os = "macos"))]
        assert!(r.next_batch(5).records.is_empty());
    }
}
