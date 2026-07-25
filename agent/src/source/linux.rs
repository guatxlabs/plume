//! Lecteur journald (Linux) — PLEINEMENT IMPLÉMENTÉ.
//!
//! Stratégie : sous-processus `journalctl -o json --no-pager` (portable, pas de FFI sd-journal), repris
//! par `--after-cursor=<c>` (ou `--since=-<since>` au 1er démarrage). Chaque ligne stdout est un objet
//! JSON journald valide -> `NativeRecord { raw: ligne, cursor: __CURSOR }`. On lit AU PLUS `max` lignes
//! puis on tue l'enfant (borne le batch) ; le tour suivant reprend au dernier `__CURSOR` consommé.
//!
//! Expédition : `Wire::Journal` -> les lignes brutes sont concaténées en ndjson et POSTées sur
//! /api/ingest/journal, où le DAEMON fait le parsing (extract_src_ip/journal_user/journal_action, cf.
//! daemon/src/ingest/mod.rs). C'est pourquoi `to_event` reste MINIMAL ici : il reproduit le sous-ensemble
//! du contrat serveur (ts/source/message/severity/dedup, category='auth') pour rester testable hors-ligne
//! et pour les diagnostics `test-ship`.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::{Cursor, Event, NativeRecord, SourceReader, Wire};
use crate::config::JournaldCfg;
use serde_json::Value;

pub struct JournaldReader {
    cfg: JournaldCfg,
    host: String,
    /// Curseur INTERNE (dernier `__CURSOR` consommé), avance à chaque batch. `None` -> repli `--since`.
    cursor: Option<String>,
}

impl JournaldReader {
    pub fn new(cfg: JournaldCfg, host: String) -> Self {
        Self { cfg, host, cursor: None }
    }

    /// Construit la ligne de commande journalctl pour la position courante (testable sans exécuter).
    fn args(&self) -> Vec<String> {
        let mut a = vec![
            "-o".to_string(),
            "json".to_string(),
            "--no-pager".to_string(),
        ];
        match &self.cursor {
            Some(c) => a.push(format!("--after-cursor={c}")),
            None => a.push(format!("--since=-{}", self.cfg.since)),
        }
        // Unités systemd (`-u <unit>`, #66/#67) — OR-ées par journald avec les filtres `_COMM=`.
        for unit in &self.cfg.units {
            a.push("-u".to_string());
            a.push(unit.clone());
        }
        // `_COMM=` multiples sont OR-és par journald (comme journal.sh).
        for comm in &self.cfg.comm {
            a.push(format!("_COMM={comm}"));
        }
        a
    }
}

impl SourceReader for JournaldReader {
    fn source_id(&self) -> &str {
        &self.cfg.id
    }

    fn wire(&self) -> Wire {
        Wire::Journal
    }

    fn open(&mut self, cursor: Cursor) {
        self.cursor = cursor.0;
    }

    fn next_batch(&mut self, max: usize) -> Vec<NativeRecord> {
        #[cfg(target_os = "linux")]
        {
            use std::io::{BufRead, BufReader};
            use std::process::{Command, Stdio};

            if max == 0 {
                return Vec::new();
            }
            let mut child = match Command::new("journalctl")
                .args(self.args())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[journald:{}] spawn journalctl échoué : {e}", self.cfg.id);
                    return Vec::new();
                }
            };
            let mut out = Vec::with_capacity(max.min(1024));
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    let cursor = json_cursor(&line);
                    out.push(NativeRecord { raw: line, cursor });
                    if out.len() >= max {
                        break; // batch borné -> on arrête de lire et on tue l'enfant
                    }
                }
            }
            // Tue l'enfant (on n'a peut-être pas drainé tout stdout) puis reap -> pas de zombie.
            let _ = child.kill();
            let _ = child.wait();
            // Avance le curseur interne au dernier record consommé.
            if let Some(last) = out.iter().rev().find_map(|r| r.cursor.clone()) {
                self.cursor = Some(last);
            }
            out
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = max;
            Vec::new()
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor(self.cursor.clone())
    }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        journald_to_event(&rec.raw, &self.host)
    }
}

/// Extrait `__CURSOR` d'une ligne journald sans désérialiser tout l'objet (chemin chaud).
fn json_cursor(line: &str) -> Option<String> {
    let j: Value = serde_json::from_str(line).ok()?;
    j.get("__CURSOR").and_then(|c| c.as_str()).map(|s| s.to_string())
}

/// Contrat MINIMAL journald -> Event, aligné sur `ingest_journal_lines` du daemon (sous-ensemble) :
/// ts=__REALTIME_TIMESTAMP/1e6, source=_COMM, message=MESSAGE (tableau -> `<binaire N octets>`),
/// severity dérivée de PRIORITY + mots-clés, dedup=__CURSOR, category='auth' (le daemon la force pour
/// le chemin /journal). fields = {pid,uid}. Réutilisé par le test fixture + `test-ship`.
pub fn journald_to_event(line: &str, host: &str) -> Option<Event> {
    let j: Value = serde_json::from_str(line).ok()?;
    let ts = j
        .get("__REALTIME_TIMESTAMP")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|us| us / 1_000_000)
        .unwrap_or_else(super::now_secs);
    let source = j.get("_COMM").and_then(|x| x.as_str()).unwrap_or("journal").to_string();
    let message = match j.get("MESSAGE") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => format!("<binaire {} octets>", a.len()),
        _ => String::new(),
    };
    let pri = j.get("PRIORITY").and_then(|x| x.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(6);
    let ml = message.to_lowercase();
    let severity = if ml.contains("fail") || ml.contains("invalid") || ml.contains("error") || ml.contains("denied") {
        3
    } else if pri <= 3 {
        3
    } else if pri == 4 {
        2
    } else {
        0
    };
    let dedup = j.get("__CURSOR").and_then(|x| x.as_str()).map(|s| s.to_string());
    let fields = serde_json::json!({
        "pid": j.get("_PID").and_then(|x| x.as_str()),
        "uid": j.get("_UID").and_then(|x| x.as_str()),
    });
    Some(Event {
        ts,
        host: host.to_string(),
        source,
        category: "auth".to_string(),
        severity,
        message,
        fields,
        dedup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JournaldCfg;

    const FIXTURE_FAILED: &str = r#"{"__CURSOR":"s=abc;i=1;b=2","__REALTIME_TIMESTAMP":"1700000000000000","_COMM":"sshd","_PID":"4242","_UID":"0","PRIORITY":"5","MESSAGE":"Failed password for invalid user root from 1.2.3.4 port 22 ssh2"}"#;
    const FIXTURE_ACCEPTED: &str = r#"{"__CURSOR":"s=abc;i=2;b=2","__REALTIME_TIMESTAMP":"1700000123000000","_COMM":"sudo","PRIORITY":"6","MESSAGE":"pam_unix(sudo:session): session opened for user root"}"#;

    #[test]
    fn journald_record_to_event_fixture() {
        let e = journald_to_event(FIXTURE_FAILED, "web01").expect("event");
        assert_eq!(e.ts, 1_700_000_000, "us -> s");
        assert_eq!(e.source, "sshd");
        assert_eq!(e.host, "web01");
        assert_eq!(e.category, "auth", "le daemon force category=auth pour /journal");
        assert_eq!(e.severity, 3, "message contient 'fail'/'invalid'");
        assert_eq!(e.message, "Failed password for invalid user root from 1.2.3.4 port 22 ssh2");
        assert_eq!(e.dedup.as_deref(), Some("s=abc;i=1;b=2"));
        assert_eq!(e.fields["pid"], "4242");
        assert_eq!(e.fields["uid"], "0");
    }

    #[test]
    fn severity_from_priority_when_no_keyword() {
        // PRIORITY=6 (info), message sans mot-clé d'échec -> severity 0.
        let e = journald_to_event(FIXTURE_ACCEPTED, "h").unwrap();
        assert_eq!(e.severity, 0);
        assert_eq!(e.source, "sudo");
    }

    #[test]
    fn binary_message_is_stubbed() {
        let line = r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"2000000","_COMM":"x","PRIORITY":"3","MESSAGE":[104,105]}"#;
        let e = journald_to_event(line, "h").unwrap();
        assert_eq!(e.message, "<binaire 2 octets>");
        assert_eq!(e.severity, 3, "PRIORITY<=3 -> severity 3");
    }

    #[test]
    fn bad_json_yields_none() {
        assert!(journald_to_event("not json", "h").is_none());
    }

    #[test]
    fn args_use_since_then_cursor() {
        let mut r = JournaldReader::new(
            JournaldCfg {
                id: "auth".into(),
                comm: vec!["sshd".into(), "sudo".into()],
                units: vec!["nginx.service".into()],
                since: "15min".into(),
            },
            "h".into(),
        );
        let a = r.args();
        assert!(a.contains(&"--since=-15min".to_string()), "1er run -> since");
        assert!(a.contains(&"_COMM=sshd".to_string()));
        assert!(a.contains(&"_COMM=sudo".to_string()));
        // unité systemd déclarée -> `-u nginx.service`
        let upos = a.iter().position(|x| x == "-u");
        assert!(upos.is_some() && a.get(upos.unwrap() + 1).map(|s| s.as_str()) == Some("nginx.service"));
        // après ouverture sur un curseur -> --after-cursor
        r.open(Cursor(Some("s=abc;i=9".into())));
        let a2 = r.args();
        assert!(a2.contains(&"--after-cursor=s=abc;i=9".to_string()));
        assert!(!a2.iter().any(|x| x.starts_with("--since")), "curseur présent -> plus de --since");
    }

    #[test]
    fn cursor_roundtrips() {
        let mut r = JournaldReader::new(JournaldCfg::default(), "h".into());
        assert_eq!(r.cursor(), Cursor(None));
        r.open(Cursor(Some("cur-42".into())));
        assert_eq!(r.cursor(), Cursor(Some("cur-42".into())));
        assert_eq!(r.wire(), Wire::Journal);
    }
}
