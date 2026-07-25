//! Ecriture ATOMIQUE d'enveloppes d'events dans le spool (0640, publication par `rename`).
//!
//! Format IDENTIQUE aux autres collecteurs (cf. `collectors/conntrack.sh`, `collector-mail`) :
//! `{ "ts":<epoch>, "host":<str>, "kind":"events", "events":[ ... ] }`.
//! `ship.sh` POST ces `*.json` vers `/api/ingest` (mTLS + token). On ne parle JAMAIS au daemon
//! directement -> on herite gratis de la garde-disque, du cap events/req, du marqueur tenant et du
//! host lie a l'agent (anti-forge) cote daemon.

use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Ecrit UNE enveloppe `kind=events` atomiquement. Nom `syslog-<ts>-<pid>-<seq>.json` (jamais un
/// dotfile -> `ship.sh` le voit ; le `.tmp` en cours d'ecriture commence par `.` -> ignore).
pub fn write_events(spool: &str, host: &str, ts: i64, events: &[Value]) -> std::io::Result<String> {
    if events.is_empty() {
        return Ok(String::new());
    }
    std::fs::create_dir_all(spool).ok();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base = format!("syslog-{ts}-{pid}-{seq}");
    let tmp = format!("{spool}/.{base}.tmp");
    let dst = format!("{spool}/{base}.json");

    let env: Value = json!({ "ts": ts, "host": host, "kind": "events", "events": events });
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string(&env)?.as_bytes())?;
        f.flush()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640)).ok();
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_valid_envelope() {
        let dir = std::env::temp_dir().join(format!("plume-syslog-test-{}", std::process::id()));
        let dir_s = dir.to_string_lossy().to_string();
        let _ = std::fs::create_dir_all(&dir);
        let events = vec![json!({"ts":1,"source":"fortigate","category":"firewall","severity":1,"message":"x"})];
        let path = write_events(&dir_s, "host1", 123, &events).unwrap();
        assert!(path.ends_with(".json"));
        assert!(!std::path::Path::new(&path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with('.'));
        let content = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["kind"], "events");
        assert_eq!(v["host"], "host1");
        assert_eq!(v["events"].as_array().unwrap().len(), 1);
        // permissions 0640
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_events_noop() {
        let path = write_events("/nonexistent/should/not/matter", "h", 1, &[]).unwrap();
        assert!(path.is_empty());
    }
}
