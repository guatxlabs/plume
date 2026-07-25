//! Collecteur SOC mail (host-natif) — cf. GuatX-Infra ADR-0008.
//! Lit le maildir, applique des patterns IOC/phishing, emet des events MINIMAUX vers le spool
//! (compte, dossier, sujet/exp., message-id, sample IOC/URL). JAMAIS de body en clair.
//! Le body complet reste un pull gate+audite (capacite agent-side distincte, hors de ce binaire).
mod maildir;
mod patterns;
mod url_extract;

use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
fn mtime_epoch(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(now)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Sous-commandes : `scan` (defaut, detection -> events) | `body` (lecture complete gate+auditee)
    let res = match args.get(1).map(|s| s.as_str()) {
        Some("body") => run_body(&args),
        Some("scan") | None => run(),
        Some(other) => Err(anyhow!("sous-commande inconnue '{other}' (attendu: scan | body)")),
    };
    if let Err(e) = res {
        eprintln!("collector-mail: {e}");
        std::process::exit(1);
    }
}

/// Ecriture atomique d'une enveloppe dans le spool (0640), reutilisee par scan ET audit body.
fn write_spool(spool: &str, name: &str, env: &serde_json::Value) -> Result<String> {
    std::fs::create_dir_all(spool).ok();
    let tmp = format!("{spool}/.{name}.tmp");
    let dst = format!("{spool}/{name}.json");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string(env)?.as_bytes())?;
        f.flush()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640)).ok();
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

/// body-fetch GATE + AUDITE (cf. ADR-0006/0008) : lecture complete d'UN message a la demande.
/// Gate = l'invocation est reservee au central admin (acces agent/SSH) ; chaque lecture est tracee
/// par un event `source=mail-audit` -> SOC (cherchable). Le central rend le html en iframe sandbox+CSP.
/// Usage : plume-collector-mail body <account> <id> [folder]
fn run_body(args: &[String]) -> Result<()> {
    let account = args.get(2).ok_or_else(|| anyhow!("usage: body <account> <id> [folder]"))?;
    let id = args.get(3).ok_or_else(|| anyhow!("usage: body <account> <id> [folder]"))?;
    let folder = args.get(4).map(|s| s.as_str()).unwrap_or("*");
    let root = std::env::var("PLUME_MAIL_ROOT").map_err(|_| anyhow!("PLUME_MAIL_ROOT requis"))?;
    let spool = env_or("PLUME_SPOOL", "/var/lib/plume/spool");
    let host = env_or("PLUME_HOST", &hostname());
    let actor = env_or("PLUME_ACTOR", "unknown"); // le central renseigne QUI declenche la lecture

    let (fname, path) = maildir::find_message(&root, account, folder, id)?;
    let raw = maildir::read_capped(&path)?;
    let parsed = maildir::parse_msg(&raw);

    // AUDIT : trace la lecture AVANT de rendre le body (best-effort -> spool -> SOC + ledger central)
    let ts = now();
    let audit = serde_json::json!({ "ts": ts, "host": host, "kind": "events", "events": [{
        "ts": ts, "source": "mail-audit", "category": "mail", "severity": 1,
        "message": format!("body read: {}/{}/{} by {}", account, fname, id, actor)
    }]});
    if let Err(e) = write_spool(&spool, &format!("mail-audit-{ts}-{}", std::process::id()), &audit) {
        eprintln!("collector-mail: audit non ecrit ({e})"); // on n'avorte pas la lecture pour autant
    }

    // BODY complet -> stdout (le central capte et rend en iframe sandbox + CSP, cf. ADR-0006)
    let headers: serde_json::Map<String, serde_json::Value> = parsed
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    let out = serde_json::json!({
        "account": account, "folder": fname, "id": id,
        "subject": parsed.subject, "from": parsed.from, "to": parsed.to,
        "date": parsed.date, "message_id": parsed.message_id,
        "headers": headers,
        "text": parsed.text_body.unwrap_or_default(),
        "html": parsed.html_body.unwrap_or_default(),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

fn run() -> Result<()> {
    let root = std::env::var("PLUME_MAIL_ROOT")
        .map_err(|_| anyhow!("PLUME_MAIL_ROOT requis (racine maildir, ex: /opt/local-path-provisioner/<pvc>_mail_mail-data-mailserver-0)"))?;
    let domain = env_or("PLUME_MAIL_DOMAIN", "localhost");
    let spool = env_or("PLUME_SPOOL", "/var/lib/plume/spool");
    let host = env_or("PLUME_HOST", &hostname());
    let folder = env_or("PLUME_MAIL_FOLDER", "*");
    let limit: usize = env_or("PLUME_MAIL_LIMIT", "2000").parse().unwrap_or(2000);
    let max_events: usize = env_or("PLUME_MAIL_MAX_EVENTS", "1000").parse().unwrap_or(1000);
    let state_path = env_or("PLUME_MAIL_STATE", &format!("{spool}/.mail-seen"));
    let pat_file = std::env::var("PLUME_MAIL_PATTERNS").ok().filter(|v| !v.is_empty());

    std::fs::create_dir_all(&spool).ok();
    let patterns = patterns::load(pat_file.as_deref())?;

    // etat : messages deja traites (account|folder|fileid) -> scan INCREMENTAL
    let mut seen: HashSet<String> = std::fs::read_to_string(&state_path)
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default();

    let accounts = maildir::list_account_emails(&root, &domain)?;
    let ts = now();
    let mut events: Vec<serde_json::Value> = Vec::new();
    let mut scanned = 0usize;
    let mut newly_seen: Vec<String> = Vec::new();
    let mut capped = false;

    'outer: for account in &accounts {
        let mut paths = match maildir::message_paths(&root, account, &folder) {
            Ok(p) => p,
            Err(_) => continue, // compte/dossier absent -> skip silencieux
        };
        // plus recent d'abord + plafond par compte (borne le cout du 1er run)
        paths.sort_by_cached_key(|(_, p)| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        paths.reverse();
        paths.truncate(limit);

        for (fname, path) in paths {
            let fileid = path.file_name().and_then(|s| s.to_str()).unwrap_or("?").to_string();
            let key = format!("{account}|{fname}|{fileid}");
            if seen.contains(&key) {
                continue; // deja traite
            }
            if events.len() >= max_events {
                capped = true;
                break 'outer; // on laisse le reste NON-vu -> prochain run (pas de flood)
            }
            // a partir d'ici le message est traite -> marque vu meme sans hit
            newly_seen.push(key.clone());
            seen.insert(key);
            scanned += 1;

            let raw = match maildir::read_capped(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let parsed = maildir::parse_msg(&raw);
            let urls = url_extract::extract_urls(parsed.html_body.as_deref(), parsed.text_body.as_deref());
            let hits = patterns::scan_message(&parsed, &raw, &urls, &patterns);
            if hits.is_empty() {
                continue;
            }
            // 1 event MINIMAL par message flagge (severite = max ; pas de body)
            let top = hits.iter().max_by_key(|h| h.severity).unwrap();
            let ids: Vec<&str> = hits.iter().map(|h| h.pattern_id.as_str()).collect();
            let msgid = if parsed.message_id.is_empty() { fileid.clone() } else { parsed.message_id.clone() };
            let subj: String = parsed.subject.chars().take(160).collect();
            let from: String = parsed.from.chars().take(160).collect();
            let message = format!(
                "mail {}: {} -> {}/{} | subj: {} | msgid: {} | patterns: {} | sample: {}",
                top.category, from, account, fname, subj, msgid, ids.join(","), top.sample
            );
            events.push(serde_json::json!({
                "ts": mtime_epoch(&path),
                "source": "mail",
                "category": top.category,
                "severity": top.severity,
                "message": message,
                "dedup": format!("mail:{account}:{fname}:{fileid}"),
                // champs structures -> le central peut cibler le message (body-fetch) sans parser le texte
                "fields": {
                    "account": account, "folder": fname, "fileid": fileid,
                    "msgid": msgid, "patterns": ids.join(","), "sample": top.sample
                },
            }));
        }
    }

    // persiste l'etat (incremental) meme s'il n'y a pas d'event
    if !newly_seen.is_empty() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&state_path) {
            let _ = f.write_all(newly_seen.join("\n").as_bytes());
            let _ = f.write_all(b"\n");
            let _ = std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640));
        }
    }

    if events.is_empty() {
        eprintln!("collector-mail: {} compte(s), {scanned} nouveau(x) message(s), 0 alerte{}",
            accounts.len(), if capped { " (cap atteint)" } else { "" });
        return Ok(());
    }

    // enveloppe spool (meme format que les autres collecteurs) -> ship.sh la poste
    let n_ev = events.len();
    let env = serde_json::json!({ "ts": ts, "host": host, "kind": "events", "events": events });
    let dst = write_spool(&spool, &format!("mail-{ts}"), &env)?;
    eprintln!("collector-mail: {} compte(s), {scanned} nouveau(x) message(s), {n_ev} alerte(s) -> {dst}{}",
        accounts.len(), if capped { " (cap atteint)" } else { "" });
    Ok(())
}
