//! Lecture maildir (porte du mail-scanner-service GuatX-Infra, cf. ADR-0008).
//! Detecte le layout (PLAT <root>/<user> ou NESTED <root>/<domain>/<user>),
//! liste les comptes, enumere les messages, parse les CHAMPS (jamais de body shippe).
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Plafond d'octets lus par fichier maildir (couvre message_size_limit + overhead MIME/base64).
pub const MAX_RAW_BYTES: usize = 15_000_000;
/// Plafond du foin passe au moteur regex sur les parties body (apres decodage MIME).
pub const MAX_HAYSTACK_BYTES: usize = 5_000_000;

pub fn validate_email(email: &str) -> Result<(&str, &str)> {
    let (local, domain) = email.split_once('@').ok_or_else(|| anyhow!("email invalide"))?;
    if local.is_empty() || domain.is_empty() {
        return Err(anyhow!("email invalide"));
    }
    if local.contains('/') || local.contains("..") || domain.contains('/') || domain.contains("..") {
        return Err(anyhow!("caracteres invalides dans l'email"));
    }
    Ok((local, domain))
}

pub fn account_path(root: &str, email: &str) -> Result<PathBuf> {
    let (local, domain) = validate_email(email)?;
    let nested = Path::new(root).join(domain).join(local);
    if nested.exists() {
        return Ok(nested);
    }
    Ok(Path::new(root).join(local))
}

fn folder_subpath(folder: &str) -> String {
    if folder == "INBOX" {
        String::new()
    } else {
        format!(".{}", folder.trim_start_matches('.'))
    }
}

fn is_maildir(path: &Path) -> bool {
    path.join("cur").is_dir() || path.join("new").is_dir()
}

fn has_maildir_children(path: &Path) -> bool {
    if let Ok(entries) = std::fs::read_dir(path) {
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && is_maildir(&e.path()) {
                return true;
            }
        }
    }
    false
}

/// Emails des comptes (gere layout PLAT et NESTED, comme le scanner).
pub fn list_account_emails(root: &str, mail_domain: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(anyhow!("maildir root introuvable: {}", root));
    }
    for entry in std::fs::read_dir(root_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if is_maildir(&path) {
            out.push(format!("{}@{}", name, mail_domain));
        } else if has_maildir_children(&path) {
            let domain = name;
            for ue in std::fs::read_dir(&path)? {
                let ue = ue?;
                if !ue.file_type()?.is_dir() {
                    continue;
                }
                let user = ue.file_name().to_string_lossy().to_string();
                if user.starts_with('.') {
                    continue;
                }
                out.push(format!("{}@{}", user, domain));
            }
        } else {
            out.push(format!("{}@{}", name, mail_domain));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Chemins (dossier, fichier) des messages cur+new ; folder "*"/"all" = tous les dossiers.
pub fn message_paths(root: &str, email: &str, folder: &str) -> Result<Vec<(String, PathBuf)>> {
    let base = account_path(root, email)?;
    if !base.exists() {
        return Err(anyhow!("compte introuvable: {}", email));
    }
    let folder_dirs: Vec<(String, PathBuf)> = if folder == "*" || folder.eq_ignore_ascii_case("all") {
        let mut dirs = vec![("INBOX".to_string(), base.clone())];
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with('.') && n.len() > 1 && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    dirs.push((n.trim_start_matches('.').to_string(), e.path()));
                }
            }
        }
        dirs
    } else if folder == "INBOX" {
        vec![("INBOX".to_string(), base.clone())]
    } else {
        let p = base.join(folder_subpath(folder));
        if !p.exists() {
            return Err(anyhow!("dossier introuvable: {}", folder));
        }
        vec![(folder.to_string(), p)]
    };

    let mut out = Vec::new();
    for (folder_name, folder_dir) in folder_dirs {
        for sub in ["cur", "new"] {
            let d = folder_dir.join(sub);
            if !d.exists() {
                continue;
            }
            for entry in WalkDir::new(&d).max_depth(1).into_iter().flatten() {
                if entry.file_type().is_file() {
                    out.push((folder_name.clone(), entry.path().to_path_buf()));
                }
            }
        }
    }
    Ok(out)
}

/// Localise un message par son id de fichier (egal ou prefixe). Pour le body-fetch gate.
pub fn find_message(root: &str, email: &str, folder: &str, id: &str) -> Result<(String, PathBuf)> {
    for (fname, p) in message_paths(root, email, folder)? {
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name == id || name.starts_with(id) {
                return Ok((fname, p));
            }
        }
    }
    Err(anyhow!("message introuvable: {}", id))
}

pub fn read_capped(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut buf = Vec::new();
    f.by_ref().take(MAX_RAW_BYTES as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// En-tetes pertinents pour le triage/forensique (allowliste : spam, auth, provenance).
pub const RELEVANT_HEADERS: [&str; 8] = [
    "X-Spam-Flag", "X-Spam-Score", "X-Spam-Level", "Authentication-Results",
    "Received-SPF", "Return-Path", "Message-ID", "DKIM-Signature",
];

/// Champs parses d'un message. `text_body`/`html_body` ne sont retournes au central
/// QUE par le chemin body-fetch gate+audite ; le scan local ne shippe que des samples.
pub struct Parsed {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: Vec<(String, String)>,
}

pub fn parse_msg(raw: &[u8]) -> Parsed {
    use mail_parser::MessageParser;
    match MessageParser::default().parse(raw) {
        Some(m) => {
            let from = m
                .from()
                .and_then(|a| a.first())
                .and_then(|a| a.address.as_deref().map(|s| s.to_string()))
                .unwrap_or_default();
            let to = m
                .to()
                .and_then(|a| a.first())
                .and_then(|a| a.address.as_deref().map(|s| s.to_string()))
                .unwrap_or_default();
            let headers = RELEVANT_HEADERS
                .iter()
                .filter_map(|h| {
                    m.header(*h)
                        .and_then(|v| v.as_text())
                        .map(|t| (h.to_string(), t.to_string()))
                })
                .collect();
            Parsed {
                from,
                to,
                subject: m.subject().unwrap_or("").to_string(),
                date: m.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
                message_id: m.message_id().unwrap_or("").to_string(),
                text_body: m.body_text(0).map(|s| s.into_owned()),
                html_body: m.body_html(0).map(|s| s.into_owned()),
                headers,
            }
        }
        None => Parsed {
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            date: String::new(),
            message_id: String::new(),
            text_body: None,
            html_body: None,
            headers: Vec::new(),
        },
    }
}
