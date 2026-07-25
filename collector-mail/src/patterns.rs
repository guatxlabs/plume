//! Patterns de detection (curated) + scan d'un message -> hits MINIMAUX.
//! Moteur `regex` (automate fini, temps lineaire = pas de ReDoS) + cap taille compilee.
use crate::maildir::{Parsed, MAX_HAYSTACK_BYTES};
use crate::url_extract::ExtractedUrl;
use anyhow::{anyhow, Result};
use regex::{Regex, RegexBuilder};

pub const MAX_PATTERN_LEN: usize = 512;
const MAX_SAMPLE: usize = 200;

#[derive(Clone, Copy, PartialEq)]
pub enum Target {
    Subject,
    From,
    TextBody,
    HtmlBody,
    Url,
    DecodedUrl,
    Headers,
}
impl Target {
    fn parse(s: &str) -> Target {
        match s {
            "subject" => Target::Subject,
            "from" => Target::From,
            "text_body" => Target::TextBody,
            "html_body" => Target::HtmlBody,
            "url" => Target::Url,
            "headers" => Target::Headers,
            _ => Target::DecodedUrl,
        }
    }
}

pub struct Pattern {
    pub id: String,
    pub category: String,
    pub severity: i64,
    pub target: Target,
    pub re: Regex,
}

pub struct Hit {
    pub pattern_id: String,
    pub category: String,
    pub severity: i64,
    pub sample: String,
}

fn compile(rx: &str) -> Result<Regex> {
    if rx.is_empty() || rx.len() > MAX_PATTERN_LEN {
        return Err(anyhow!("regex vide ou trop longue (max {})", MAX_PATTERN_LEN));
    }
    RegexBuilder::new(rx)
        .size_limit(1 << 20) // borne la taille de l'automate compile
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| anyhow!("regex invalide: {}", e))
}

fn p(id: &str, category: &str, severity: i64, target: &str, rx: &str) -> Result<Pattern> {
    Ok(Pattern {
        id: id.to_string(),
        category: category.to_string(),
        severity,
        target: Target::parse(target),
        re: compile(rx)?,
    })
}

/// Jeu par defaut (IOC / phishing / URL). Surchargeable via un fichier JSON (PLUME_MAIL_PATTERNS).
pub fn defaults() -> Vec<Pattern> {
    [
        p("phishing-account-action", "mail-phishing", 2, "subject",
          r"(?i)(password|mot de passe|reset|verif(y|ier)|suspend|locked|verrouill|unusual sign|connexion inhabituelle)"),
        p("phishing-urgent", "mail-phishing", 1, "subject",
          r"(?i)(urgent|immediate|action required|action requise|derniere chance|expire|24\s*hours|24\s*heures)"),
        p("raw-ip-url", "mail-url", 2, "url",
          r"https?://\d{1,3}(\.\d{1,3}){3}"),
        p("punycode-url", "mail-url", 2, "url",
          r"https?://[^/\s]*xn--"),
        p("credential-url", "mail-phishing", 2, "url",
          r"(?i)https?://[^/\s]+/[^\s]*(login|signin|verify|secure|account|update|confirm)"),
        p("executable-link", "mail-malware", 3, "url",
          r"(?i)https?://[^\s]+\.(exe|scr|js|vbs|hta|jar|apk|iso|img|bat|cmd|ps1)(\?|$)"),
        p("decoded-credential", "mail-url", 2, "decoded_url",
          r"(?i)(login|password|passwd|token|secret|email=)"),
    ]
    .into_iter()
    .collect::<Result<Vec<_>>>()
    .expect("patterns par defaut valides")
}

/// Charge des patterns depuis un JSON [{id,category,severity,target,regex}] (sinon defaults()).
pub fn load(path: Option<&str>) -> Result<Vec<Pattern>> {
    let Some(path) = path else { return Ok(defaults()) };
    let txt = std::fs::read_to_string(path).map_err(|e| anyhow!("lecture {}: {}", path, e))?;
    let arr: serde_json::Value = serde_json::from_str(&txt)?;
    let arr = arr.as_array().ok_or_else(|| anyhow!("patterns: tableau JSON attendu"))?;
    let mut out = Vec::new();
    for it in arr {
        out.push(p(
            it.get("id").and_then(|v| v.as_str()).unwrap_or("custom"),
            it.get("category").and_then(|v| v.as_str()).unwrap_or("mail"),
            it.get("severity").and_then(|v| v.as_i64()).unwrap_or(1),
            it.get("target").and_then(|v| v.as_str()).unwrap_or("decoded_url"),
            it.get("regex").and_then(|v| v.as_str()).unwrap_or(""),
        )?);
    }
    if out.is_empty() {
        return Err(anyhow!("patterns: fichier vide"));
    }
    Ok(out)
}

fn cap_boundary(s: &str) -> &str {
    if s.len() <= MAX_HAYSTACK_BYTES {
        return s;
    }
    let mut cut = MAX_HAYSTACK_BYTES;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

fn sample_of(s: &str) -> String {
    s.chars().take(MAX_SAMPLE).collect()
}

/// Scanne un message : au plus 1 hit par pattern (suffit pour un event). Aucun body retourne.
pub fn scan_message(parsed: &Parsed, raw: &[u8], urls: &[ExtractedUrl], patterns: &[Pattern]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for pat in patterns {
        let hit_sample: Option<String> = match pat.target {
            Target::Subject => pat.re.find(&parsed.subject).map(|m| sample_of(m.as_str())),
            Target::From => pat.re.find(&parsed.from).map(|m| sample_of(m.as_str())),
            Target::TextBody => parsed
                .text_body
                .as_deref()
                .and_then(|t| pat.re.find(cap_boundary(t)).map(|m| sample_of(m.as_str()))),
            Target::HtmlBody => parsed
                .html_body
                .as_deref()
                .and_then(|h| pat.re.find(cap_boundary(h)).map(|m| sample_of(m.as_str()))),
            Target::Headers => {
                let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len().min(8192));
                let h = String::from_utf8_lossy(&raw[..end]);
                pat.re.find(&h).map(|m| sample_of(m.as_str()))
            }
            Target::Url => urls
                .iter()
                .find(|u| pat.re.is_match(&u.url))
                .map(|u| sample_of(&u.url)),
            Target::DecodedUrl => urls.iter().find_map(|u| {
                if pat.re.is_match(&u.url) {
                    return Some(sample_of(&u.url));
                }
                u.decoded_params
                    .values()
                    .find(|v| pat.re.is_match(v))
                    .map(|v| sample_of(v))
            }),
        };
        if let Some(sample) = hit_sample {
            hits.push(Hit {
                pattern_id: pat.id.clone(),
                category: pat.category.clone(),
                severity: pat.severity,
                sample,
            });
        }
    }
    hits
}
