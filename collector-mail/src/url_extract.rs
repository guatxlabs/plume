//! Extraction d'URL (porte du mail-scanner-service, cf. ADR-0008) : ancres HTML + URLs
//! texte, avec decodage base64 des parametres (tracking/redirections obfusquees).
use base64::{engine::general_purpose, Engine};
use once_cell::sync::Lazy;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone)]
#[allow(dead_code)] // anchor_text/source : portes du scanner, utiles pour des events plus riches
pub struct ExtractedUrl {
    pub url: String,
    pub anchor_text: String,
    pub decoded_params: HashMap<String, String>,
    pub source: String, // "html-anchor" | "text"
}

static URL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"https?://[^\s<>"'\)\]\}]+"#).unwrap());
static A_SELECTOR: Lazy<Selector> = Lazy::new(|| Selector::parse("a").unwrap());
static B64_HINT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9+/=_-]{16,}$").unwrap());

const MAX_PARAM_LEN: usize = 16_000;

fn try_decode_b64(s: &str) -> Option<String> {
    if !B64_HINT.is_match(s) || s.len() > MAX_PARAM_LEN {
        return None;
    }
    let engines: [&general_purpose::GeneralPurpose; 4] = [
        &general_purpose::STANDARD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in engines {
        let bytes = match engine.decode(s) {
            Ok(b) if !b.is_empty() => b,
            _ => continue,
        };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue };
        let chars_total = text.chars().count();
        if chars_total == 0 {
            continue;
        }
        let plausible = text
            .chars()
            .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t'))
            .count();
        if plausible * 10 >= chars_total * 7 {
            return Some(text.to_string());
        }
    }
    None
}

fn decode_url_params(u: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let parsed = match Url::parse(u) {
        Ok(p) => p,
        Err(_) => return out,
    };
    for (k, v) in parsed.query_pairs() {
        if v.len() > MAX_PARAM_LEN {
            continue;
        }
        if let Some(decoded) = try_decode_b64(&v) {
            out.insert(k.into_owned(), decoded);
        }
    }
    out
}

pub fn extract_urls(html: Option<&str>, text: Option<&str>) -> Vec<ExtractedUrl> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    if let Some(h) = html {
        if h.len() < 5_000_000 {
            let doc = Html::parse_document(h);
            for a in doc.select(&A_SELECTOR) {
                if let Some(href) = a.value().attr("href") {
                    if !href.starts_with("http") {
                        continue;
                    }
                    if seen.insert(href.to_string()) {
                        let anchor = a.text().collect::<String>().trim().to_string();
                        out.push(ExtractedUrl {
                            url: href.to_string(),
                            anchor_text: anchor.chars().take(200).collect(),
                            decoded_params: decode_url_params(href),
                            source: "html-anchor".into(),
                        });
                    }
                }
            }
        }
    }

    if let Some(t) = text {
        for m in URL_REGEX.find_iter(t) {
            let u = m.as_str().trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ')' | ']'));
            if seen.insert(u.to_string()) {
                out.push(ExtractedUrl {
                    url: u.to_string(),
                    anchor_text: String::new(),
                    decoded_params: decode_url_params(u),
                    source: "text".into(),
                });
            }
        }
    }

    out
}
