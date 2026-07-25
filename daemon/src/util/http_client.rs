//! Client HTTP/1.1 minimal (TCP nu + rustls/ring), parsing réponse, dé-chunk. Sans dépendance sur
//! AppState. Extrait de main.rs (refactor split #25 — byte-identique). Utilisé par Vault, le
//! connecteur Defender et les notifiers. Les racines TLS (vault_root_store/pem_certs) restent au
//! crate root (module crypto) — appel résolu via le glob re-export.
use crate::*;

/// Réponse HTTP structurée (#3a) : statut + en-têtes + corps. Le corps n'est JAMAIS mis dans un message
/// d'erreur (invariant conservé) ; le statut/motif seul remonte. Sert le POST OAuth (token) + le GET Graph
/// (pagination) + la lecture de `Retry-After` sur 429, sans dépendance nouvelle (mêmes primitives rustls/TCP).
pub(crate) struct HttpResp {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}
impl HttpResp {
    /// En-tête par nom (insensible à la casse) — ex. `Retry-After` sur 429.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Requête HTTP/1.1 MINIMALE généralisée (#3a) : http:// (TCP nu) ou https:// (rustls/ring + racines
/// système). `method` = GET/POST ; `body`=Some -> ajoute Content-Length + le corps (Content-Type fourni
/// via `headers`). Lit toute la réponse (Connection: close), gère `Transfer-Encoding: chunked`, renvoie
/// HttpResp (statut+headers+corps) SANS jamais mettre le corps dans une erreur. Timeouts connect/read
/// bornés (10 s). Modèle exact de l'ancien http_get, factorisé pour POST + lecture des headers de réponse.
pub(crate) fn http_request(method: &str, base: &str, path: &str,
                headers: &[(&str, &str)], body: Option<&[u8]>) -> Result<HttpResp, String> {
    use std::io::{Read, Write};
    let (https, host, port) = parse_http_addr(base)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    let mut req_bytes: Vec<u8> = Vec::new();
    match body {
        Some(b) => {
            req.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
            req_bytes.extend_from_slice(req.as_bytes());
            req_bytes.extend_from_slice(b);
        }
        None => {
            req.push_str("\r\n");
            req_bytes.extend_from_slice(req.as_bytes());
        }
    }

    let addrs = (host.as_str(), port);
    let sock = std::net::TcpStream::connect(addrs).map_err(|e| format!("connexion {host}:{port} : {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));

    let raw: Vec<u8> = if https {
        http_tls_roundtrip(sock, &host, &req_bytes)?
    } else {
        let mut sock = sock;
        sock.write_all(&req_bytes).map_err(|e| format!("écriture HTTP : {e}"))?;
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).map_err(|e| format!("lecture HTTP : {e}"))?;
        buf
    };
    parse_http_full(&raw)
}

/// (base, path) depuis une URL complète `scheme://host[:port]/path?query`. Le `@odata.nextLink` Graph et
/// l'endpoint token sont des URL complètes -> on les scinde pour http_request (qui prend base+path). Path
/// vide -> "/". Ne touche pas au query-string (déjà encodé côté appelant / renvoyé tel quel par Graph).
pub(crate) fn split_url(url: &str) -> (String, String) {
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let after = &url[scheme_end..];
    match after.find('/') {
        Some(slash) => (url[..scheme_end + slash].to_string(), after[slash..].to_string()),
        None => (url.to_string(), "/".to_string()),
    }
}

/// Transport réel (#3a) : `fetch(method, url_complète, headers, body) -> HttpResp`. Scinde l'URL puis
/// délègue à http_request. Injectable en test par une closure mockée (aucun socket) -> l'OAuth/Graph se
/// testent offline sans credential Azure.
pub(crate) fn http_call(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Result<HttpResp, String> {
    let (base, path) = split_url(url);
    http_request(method, &base, &path, headers, body)
}

/// Percent-encoding RFC3986 (unreserved conservés) — pour le corps form-urlencoded de l'OAuth (client_id,
/// client_secret) et la valeur du $filter Graph. Le secret encodé ne transite QUE dans le corps du POST
/// token (en mémoire, jamais loggé).
pub(crate) fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// GET HTTP/1.1 MINIMAL (wrapper de http_request, #3a) : renvoie le CORPS sur 2xx sinon `Err` (statut seul,
/// JAMAIS le corps) — comportement IDENTIQUE à l'ancien http_get (zéro régression Vault).
pub(crate) fn http_get(base: &str, path: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let resp = http_request("GET", base, path, headers, None)?;
    if (200..300).contains(&resp.status) {
        Ok(resp.body)
    } else {
        Err(format!("HTTP {} (GET)", resp.status)) // jamais le corps
    }
}

/// (https?, host, port) depuis une URL http(s)://host[:port][/...]. Erreur si schéma manquant/host vide.
pub(crate) fn parse_http_addr(url: &str) -> Result<(bool, String, u16), String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("PLUME_VAULT_ADDR doit commencer par http:// ou https://".into());
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "port Vault invalide".to_string())?),
        None => (hostport.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err("hôte Vault vide".into());
    }
    Ok((https, host, port))
}

/// Sépare en-têtes/corps, PARSE le statut + tous les en-têtes, dé-chunk si nécessaire. Renvoie HttpResp
/// (statut+headers+corps) SANS jamais mettre le corps dans une erreur. Ne juge PAS le code (le 4xx/5xx est
/// une réponse valide dont l'appelant lit le statut + `Retry-After` — indispensable pour le 429 Graph).
pub(crate) fn parse_http_full(raw: &[u8]) -> Result<HttpResp, String> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("réponse HTTP sans en-têtes")?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = &raw[sep + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code: u16 = status_line.split_whitespace().nth(1).and_then(|c| c.parse().ok())
        .ok_or("statut HTTP illisible")?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            headers.push((k, v));
        }
    }
    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok(HttpResp { status: code, headers, body })
}

/// Compat : sépare en-têtes/corps, vérifie 2xx, dé-chunk. Renvoie le corps sur 2xx sinon `Err` (statut
/// seul, jamais le corps). Wrapper de parse_http_full (conservé pour d'éventuels appelants directs).
#[allow(dead_code)]
pub(crate) fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let resp = parse_http_full(raw)?;
    if (200..300).contains(&resp.status) {
        Ok(resp.body)
    } else {
        Err(format!("HTTP {} (jamais le corps)", resp.status))
    }
}

/// Dé-chunk un corps `Transfer-Encoding: chunked`.
pub(crate) fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let nl = data.windows(2).position(|w| w == b"\r\n").ok_or("chunk malformé")?;
        let size_hex = std::str::from_utf8(&data[..nl]).map_err(|_| "taille de chunk non-UTF8")?
            .split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "taille de chunk invalide")?;
        data = &data[nl + 2..];
        if size == 0 { break; }
        if data.len() < size { return Err("chunk tronqué".into()); }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.len() >= 2 { data = &data[2..]; } // CRLF de fin de chunk
    }
    Ok(out)
}

/// Aller-retour TLS (rustls/ring, racines système). Racines chargées via vault_root_store (FAIL-CLOSED si
/// aucune). Tolère une fermeture sans close_notify si la réponse est déjà lue.
pub(crate) fn http_tls_roundtrip(sock: std::net::TcpStream, host: &str, req: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    let roots = vault_root_store()?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().map_err(|e| format!("rustls versions : {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("nom TLS invalide : {host}"))?;
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|e| format!("rustls client : {e}"))?;
    let mut sock = sock;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(req).map_err(|e| format!("écriture TLS : {e}"))?;
    let mut buf = Vec::new();
    match tls.read_to_end(&mut buf) {
        Ok(_) => Ok(buf),
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => Ok(buf),
        Err(e) => Err(format!("lecture TLS : {e}")),
    }
}
