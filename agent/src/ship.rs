//! Expédition HTTP vers le endpoint d'ingest Plume + orchestration du drainage du spool.
//!
//! `Transport` = SPI HTTP injectable (les tests branchent un mock ; la prod branche `HttpTransport`,
//! un client HTTP/1.1 fait main sur `std::net::TcpStream` + rustls, `Connection: close`). `Shipper`
//! draine le spool : sur ACK (202/204) il supprime l'entrée ET persiste le curseur ; sur 5xx/429/réseau
//! il conserve l'entrée et recule (backoff, conscience du 503) ; sur 4xx permanent il DROP-FORWARD
//! (supprime + avance le curseur en journalisant fort — jamais de boucle infinie sur un poison).

use crate::buffer::{Backoff, CursorStore, Spool, SpoolEntry};
use crate::config::TlsConfig;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

/// Réponse HTTP minimale.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Erreur de transport (connexion/IO/TLS/URL). Toutes -> réessai (jamais une perte).
#[derive(Debug)]
pub enum TransportError {
    Url(String),
    Connect(String),
    Io(String),
    Tls(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Url(s) => write!(f, "url: {s}"),
            TransportError::Connect(s) => write!(f, "connect: {s}"),
            TransportError::Io(s) => write!(f, "io: {s}"),
            TransportError::Tls(s) => write!(f, "tls: {s}"),
        }
    }
}

/// SPI HTTP injectable (POST unique, corps binaire).
pub trait Transport {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError>;
}

// -------------------------------------------------------------------------------------------------
// Client HTTP/1.1 réel (TCP + rustls), sans dépendance à un client HTTP lourd.
// -------------------------------------------------------------------------------------------------

pub struct HttpTransport {
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl HttpTransport {
    pub fn new(tls_cfg: &TlsConfig, timeout: Duration) -> anyhow::Result<Self> {
        Ok(Self { tls: build_client_config(tls_cfg)?, timeout })
    }

    /// GET d'une URL (source générique `http` #66/#67) — mêmes options TLS/timeout que l'expédition.
    /// Aucun corps ; réutilise `request`. Erreurs -> `TransportError` (le lecteur http les journalise).
    pub fn get(&self, url: &str, headers: &[(String, String)]) -> Result<HttpResponse, TransportError> {
        self.request("GET", url, headers, &[])
    }

    fn exchange<S: Read + Write>(
        mut s: S,
        head: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        s.write_all(head).map_err(classer_erreur)?;
        s.write_all(body).map_err(classer_erreur)?;
        s.flush().map_err(classer_erreur)?;
        let mut buf = Vec::new();
        match s.read_to_end(&mut buf) {
            Ok(_) => Ok(buf),
            // Fermeture non propre (pas de close_notify TLS) mais réponse déjà lue -> on tolère.
            Err(_) if !buf.is_empty() => Ok(buf),
            Err(e) => Err(classer_erreur(e)),
        }
    }
}

/// CLASSE UNE ERREUR D'ÉCHANGE, ET DIT QUOI FAIRE QUAND C'EST LE CERTIFICAT.
///
/// CE QUI ÉTAIT CASSÉ. Le handshake TLS n'a pas lieu à la construction de la connexion rustls mais à
/// la PREMIÈRE écriture : son échec remontait donc par `io::Error`, était aplati en chaîne
/// (`e.to_string()`) et rangé dans `TransportError::Io` — alors qu'une variante `Tls` existait.
/// MESURÉ le 2026-08-02 contre un `openssl s_server` à certificat auto-signé, le technicien lisait :
///     `plume-agent: erreur: échec d'envoi : io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))`
/// Ni le mot « certificat » en français, ni le nom du réglage qui corrige (`[tls].ca_cert`), ni même
/// l'indication que c'est le certificat DU SERVEUR qui est refusé. Le programme, lui, SAVAIT :
/// rustls le lui avait dit dans un type.
///
/// LA FORME DÉRIVÉE. On ne devine pas à partir du TEXTE de l'erreur (il change de version en version,
/// et il y a une dizaine de causes de refus : auto-signé, expiré, mauvais nom, CA inconnue…). On
/// remonte au TYPE : `io::Error` porte la `rustls::Error` d'origine ; `InvalidCertificate(_)` — quelle
/// que soit la cause précise, présente ou future — est un refus de la chaîne du serveur, et le remède
/// est le même. Toute autre erreur garde son classement (une coupure réseau reste une erreur d'IO).
fn classer_erreur(e: std::io::Error) -> TransportError {
    // `io::Error` enveloppe la `rustls::Error` : on la RÉCUPÈRE au lieu de lire son texte.
    if let Some(rerr) = e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        if let rustls::Error::InvalidCertificate(cause) = rerr {
            // Les deux remèdes ci-dessous ont été EXÉCUTÉS le 2026-08-02 contre un `openssl s_server`
            // (cf. `remede_tls_dit_ce_qui_a_ete_mesure`). On n'écrit pas un conseil non vérifié : le
            // cas « CA présentée comme certificat serveur » ne se corrige PAS côté agent — mesuré.
            // `CertificateError::Other` est un FOURRE-TOUT (toute cause webpki non nommée) : on ne
            // peut donc pas l'assimiler à `CaUsedAsEndEntity`. On donne le remède général — le seul
            // qui soit vrai dans tous les cas d'émetteur inconnu, mesuré — ET on nomme le piège
            // quand le libellé le désigne, sans jamais présenter l'un pour l'autre.
            let remede_general = "Déclare l'autorité du central dans la config de l'agent : [tls] \
                 ca_cert = \"/etc/plume/ca.pem\" — le PEM de la CA interne qui a signé son \
                 certificat (un certificat auto-signé sans CA se déclare lui-même ici : mesuré, \
                 accepté).";
            let piege = if matches!(cause, rustls::CertificateError::Other(_)) {
                " EXCEPTION MESURÉE : si le libellé ci-dessus dit `CaUsedAsEndEntity`, le central \
                 présente le certificat de sa CA COMME SON PROPRE certificat serveur — et le \
                 déclarer dans ca_cert ne corrige RIEN (mesuré). Il faut alors que le CENTRAL \
                 présente une FEUILLE signée par cette CA (basicConstraints CA:FALSE)."
            } else {
                ""
            };
            let remede = format!("{remede_general}{piege}");
            return TransportError::Tls(format!(
                "le certificat du SERVEUR a été refusé ({cause:?}). {remede} En dernier recours et \
                 en DEV uniquement : [tls] insecure = true (aucune vérification — jamais en production)"
            ));
        }
        return TransportError::Tls(rerr.to_string());
    }
    TransportError::Io(e.to_string())
}

impl HttpTransport {
    /// Requête HTTP/1.1 générique (méthode paramétrable), `Connection: close`. `post`/`get` délèguent
    /// ici. `Content-Length` émis pour toute méthode à corps (toujours pour POST — octets identiques à
    /// l'existant) et jamais pour un GET sans corps.
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let (is_tls, host, port, path) = parse_url(url)?;
        let addr = format!("{host}:{port}");
        let tcp = std::net::TcpStream::connect(&addr)
            .map_err(|e| TransportError::Connect(format!("{addr}: {e}")))?;
        tcp.set_read_timeout(Some(self.timeout)).ok();
        tcp.set_write_timeout(Some(self.timeout)).ok();

        // En-tête de requête. Host explicite si l'appelant n'en fournit pas.
        let has_host = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host"));
        let mut head = format!("{method} {path} HTTP/1.1\r\n");
        if !has_host {
            head.push_str(&format!("Host: {host}\r\n"));
        }
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if method != "GET" || !body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("Connection: close\r\n\r\n");

        let raw = if is_tls {
            let server_name = rustls_pki_types::ServerName::try_from(host.clone())
                .map_err(|e| TransportError::Tls(format!("nom serveur invalide {host}: {e}")))?;
            let conn = rustls::ClientConnection::new(self.tls.clone(), server_name)
                .map_err(|e| TransportError::Tls(e.to_string()))?;
            let stream = rustls::StreamOwned::new(conn, tcp);
            Self::exchange(stream, head.as_bytes(), body)?
        } else {
            Self::exchange(tcp, head.as_bytes(), body)?
        };
        parse_response(&raw)
    }
}

impl Transport for HttpTransport {
    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.request("POST", url, headers, body)
    }
}

/// Parse `scheme://host[:port][/path]` -> (tls, host, port, path).
fn parse_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| TransportError::Url(format!("schéma manquant : {url}")))?;
    let is_tls = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(TransportError::Url(format!("schéma non supporté : {other}"))),
    };
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(if is_tls { 443 } else { 80 }))
        }
        _ => (host_port.to_string(), if is_tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(TransportError::Url(format!("hôte vide : {url}")));
    }
    Ok((is_tls, host, port, path))
}

/// Parse une réponse HTTP brute (statut + corps). Ligne 1 : `HTTP/1.1 <code> <reason>`.
fn parse_response(raw: &[u8]) -> Result<HttpResponse, TransportError> {
    let text = String::from_utf8_lossy(raw);
    let (headers, body) = match text.find("\r\n\r\n") {
        Some(i) => (&text[..i], text[i + 4..].to_string()),
        None => (text.as_ref(), String::new()),
    };
    let status = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| TransportError::Io("statut HTTP illisible".into()))?;
    Ok(HttpResponse { status, body })
}

/// Construit la config client rustls depuis les options TLS (racines publiques + CA interne, mTLS, insecure).
fn build_client_config(tls: &TlsConfig) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    // Provider crypto = ring (cohérent avec le daemon ; pas de cmake/nasm requis par aws-lc).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let base = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?;

    let wants_client_auth = if tls.insecure {
        // DANGER (dev only) : accepte tout certificat serveur.
        eprintln!("[tls] AVERTISSEMENT : insecure=true -> vérification du certificat serveur DÉSACTIVÉE");
        base.dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerify::new()))
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = &tls.ca_cert {
            let pem = std::fs::read_to_string(ca)
                .map_err(|e| anyhow::anyhow!("lecture CA {}: {e}", ca.display()))?;
            for der in pem_blocks(&pem, "CERTIFICATE") {
                roots
                    .add(rustls_pki_types::CertificateDer::from(der))
                    .map_err(|e| anyhow::anyhow!("CA invalide {}: {e}", ca.display()))?;
            }
        }
        base.with_root_certificates(roots)
    };

    let cfg = match (&tls.client_cert, &tls.client_key) {
        (Some(cp), Some(kp)) => {
            let certs = load_certs(cp)?;
            let key = load_key(kp)?;
            wants_client_auth
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("mTLS cert client invalide : {e}"))?
        }
        _ => wants_client_auth.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read_to_string(path)?;
    let certs: Vec<_> = pem_blocks(&pem, "CERTIFICATE")
        .into_iter()
        .map(rustls_pki_types::CertificateDer::from)
        .collect();
    if certs.is_empty() {
        anyhow::bail!("aucun CERTIFICATE dans {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> anyhow::Result<rustls_pki_types::PrivateKeyDer<'static>> {
    use rustls_pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
    let pem = std::fs::read_to_string(path)?;
    if let Some(der) = pem_blocks(&pem, "PRIVATE KEY").into_iter().next() {
        return Ok(PrivatePkcs8KeyDer::from(der).into());
    }
    if let Some(der) = pem_blocks(&pem, "RSA PRIVATE KEY").into_iter().next() {
        return Ok(PrivatePkcs1KeyDer::from(der).into());
    }
    if let Some(der) = pem_blocks(&pem, "EC PRIVATE KEY").into_iter().next() {
        return Ok(PrivateSec1KeyDer::from(der).into());
    }
    anyhow::bail!("aucune clé privée (PKCS8/PKCS1/SEC1) dans {}", path.display())
}

/// Décode tous les blocs PEM d'un tag donné (`-----BEGIN <tag>-----` … `-----END <tag>-----`) en DER.
fn pem_blocks(pem: &str, tag: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let mut out = Vec::new();
    let mut lines = pem.lines();
    while let Some(l) = lines.next() {
        if l.trim() == begin {
            let mut b64 = String::new();
            for l2 in lines.by_ref() {
                if l2.trim() == end {
                    break;
                }
                b64.push_str(l2.trim());
            }
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                out.push(der);
            }
        }
    }
    out
}

/// Vérificateur de certificat serveur "accepte-tout" — UNIQUEMENT quand `[tls].insecure = true`.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    pub struct NoVerify;

    impl NoVerify {
        pub fn new() -> Self {
            NoVerify
        }
    }

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Orchestration du drainage du spool.
// -------------------------------------------------------------------------------------------------

/// Issue de l'envoi d'une entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipOutcome {
    /// 2xx acceptant (202/204/2xx) -> supprimer + avancer le curseur.
    Acked,
    /// 4xx permanent (hors 429) -> DROP-FORWARD (supprimer + avancer, journaliser fort).
    Poison(u16),
    /// 429/5xx/réseau -> conserver + reculer (backoff). `Some(503)` -> recul maximal.
    Retry(Option<u16>),
}

/// Classe un code HTTP en issue.
pub fn classify_status(status: u16) -> ShipOutcome {
    match status {
        202 | 204 => ShipOutcome::Acked,
        200..=299 => ShipOutcome::Acked,
        429 => ShipOutcome::Retry(Some(429)),
        500..=599 => ShipOutcome::Retry(Some(status)),
        400..=499 => ShipOutcome::Poison(status),
        other => ShipOutcome::Retry(Some(other)),
    }
}

#[derive(Debug, Default, Clone)]
pub struct DrainStats {
    pub acked: usize,
    pub poisoned: usize,
    /// True si un réessai a interrompu le drainage (le central est down/surchargé).
    pub retried: bool,
    /// Délai à attendre avant le prochain tour quand `retried` (issu du backoff).
    pub delay: Option<Duration>,
}

pub struct Shipper<T: Transport> {
    transport: T,
    base_url: String,
    auth_header: Option<String>,
    host_header: Option<String>,
}

impl<T: Transport> Shipper<T> {
    pub fn new(
        transport: T,
        base_url: impl Into<String>,
        auth_header: Option<String>,
        host_header: Option<String>,
    ) -> Self {
        Self { transport, base_url: base_url.into(), auth_header, host_header }
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
        if let Some(a) = &self.auth_header {
            h.push(("Authorization".to_string(), a.clone()));
        }
        if let Some(hh) = &self.host_header {
            h.push(("Host".to_string(), hh.clone()));
        }
        h
    }

    /// URL complète pour un endpoint relatif.
    pub fn url_for(&self, endpoint: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), endpoint)
    }

    /// POST direct (endpoint relatif) via le transport + en-têtes de l'agent. Utilisé par `test-ship`.
    pub fn post(&self, endpoint: &str, body: &[u8]) -> Result<HttpResponse, TransportError> {
        self.transport.post(&self.url_for(endpoint), &self.headers(), body)
    }

    /// Expédie UNE entrée et renvoie l'issue (sans toucher au spool).
    pub fn ship_entry(&self, e: &SpoolEntry) -> ShipOutcome {
        let url = self.url_for(&e.endpoint);
        match self.transport.post(&url, &self.headers(), e.body.as_bytes()) {
            Ok(r) => classify_status(r.status),
            Err(err) => {
                eprintln!("[ship] {} -> {err} (conservé pour réessai)", e.endpoint);
                ShipOutcome::Retry(None)
            }
        }
    }

    /// Draine le spool FIFO : ack -> remove + save curseur ; poison -> drop-forward ; retry -> stop + backoff.
    pub fn drain(&self, spool: &Spool, cursors: &CursorStore, backoff: &mut Backoff) -> DrainStats {
        let mut st = DrainStats::default();
        for (path, entry) in spool.entries() {
            match self.ship_entry(&entry) {
                ShipOutcome::Acked => {
                    spool.remove(&path);
                    if let Err(e) = cursors.save(&entry.source_id, &entry.cursor) {
                        eprintln!("[ship] curseur {} non persisté : {e}", entry.source_id);
                    }
                    st.acked += 1;
                }
                ShipOutcome::Poison(code) => {
                    eprintln!(
                        "[ship] REJET PERMANENT HTTP {code} pour {} (source {}) -> abandon de ce lot (drop-forward)",
                        entry.endpoint, entry.source_id
                    );
                    spool.remove(&path);
                    let _ = cursors.save(&entry.source_id, &entry.cursor);
                    st.poisoned += 1;
                }
                ShipOutcome::Retry(code) => {
                    // Conserve l'entrée (et l'ordre) ; recule et arrête ce tour.
                    if code == Some(503) {
                        backoff.bump_503();
                    }
                    st.retried = true;
                    st.delay = Some(backoff.next_delay());
                    break;
                }
            }
        }
        if !st.retried {
            backoff.reset();
        }
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// LE REMÈDE DIT CE QUI A ÉTÉ MESURÉ — et rien d'autre.
    ///
    /// MESURÉ le 2026-08-02 contre `openssl s_server` (quatre configurations, même agent) :
    ///  A. CA interne (CA:TRUE) signant une FEUILLE (CA:FALSE), `ca_cert` = la CA  -> handshake OK.
    ///  B. `insecure = true`                                                        -> handshake OK.
    ///  C. feuille AUTO-SIGNÉE (CA:FALSE) déclarée telle quelle dans `ca_cert`      -> handshake OK.
    ///  D. la MÊME feuille, rien de déclaré                                         -> UnknownIssuer.
    ///  E. certificat auto-signé CA:TRUE servi comme certificat serveur, déclaré dans `ca_cert`
    ///     -> TOUJOURS refusé (`CaUsedAsEndEntity`) : le remède « mets-le dans ca_cert » est FAUX
    ///        pour ce cas-là, et le message ne doit pas le donner.
    ///
    /// Le classement vient du TYPE (`rustls::Error::InvalidCertificate`), pas du texte de l'erreur :
    /// une coupure réseau reste une erreur d'IO.
    ///
    /// CE QUE CE TEST NE PROUVE PAS (et qui l'a été autrement) : il FABRIQUE l'`io::Error` enveloppe,
    /// donc il ne dit rien de la façon dont rustls emballe réellement l'erreur. C'est le tir de bout
    /// en bout qui l'a montré, le même jour, contre un `openssl s_server` auto-signé :
    ///   `plume-agent: erreur: échec d'envoi : tls: le certificat du SERVEUR a été refusé
    ///    (Other(OtherError(CaUsedAsEndEntity))). Déclare l'autorité du central … ca_cert …`
    /// (avant : `io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))`).
    #[test]
    fn remede_tls_dit_ce_qui_a_ete_mesure() {
        let cert_err = |c: rustls::CertificateError| {
            let io = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::InvalidCertificate(c));
            match classer_erreur(io) {
                TransportError::Tls(m) => m,
                autre => panic!("un refus de certificat doit être classé TLS, pas {autre:?}"),
            }
        };
        // Cas D (émetteur inconnu) : le remède mesuré est `ca_cert`.
        let d = cert_err(rustls::CertificateError::UnknownIssuer);
        assert!(d.contains("ca_cert"), "{d}");
        assert!(d.contains("certificat du SERVEUR a été refusé"), "{d}");
        assert!(d.contains("insecure = true"), "le dernier recours est nommé ET encadré : {d}");
        // Cas E (CA servie comme feuille) : le remède général reste donné — `Other` est un
        // FOURRE-TOUT, on n'a pas le droit de le prendre pour `CaUsedAsEndEntity` — et le piège est
        // nommé EN PLUS, conditionné au libellé.
        let e = cert_err(rustls::CertificateError::Other(rustls::OtherError(std::sync::Arc::new(
            std::io::Error::other("CaUsedAsEndEntity"),
        ))));
        assert!(e.contains("ca_cert"), "le remède général n'est jamais escamoté : {e}");
        assert!(e.contains("ne corrige RIEN"), "{e}");
        assert!(e.contains("FEUILLE signée"), "{e}");
        // Une VRAIE erreur d'IO n'est PAS re-classée en TLS (contre-épreuve mesurée : port fermé).
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset par le pair");
        assert!(matches!(classer_erreur(io), TransportError::Io(_)));
    }

    /// Transport injectable : rejoue une file de réponses, enregistre chaque appel (url + corps).
    struct MockTransport {
        responses: Mutex<VecDeque<Result<HttpResponse, TransportError>>>,
        calls: Mutex<Vec<(String, Vec<(String, String)>, Vec<u8>)>>,
    }
    impl MockTransport {
        fn new(codes: &[u16]) -> Self {
            let responses = codes
                .iter()
                .map(|c| Ok(HttpResponse { status: *c, body: String::new() }))
                .collect();
            Self { responses: Mutex::new(responses), calls: Mutex::new(Vec::new()) }
        }
    }
    impl Transport for MockTransport {
        fn post(
            &self,
            url: &str,
            headers: &[(String, String)],
            body: &[u8],
        ) -> Result<HttpResponse, TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), headers.to_vec(), body.to_vec()));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(HttpResponse { status: 202, body: String::new() }))
        }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("plume-agent-ship-{tag}-{}-{}", std::process::id(), crate::source::now_secs()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn entry(endpoint: &str, body: &str, source: &str, cursor: &str) -> SpoolEntry {
        SpoolEntry {
            endpoint: endpoint.into(),
            body: body.into(),
            source_id: source.into(),
            cursor: Some(cursor.into()),
        }
    }

    #[test]
    fn classify_covers_contract() {
        assert_eq!(classify_status(202), ShipOutcome::Acked);
        assert_eq!(classify_status(204), ShipOutcome::Acked);
        assert_eq!(classify_status(503), ShipOutcome::Retry(Some(503)));
        assert_eq!(classify_status(500), ShipOutcome::Retry(Some(500)));
        assert_eq!(classify_status(429), ShipOutcome::Retry(Some(429)));
        assert_eq!(classify_status(400), ShipOutcome::Poison(400));
        assert_eq!(classify_status(413), ShipOutcome::Poison(413));
    }

    #[test]
    fn drain_acks_all_and_saves_cursor() {
        let sdir = tmpdir("ack-spool");
        let cdir = tmpdir("ack-cur");
        let spool = Spool::open(&sdir, 100).unwrap();
        let cursors = CursorStore::open(&cdir).unwrap();
        spool.push(&entry("/api/ingest", "{\"a\":1}", "s1", "cur-1")).unwrap();
        spool
            .push(&entry("/api/ingest/journal", "line1\nline2", "s2", "cur-2"))
            .unwrap();

        let mock = MockTransport::new(&[202, 202]);
        let shipper = Shipper::new(mock, "https://plume.example.com/", Some("Bearer tok".into()), None);
        let mut bo = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let st = shipper.drain(&spool, &cursors, &mut bo);

        assert_eq!(st.acked, 2);
        assert!(!st.retried);
        assert!(spool.is_empty(), "spool drainé");
        assert_eq!(cursors.load("s1").as_deref(), Some("cur-1"), "curseur persisté APRÈS ack");
        assert_eq!(cursors.load("s2").as_deref(), Some("cur-2"));

        // Vérifie l'URL, l'endpoint routé et les en-têtes (auth + content-type).
        let calls = shipper.transport.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://plume.example.com/api/ingest");
        assert_eq!(calls[1].0, "https://plume.example.com/api/ingest/journal");
        assert!(calls[0].1.iter().any(|(k, v)| k == "Authorization" && v == "Bearer tok"));
        assert!(calls[0].1.iter().any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert_eq!(calls[1].2, b"line1\nline2", "corps ndjson brut expédié tel quel");
        drop(calls);
        std::fs::remove_dir_all(&sdir).ok();
        std::fs::remove_dir_all(&cdir).ok();
    }

    #[test]
    fn drain_503_keeps_entry_bumps_backoff_no_cursor() {
        let sdir = tmpdir("503-spool");
        let cdir = tmpdir("503-cur");
        let spool = Spool::open(&sdir, 100).unwrap();
        let cursors = CursorStore::open(&cdir).unwrap();
        spool.push(&entry("/api/ingest", "{}", "s1", "cur-1")).unwrap();
        spool.push(&entry("/api/ingest", "{}", "s1", "cur-2")).unwrap();

        let mock = MockTransport::new(&[503]);
        let shipper = Shipper::new(mock, "https://x", None, None);
        let mut bo = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let st = shipper.drain(&spool, &cursors, &mut bo);

        assert_eq!(st.acked, 0);
        assert!(st.retried, "503 -> réessai");
        assert_eq!(st.delay, Some(Duration::from_secs(30)), "503 -> recul maximal");
        assert_eq!(spool.len(), 2, "les deux entrées conservées (rien perdu)");
        assert_eq!(cursors.load("s1"), None, "curseur NON avancé sans ack");
        // un seul POST tenté (drain s'arrête au 1er retry).
        assert_eq!(shipper.transport.calls.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&sdir).ok();
        std::fs::remove_dir_all(&cdir).ok();
    }

    #[test]
    fn drain_poison_drops_forward() {
        let sdir = tmpdir("poison-spool");
        let cdir = tmpdir("poison-cur");
        let spool = Spool::open(&sdir, 100).unwrap();
        let cursors = CursorStore::open(&cdir).unwrap();
        spool.push(&entry("/api/ingest", "bad", "s1", "cur-1")).unwrap();
        spool.push(&entry("/api/ingest", "{}", "s1", "cur-2")).unwrap();

        // 400 (poison) puis 202 (ack) -> la 2e passe après le drop-forward de la 1re.
        let mock = MockTransport::new(&[400, 202]);
        let shipper = Shipper::new(mock, "https://x", None, None);
        let mut bo = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let st = shipper.drain(&spool, &cursors, &mut bo);

        assert_eq!(st.poisoned, 1);
        assert_eq!(st.acked, 1);
        assert!(spool.is_empty(), "poison supprimé + 2e ackée");
        assert_eq!(cursors.load("s1").as_deref(), Some("cur-2"));
        std::fs::remove_dir_all(&sdir).ok();
        std::fs::remove_dir_all(&cdir).ok();
    }

    #[test]
    fn parse_url_variants() {
        assert_eq!(
            parse_url("https://plume.example.com/api/ingest").unwrap(),
            (true, "plume.example.com".to_string(), 443, "/api/ingest".to_string())
        );
        assert_eq!(
            parse_url("http://10.0.0.1:7000/api/ingest/journal").unwrap(),
            (false, "10.0.0.1".to_string(), 7000, "/api/ingest/journal".to_string())
        );
        assert_eq!(
            parse_url("https://host").unwrap(),
            (true, "host".to_string(), 443, "/".to_string())
        );
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("no-scheme").is_err());
    }

    #[test]
    fn parse_response_extracts_status() {
        let raw = b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{\"queued\":true}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 202);
        assert_eq!(r.body, "{\"queued\":true}");
    }
}
