//! Configuration TOML de l'agent : endpoint, auth, TLS, sélecteurs de sources, tampon.
//!
//! Chemins par défaut par-OS (spool/state/config) résolus par `default_*()`. Le fichier est du TOML
//! plat + un tableau `[[source]]` (une entrée par source native à collecter). Tout est defaulté :
//! un `endpoint = "..."` seul suffit (une source journald auth par défaut est injectée).
use serde::Deserialize;
use std::path::PathBuf;

/// Racine de configuration (désérialisée depuis le TOML).
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// URL de base du endpoint Plume (ex `https://plume.example.com`). Les chemins `/api/ingest[/journal]`
    /// y sont concaténés. Obligatoire.
    pub endpoint: String,
    /// Jeton Bearer (recommandé — `plume-daemon token <nom>` côté central). Prioritaire sur basic.
    #[serde(default)]
    pub token: Option<String>,
    /// Auth basic (repli si pas de token) : `username` + `password`.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Override du hostname envoyé dans l'enveloppe (défaut = hostname machine). NB : un token AGENT
    /// LIÉ côté central écrase de toute façon `host` (anti-forge M2) — ceci ne sert qu'au non-lié.
    #[serde(default)]
    pub host: Option<String>,
    /// Override de l'en-tête HTTP `Host` (cas central atteint par IP alors que le daemon valide un vhost).
    #[serde(default)]
    pub host_header: Option<String>,
    /// Nb max d'enregistrements natifs lus par source et par tour (borne la cardinalité d'un batch).
    #[serde(default = "d_batch")]
    pub batch_size: usize,
    /// Intervalle (s) entre deux tours de lecture+envoi quand tout est calme.
    #[serde(default = "d_flush")]
    pub flush_interval_secs: u64,
    /// Répertoire du spool disque (tampon at-least-once). Défaut par-OS.
    #[serde(default = "default_spool_dir")]
    pub spool_dir: PathBuf,
    /// Répertoire d'état (curseurs de source persistés après ack). Défaut par-OS.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Plafond d'entrées du spool (ring borné : au-delà, on évince les plus VIEILLES).
    #[serde(default = "d_cap")]
    pub spool_cap: usize,
    /// Options TLS (CA interne, cert client mTLS, skip-verify dev).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Sources DÉCLARÉES par le technicien (tableau `[[source]]`). Désérialisées en Value brute puis
    /// converties une-à-une dans `from_toml` : une entrée MALFORMÉE est IGNORÉE (warning) sans faire
    /// planter l'agent (contrat #66/#67 : une source cassée n'emporte pas les autres).
    #[serde(rename = "source", default)]
    raw_sources: Vec<toml::Value>,
    /// Sources effectivement retenues (natives + génériques). Peuplé par `from_toml` à partir de
    /// `raw_sources` (skip des malformées). Vide dans le TOML -> une source journald auth par défaut.
    #[serde(skip)]
    pub source: Vec<SourceCfg>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TlsConfig {
    /// CA supplémentaire (PEM) à ajouter aux racines publiques — pour valider une PKI interne.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Cert client (PEM) pour mTLS (chemin agent dédié Traefik websecure).
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// Clé privée client (PEM, PKCS8/PKCS1/SEC1).
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    /// DANGER (dev only) : ne PAS vérifier le certificat serveur. Défaut false.
    #[serde(default)]
    pub insecure: bool,
}

/// Un sélecteur de source (tagué par `type`). Les variantes sont compilées sur TOUS les OS (données
/// pures) ; seul le *lecteur* concret est cfg-gated (cf. `source::build_reader`). Ainsi une config
/// écrite pour Windows se parse aussi sur Linux (elle no-op-e à l'exécution).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceCfg {
    /// Linux : journald (`journalctl -o json --after-cursor`). PLEINEMENT implémenté.
    Journald(JournaldCfg),
    /// Windows : Event Log (EvtQuery/EvtNext/EvtRender). STUB.
    Wineventlog(WinEventCfg),
    /// macOS : unified log (`log stream --style ndjson`). STUB.
    Oslog(OsLogCfg),
    /// FIM natif (#58) : surveillance d'intégrité de fichiers (Linux fanotify/inotify ; Windows
    /// `ReadDirectoryChangesW` stubbé). Émet des events CIM `category=integrity` (mêmes champs `fim_*`
    /// que l'ingest endpoint #57 -> les vues natives s'allument à l'identique). `paths` VIDE = inerte
    /// (mode 0 : aucun comportement, aucun accès disque). Observationnel STRICT (jamais d'écriture).
    Fim(FimCfg),
    /// GÉNÉRIQUE (#66/#67) : suit (tail) un fichier de log. Chaque nouvelle ligne = un event. Curseur =
    /// offset en octets (reprise sans re-lire). Rotation/troncature détectées (offset > taille -> 0).
    File(FileCfg),
    /// GÉNÉRIQUE (#66/#67) : exécute une commande toutes les `interval` s ; chaque ligne stdout = event.
    /// Équivalent déclaratif de `collectors/custom.sh` (les fichiers `.input` KEY=value restent
    /// supportés). Non-reprenable -> dédup horaire côté daemon (comme custom.sh).
    Command(CommandCfg),
    /// GÉNÉRIQUE (#66/#67) : poll HTTP GET d'une URL toutes les `interval` s ; chaque ligne du corps =
    /// event (ndjson/texte). Réutilise le transport rustls de l'agent (CA interne / mTLS de `[tls]`).
    Http(HttpCfg),
}

/// Parseur de champs OPTIONNEL pour une source générique (#66/#67). Deux modes, exclusifs :
///   - `regex` : une regex à GROUPES NOMMÉS `(?P<champ>…)` ; chaque groupe nommé capturé -> un champ.
///   - `delimiter` + `fields` : découpe la ligne sur `delimiter` et nomme les colonnes via `fields`
///     (mode ZÉRO-dép, pour du CSV/espacé/pipé). Ignore les colonnes en trop, absente si trop peu.
///
/// Dans tous les cas le `message` de l'event reste la LIGNE brute (les champs sont additifs).
#[derive(Debug, Clone, Deserialize)]
pub struct ParserCfg {
    /// Regex à groupes nommés (`(?P<user>\w+)`). Une regex INVALIDE -> la source est ignorée (warning).
    #[serde(default)]
    pub regex: Option<String>,
    /// Séparateur de colonnes (mode découpe). Ex `" "`, `","`, `"|"`. Requiert `fields`.
    #[serde(default)]
    pub delimiter: Option<String>,
    /// Noms des colonnes (mode découpe), dans l'ordre.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Source générique `file` : tail d'un chemin de log (#66/#67).
#[derive(Debug, Clone, Deserialize)]
pub struct FileCfg {
    /// Nom logique -> `source=` cherchable ET nom du fichier curseur d'état.
    #[serde(default = "d_file_name")]
    pub name: String,
    /// Chemin du fichier suivi. OBLIGATOIRE (absent -> entrée malformée, ignorée).
    pub path: String,
    /// Catégorie CIM (défaut vide -> le parseur serveur tranche).
    #[serde(default)]
    pub category: String,
    /// Sévérité 0..4 (clampée). Défaut 1.
    #[serde(default = "d_gen_sev")]
    pub severity: i64,
    /// Parseur de champs optionnel.
    #[serde(default)]
    pub parser: Option<ParserCfg>,
    /// Au 1er démarrage (sans curseur) : lire depuis le DÉBUT (`true`) ou seulement les nouvelles
    /// lignes (`false`, défaut — comportement `tail -f`, évite de rejouer tout l'historique).
    #[serde(default)]
    pub from_start: bool,
}

/// Source générique `command` : sortie d'une commande périodique (#66/#67).
#[derive(Debug, Clone, Deserialize)]
pub struct CommandCfg {
    #[serde(default = "d_cmd_name")]
    pub name: String,
    /// Programme à exécuter. OBLIGATOIRE (absent -> entrée malformée, ignorée).
    pub cmd: String,
    /// Arguments passés au programme (chacun un élément — pas de découpe shell, pas d'injection).
    #[serde(default)]
    pub args: Vec<String>,
    /// Intervalle (s) entre deux exécutions. Défaut 60.
    #[serde(default = "d_poll_interval")]
    pub interval: u64,
    #[serde(default)]
    pub category: String,
    #[serde(default = "d_gen_sev")]
    pub severity: i64,
    #[serde(default)]
    pub parser: Option<ParserCfg>,
    /// Plafond de lignes lues par exécution (anti-flood). Défaut 500.
    #[serde(default = "d_gen_max")]
    pub max_lines: usize,
}

/// Source générique `http` : poll GET d'une URL (#66/#67).
#[derive(Debug, Clone, Deserialize)]
pub struct HttpCfg {
    #[serde(default = "d_http_name")]
    pub name: String,
    /// URL à interroger (GET). OBLIGATOIRE (absente -> entrée malformée, ignorée).
    pub url: String,
    /// Intervalle (s) entre deux polls. Défaut 60.
    #[serde(default = "d_poll_interval")]
    pub interval: u64,
    #[serde(default)]
    pub category: String,
    #[serde(default = "d_gen_sev")]
    pub severity: i64,
    #[serde(default)]
    pub parser: Option<ParserCfg>,
    /// Plafond de lignes retenues par réponse (anti-flood). Défaut 500.
    #[serde(default = "d_gen_max")]
    pub max_lines: usize,
}

/// Config d'une source FIM native (#58). Tous les champs sont defaultés : `type = "fim"` +
/// `paths = [...]` suffit. `paths` vide -> le lecteur no-op-e (invariant mode 0).
#[derive(Debug, Clone, Deserialize)]
pub struct FimCfg {
    /// Identifiant logique (fichier d'état/baseline + `source_id`). Défaut `integrity` — aligné sur le
    /// collecteur `integrity.sh` et le rollup santé `source='integrity'`, pour que le MÊME panneau FIM
    /// (`search source=integrity`) s'allume sans changement daemon.
    #[serde(default = "d_fim_id")]
    pub id: String,
    /// Racines surveillées (ALLOWLIST). VIDE = source inerte (mode 0). Chemins absolus.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Descente récursive dans les sous-répertoires des racines. Défaut `true`.
    #[serde(default = "d_true")]
    pub recursive: bool,
    /// Motifs d'EXCLUSION (glob simple `*`/`?`, matché sur le chemin absolu). Ex `*/.git/*`, `*.swp`.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Taille max (octets) d'un fichier hashé en SHA-256. Au-delà : taille seule, hash omis (borne le CPU).
    #[serde(default = "d_fim_hash_cap")]
    pub hash_max_bytes: u64,
    /// Plafond de watches noyau (inotify) / d'entrées baseline (anti-OOM sur arbre profond/hostile).
    #[serde(default = "d_fim_max_watches")]
    pub max_watches: usize,
    /// Plafond d'entrées baseline (fichiers suivis). Anti-OOM sur arbres énormes.
    #[serde(default = "d_fim_max_files")]
    pub max_files: usize,
    /// Fenêtre de coalescence (ms) : rafales d'events sur le même chemin fusionnées (borne le bruit d'écriture).
    #[serde(default = "d_fim_debounce")]
    pub debounce_ms: u64,
    /// Intervalle MINIMAL (s) entre deux rescans complets FORCÉS (overflow file noyau / repli scan).
    /// INDÉPENDANT de `flush_interval_secs` : la churn de routine ne peut pas déclencher des marches
    /// récursives dos-à-dos (anti-amplification CPU/I/O). Défaut 60 s.
    #[serde(default = "d_fim_min_rescan")]
    pub min_rescan_interval_secs: u64,
}

impl Default for FimCfg {
    fn default() -> Self {
        Self {
            id: d_fim_id(),
            paths: Vec::new(),
            recursive: true,
            exclude: Vec::new(),
            hash_max_bytes: d_fim_hash_cap(),
            max_watches: d_fim_max_watches(),
            max_files: d_fim_max_files(),
            debounce_ms: d_fim_debounce(),
            min_rescan_interval_secs: d_fim_min_rescan(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JournaldCfg {
    /// Identifiant logique (nom du fichier curseur d'état). Défaut `journald`.
    #[serde(default = "d_journald_id")]
    pub id: String,
    /// Filtres `_COMM=` (OR entre eux, comme journal.sh). Défaut = auth (sshd/sudo/su).
    #[serde(default = "d_journald_comm")]
    pub comm: Vec<String>,
    /// Unités systemd à suivre (`journalctl -u <unit>`, #66/#67). OR entre elles ET avec `comm`. Vide
    /// par défaut. Permet de DÉCLARER « suis les logs de nginx.service » sans script.
    #[serde(default)]
    pub units: Vec<String>,
    /// Fenêtre de rattrapage au 1er démarrage (sans curseur), ex `15min`, `1h`.
    #[serde(default = "d_journald_since")]
    pub since: String,
}

impl Default for JournaldCfg {
    fn default() -> Self {
        Self {
            id: d_journald_id(),
            comm: d_journald_comm(),
            units: Vec::new(),
            since: d_journald_since(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // champs lus par le lecteur cfg(windows) — inertes sur un build Linux
pub struct WinEventCfg {
    #[serde(default = "d_win_id")]
    pub id: String,
    /// Canaux Event Log (ex `Security`, `System`, `Application`).
    #[serde(default = "d_win_channels")]
    pub channels: Vec<String>,
    /// Requête XPath optionnelle (filtre EvtQuery). Défaut `*` (tout).
    #[serde(default = "d_star")]
    pub query: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // champs lus par le lecteur cfg(macos) — inertes sur un build Linux
pub struct OsLogCfg {
    #[serde(default = "d_mac_id")]
    pub id: String,
    /// Prédicat `log show --predicate` optionnel (filtre subsystem/process, cf. macos.rs).
    #[serde(default)]
    pub predicate: Option<String>,
    /// Fenêtre de rattrapage au 1er démarrage (sans curseur), format `log --last`, ex `15m`, `1h`.
    #[serde(default = "d_mac_since")]
    pub since: String,
}

fn d_batch() -> usize { 500 }
fn d_flush() -> u64 { 10 }
fn d_cap() -> usize { 10_000 }
fn d_star() -> String { "*".into() }
fn d_journald_id() -> String { "journald".into() }
fn d_journald_since() -> String { "15min".into() }
fn d_journald_comm() -> Vec<String> {
    ["sshd", "sshd-session", "sudo", "su"].iter().map(|s| s.to_string()).collect()
}
fn d_win_id() -> String { "wineventlog".into() }
fn d_win_channels() -> Vec<String> {
    // Security/System/Application + Sysmon operational si présent (canaux inconnus tolérés par
    // EvtQueryTolerateQueryErrors — cf. source/windows.rs).
    [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn d_file_name() -> String { "file".into() }
fn d_cmd_name() -> String { "command".into() }
fn d_http_name() -> String { "http".into() }
fn d_gen_sev() -> i64 { 1 }
fn d_poll_interval() -> u64 { 60 }
fn d_gen_max() -> usize { 500 }
fn d_mac_id() -> String { "oslog".into() }
fn d_mac_since() -> String { "15m".into() }
fn d_true() -> bool { true }
fn d_fim_id() -> String { "integrity".into() }
fn d_fim_hash_cap() -> u64 { 10 * 1024 * 1024 } // 10 MiB
fn d_fim_max_watches() -> usize { 8192 }
fn d_fim_max_files() -> usize { 200_000 }
fn d_fim_debounce() -> u64 { 200 }
fn d_fim_min_rescan() -> u64 { 60 }

impl Config {
    /// Parse un document TOML. Convertit chaque `[[source]]` INDIVIDUELLEMENT : une entrée malformée
    /// (type inconnu, champ obligatoire manquant/mal typé) est IGNORÉE avec un warning — jamais un
    /// crash de l'agent (#66/#67). Injecte la source journald par défaut si AUCUN `[[source]]` déclaré.
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        let mut c: Config = toml::from_str(s)?;
        if c.endpoint.trim().is_empty() {
            anyhow::bail!("`endpoint` est requis dans la config");
        }
        let raw = std::mem::take(&mut c.raw_sources);
        let declared = !raw.is_empty();
        for (i, entry) in raw.into_iter().enumerate() {
            match entry.clone().try_into::<SourceCfg>() {
                Ok(sc) => c.source.push(sc),
                Err(e) => eprintln!(
                    "[config] source #{i} ignorée (malformée) : {e} — entrée brute : {entry}"
                ),
            }
        }
        // Injection par défaut UNIQUEMENT si aucune source n'a été déclarée. Si des sources ont été
        // déclarées mais toutes rejetées, on NE réinjecte PAS journald (comportement honnête : l'agent
        // tourne avec les sources valides restantes, éventuellement zéro).
        if !declared {
            c.source.push(SourceCfg::Journald(JournaldCfg::default()));
        }
        Ok(c)
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("lecture config {}: {e}", path.display()))?;
        Self::from_toml(&s)
    }

    /// Header d'auth HTTP à présenter (Bearer prioritaire, sinon Basic), ou None (M2M non authentifié).
    pub fn auth_header(&self) -> Option<String> {
        if let Some(t) = &self.token {
            return Some(format!("Bearer {t}"));
        }
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            use base64::Engine;
            let b = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            return Some(format!("Basic {b}"));
        }
        None
    }
}

// --- chemins par défaut par-OS -------------------------------------------------------------------
#[cfg(target_os = "linux")]
pub fn default_config_path() -> PathBuf { PathBuf::from("/etc/plume-agent/agent.toml") }
#[cfg(target_os = "linux")]
pub fn default_spool_dir() -> PathBuf { PathBuf::from("/var/lib/plume-agent/spool") }
#[cfg(target_os = "linux")]
pub fn default_state_dir() -> PathBuf { PathBuf::from("/var/lib/plume-agent/state") }

#[cfg(target_os = "macos")]
pub fn default_config_path() -> PathBuf { PathBuf::from("/Library/Application Support/plume-agent/agent.toml") }
#[cfg(target_os = "macos")]
pub fn default_spool_dir() -> PathBuf { PathBuf::from("/Library/Application Support/plume-agent/spool") }
#[cfg(target_os = "macos")]
pub fn default_state_dir() -> PathBuf { PathBuf::from("/Library/Application Support/plume-agent/state") }

#[cfg(target_os = "windows")]
pub fn default_config_path() -> PathBuf { PathBuf::from(r"C:\ProgramData\plume-agent\agent.toml") }
#[cfg(target_os = "windows")]
pub fn default_spool_dir() -> PathBuf { PathBuf::from(r"C:\ProgramData\plume-agent\spool") }
#[cfg(target_os = "windows")]
pub fn default_state_dir() -> PathBuf { PathBuf::from(r"C:\ProgramData\plume-agent\state") }

// Repli portable pour les cibles non listées (BSD, etc.) — garde le crate buildable partout.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_config_path() -> PathBuf { PathBuf::from("/etc/plume-agent/agent.toml") }
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_spool_dir() -> PathBuf { PathBuf::from("/var/lib/plume-agent/spool") }
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_state_dir() -> PathBuf { PathBuf::from("/var/lib/plume-agent/state") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_injects_default_journald() {
        let c = Config::from_toml(r#"endpoint = "https://plume.example.com""#).unwrap();
        assert_eq!(c.endpoint, "https://plume.example.com");
        assert_eq!(c.batch_size, 500);
        assert_eq!(c.flush_interval_secs, 10);
        assert_eq!(c.spool_cap, 10_000);
        assert!(!c.tls.insecure);
        assert_eq!(c.source.len(), 1, "une source journald par défaut injectée");
        match &c.source[0] {
            SourceCfg::Journald(j) => {
                assert_eq!(j.comm, vec!["sshd", "sshd-session", "sudo", "su"]);
                assert_eq!(j.since, "15min");
            }
            _ => panic!("attendu Journald"),
        }
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
endpoint = "https://plume.example.com"
token = "abc123"
host = "web01"
host_header = "plume.example.com"
batch_size = 200
flush_interval_secs = 5
spool_cap = 42
spool_dir = "/tmp/spool"
state_dir = "/tmp/state"

[tls]
ca_cert = "/etc/plume/ca.pem"
client_cert = "/etc/plume/agent.crt"
client_key = "/etc/plume/agent.key"
insecure = true

[[source]]
type = "journald"
id = "auth"
comm = ["sshd"]
since = "1h"

[[source]]
type = "wineventlog"
channels = ["Security"]
"#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.token.as_deref(), Some("abc123"));
        assert_eq!(c.auth_header().as_deref(), Some("Bearer abc123"));
        assert_eq!(c.host.as_deref(), Some("web01"));
        assert_eq!(c.batch_size, 200);
        assert_eq!(c.spool_cap, 42);
        assert_eq!(c.spool_dir, PathBuf::from("/tmp/spool"));
        assert!(c.tls.insecure);
        assert_eq!(c.tls.ca_cert, Some(PathBuf::from("/etc/plume/ca.pem")));
        assert_eq!(c.source.len(), 2, "config [[source]] explicite conservée, pas de défaut injecté");
    }

    #[test]
    fn basic_auth_header() {
        let c = Config::from_toml(
            "endpoint = \"https://x\"\nusername = \"admin\"\npassword = \"pw\"\n",
        )
        .unwrap();
        // base64("admin:pw") = "YWRtaW46cHc="
        assert_eq!(c.auth_header().as_deref(), Some("Basic YWRtaW46cHc="));
    }

    #[test]
    fn missing_endpoint_errors() {
        assert!(Config::from_toml("token = \"x\"").is_err());
    }

    #[test]
    fn parse_generic_sources() {
        let toml = r#"
endpoint = "https://plume.example.com"

[[source]]
type = "file"
name = "nginx-access"
path = "/var/log/nginx/access.log"
category = "web"
severity = 1
from_start = true
[source.parser]
regex = '^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)"'

[[source]]
type = "command"
name = "docker-events"
cmd = "docker"
args = ["events", "--since", "1m", "--until", "1m"]
interval = 30
category = "container"

[[source]]
type = "http"
name = "app-health"
url = "http://127.0.0.1:9000/metrics"
interval = 60
"#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.source.len(), 3, "3 sources génériques déclarées, aucune injection");
        match &c.source[0] {
            SourceCfg::File(f) => {
                assert_eq!(f.name, "nginx-access");
                assert_eq!(f.path, "/var/log/nginx/access.log");
                assert_eq!(f.category, "web");
                assert!(f.from_start);
                assert!(f.parser.as_ref().unwrap().regex.is_some());
            }
            _ => panic!("attendu File"),
        }
        match &c.source[1] {
            SourceCfg::Command(cc) => {
                assert_eq!(cc.cmd, "docker");
                assert_eq!(cc.args, vec!["events", "--since", "1m", "--until", "1m"]);
                assert_eq!(cc.interval, 30);
                assert_eq!(cc.max_lines, 500, "défaut max_lines");
            }
            _ => panic!("attendu Command"),
        }
        match &c.source[2] {
            SourceCfg::Http(h) => {
                assert_eq!(h.url, "http://127.0.0.1:9000/metrics");
                assert_eq!(h.interval, 60);
            }
            _ => panic!("attendu Http"),
        }
    }

    #[test]
    fn malformed_source_is_skipped_not_fatal() {
        // Une entrée de type inconnu + une entrée `file` sans `path` (champ obligatoire) sont IGNORÉES ;
        // la source journald valide est conservée. L'agent ne plante pas (contrat #66/#67).
        let toml = r#"
endpoint = "https://plume.example.com"

[[source]]
type = "journald"
id = "auth"
comm = ["sshd"]

[[source]]
type = "bogus-type-does-not-exist"
name = "oops"

[[source]]
type = "file"
name = "no-path"
"#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.source.len(), 1, "seule la source valide survit, les 2 malformées sont sautées");
        match &c.source[0] {
            SourceCfg::Journald(j) => assert_eq!(j.id, "auth"),
            _ => panic!("attendu Journald"),
        }
    }

    #[test]
    fn shipped_example_sources_all_parse() {
        // Garde-fou anti-dérive : `examples/sources.toml` (que le technicien copie) doit rester valide.
        // On le préfixe d'un endpoint (le fragment d'exemple n'en contient pas) et on vérifie qu'AUCUNE
        // des 6 sources d'exemple n'est rejetée comme malformée.
        let example = include_str!("../examples/sources.toml");
        let full = format!("endpoint = \"https://plume.example.com\"\n{example}");
        let c = Config::from_toml(&full).expect("l'exemple doit parser");
        assert_eq!(c.source.len(), 6, "les 6 sources d'exemple parsent (aucune malformée)");
    }

    #[test]
    fn all_sources_malformed_does_not_inject_default() {
        // Des sources ont été DÉCLARÉES (mais toutes rejetées) -> pas de réinjection journald implicite.
        let toml = r#"
endpoint = "https://plume.example.com"

[[source]]
type = "nope"
"#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.source.len(), 0, "sources déclarées mais toutes malformées -> 0, pas d'injection");
    }
}
