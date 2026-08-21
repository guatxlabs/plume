//! Abstraction de source native + types du contrat d'enveloppe Plume.
//!
//! Contrat de fil (identique aux collecteurs .sh et à l'émetteur HEC) :
//!   enveloppe events -> POST /api/ingest :
//!     {"ts":<epoch>,"host":"<h>","kind":"events","events":[ <event>, ... ]}
//!   event : {"ts":<epoch>,"source":"<s>","category":"<c>","severity":<n>,"message":"<m>","fields":{..}[,"dedup":".."]}
//!   journald BRUT (ndjson, 1 objet/ligne) -> POST /api/ingest/journal (le daemon parse côté serveur).
//!
//! Une `SourceReader` lit des `NativeRecord` (ligne native opaque + curseur), expose son curseur
//! courant (persisté APRÈS ship+ack — cf. buffer/ship) et sait mapper un record en `Event` (utile pour
//! les sources qui expédient en enveloppe events ; pour journald `to_event` reste MINIMAL car on
//! expédie le ndjson brut au endpoint /journal).

use serde_json::{json, Value};

pub mod fim;
/// `S36` — la garde dérivée de cette surface (suite seulement) : aucune forme de source ne peut
/// rendre un lot vide sans dire si elle a lu.
mod garde_lisibilite;
pub mod generic;
pub mod linux;
pub mod macos;
pub mod windows;

use crate::config::{SourceCfg, TlsConfig};

/// Un enregistrement natif brut tel que lu de la source (une ligne journald json, un XML EvtRender, …),
/// accompagné de son curseur (position reprenable) quand la source en fournit un.
#[derive(Debug, Clone)]
pub struct NativeRecord {
    /// Charge utile native brute (p.ex. une ligne `journalctl -o json`).
    pub raw: String,
    /// Curseur de CE record (p.ex. `__CURSOR` journald). `None` si la source n'est pas reprenable.
    pub cursor: Option<String>,
}

/// Curseur opaque d'une source (dernier record consommé). Sérialisé tel quel dans l'état.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor(pub Option<String>);

/// Un événement normalisé au contrat d'enveloppe Plume.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub ts: i64,
    pub host: String,
    pub source: String,
    pub category: String,
    pub severity: i64,
    pub message: String,
    /// Objet JSON (jamais scalaire) — enrichissement structuré.
    pub fields: Value,
    /// Clé de déduplication (INSERT OR IGNORE côté daemon). Optionnelle.
    pub dedup: Option<String>,
}

impl Event {
    /// Sérialise l'objet event AU CONTRAT (mêmes clés/ordre sémantique que lib.sh `emit_event`/HEC).
    pub fn to_value(&self) -> Value {
        let mut v = json!({
            "ts": self.ts,
            "source": self.source,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "fields": self.fields,
        });
        if let Some(d) = &self.dedup {
            v["dedup"] = Value::String(d.clone());
        }
        v
    }
}

/// Comment une source est expédiée sur le fil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// journald brut -> ndjson concaténé -> POST /api/ingest/journal.
    Journal,
    /// events normalisés -> enveloppe kind:events -> POST /api/ingest.
    Events,
}

impl Wire {
    /// Chemin d'ingest correspondant.
    pub fn endpoint(self) -> &'static str {
        match self {
            Wire::Journal => "/api/ingest/journal",
            Wire::Events => "/api/ingest",
        }
    }
}

/// Une source d'événements native reprenable.
pub trait SourceReader {
    /// Identifiant logique (nom du fichier curseur d'état).
    fn source_id(&self) -> &str;
    /// Comment cette source est expédiée (choisit l'endpoint d'ingest).
    fn wire(&self) -> Wire;
    /// (Ré)ouvre la source à partir d'un curseur persisté (reprise après redémarrage/ack).
    fn open(&mut self, cursor: Cursor);
    /// Lit le prochain lot (au plus `max` records), en avançant le curseur INTERNE de la source, ET
    /// DIT SI LA SOURCE A PU ÊTRE LUE (`S36`).
    ///
    /// LE TYPE DE RETOUR EST LA GARDE. Cette méthode rendait un `Vec<NativeRecord>` : chacun de ses
    /// chemins d'échec — binaire de collecte absent, journal refusé, fichier illisible, poll en
    /// erreur, flux coupé en cours de lot — rendait alors `Vec::new()`, c'est-à-dire EXACTEMENT ce
    /// que rend une source lue dont il ne s'est rien passé. Le cycle appelant lisait « rien à
    /// signaler » au moment précis où la source cessait d'être lisible, et les règles armées par
    /// cette source devenaient inertes sans qu'aucune alerte ne le dise.
    ///
    /// `Releve` n'a ni `Default` ni conversion depuis un `Vec` : un lecteur écrit demain ne PEUT PAS
    /// rendre un lot vide sans choisir entre `lu`, `illisible` et `partiel`. C'est la garde dérivée
    /// de cette surface — elle ne nomme aucun lecteur, elle ferme l'écriture du défaut.
    fn next_batch(&mut self, max: usize) -> crate::lisibilite::Releve;
    /// Curseur courant (dernier record consommé) — c'est CE curseur qui sera persisté après ship+ack.
    fn cursor(&self) -> Cursor;
    /// Mappe un record natif en Event (contrat d'enveloppe). `None` = record ignoré.
    fn to_event(&self, rec: &NativeRecord) -> Option<Event>;
}

/// Construit l'enveloppe `kind:events` autour d'events déjà normalisés (contrat lib.sh `emit_event`).
pub fn events_envelope(host: &str, ts: i64, events: &[Event]) -> Value {
    json!({
        "ts": ts,
        "host": host,
        "kind": "events",
        "events": events.iter().map(|e| e.to_value()).collect::<Vec<_>>(),
    })
}

/// Lecteur no-op pour une source déclarée mais NON supportée sur cet OS (ou binaire natif absent).
/// Garde le crate buildable partout et laisse une config cross-OS se charger sans planter : la source
/// ne produit simplement rien.
pub struct UnsupportedReader {
    id: String,
    reason: String,
}

impl UnsupportedReader {
    pub fn new(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { id: id.into(), reason: reason.into() }
    }
}

impl SourceReader for UnsupportedReader {
    fn source_id(&self) -> &str { &self.id }
    fn wire(&self) -> Wire { Wire::Events }
    fn open(&mut self, _c: Cursor) {
        eprintln!("[source:{}] non supportée sur cet OS : {} (ignorée)", self.id, self.reason);
    }
    /// UNE SOURCE DÉCLARÉE QUE CET OS NE SAIT PAS SERVIR EST UNE INCAPACITÉ, PAS UN CALME. Elle ne
    /// produira RIEN tant qu'un opérateur n'agit pas (retirer la source, ou l'installer sur le bon
    /// OS) : c'est le cas (I) de la partition de `collectors/lib.sh`, et il DOIT se dire. L'aveu est
    /// dédoublonné à l'heure côté central, donc une source mal déclarée écrit ~24 lignes par jour —
    /// pas 1440 — tout en ré-affirmant le trou.
    fn next_batch(&mut self, _max: usize) -> crate::lisibilite::Releve {
        crate::lisibilite::Releve::illisible(
            crate::lisibilite::RAISON_SOUS_SYSTEME_ABSENT,
            crate::lisibilite::CAUSE_SOURCE_ABSENTE,
            format!("source déclarée mais non servie sur cet OS : {}", self.reason),
        )
    }
    fn cursor(&self) -> Cursor { Cursor(None) }
    fn to_event(&self, _r: &NativeRecord) -> Option<Event> { None }
}

/// Fabrique le lecteur concret pour une config de source. Le lecteur RÉEL est cfg-gated par OS ; sur
/// un OS où la source n'a pas d'implémentation, on renvoie un `UnsupportedReader` (no-op). `state_dir`
/// sert aux sources qui persistent un état hors curseur (FIM : baseline path->hash).
pub fn build_reader(
    cfg: &SourceCfg,
    host: &str,
    state_dir: &std::path::Path,
    tls: &TlsConfig,
) -> Box<dyn SourceReader> {
    match cfg {
        SourceCfg::Journald(j) => {
            let _ = state_dir;
            #[cfg(target_os = "linux")]
            {
                return Box::new(linux::JournaldReader::new(j.clone(), host.to_string()));
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = j;
                Box::new(UnsupportedReader::new(
                    j.id.clone(),
                    "journald n'existe que sur Linux",
                ))
            }
        }
        SourceCfg::Wineventlog(w) => {
            #[cfg(target_os = "windows")]
            {
                return Box::new(windows::WinEventReader::new(w.clone(), host.to_string()));
            }
            #[cfg(not(target_os = "windows"))]
            {
                Box::new(UnsupportedReader::new(
                    w.id.clone(),
                    "Windows Event Log n'existe que sur Windows",
                ))
            }
        }
        SourceCfg::Oslog(m) => {
            #[cfg(target_os = "macos")]
            {
                return Box::new(macos::OsLogReader::new(m.clone(), host.to_string()));
            }
            #[cfg(not(target_os = "macos"))]
            {
                Box::new(UnsupportedReader::new(
                    m.id.clone(),
                    "unified log n'existe que sur macOS",
                ))
            }
        }
        SourceCfg::Fim(f) => {
            // FIM natif (#58) : le lecteur est cross-OS (logique baseline/CIM pure) ; seul le BACKEND
            // (fanotify/inotify sur Linux, ReadDirectoryChangesW sur Windows) est cfg-gated. Sur un OS
            // sans backend disponible, le reader no-op-e proprement (comme `paths` vide).
            Box::new(fim::FimReader::new(f.clone(), host.to_string(), state_dir))
        }
        // Sources GÉNÉRIQUES DÉCLARATIVES (#66/#67). Le parseur est COMPILÉ ici : une regex invalide
        // -> le lecteur est remplacé par un `UnsupportedReader` no-op + warning (la source est ignorée
        // sans emporter les autres, contrat de résilience #66/#67).
        SourceCfg::File(fc) => match generic::Parser::compile(&fc.parser) {
            Ok(p) => Box::new(generic::FileReader::new(fc.clone(), host.to_string(), p)),
            Err(e) => Box::new(UnsupportedReader::new(fc.name.clone(), format!("parseur invalide : {e}"))),
        },
        SourceCfg::Command(cc) => match generic::Parser::compile(&cc.parser) {
            Ok(p) => Box::new(generic::CommandReader::new(cc.clone(), host.to_string(), p)),
            Err(e) => Box::new(UnsupportedReader::new(cc.name.clone(), format!("parseur invalide : {e}"))),
        },
        SourceCfg::Http(hc) => match generic::Parser::compile(&hc.parser) {
            Ok(p) => Box::new(generic::HttpReader::new(hc.clone(), host.to_string(), p, tls)),
            Err(e) => Box::new(UnsupportedReader::new(hc.name.clone(), format!("parseur invalide : {e}"))),
        },
    }
}

// --- utilitaires partagés ------------------------------------------------------------------------

/// Horodatage epoch (secondes).
pub fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Nombre de jours depuis l'epoch Unix pour une date civile (algorithme de Howard Hinnant, pur/exact,
/// pas de dépendance calendrier). `m` ∈ [1,12], `d` ∈ [1,31].
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse un offset de fuseau `±HH:MM` / `±HHMM` / `±HH` en secondes (signé).
fn parse_tz_offset(tz: &str) -> Option<i64> {
    let bytes = tz.as_bytes();
    let sign: i64 = match bytes.first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let rest: String = tz[1..].chars().filter(|c| *c != ':').collect();
    let h: i64 = rest.get(0..2)?.parse().ok()?;
    let mm: i64 = rest.get(2..4).unwrap_or("00").parse().ok()?;
    Some(sign * (h * 3600 + mm * 60))
}

/// Convertit un horodatage ISO-8601 / format `log`(macOS) en epoch secondes. Accepte `T` ou espace
/// comme séparateur date/heure, une partie fractionnaire optionnelle, et un fuseau `Z` / `±HH[:]MM`
/// (absence de fuseau = UTC). Pur -> testable hors-ligne ; partagé par les lecteurs Windows et macOS.
///   `2026-06-28T12:34:56.1234567Z`         (Event Log XML SystemTime)
///   `2026-06-28 12:34:56.789012-0700`      (`log show --style ndjson` timestamp)
pub(crate) fn parse_epoch(s: &str) -> Option<i64> {
    let s = s.trim().replace('T', " ");
    let mut parts = s.split_whitespace();
    let date = parts.next()?;
    let time_full = parts.next()?;
    let mut ds = date.split('-');
    let y: i64 = ds.next()?.parse().ok()?;
    let mo: i64 = ds.next()?.parse().ok()?;
    let d: i64 = ds.next()?.parse().ok()?;

    // Détache le fuseau horaire de la fin de la partie heure.
    let mut off = 0i64;
    let mut time: &str = time_full;
    if let Some(stripped) = time.strip_suffix('Z').or_else(|| time.strip_suffix('z')) {
        time = stripped;
    } else {
        let bytes = time.as_bytes();
        let mut idx = None;
        for (i, c) in bytes.iter().enumerate().skip(1) {
            if *c == b'+' || *c == b'-' {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            off = parse_tz_offset(&time[i..])?;
            time = &time[..i];
        }
    }
    // Retire la partie fractionnaire éventuelle.
    let time = time.split('.').next()?;
    let mut ts = time.split(':');
    let hh: i64 = ts.next()?.parse().ok()?;
    let mm: i64 = ts.next()?.parse().ok()?;
    let ss: i64 = ts.next().unwrap_or("0").parse().ok()?;

    Some(days_from_civil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss - off)
}

// L'IDENTITÉ DE CETTE MACHINE NE SE LIT PLUS ICI (`S36`).
//
// Ce module portait un `hostname()` qui rendait `"unknown"` quand aucune de ses deux sources n'était
// lisible. La fonction a été RETIRÉE, et pas seulement corrigée : tant qu'elle existait, elle restait
// disponible pour le prochain site qui aurait besoin d'un nom d'hôte, et il aurait hérité du repli
// sans même savoir qu'il en héritait. La lecture vit désormais dans `lisibilite::identite_hote`, qui
// rend un VERDICT ; chaque appelant doit donc décider quoi faire quand la source n'est pas lisible,
// et les trois qui existent AVOUENT par le canal d'indisponibilité.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_plume_contract() {
        let ev = Event {
            ts: 1_700_000_000,
            host: "web01".into(),
            source: "sshd".into(),
            category: "auth".into(),
            severity: 3,
            message: "Failed password for root".into(),
            fields: json!({"pid": "42"}),
            dedup: Some("cur-1".into()),
        };
        let env = events_envelope("web01", 1_700_000_100, std::slice::from_ref(&ev));
        // enveloppe
        assert_eq!(env["ts"], 1_700_000_100);
        assert_eq!(env["host"], "web01");
        assert_eq!(env["kind"], "events");
        let arr = env["events"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        // event : toutes les clés du contrat présentes et typées correctement
        let e = &arr[0];
        assert_eq!(e["ts"], 1_700_000_000);
        assert_eq!(e["source"], "sshd");
        assert_eq!(e["category"], "auth");
        assert_eq!(e["severity"], 3);
        assert_eq!(e["message"], "Failed password for root");
        assert_eq!(e["fields"]["pid"], "42");
        assert_eq!(e["dedup"], "cur-1");
    }

    #[test]
    fn event_without_dedup_omits_key() {
        let ev = Event {
            ts: 1,
            host: "h".into(),
            source: "s".into(),
            category: "".into(),
            severity: 0,
            message: "m".into(),
            fields: json!({}),
            dedup: None,
        };
        let v = ev.to_value();
        assert!(v.get("dedup").is_none(), "pas de clé dedup quand None");
        assert_eq!(v["severity"], 0);
    }

    #[test]
    fn wire_endpoints() {
        assert_eq!(Wire::Events.endpoint(), "/api/ingest");
        assert_eq!(Wire::Journal.endpoint(), "/api/ingest/journal");
    }

    #[test]
    fn parse_epoch_iso_utc_z() {
        // 2026-06-28T12:34:56Z ; vérifié contre `date -u -d '2026-06-28T12:34:56Z' +%s` = 1782909296.
        assert_eq!(parse_epoch("2026-06-28T12:34:56.1234567Z"), Some(1_782_650_096));
    }

    #[test]
    fn parse_epoch_space_with_offset() {
        // format `log` macOS : espace + partie fractionnaire + fuseau collé `-0700`.
        // 12:34:56 -0700 == 19:34:56 UTC -> 1782909296 + 7*3600.
        assert_eq!(
            parse_epoch("2026-06-28 12:34:56.789012-0700"),
            Some(1_782_650_096 + 7 * 3600)
        );
    }

    #[test]
    fn parse_epoch_no_tz_is_utc() {
        assert_eq!(parse_epoch("2026-06-28 12:34:56"), Some(1_782_650_096));
    }

    #[test]
    fn parse_epoch_colon_offset_and_epoch_zero() {
        assert_eq!(parse_epoch("1970-01-01T00:00:00Z"), Some(0));
        // +02:00 -> soustrait 2h.
        assert_eq!(parse_epoch("1970-01-01T02:00:00+02:00"), Some(0));
    }

    #[test]
    fn parse_epoch_rejects_garbage() {
        assert!(parse_epoch("not-a-date").is_none());
    }
}
