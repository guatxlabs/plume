//! Lecteur Windows Event Log — IMPLÉMENTÉ (cfg(windows) pour la partie FFI).
//!
//! Stratégie (miroir de journald) : à chaque `next_batch`, on ouvre une requête Event Log FORWARD sur
//! l'ensemble des canaux configurés (Security/System/Application/Sysmon) via une requête STRUCTURÉE
//! `<QueryList>` (un seul jeu de résultats, un seul signet couvrant tous les canaux), on reprend au
//! signet persisté (`EvtSeek RelativeToBookmark`, offset +1), on tire au plus `max` events
//! (`EvtNext`), on rend chacun en XML (`EvtRender EventXml`) et on met à jour le signet
//! (`EvtUpdateBookmark` + `EvtRender Bookmark`) — c'est notre `Cursor` (XML `<BookmarkList>` persisté
//! après ship+ACK). Le lot est borné puis les handles fermés (`EvtClose`) : pas de fuite.
//!
//! Séquence Win32 (crate `windows`, `Win32::System::EventLog`) :
//!   1. `EvtQuery(NULL, NULL, <QueryList xml>, EvtQueryChannelPath|ForwardDirection|TolerateQueryErrors)`
//!   2. reprise : `EvtCreateBookmark(<xml persisté>)` -> `EvtSeek(hResults, 1, hBookmark, 0, RelativeToBookmark)`
//!   3. `EvtNext(hResults, &events[..max], 0, 0, &returned)` -> lot de EVT_HANDLE
//!   4. par event : `EvtRender(NULL, hEvent, EvtRenderEventXml, ...)` -> XML UTF-16
//!   5. `EvtUpdateBookmark(hBookmark, hEvent)` + `EvtRender(NULL, hBookmark, EvtRenderBookmark, ...)`
//!      -> XML signet (curseur à persister)
//!   6. `EvtClose` de chaque event, du signet et du jeu de résultats.
//! (Alternative temps-réel : `EvtSubscribe` avec le même signet ; le modèle pull `EvtQuery` colle au
//!  cycle borné `next_batch` du reste de l'agent — cf. linux::JournaldReader.)
//!
//! Fil : `Wire::Events` -> enveloppe `kind:events` sur `/api/ingest` (pas de nouvel endpoint daemon).
//! Le mapping Event XML -> `Event` (CIM) est fait AGENT-SIDE et est PUR (`winxml_to_event`) donc
//! testé sur Linux ; seule la lecture FFI (`read_batch`) est `cfg(windows)`.
//!
//! Validation runtime : nécessite un hôte Windows (EvtQuery renvoie ERROR_EVT_CHANNEL_NOT_FOUND sinon).
//! Cross-compile depuis Linux : `cargo build --target x86_64-pc-windows-gnu` (ou `cargo-xwin` MSVC).
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use super::{Cursor, Event, NativeRecord, SourceReader, Wire};
use crate::config::WinEventCfg;
use serde_json::{Map, Value};

pub struct WinEventReader {
    cfg: WinEventCfg,
    host: String,
    /// Curseur = XML `<BookmarkList>` (EvtRender EvtRenderBookmark). `None` -> depuis le début des canaux.
    cursor: Option<String>,
}

impl WinEventReader {
    pub fn new(cfg: WinEventCfg, host: String) -> Self {
        Self { cfg, host, cursor: None }
    }
}

impl SourceReader for WinEventReader {
    fn source_id(&self) -> &str {
        &self.cfg.id
    }

    fn wire(&self) -> Wire {
        Wire::Events
    }

    fn open(&mut self, cursor: Cursor) {
        self.cursor = cursor.0;
    }

    fn next_batch(&mut self, max: usize) -> Vec<NativeRecord> {
        if max == 0 {
            return Vec::new();
        }
        #[cfg(target_os = "windows")]
        {
            self.read_batch(max)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = max;
            Vec::new()
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor(self.cursor.clone())
    }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        winxml_to_event(&rec.raw, &self.host)
    }
}

/// Requête structurée `<QueryList>` sélectionnant tous les canaux (filtre XPath commun). Pure/testable.
/// Un seul jeu de résultats + un seul signet couvrent l'ensemble (le `<BookmarkList>` Windows encode une
/// position PAR canal), ce qui donne un unique `Cursor` opaque à persister.
fn build_query_xml(channels: &[String], query: &str) -> String {
    let q = if query.trim().is_empty() { "*" } else { query };
    let mut selects = String::new();
    for ch in channels {
        selects.push_str(&format!(
            "<Select Path=\"{}\">{}</Select>",
            xml_escape(ch),
            q
        ));
    }
    format!("<QueryList><Query Id=\"0\">{selects}</Query></QueryList>")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// --- mapping Event XML -> Event (PUR, testé sur Linux) -------------------------------------------

/// Niveau Event Log -> sévérité Plume : 1=Critical/2=Error -> 3 ; 3=Warning -> 2 ; sinon (Info/Verbose/0) -> 0.
fn severity_from_level(level: i64) -> i64 {
    match level {
        1 | 2 => 3,
        3 => 2,
        _ => 0,
    }
}

/// (Provider, Channel, EventID, Level) -> (catégorie CIM, sévérité). Vocabulaire aligné sur le daemon
/// (`auth`/`endpoint`/`network`/`dns`/`process`) ; catégorie vide = laisser le dparser côté serveur trancher.
fn map_cim(provider: &str, channel: &str, eid: i64, level: i64) -> (String, i64) {
    let base = severity_from_level(level);
    // Sysmon (endpoint telemetry) : ID 3 = connexion réseau, 22 = requête DNS, sinon endpoint.
    if provider.to_ascii_lowercase().contains("sysmon") {
        let cat = match eid {
            3 => "network",
            22 => "dns",
            _ => "endpoint",
        };
        return (cat.to_string(), base);
    }
    match channel {
        "Security" => match eid {
            4625 => ("auth".to_string(), 3), // échec d'ouverture de session
            4624 | 4634 | 4647 | 4648 | 4672 | 4768 | 4769 | 4776 => ("auth".to_string(), base),
            // gestion de comptes / verrouillage -> auth, plancher 1
            4720 | 4722 | 4724 | 4725 | 4726 | 4728 | 4732 | 4735 | 4738 | 4740 => {
                ("auth".to_string(), base.max(1))
            }
            4688 => ("process".to_string(), base), // création de processus
            4697 => ("endpoint".to_string(), base.max(2)), // installation de service
            1102 => ("endpoint".to_string(), 3),   // journal d'audit effacé
            _ => (String::new(), base),
        },
        "System" => match eid {
            7045 => ("endpoint".to_string(), base.max(2)), // nouveau service
            7036 | 7040 => ("endpoint".to_string(), base),
            _ => (String::new(), base),
        },
        _ => (String::new(), base),
    }
}

/// Extrait la valeur d'un attribut `attr` du premier tag `<{tag} ...>` (guillemets simples ou doubles).
fn tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}"))?;
    let rest = &xml[start..];
    let end = rest.find('>')?;
    let open = &rest[..end];
    let key = format!("{attr}=");
    let ki = open.find(&key)?;
    let after = &open[ki + key.len()..];
    let quote = after.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after = &after[1..];
    let qend = after.find(quote)?;
    Some(xml_unescape(&after[..qend]))
}

/// Texte interne du premier `<{tag}[ attrs]>TEXTE</{tag}>`.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}"))?;
    let rest = &xml[start..];
    let gt = rest.find('>')?;
    let after = &rest[gt + 1..];
    let close = after.find("</")?;
    Some(xml_unescape(after[..close].trim()))
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Collecte les paires `<Data Name='k'>v</Data>` (et `<Data>v</Data>` anonymes -> `data{n}`) de l'EventData.
fn extract_event_data(xml: &str) -> Map<String, Value> {
    let mut m = Map::new();
    let mut anon = 0;
    let mut hay = xml;
    while let Some(p) = hay.find("<Data") {
        let rest = &hay[p..];
        let Some(gt) = rest.find('>') else { break };
        let open = &rest[..gt];
        let after = &rest[gt + 1..];
        let Some(close) = after.find("</Data>") else { break };
        let val = xml_unescape(after[..close].trim());
        let name = tag_attr_in(open, "Name").unwrap_or_else(|| {
            anon += 1;
            format!("data{anon}")
        });
        if !name.is_empty() {
            m.insert(name, Value::String(val));
        }
        hay = &after[close + "</Data>".len()..];
    }
    m
}

/// Variante de `tag_attr` bornée à un fragment de tag ouvrant déjà isolé (`<Data Name='..'`).
fn tag_attr_in(open: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=");
    let ki = open.find(&key)?;
    let after = &open[ki + key.len()..];
    let quote = after.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after = &after[1..];
    let qend = after.find(quote)?;
    Some(xml_unescape(&after[..qend]))
}

/// Event Log XML (EvtRender EventXml) -> `Event` normalisé au contrat Plume. Pur -> testé sur Linux.
pub fn winxml_to_event(xml: &str, host: &str) -> Option<Event> {
    let provider = tag_attr(xml, "Provider", "Name").unwrap_or_else(|| "EventLog".to_string());
    let eid: i64 = tag_text(xml, "EventID").and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let level: i64 = tag_text(xml, "Level").and_then(|s| s.trim().parse().ok()).unwrap_or(4);
    let channel = tag_text(xml, "Channel").unwrap_or_default();
    let record_id = tag_text(xml, "EventRecordID").unwrap_or_default();
    let ts = tag_attr(xml, "TimeCreated", "SystemTime")
        .and_then(|s| super::parse_epoch(&s))
        .unwrap_or_else(super::now_secs);

    let (category, severity) = map_cim(&provider, &channel, eid, level);
    let data = extract_event_data(xml);

    // Message synthétique : le XML brut ne porte PAS le texte rendu (EvtFormatMessage requis) — on
    // compose un résumé stable + les champs auth saillants ; le daemon enrichit/dparse ensuite.
    let mut message = format!("{provider} EventID {eid}");
    if !channel.is_empty() {
        message.push_str(&format!(" [{channel}]"));
    }
    if let Some(u) = data.get("TargetUserName").and_then(|v| v.as_str()) {
        message.push_str(&format!(" user={u}"));
    }
    if let Some(ip) = data.get("IpAddress").and_then(|v| v.as_str()) {
        message.push_str(&format!(" src={ip}"));
    }

    let mut fields = data;
    fields.insert("provider".to_string(), Value::String(provider));
    fields.insert("channel".to_string(), Value::String(channel.clone()));
    fields.insert("event_id".to_string(), Value::from(eid));
    fields.insert("level".to_string(), Value::from(level));

    let dedup = if record_id.is_empty() {
        Some(format!("win-{eid}-{ts}"))
    } else {
        Some(format!("win-{channel}-{record_id}"))
    };

    Some(Event {
        ts,
        host: host.to_string(),
        source: format!("WinEventLog:{channel}"),
        category,
        severity,
        message,
        fields: Value::Object(fields),
        dedup,
    })
}

// --- lecture FFI (Windows uniquement) ------------------------------------------------------------
#[cfg(target_os = "windows")]
impl WinEventReader {
    fn read_batch(&mut self, max: usize) -> Vec<NativeRecord> {
        use core::ffi::c_void;
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{
            EvtClose, EvtCreateBookmark, EvtNext, EvtQuery, EvtQueryChannelPath,
            EvtQueryForwardDirection, EvtQueryTolerateQueryErrors, EvtRender, EvtRenderBookmark,
            EvtRenderEventXml, EvtSeek, EvtSeekRelativeToBookmark, EvtUpdateBookmark, EVT_HANDLE,
        };

        // Handle NUL indépendant de la représentation (isize vs *mut c_void selon la version de windows-rs).
        let null_h: EVT_HANDLE = unsafe { core::mem::zeroed() };

        // Vec<u16> NUL-terminé pour PCWSTR (doit vivre pendant l'appel).
        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        // EvtRender générique (2 passes : taille puis rendu). Renvoie l'XML UTF-16 décodé.
        unsafe fn render(context: EVT_HANDLE, handle: EVT_HANDLE, flags: u32) -> Option<String> {
            let mut used = 0u32;
            let mut props = 0u32;
            // 1re passe : buffer NULL -> `used` = octets requis.
            let _ = EvtRender(context, handle, flags, 0, Some(std::ptr::null_mut()), &mut used, &mut props);
            if used == 0 {
                return None;
            }
            let mut buf = vec![0u8; used as usize];
            EvtRender(
                context,
                handle,
                flags,
                used,
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut used,
                &mut props,
            )
            .ok()?;
            let n = (used as usize) / 2;
            let u16s = std::slice::from_raw_parts(buf.as_ptr() as *const u16, n);
            Some(String::from_utf16_lossy(u16s).trim_end_matches('\0').to_string())
        }

        let mut out: Vec<NativeRecord> = Vec::new();
        unsafe {
            let query = wide(&build_query_xml(&self.cfg.channels, &self.cfg.query));
            let flags = (EvtQueryChannelPath.0
                | EvtQueryForwardDirection.0
                | EvtQueryTolerateQueryErrors.0) as u32;
            let results = match EvtQuery(null_h, PCWSTR::null(), PCWSTR(query.as_ptr()), flags) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[wineventlog:{}] EvtQuery échoué : {e}", self.cfg.id);
                    return out;
                }
            };

            // Signet (curseur). Reprise -> seek au signet puis +1 (skip le dernier déjà consommé).
            let bookmark = match &self.cursor {
                Some(xml) => {
                    let w = wide(xml);
                    match EvtCreateBookmark(PCWSTR(w.as_ptr())) {
                        Ok(bm) => {
                            let _ = EvtSeek(
                                results,
                                1,
                                bm,
                                0,
                                EvtSeekRelativeToBookmark.0 as u32,
                            );
                            bm
                        }
                        Err(_) => EvtCreateBookmark(PCWSTR::null()).unwrap_or(null_h),
                    }
                }
                None => EvtCreateBookmark(PCWSTR::null()).unwrap_or(null_h),
            };

            // EvtNext (windows 0.58) attend `&mut [isize]` (handles bruts) : le tableau est en isize et
            // chaque handle est re-typé en `EVT_HANDLE` avant les autres appels FFI.
            let mut events = [0isize; 64];
            'outer: while out.len() < max {
                let want = (max - out.len()).min(events.len());
                let mut returned = 0u32;
                if EvtNext(results, &mut events[..want], 0, 0, &mut returned).is_err() {
                    break; // ERROR_NO_MORE_ITEMS ou fin
                }
                if returned == 0 {
                    break;
                }
                for &ev in events.iter().take(returned as usize) {
                    let ev = EVT_HANDLE(ev);
                    if let Some(xml) = render(null_h, ev, EvtRenderEventXml.0 as u32) {
                        let cursor = if EvtUpdateBookmark(bookmark, ev).is_ok() {
                            render(null_h, bookmark, EvtRenderBookmark.0 as u32)
                        } else {
                            None
                        };
                        out.push(NativeRecord { raw: xml, cursor });
                    }
                    let _ = EvtClose(ev);
                    if out.len() >= max {
                        break 'outer;
                    }
                }
            }

            let _ = EvtClose(bookmark);
            let _ = EvtClose(results);
        }

        if let Some(last) = out.iter().rev().find_map(|r| r.cursor.clone()) {
            self.cursor = Some(last);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WinEventCfg;

    // Fragment Event XML typique d'un échec d'ouverture de session (4625), tel que rendu par EvtRender.
    const XML_4625: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Channel>Security</Channel><Computer>WIN-EP01</Computer><EventRecordID>91234</EventRecordID><TimeCreated SystemTime='2026-06-28T12:34:56.1234567Z'/></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>10.0.0.9</Data><Data Name='LogonType'>3</Data></EventData></Event>"#;

    const XML_SYSMON_DNS: &str = r#"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>22</EventID><Level>4</Level><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>5</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:01Z'/></System><EventData><Data Name='QueryName'>evil.example.com</Data></EventData></Event>"#;

    #[test]
    fn maps_4625_to_auth_failure() {
        let e = winxml_to_event(XML_4625, "ep01").expect("event");
        assert_eq!(e.category, "auth");
        assert_eq!(e.severity, 3, "4625 = échec -> sévérité 3 quel que soit Level");
        assert_eq!(e.source, "WinEventLog:Security");
        assert_eq!(e.ts, 1_782_650_096, "TimeCreated -> epoch");
        assert_eq!(e.fields["event_id"], 4625);
        assert_eq!(e.fields["TargetUserName"], "administrator");
        assert_eq!(e.fields["IpAddress"], "10.0.0.9");
        assert_eq!(e.dedup.as_deref(), Some("win-Security-91234"));
        assert!(e.message.contains("user=administrator"));
        assert!(e.message.contains("src=10.0.0.9"));
    }

    #[test]
    fn maps_sysmon_dns_to_dns_category() {
        let e = winxml_to_event(XML_SYSMON_DNS, "ep01").unwrap();
        assert_eq!(e.category, "dns");
        assert_eq!(e.severity, 0, "Level 4 (Info) -> 0");
        assert_eq!(e.fields["QueryName"], "evil.example.com");
        assert_eq!(e.dedup.as_deref(), Some("win-Microsoft-Windows-Sysmon/Operational-5"));
    }

    #[test]
    fn sysmon_network_and_process() {
        let net = r#"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><Level>4</Level><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>7</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:02Z'/></System><EventData><Data Name='DestinationIp'>1.2.3.4</Data></EventData></Event>"#;
        assert_eq!(winxml_to_event(net, "h").unwrap().category, "network");
        let proc = r#"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><Level>4</Level><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>8</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:03Z'/></System><EventData><Data Name='Image'>C:\evil.exe</Data></EventData></Event>"#;
        assert_eq!(winxml_to_event(proc, "h").unwrap().category, "endpoint");
    }

    #[test]
    fn security_4688_is_process() {
        let xml = r#"<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID><Level>0</Level><Channel>Security</Channel><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:00Z'/></System><EventData><Data Name='NewProcessName'>C:\Windows\cmd.exe</Data></EventData></Event>"#;
        let e = winxml_to_event(xml, "h").unwrap();
        assert_eq!(e.category, "process");
    }

    #[test]
    fn query_xml_covers_all_channels() {
        let cfg = WinEventCfg { id: "w".into(), channels: vec!["Security".into(), "System".into()], query: "*".into() };
        let xml = build_query_xml(&cfg.channels, &cfg.query);
        assert!(xml.contains("<Select Path=\"Security\">*</Select>"));
        assert!(xml.contains("<Select Path=\"System\">*</Select>"));
        assert!(xml.starts_with("<QueryList>"));
    }

    #[test]
    fn cursor_roundtrips_and_wire() {
        let mut r = WinEventReader::new(
            WinEventCfg { id: "wineventlog".into(), channels: d_channels(), query: "*".into() },
            "ep01".into(),
        );
        assert_eq!(r.wire(), Wire::Events);
        assert_eq!(r.source_id(), "wineventlog");
        assert_eq!(r.cursor(), Cursor(None));
        r.open(Cursor(Some("<BookmarkList/>".into())));
        assert_eq!(r.cursor(), Cursor(Some("<BookmarkList/>".into())));
        // Sur une cible non-Windows, next_batch est un no-op (pas de FFI Event Log).
        #[cfg(not(target_os = "windows"))]
        assert!(r.next_batch(10).is_empty());
    }

    fn d_channels() -> Vec<String> {
        vec!["Security".into(), "System".into()]
    }
}
