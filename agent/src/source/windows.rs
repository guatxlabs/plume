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

/// ISSUE d'un événement — le vocabulaire NEUTRE `action` du CIM (`CIM_ACTION_VOCAB`), en somme FERMÉE.
///
/// POURQUOI UN TYPE ET PAS UN `Option<&str>`. `fields.action` est l'OUTCOME normalisé : c'est lui que
/// les détections cross-source interrogent. Les deux règles de brute-force LIVRÉES
/// (« Brute-force auth par IP » et « RBA : brute-force d'authentification », toutes deux T1110 et
/// activées) compilent `category=auth action=failure`. MESURÉ le 2026-08-02 sur trois échecs
/// d'ouverture de session Windows (4625) réellement ingérés à la forme des DEUX émetteurs livrés :
/// `search category=auth | stats count by source` rend `WinEventLog:Security 1 · windows-security 2 ·
/// sudo 366`, tandis que `search category=auth action=failure | stats count by source` rend **sudo 17
/// et RIEN pour Windows**. Les événements étaient là, la règle ne les voyait pas — un `Option` par
/// défaut à `None` est exactement ce qui rend ce trou écrivable sans y penser.
///
/// `SansIssue` n'est PAS un défaut : c'est une DÉCLARATION qu'il faut écrire (« cet enregistrement ne
/// porte pas d'issue »). `SelonStatut` dit que l'issue n'est pas dans l'identifiant mais dans
/// l'enregistrement (code de statut Kerberos/NTLM) — le résolveur va la lire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Issue {
    Reussite,
    Echec,
    SessionOuverte,
    SessionFermee,
    /// L'identifiant seul ne tranche pas : lire `Status` (4768/4769/4771) ou `Error Code` (4776).
    SelonStatut,
    /// Aucune issue à porter — déclaré, pas oublié.
    SansIssue,
}

impl Issue {
    /// Mot du vocabulaire NEUTRE `CIM_ACTION_VOCAB`, ou `None` quand il n'y a rien à écrire.
    /// Le test `issue_vocabulary_is_within_cim_action_vocab` confronte ces mots au miroir machine.
    fn mot(self, data: &Map<String, Value>) -> Option<&'static str> {
        match self {
            Issue::Reussite => Some("success"),
            Issue::Echec => Some("failure"),
            Issue::SessionOuverte => Some("session_open"),
            Issue::SessionFermee => Some("session_close"),
            Issue::SelonStatut => Some(if statut_est_succes(data) { "success" } else { "failure" }),
            Issue::SansIssue => None,
        }
    }
}

/// Le code de statut Windows d'un enregistrement d'authentification vaut-il SUCCÈS ?
/// `Status` (Kerberos 4768/4769/4771) et `Error Code` (NTLM 4776) portent `0x0` en cas de succès.
/// ABSENT ou ILLISIBLE -> `false` : on ne déclare pas un succès qu'on n'a pas lu (un faux `failure`
/// fait du bruit, un faux `success` fabrique un angle mort sur la détection de brute-force).
fn statut_est_succes(data: &Map<String, Value>) -> bool {
    let brut = data
        .get("Status")
        .or_else(|| data.get("Error Code"))
        .or_else(|| data.get("ErrorCode"))
        .and_then(|v| v.as_str());
    match brut {
        Some(s) => {
            let s = s.trim();
            let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
            match hex {
                Some(h) => i64::from_str_radix(h, 16).map(|n| n == 0).unwrap_or(false),
                None => s.parse::<i64>().map(|n| n == 0).unwrap_or(false),
            }
        }
        None => false,
    }
}

/// CLASSIFICATION D'UN ENREGISTREMENT WINDOWS — UNE SEULE DÉCISION, INDIVISIBLE.
///
/// La variante `Cim` porte les TROIS choses en même temps : la catégorie CIM, la sévérité et l'ISSUE.
/// Elle n'a **pas** de `Default` et aucun champ optionnel : une branche ajoutée demain qui omettrait
/// l'issue **ne compile pas** (E0063, « missing field `issue` »). C'est la garantie, et elle ne dépend
/// d'aucune relecture : on ne peut plus classer un événement d'authentification sans dire s'il a
/// réussi ou échoué.
///
/// `NonClasse` est l'AUTRE moitié de la partition, et elle est nommée. Elle rend `category=""` sur le
/// fil, ce qui est honnête (rien n'a été classé) — mais ce n'est PAS « le serveur tranchera » : aucun
/// des 5 parseurs déclaratifs livrés ne cible `WinEventLog:*` (mesuré le 2026-08-02 : 4 événements à
/// catégorie vide ingérés -> 4 stockés tels quels, 0 ligne de journal). Ce que devient un événement
/// non classé est décidé côté central, où il est désormais compté et signalé
/// (`CategorieIngeree::resoudre`, daemon/src/ingest/store.rs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClasseWin {
    Cim { categorie: &'static str, severite: i64, issue: Issue },
    NonClasse { severite: i64 },
}

/// (Provider, Channel, EventID, Level) -> classification CIM. Vocabulaire aligné sur le daemon
/// (`auth`/`endpoint`/`network`/`dns`/`exec`).
/// CONTRAT : toute catégorie émise ici DOIT appartenir à `CIM_CATEGORIES` (guatx-core, v1.3) — le test
/// `every_emitted_category_is_canonical_cim` le vérifie contre le miroir machine `config.d/cim/cim.v1.json`
/// (l'agent ne dépend PAS de guatx-core : le miroir EST la source de vérité accessible d'ici).
fn classer(provider: &str, channel: &str, eid: i64, level: i64) -> ClasseWin {
    let base = severity_from_level(level);
    let cim = |categorie, severite, issue| ClasseWin::Cim { categorie, severite, issue };
    // Sysmon (endpoint telemetry) : ID 3 = connexion réseau, 22 = requête DNS, sinon endpoint.
    // Aucun de ces enregistrements ne porte un verdict autorisé/refusé : `SansIssue` est DÉCLARÉ.
    if provider.to_ascii_lowercase().contains("sysmon") {
        return match eid {
            3 => cim("network", base, Issue::SansIssue),
            22 => cim("dns", base, Issue::SansIssue),
            _ => cim("endpoint", base, Issue::SansIssue),
        };
    }
    match channel {
        "Security" => match eid {
            4625 => cim("auth", 3, Issue::Echec), // échec d'ouverture de session
            4624 => cim("auth", base, Issue::SessionOuverte),
            4634 | 4647 => cim("auth", base, Issue::SessionFermee),
            4648 => cim("auth", base, Issue::SansIssue), // tentative avec identifiants explicites
            4672 => cim("auth", base, Issue::Reussite),  // privilèges spéciaux attribués
            // KERBEROS / NTLM — l'authentification de tout un domaine passe par là sur un contrôleur
            // de domaine. Ces identifiants sont écrits AUSSI BIEN en succès qu'en échec : l'issue est
            // dans le code de statut de l'enregistrement, pas dans l'identifiant.
            //   4768 = ticket TGT demandé · 4769 = ticket de service demandé
            //   4776 = validation d'identifiants NTLM
            4768 | 4769 | 4776 => cim("auth", base, Issue::SelonStatut),
            // 4771 = échec de pré-authentification Kerberos : Windows ne l'écrit QUE sur échec.
            // On le DIT plutôt que de relire un statut qui pourrait, sur une forme inattendue,
            // rendre un `success` que l'identifiant contredit.
            4771 => cim("auth", base, Issue::Echec),
            // Gestion de comptes / verrouillage -> `auth`, plancher 1. Windows n'écrit ces
            // enregistrements QUE lorsque l'opération a abouti -> `Reussite`.
            // ÉCART CONNU ET ÉCRIT : le collecteur PowerShell livré range les mêmes identifiants en
            // `category=account` (le home canonique CIM v1.3). Basculer l'agent rouvrirait la dette du
            // §5.2 de docs/CIM.md (l'historique agent rangé en `auth` deviendrait inatteignable par
            // `category=account`, et aucun alias ne peut le désambiguïser puisque `auth` porte aussi
            // les ouvertures de session). Non fait, écrit — cf. docs/CIM.md §5.5.
            4720 | 4722 | 4724 | 4725 | 4726 | 4728 | 4732 | 4735 | 4738 => {
                cim("auth", base.max(1), Issue::Reussite)
            }
            4740 => cim("auth", base.max(1), Issue::SansIssue), // compte verrouillé : constat, pas une issue
            // 4688 = création de processus. `exec` est le nom CANONIQUE CIM v1.3 ; l'agent a émis
            // `process` (hors taxonomie) jusqu'au 2026-07-23 — l'historique est retrouvé par l'alias
            // de LECTURE du daemon (`cim_read_alias_exec`), jamais par une réécriture des données.
            // Windows n'écrit 4688 QUE lorsque le processus A ÉTÉ créé -> `Reussite`. C'est ce qui
            // aligne `category=exec` sur le flux Linux (`collectors/auditd.sh` rend `action=failure`
            // quand l'`execve` échoue) : sans issue ici, la MÊME catégorie ne répondrait pas à la
            // même requête selon l'OS.
            4688 => cim("exec", base, Issue::Reussite),
            4697 => cim("endpoint", base.max(2), Issue::Reussite), // installation de service
            1102 => cim("endpoint", 3, Issue::Reussite),           // journal d'audit effacé
            _ => ClasseWin::NonClasse { severite: base },
        },
        "System" => match eid {
            7045 => cim("endpoint", base.max(2), Issue::Reussite), // nouveau service
            7036 | 7040 => cim("endpoint", base, Issue::SansIssue),
            _ => ClasseWin::NonClasse { severite: base },
        },
        _ => ClasseWin::NonClasse { severite: base },
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

    let classe = classer(&provider, &channel, eid, level);
    let data = extract_event_data(xml);
    // L'issue est résolue AVANT que `data` ne soit consommé par le sac `fields` (elle lit le code de
    // statut de l'enregistrement pour les identifiants Kerberos/NTLM).
    let (category, severity, action) = match classe {
        ClasseWin::Cim { categorie, severite, issue } => {
            (categorie.to_string(), severite, issue.mot(&data))
        }
        ClasseWin::NonClasse { severite } => (String::new(), severite, None),
    };

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
    // OUTCOME normalisé CIM (`CIM_ACTION_VOCAB`) — c'est le champ sur lequel les détections
    // cross-source composent. Absent ici, un échec d'ouverture de session Windows n'existe pas pour
    // `search category=auth action=failure` (mesuré : 0 sur 3 avant ce correctif).
    if let Some(a) = action {
        fields.insert("action".to_string(), Value::String(a.to_string()));
    }

    // L'HÔTE FAIT PARTIE DE LA CLÉ — et depuis le 2026-08-02 le CENTRAL le garantit aussi de son côté.
    // Le défaut : `event.dedup` était UNIQUE au niveau de la BASE du central, pas de l'hôte ; deux
    // machines qui formaient la même clé se volaient leurs événements, la seconde écartée en SILENCE
    // (INSERT OR IGNORE). Or `record_id` repart de 1 sur CHAQUE machine Windows — la collision n'était
    // pas un cas limite, c'était le cas NOMINAL dès le 2e poste enrôlé, et elle frappait le plus fort
    // au démarrage, quand le SOC a le plus besoin des événements.
    // MESURÉ le 2026-08-02 sur deux Windows Server 2022 (WS22-LAB / WS22-GUI, même central) : la 2e
    // machine avait 311 enregistrements dans son canal Sysmon, 266 sont arrivés et 45 ont disparu —
    // exactement les 45 déjà expédiés par la 1re machine. Vérifié APRÈS ce correctif : les 45
    // manquants arrivent (cf. collectors/windows/README.md).
    // LA GARANTIE N'EST PLUS ICI : le central cloisonne `event.dedup` par l'hôte de la ligne
    // (`dedup_scoped_by_host`, daemon/src/ingest/store.rs), parce qu'un correctif par émetteur ne
    // tenait pas à l'échelle (mesuré côté Linux : 26 événements sur 78 perdus entre deux hôtes, avec
    // au moins 29 formes de clé distinctes réparties sur 30 fichiers et 6 langages). Ce préfixe-ci est donc REDONDANT et
    // CONSERVÉ : il reste correct face à un central plus ancien, et il ne coûte rien. Ce qui est
    // encore EXIGÉ d'un émetteur, c'est une clé STABLE (elle absorbe les réémissions), pas une clé
    // qui porte l'hôte.
    let dedup = if record_id.is_empty() {
        Some(format!("win-{host}-{eid}-{ts}"))
    } else {
        Some(format!("win-{host}-{channel}-{record_id}"))
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
        assert_eq!(e.dedup.as_deref(), Some("win-ep01-Security-91234"));
        // La clé anti-doublon est UNIQUE au niveau de la base du central : deux machines qui rendent
        // la même clé se volent leurs événements. Les EventRecordID repartent de 1 sur chaque poste
        // Windows -> le MÊME enregistrement vu depuis deux hôtes doit donner deux clés DISTINCTES.
        let autre = winxml_to_event(XML_4625, "ep02").expect("event");
        assert_ne!(e.dedup, autre.dedup, "deux hôtes, même EventRecordID -> clés distinctes");
        assert!(e.message.contains("user=administrator"));
        assert!(e.message.contains("src=10.0.0.9"));
    }

    #[test]
    fn maps_sysmon_dns_to_dns_category() {
        let e = winxml_to_event(XML_SYSMON_DNS, "ep01").unwrap();
        assert_eq!(e.category, "dns");
        assert_eq!(e.severity, 0, "Level 4 (Info) -> 0");
        assert_eq!(e.fields["QueryName"], "evil.example.com");
        assert_eq!(e.dedup.as_deref(), Some("win-ep01-Microsoft-Windows-Sysmon/Operational-5"));
    }

    #[test]
    fn sysmon_network_and_process() {
        let net = r#"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><Level>4</Level><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>7</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:02Z'/></System><EventData><Data Name='DestinationIp'>1.2.3.4</Data></EventData></Event>"#;
        assert_eq!(winxml_to_event(net, "h").unwrap().category, "network");
        let proc = r#"<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><Level>4</Level><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>8</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:03Z'/></System><EventData><Data Name='Image'>C:\evil.exe</Data></EventData></Event>"#;
        assert_eq!(winxml_to_event(proc, "h").unwrap().category, "endpoint");
    }

    #[test]
    fn security_4688_is_exec() {
        let xml = r#"<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID><Level>0</Level><Channel>Security</Channel><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-06-28T00:00:00Z'/></System><EventData><Data Name='NewProcessName'>C:\Windows\cmd.exe</Data></EventData></Event>"#;
        let e = winxml_to_event(xml, "h").unwrap();
        assert_eq!(e.category, "exec", "4688 = création de processus -> `exec` (nom canonique CIM v1.3)");
    }

    /// GARDE DÉRIVÉE (pas une énumération) : BALAYE l'espace d'entrée de `classer` et exige que
    /// CHAQUE catégorie qu'il peut produire appartienne à `CIM_CATEGORIES`. La taxonomie est lue du
    /// MIROIR MACHINE du dépôt (`config.d/cim/cim.v1.json`, tenu en parité avec `guatx_core::cim` par
    /// le test daemon `cim_const_mirror_matches_config_schema`) : l'agent ne dépend pas de guatx-core,
    /// c'est la seule source de vérité qu'il puisse atteindre sans ajouter une dépendance.
    /// Ajouter demain un `NNNN => ("foo", …)` hors taxonomie fait ROUGIR ce test — y compris un
    /// RETOUR à `process`, qui n'est PAS dans la taxonomie (c'est le défaut corrigé le 2026-07-23).
    #[test]
    fn every_emitted_category_is_canonical_cim() {
        let mirror = include_str!("../../../config.d/cim/cim.v1.json");
        let v: serde_json::Value = serde_json::from_str(mirror).expect("miroir CIM illisible");
        let cats: Vec<String> = v["categories"].as_array().expect("categories[]").iter()
            .map(|c| c["name"].as_str().expect("name").to_string()).collect();
        assert!(cats.len() >= 40, "miroir CIM suspect : {} catégories", cats.len());
        assert!(cats.iter().any(|c| c == "exec"), "`exec` DOIT être canonique (sinon la bascule 4688 est fausse)");
        assert!(!cats.iter().any(|c| c == "process"), "`process` n'est PAS canonique — c'est le postulat de la bascule");
        // Balayage : tous les providers/canaux que `classer` distingue × tout l'espace d'EventID réel.
        for provider in ["", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon", "Sysmon"] {
            for channel in ["Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational", ""] {
                for eid in 0i64..=10_000 {
                    for level in [0i64, 2] {
                        if let ClasseWin::Cim { categorie, .. } = classer(provider, channel, eid, level) {
                            assert!(
                                cats.contains(&categorie.to_string()),
                                "classer({provider:?},{channel:?},{eid},{level}) -> catégorie '{categorie}' HORS CIM_CATEGORIES"
                            );
                        }
                    }
                }
            }
        }
    }

    /// GARDE DÉRIVÉE, MÊME FORME, SUR L'AUTRE MOITIÉ DE LA DÉCISION : tout mot d'`action` que la
    /// classification peut produire doit appartenir au vocabulaire NEUTRE du CIM (`action_vocab` du
    /// miroir machine). Le balayage couvre l'espace d'entrée entier ET les deux résolutions de
    /// `SelonStatut` (statut présent/absent), donc un mot inventé demain ROUGIT — quelle que soit la
    /// branche qui l'introduit. Sans cette garde, un `action` hors vocabulaire serait STOCKÉ sans un
    /// mot (le CIM n'est pas un DROP) et aucune règle ne le verrait jamais.
    #[test]
    fn issue_vocabulary_is_within_cim_action_vocab() {
        let mirror = include_str!("../../../config.d/cim/cim.v1.json");
        let v: serde_json::Value = serde_json::from_str(mirror).expect("miroir CIM illisible");
        let vocab: Vec<String> = v["action_vocab"].as_array().expect("action_vocab[]").iter()
            .map(|c| c.as_str().expect("mot").to_string()).collect();
        assert!(vocab.len() >= 11, "miroir CIM suspect : {} mots d'action", vocab.len());
        let mut succes = Map::new();
        succes.insert("Status".into(), Value::String("0x0".into()));
        let mut echec = Map::new();
        echec.insert("Status".into(), Value::String("0x18".into()));
        let vide = Map::new();
        let mut vus = 0usize;
        for provider in ["", "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon"] {
            for channel in ["Security", "System", "Application", ""] {
                for eid in 0i64..=10_000 {
                    let ClasseWin::Cim { issue, .. } = classer(provider, channel, eid, 0) else { continue };
                    for data in [&succes, &echec, &vide] {
                        if let Some(mot) = issue.mot(data) {
                            assert!(vocab.contains(&mot.to_string()),
                                "classer({provider:?},{channel:?},{eid}) -> action '{mot}' HORS action_vocab");
                            vus += 1;
                        }
                    }
                }
            }
        }
        assert!(vus > 0, "aucune action produite : le balayage a décroché, cette garde ne vérifierait rien");
    }

    /// Le contrôleur de domaine : l'authentification de tout le parc passe par Kerberos/NTLM, et son
    /// issue est dans le CODE DE STATUT, pas dans l'identifiant. Un `4768` de succès et un `4768`
    /// d'échec doivent donc rendre DEUX actions différentes — sinon la règle `action=failure` compte
    /// les succès, ou n'en compte aucun.
    #[test]
    fn kerberos_outcome_comes_from_the_status_code() {
        let xml = |eid: i64, st: &str| format!(
            "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{eid}</EventID>\
             <Level>0</Level><Channel>Security</Channel><EventRecordID>{eid}</EventRecordID>\
             <TimeCreated SystemTime='2026-08-02T00:00:00Z'/></System><EventData>\
             <Data Name='TargetUserName'>svc</Data><Data Name='Status'>{st}</Data></EventData></Event>");
        // 4768/4769/4776 sont écrits en succès COMME en échec -> l'issue vient du statut.
        for eid in [4768i64, 4769, 4776] {
            let ok = winxml_to_event(&xml(eid, "0x0"), "dc01").expect("event");
            assert_eq!(ok.category, "auth", "{eid} = authentification");
            assert_eq!(ok.fields["action"], "success", "{eid} statut 0x0 -> succès");
            let ko = winxml_to_event(&xml(eid, "0x18"), "dc01").expect("event");
            assert_eq!(ko.fields["action"], "failure", "{eid} statut non nul -> échec");
        }
        // 4771 = échec de pré-authentification : l'identifiant DIT l'échec, quel que soit le statut.
        // Une forme de statut inattendue ne doit pas pouvoir le retourner en succès.
        for st in ["0x0", "0x18", "", "n'importe quoi"] {
            let e = winxml_to_event(&xml(4771, st), "dc01").expect("event");
            assert_eq!(e.category, "auth");
            assert_eq!(e.fields["action"], "failure", "4771 est un échec, statut={st:?}");
        }
        // Statut ABSENT : on ne déclare pas un succès qu'on n'a pas lu.
        let sans = r#"<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4768</EventID><Level>0</Level><Channel>Security</Channel><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-08-02T00:00:00Z'/></System><EventData><Data Name='TargetUserName'>svc</Data></EventData></Event>"#;
        assert_eq!(winxml_to_event(sans, "dc01").unwrap().fields["action"], "failure");
    }

    /// LA RÈGLE LIVRÉE DOIT VOIR L'ÉVÉNEMENT. `4625` est l'échec d'ouverture de session Windows ; les
    /// deux règles de brute-force livrées compilent `category=auth action=failure`. MESURÉ le
    /// 2026-08-02 AVANT ce correctif : 3 échecs 4625 en base, `search category=auth action=failure`
    /// en comptait 0. Cette garde épingle les DEUX moitiés du prédicat.
    #[test]
    fn a_failed_windows_logon_carries_the_outcome_the_shipped_rules_query() {
        let e = winxml_to_event(XML_4625, "ep01").expect("event");
        assert_eq!(e.category, "auth");
        assert_eq!(e.fields["action"], "failure", "sans ce champ, `category=auth action=failure` ne rend rien");
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
