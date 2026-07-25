//! Couche TRANSPORT syslog : cadrage flux (TCP RFC6587) + entete message (RFC5424 / RFC3164 legacy).
//!
//! Ce module ne connait AUCUN vendeur. Il transforme des octets bruts en `SyslogFrame`
//! (pri/facility/severity + entete decode + `msg` = charge utile) que le dispatcher de parsers
//! vendeur consomme. Il ne PANIQUE jamais : toute entree non conforme retombe sur `msg = brut`.
//!
//! Choix delibere (cf. design) : on PREFERE toujours les champs du vendeur (FortiGate `eventtime`/
//! `level`) a l'entete syslog (lossy). L'entete est conserve pour la PROVENANCE, pas comme verite.

/// Resultat du decodage de l'entete transport d'un message syslog unique.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyslogFrame {
    /// `PRI / 8` (RFC3164 §4.1.1). `None` si pas de `<PRI>`.
    pub facility: Option<u8>,
    /// `PRI % 8`. `None` si pas de `<PRI>`.
    pub severity: Option<u8>,
    /// Numero de version RFC5424 (`Some(1)`). `None` => RFC3164 / brut.
    pub version: Option<u8>,
    /// Horodatage de l'ENTETE (brut, non normalise). Le parser vendeur prefere ses propres champs.
    pub timestamp: Option<String>,
    /// Hostname de l'entete (NILVALUE `-` => `None`).
    pub hostname: Option<String>,
    /// APP-NAME (RFC5424) / non peuple en RFC3164.
    pub app_name: Option<String>,
    /// PROCID (RFC5424).
    pub proc_id: Option<String>,
    /// MSGID (RFC5424).
    pub msg_id: Option<String>,
    /// STRUCTURED-DATA replie en paires `sd_<sdid>_<param> = valeur`.
    pub sd: Vec<(String, String)>,
    /// CHARGE UTILE : tout ce qui suit l'entete transport. Donnee au parser vendeur.
    pub msg: String,
}

fn nil_opt(s: &str) -> Option<String> {
    if s == "-" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Decode l'entete transport d'UN message syslog deja decadre (sans framing TCP).
///
/// Strategie robuste :
///  1. `<PRI>` optionnel -> facility/severity.
///  2. Apres le PRI : premier octet CHIFFRE => tentative RFC5424 (version) ; ALPHA => tentative
///     RFC3164 (`Mmm dd hh:mm:ss`). Tout echec de parse retombe sur `msg = reste` (ex. FortiGate qui
///     emet `<PRI>date=... time=...` directement : ni 5424 ni 3164 -> tout part en `msg`, INTACT).
pub fn parse_syslog(raw: &str) -> SyslogFrame {
    let line = raw.trim_end_matches(['\r', '\n']).trim_start();
    let mut f = SyslogFrame::default();

    // --- <PRI> (RFC3164 §4.1.1 / RFC5424 §6.2.1) ---
    let rest = 'pri: {
        if let Some(after_lt) = line.strip_prefix('<') {
            if let Some(gt) = after_lt.find('>') {
                let pri_str = &after_lt[..gt];
                if !pri_str.is_empty()
                    && pri_str.len() <= 3
                    && pri_str.bytes().all(|b| b.is_ascii_digit())
                {
                    if let Ok(pri) = pri_str.parse::<u16>() {
                        if pri <= 191 {
                            f.facility = Some((pri / 8) as u8);
                            f.severity = Some((pri % 8) as u8);
                            break 'pri &after_lt[gt + 1..];
                        }
                    }
                }
            }
        }
        line
    };

    match rest.as_bytes().first().copied() {
        Some(b) if b.is_ascii_digit() => {
            if parse_rfc5424(rest, &mut f) {
                return f;
            }
            f.msg = rest.to_string();
        }
        Some(b) if b.is_ascii_alphabetic() => {
            if parse_rfc3164(rest, &mut f) {
                return f;
            }
            f.msg = rest.to_string();
        }
        _ => f.msg = rest.to_string(),
    }
    f
}

/// RFC5424 : `VERSION SP TIMESTAMP SP HOST SP APP SP PROCID SP MSGID SP SD [SP MSG]`.
/// Retourne `false` (=> repli brut) si la structure ne tient pas.
fn parse_rfc5424(s: &str, f: &mut SyslogFrame) -> bool {
    // Les 6 champs d'entete n'ont pas d'espace interne -> split borne a 7.
    let mut parts = s.splitn(7, ' ');
    let version = match parts.next() {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => v,
        _ => return false,
    };
    let ver: u8 = match version.parse() {
        Ok(v) if v != 0 => v,
        _ => return false,
    };
    let timestamp = match parts.next() {
        Some(v) => v,
        None => return false,
    };
    let hostname = match parts.next() {
        Some(v) => v,
        None => return false,
    };
    let app = match parts.next() {
        Some(v) => v,
        None => return false,
    };
    let procid = match parts.next() {
        Some(v) => v,
        None => return false,
    };
    let msgid = match parts.next() {
        Some(v) => v,
        None => return false,
    };
    let tail = parts.next().unwrap_or(""); // "SD [SP MSG]"

    f.version = Some(ver);
    f.timestamp = nil_opt(timestamp);
    f.hostname = nil_opt(hostname);
    f.app_name = nil_opt(app);
    f.proc_id = nil_opt(procid);
    f.msg_id = nil_opt(msgid);

    let (sd, msg) = split_structured_data(tail);
    f.sd = sd;
    f.msg = msg;
    true
}

/// Separe la STRUCTURED-DATA (`- ` nil, ou une suite de `[...]`) du MSG qui suit.
fn split_structured_data(tail: &str) -> (Vec<(String, String)>, String) {
    if let Some(after) = tail.strip_prefix('-') {
        // NILVALUE : "- MSG" ou "-"
        let msg = after.strip_prefix(' ').unwrap_or(after);
        return (Vec::new(), msg.to_string());
    }
    if !tail.starts_with('[') {
        // pas de SD reconnaissable -> tout est MSG (tolerant)
        return (Vec::new(), tail.to_string());
    }
    let bytes = tail.as_bytes();
    let mut sd = Vec::new();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        // cherche le ']' fermant en respectant les guillemets et les echappements
        let mut j = i + 1;
        let mut in_quotes = false;
        let mut esc = false;
        while j < bytes.len() {
            let c = bytes[j];
            if esc {
                esc = false;
                j += 1;
                continue;
            }
            match c {
                b'\\' => esc = true,
                b'"' => in_quotes = !in_quotes,
                b']' if !in_quotes => break,
                _ => {}
            }
            j += 1;
        }
        if j >= bytes.len() {
            // element non termine -> on abandonne le parse SD, le reste devient MSG
            return (sd, tail[i..].to_string());
        }
        parse_sd_element(&tail[i + 1..j], &mut sd);
        i = j + 1;
    }
    let rest = &tail[i..];
    let msg = rest.strip_prefix(' ').unwrap_or(rest);
    (sd, msg.to_string())
}

/// Un element SD : `SD-ID PARAM="VALUE" PARAM2="VALUE2" ...` -> paires `sd_<sdid>_<param>`.
fn parse_sd_element(elem: &str, out: &mut Vec<(String, String)>) {
    let mut split = elem.splitn(2, ' ');
    let sdid = split.next().unwrap_or("");
    let params = split.next().unwrap_or("");
    let b = params.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let ns = i;
        while i < b.len() && b[i] != b'=' && b[i] != b' ' {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            break;
        }
        let name = &params[ns..i];
        i += 1; // '='
        let val = if i < b.len() && b[i] == b'"' {
            i += 1;
            let vs = i;
            let mut esc = false;
            while i < b.len() {
                if esc {
                    esc = false;
                    i += 1;
                    continue;
                }
                match b[i] {
                    b'\\' => {
                        esc = true;
                        i += 1;
                    }
                    b'"' => break,
                    _ => i += 1,
                }
            }
            let v = unescape(&params[vs..i]);
            if i < b.len() {
                i += 1; // guillemet fermant
            }
            v
        } else {
            let vs = i;
            while i < b.len() && b[i] != b' ' {
                i += 1;
            }
            params[vs..i].to_string()
        };
        let key = if sdid.is_empty() {
            format!("sd_{name}")
        } else {
            format!("sd_{sdid}_{name}")
        };
        out.push((sanitize_key(&key), val));
    }
}

/// RFC3164 legacy (BSD) : `Mmm dd hh:mm:ss HOSTNAME MSG...`. Heuristique tolerante ; echec -> `false`.
///
/// ROBUSTESSE UTF-8 : `s` vient de `String::from_utf8_lossy` (donc UTF-8 valide, multi-octets possible).
/// On NE tranche JAMAIS a l'octet 15 sans verifier la frontiere de caractere : un `<PRI>` suivi de 14
/// octets ASCII puis d'un caractere multi-octets (ex. `€` = 3 octets a cheval sur l'index 15) ferait
/// paniquer `&s[..15]`. `is_char_boundary(15)` garde-fou -> repli propre (jamais un panic, donc jamais
/// la mort silencieuse du thread udp_loop sur un seul datagramme force).
fn parse_rfc3164(s: &str, f: &mut SyslogFrame) -> bool {
    if s.len() < 16 || !s.is_char_boundary(15) || !looks_like_bsd_ts(&s[..15]) {
        return false;
    }
    f.timestamp = Some(s[..15].to_string());
    let after = s[15..].strip_prefix(' ').unwrap_or(&s[15..]);
    let mut it = after.splitn(2, ' ');
    let host = it.next().unwrap_or("");
    let msg = it.next().unwrap_or("");
    if !host.is_empty() {
        f.hostname = Some(host.to_string());
    }
    f.msg = msg.to_string();
    true
}

/// `Mmm dd hh:mm:ss` : 3 alpha, puis `:` aux positions 9 et 12 (jour cadre-espace tolere).
fn looks_like_bsd_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 15 {
        return false;
    }
    b[0].is_ascii_alphabetic()
        && b[1].is_ascii_alphabetic()
        && b[2].is_ascii_alphabetic()
        && b[3] == b' '
        && b[6] == b' '
        && b[9] == b':'
        && b[12] == b':'
}

fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    if esc {
        out.push('\\');
    }
    out
}

/// Cle JSON/SOQL sure : `[a-z0-9_]`, minuscule, prefixe `_` si commence par un chiffre, bornee a 64.
pub fn sanitize_key(k: &str) -> String {
    let mut out = String::with_capacity(k.len().min(64));
    for c in k.chars().take(64) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        out.insert(0, '_');
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

// =====================================================================================
//  Cadrage TCP (RFC6587) : octet-counting `MSGLEN SP MSG` OU non-transparent (LF-delimite).
// =====================================================================================

/// Issue du decodage d'UNE trame en tete du buffer TCP.
#[derive(Debug, PartialEq)]
pub enum FrameOutcome {
    /// Une trame complete a ete extraite ; `consumed` octets sont a retirer du buffer.
    Frame { message: Vec<u8>, consumed: usize },
    /// Buffer sans delimiteur au-dela de `max_frame` : on force la coupe (anti-DoS).
    OversizeFlush { message: Vec<u8>, consumed: usize },
    /// Trame incomplete : l'appelant doit lire plus d'octets.
    Incomplete,
}

/// Extrait UNE trame en tete de `buf`. Auto-detection RFC6587 :
///   - `^[0-9]{1,9} ` (chiffres + espace) => octet-counting (on lit exactement MSGLEN octets),
///   - sinon => non-transparent, coupe au `\n` (tolere `\r\n`).
/// Ne panique jamais ; borne dure `max_frame` (une "longueur" absurde ou une ligne sans `\n` trop
/// longue -> coupe forcee plutot que bufferisation illimitee).
pub fn next_frame(buf: &[u8], max_frame: usize) -> FrameOutcome {
    if buf.is_empty() {
        return FrameOutcome::Incomplete;
    }

    // --- octet-counting ? ---
    if buf[0].is_ascii_digit() {
        let mut i = 0;
        while i < buf.len() && i <= 9 && buf[i].is_ascii_digit() {
            i += 1;
        }
        if i <= 9 && i < buf.len() && buf[i] == b' ' {
            // entete de longueur complet
            if let Ok(n) = std::str::from_utf8(&buf[..i]).unwrap_or("").parse::<usize>() {
                if n > 0 && n <= max_frame {
                    let start = i + 1;
                    return if buf.len() >= start + n {
                        FrameOutcome::Frame {
                            message: buf[start..start + n].to_vec(),
                            consumed: start + n,
                        }
                    } else {
                        FrameOutcome::Incomplete
                    };
                }
                // n == 0 ou > max_frame => malforme -> on bascule en non-transparent (ci-dessous)
            }
        } else if i == buf.len() && i <= 9 {
            // buffer entierement chiffre, pas encore de terminateur : longueur partielle -> attendre
            if buf.len() <= max_frame {
                return FrameOutcome::Incomplete;
            }
        }
        // i > 9 (trop long pour une longueur) OU chiffres suivis d'un non-espace -> non-transparent
    }

    // --- non-transparent (LF-delimite) ---
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let mut end = pos;
        if end > 0 && buf[end - 1] == b'\r' {
            end -= 1;
        }
        return FrameOutcome::Frame {
            message: buf[..end].to_vec(),
            consumed: pos + 1,
        };
    }

    if buf.len() > max_frame {
        return FrameOutcome::OversizeFlush {
            message: buf[..max_frame].to_vec(),
            consumed: max_frame,
        };
    }
    FrameOutcome::Incomplete
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pri_facility_severity() {
        let f = parse_syslog("<34>Oct 11 22:14:15 host su: msg");
        assert_eq!(f.facility, Some(4)); // 34/8
        assert_eq!(f.severity, Some(2)); // 34%8
    }

    #[test]
    fn rfc3164_legacy() {
        let f = parse_syslog("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user");
        assert_eq!(f.version, None);
        assert_eq!(f.timestamp.as_deref(), Some("Oct 11 22:14:15"));
        assert_eq!(f.hostname.as_deref(), Some("mymachine"));
        assert_eq!(f.msg, "su: 'su root' failed for user");
    }

    #[test]
    fn rfc5424_nil_sd() {
        let f =
            parse_syslog("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - message here");
        assert_eq!(f.version, Some(1));
        assert_eq!(f.timestamp.as_deref(), Some("2003-10-11T22:14:15.003Z"));
        assert_eq!(f.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(f.app_name.as_deref(), Some("su"));
        assert_eq!(f.proc_id, None); // "-"
        assert_eq!(f.msg_id.as_deref(), Some("ID47"));
        assert!(f.sd.is_empty());
        assert_eq!(f.msg, "message here");
    }

    #[test]
    fn rfc5424_structured_data() {
        let f = parse_syslog(
            "<165>1 2003-10-11T22:14:15.003Z host evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\"] real message",
        );
        assert_eq!(f.version, Some(1));
        // cles SD repliees et assainies ('@' -> '_')
        let iut = f.sd.iter().find(|(k, _)| k.ends_with("_iut")).map(|(_, v)| v.as_str());
        assert_eq!(iut, Some("3"));
        let src = f.sd.iter().find(|(k, _)| k.ends_with("_eventsource")).map(|(_, v)| v.as_str());
        assert_eq!(src, Some("App"));
        assert_eq!(f.msg, "real message");
    }

    #[test]
    fn fortigate_style_falls_back_to_msg() {
        // FortiGate emet <PRI>date=... directement : ni 5424 ni 3164 -> tout en msg, intact.
        let f = parse_syslog("<189>date=2019-05-13 time=15:00:00 type=\"traffic\" action=\"accept\"");
        assert_eq!(f.severity, Some(189 % 8));
        assert_eq!(f.version, None);
        assert_eq!(f.msg, "date=2019-05-13 time=15:00:00 type=\"traffic\" action=\"accept\"");
    }

    #[test]
    fn no_pri_at_all() {
        let f = parse_syslog("just a bare line without pri");
        assert_eq!(f.facility, None);
        assert_eq!(f.msg, "just a bare line without pri");
    }

    #[test]
    fn rfc3164_multibyte_at_boundary_no_panic() {
        // 14 octets ASCII puis '€' (E2 82 AC) a cheval sur l'octet 15 : l'ancien &s[..15] paniquait
        // ("byte index 15 is not a char boundary"). Doit RETOMBER en msg=brut sans paniquer.
        let f = parse_syslog("<13>Abcdefghijklmn\u{20ac}xxxx");
        assert_eq!(f.severity, Some(13 % 8));
        assert_eq!(f.version, None);
        assert_eq!(f.msg, "Abcdefghijklmn\u{20ac}xxxx"); // pas de crop, intact
    }

    #[test]
    fn rfc3164_multibyte_scan_no_panic() {
        // Balaye toutes les positions ou un multi-octets peut chevaucher l'index 15 : aucun panic.
        for pad in 0..20 {
            let line = format!("<13>{}\u{20ac}rest of line", "A".repeat(pad));
            let _ = parse_syslog(&line);
        }
    }

    #[test]
    fn octet_counting_single_frame() {
        // "<13>hello" = 9 octets
        let buf = b"9 <13>hello";
        match next_frame(buf, 65536) {
            FrameOutcome::Frame { message, consumed } => {
                assert_eq!(message, b"<13>hello");
                assert_eq!(consumed, 11);
            }
            other => panic!("attendu Frame, obtenu {other:?}"),
        }
    }

    #[test]
    fn octet_counting_two_frames_then_partial() {
        // deux trames octet-counting concatenees + une 3e partielle
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"5 aaaaa");
        buf.extend_from_slice(b"3 bbb");
        buf.extend_from_slice(b"9 partial"); // annonce 9, seulement 7 dispo apres l'espace
        let (m1, c1) = match next_frame(&buf, 65536) {
            FrameOutcome::Frame { message, consumed } => (message, consumed),
            o => panic!("f1 {o:?}"),
        };
        assert_eq!(m1, b"aaaaa");
        buf.drain(..c1);
        let (m2, c2) = match next_frame(&buf, 65536) {
            FrameOutcome::Frame { message, consumed } => (message, consumed),
            o => panic!("f2 {o:?}"),
        };
        assert_eq!(m2, b"bbb");
        buf.drain(..c2);
        // reste "9 partial" -> Incomplete (attend 2 octets de plus)
        assert_eq!(next_frame(&buf, 65536), FrameOutcome::Incomplete);
    }

    #[test]
    fn non_transparent_lf() {
        let buf = b"<13>line one\n<13>line two\n";
        let (m1, c1) = match next_frame(buf, 65536) {
            FrameOutcome::Frame { message, consumed } => (message, consumed),
            o => panic!("{o:?}"),
        };
        assert_eq!(m1, b"<13>line one");
        assert_eq!(c1, 13);
        let (m2, _) = match next_frame(&buf[c1..], 65536) {
            FrameOutcome::Frame { message, consumed } => (message, consumed),
            o => panic!("{o:?}"),
        };
        assert_eq!(m2, b"<13>line two");
    }

    #[test]
    fn non_transparent_crlf_stripped() {
        let buf = b"hello\r\nrest";
        match next_frame(buf, 65536) {
            FrameOutcome::Frame { message, consumed } => {
                assert_eq!(message, b"hello"); // \r retire
                assert_eq!(consumed, 7); // consomme jusqu'au \n inclus
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn oversize_length_falls_back_to_lf() {
        // "999999999999" est trop long pour une longueur (>9 chiffres) -> mode LF
        let buf = b"999999999999 payload\nnext";
        match next_frame(buf, 65536) {
            FrameOutcome::Frame { message, .. } => {
                assert_eq!(message, b"999999999999 payload");
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn oversize_no_delimiter_force_flush() {
        let buf = vec![b'x'; 100];
        match next_frame(&buf, 32) {
            FrameOutcome::OversizeFlush { message, consumed } => {
                assert_eq!(message.len(), 32);
                assert_eq!(consumed, 32);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn empty_buffer_incomplete() {
        assert_eq!(next_frame(b"", 65536), FrameOutcome::Incomplete);
    }
}
