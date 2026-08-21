//! Sources GÉNÉRIQUES DÉCLARATIVES (#66/#67) — `file` / `command` / `http`.
//!
//! Le technicien DÉCLARE une source dans le TOML (`[[source]]`) au lieu d'écrire un `.ps1`/`.sh`. Ces
//! trois lecteurs partagent le même mapping ligne -> `Event` (`line_to_event`) et le même parseur de
//! champs optionnel (`Parser`) : `message` = la ligne brute, `fields` = les champs extraits (additifs),
//! `dedup` = `<name>-<hash>-<bucket-horaire>` (parité avec `collectors/custom.sh` : la dédup horaire
//! côté daemon absorbe les relectures d'un tail/poll). Tous expédient en `Wire::Events` sur /api/ingest.
//!
//! Résilience : jamais de panic. Un fichier absent, une commande qui échoue, un poll HTTP non-2xx ->
//! warning + lot vide (l'agent continue). Une regex de parseur INVALIDE fait échouer la CONSTRUCTION du
//! lecteur (source ignorée en amont, cf. `build_reader`), pas l'exécution.

use super::{Cursor, Event, NativeRecord, SourceReader, Wire};
use crate::config::{CommandCfg, FileCfg, HttpCfg, ParserCfg, TlsConfig};
use crate::ship::HttpTransport;
use serde_json::{Map, Value};
use std::time::{Duration, Instant};

/// Parseur de champs compilé. `None` = aucun (fields vides). Construit une fois à l'ouverture.
pub enum Parser {
    /// Pas de parseur : `fields` reste un objet vide.
    None,
    /// Regex à groupes nommés -> chaque groupe nommé capturé devient un champ.
    Regex(regex::Regex),
    /// Découpe sur `delimiter` -> colonnes nommées par `fields`.
    Split { delimiter: String, fields: Vec<String> },
}

impl Parser {
    /// Compile la config parseur. Regex invalide -> `Err` (le lecteur ne sera pas construit).
    pub fn compile(cfg: &Option<ParserCfg>) -> anyhow::Result<Parser> {
        let Some(p) = cfg else { return Ok(Parser::None) };
        if let Some(rx) = &p.regex {
            let re = regex::Regex::new(rx)
                .map_err(|e| anyhow::anyhow!("regex de parseur invalide `{rx}` : {e}"))?;
            return Ok(Parser::Regex(re));
        }
        if let Some(d) = &p.delimiter {
            if p.fields.is_empty() {
                anyhow::bail!("parseur `delimiter` sans `fields` (rien à nommer)");
            }
            return Ok(Parser::Split { delimiter: d.clone(), fields: p.fields.clone() });
        }
        // parser = {} ou seulement `fields` sans delimiter : traité comme aucun parseur.
        Ok(Parser::None)
    }

    /// Applique le parseur à une ligne -> objet de champs (jamais scalaire). Non-match / trop de
    /// colonnes -> champs partiels ou vides (on n'écarte JAMAIS la ligne : `message` la porte quand même).
    pub fn apply(&self, line: &str) -> Map<String, Value> {
        let mut m = Map::new();
        match self {
            Parser::None => {}
            Parser::Regex(re) => {
                if let Some(caps) = re.captures(line) {
                    for name in re.capture_names().flatten() {
                        if let Some(mt) = caps.name(name) {
                            m.insert(name.to_string(), Value::String(mt.as_str().to_string()));
                        }
                    }
                }
            }
            Parser::Split { delimiter, fields } => {
                let parts: Vec<&str> = line.split(delimiter.as_str()).collect();
                for (i, name) in fields.iter().enumerate() {
                    if let Some(v) = parts.get(i) {
                        m.insert(name.clone(), Value::String((*v).to_string()));
                    }
                }
            }
        }
        m
    }
}

/// FNV-1a 64 bits (déterministe, zéro-dép) — repli de dédup (parité `oslog`/`custom.sh`).
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Mapping PARTAGÉ ligne brute -> `Event` (contrat d'enveloppe). `None` si la ligne est vide.
/// `message` = ligne brute (tronquée par le daemon si besoin), `fields` = champs extraits, `severity`
/// clampée 0..4, `dedup` = `<name>-<hash>-<bucket-horaire>` (dédup horaire côté daemon, cf. custom.sh).
pub fn line_to_event(
    name: &str,
    category: &str,
    severity: i64,
    host: &str,
    parser: &Parser,
    line: &str,
) -> Option<Event> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    let ts = super::now_secs();
    let fields = Value::Object(parser.apply(line));
    let dedup = format!("{name}-{:x}-{}", fnv1a(&format!("{name}\u{1}{line}")), ts / 3600);
    Some(Event {
        ts,
        host: host.to_string(),
        source: name.to_string(),
        category: category.to_string(),
        severity: severity.clamp(0, 4),
        message: line.to_string(),
        fields,
        dedup: Some(dedup),
    })
}

// ---------------------------------------------------------------------------------------------------
// file : tail d'un fichier de log. Curseur = offset en octets (reprise). Rotation/troncature gérées.
// ---------------------------------------------------------------------------------------------------
pub struct FileReader {
    cfg: FileCfg,
    host: String,
    parser: Parser,
    /// Offset d'octet courant (dernier octet consommé). `None` = pas encore positionné.
    offset: Option<u64>,
}

impl FileReader {
    pub fn new(cfg: FileCfg, host: String, parser: Parser) -> Self {
        Self { cfg, host, parser, offset: None }
    }
}

impl SourceReader for FileReader {
    fn source_id(&self) -> &str { &self.cfg.name }
    fn wire(&self) -> Wire { Wire::Events }

    fn open(&mut self, cursor: Cursor) {
        // Curseur persisté prioritaire ; sinon : fin de fichier (tail) sauf `from_start`.
        self.offset = match cursor.0.and_then(|s| s.parse::<u64>().ok()) {
            Some(off) => Some(off),
            None => {
                if self.cfg.from_start {
                    Some(0)
                } else {
                    Some(std::fs::metadata(&self.cfg.path).map(|m| m.len()).unwrap_or(0))
                }
            }
        };
    }

    /// `S36` — UN FICHIER QU'ON NE SAIT PAS LIRE N'EST PAS UN FICHIER SANS NOUVELLE LIGNE.
    ///
    /// QUATRE CHEMINS MENAIENT AU MÊME LOT VIDE : le `stat` en échec (le commentaire disait
    /// « fichier absent -> inerte », mais un accès REFUSÉ tombait dans la même branche), l'ouverture
    /// refusée, le positionnement impossible, et la lecture coupée en cours de lot. Un lot vide, ici,
    /// est exactement ce que rend un journal applicatif calme — et c'est ce que le SOC lisait pendant
    /// qu'une source de détection avait cessé d'être lisible.
    fn next_batch(&mut self, max: usize) -> crate::lisibilite::Releve {
        use crate::lisibilite::{cause_io, Releve, CAUSE_SOURCE_ILLISIBLE, RAISON_SOURCE_ABSENTE};
        use std::io::{BufRead, BufReader, Seek, SeekFrom};
        if max == 0 {
            return Releve::rien_a_faire();
        }
        let mut off = self.offset.unwrap_or(0);
        let size = match std::fs::metadata(&self.cfg.path) {
            Ok(m) => m.len(),
            Err(e) => {
                return Releve::illisible(
                    RAISON_SOURCE_ABSENTE,
                    cause_io(&e),
                    format!("[file:{}] {} : {e}", self.cfg.name, self.cfg.path),
                )
            }
        };
        if size < off {
            off = 0; // rotation / troncature : on repart du début du nouveau fichier
        }
        if size == off {
            // LU, ET RÉELLEMENT RIEN DE NEUF. C'est le cas nominal, et il doit rester distinct du
            // précédent : sans ce bras, un fichier lisible et calme lèverait un aveu à chaque cycle.
            self.offset = Some(off);
            return Releve::lu(Vec::new());
        }
        let f = match std::fs::File::open(&self.cfg.path) {
            Ok(f) => f,
            Err(e) => {
                return Releve::illisible(
                    RAISON_SOURCE_ABSENTE,
                    cause_io(&e),
                    format!("[file:{}] ouverture de {} refusée : {e}", self.cfg.name, self.cfg.path),
                )
            }
        };
        let mut f = f;
        if let Err(e) = f.seek(SeekFrom::Start(off)) {
            return Releve::illisible(
                RAISON_SOURCE_ABSENTE,
                cause_io(&e),
                format!("[file:{}] positionnement à l'offset {off} impossible : {e}", self.cfg.name),
            );
        }
        let mut reader = BufReader::new(f);
        let mut out = Vec::with_capacity(max.min(1024));
        let mut buf = String::new();
        let mut interrompu: Option<String> = None;
        loop {
            buf.clear();
            let n = match reader.read_line(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => n,
                // Le fichier a cessé d'être lisible EN COURS de lot (E/S, encodage, démontage).
                // Ce qui a été lu part quand même ; la troncature est avouée.
                Err(e) => {
                    interrompu = Some(format!(
                        "[file:{}] lecture interrompue à l'offset {off} après {} ligne(s) : {e}",
                        self.cfg.name,
                        out.len()
                    ));
                    break;
                }
            };
            // Ligne partielle en fin de fichier (pas de \n final) : on l'attend au prochain tour.
            if !buf.ends_with('\n') {
                break;
            }
            off += n as u64;
            let line = buf.trim_end_matches(['\r', '\n']).to_string();
            out.push(NativeRecord { raw: line, cursor: Some(off.to_string()) });
            if out.len() >= max {
                break;
            }
        }
        self.offset = Some(off);
        match interrompu {
            Some(d) => Releve::partiel(out, RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ILLISIBLE, d),
            None => Releve::lu(out),
        }
    }

    fn cursor(&self) -> Cursor {
        Cursor(self.offset.map(|o| o.to_string()))
    }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        line_to_event(
            &self.cfg.name,
            &self.cfg.category,
            self.cfg.severity,
            &self.host,
            &self.parser,
            &rec.raw,
        )
    }
}

// ---------------------------------------------------------------------------------------------------
// command : exécute une commande toutes les `interval` s. Non-reprenable (cursor None), dédup horaire.
// ---------------------------------------------------------------------------------------------------
pub struct CommandReader {
    cfg: CommandCfg,
    host: String,
    parser: Parser,
    last_run: Option<Instant>,
}

impl CommandReader {
    pub fn new(cfg: CommandCfg, host: String, parser: Parser) -> Self {
        Self { cfg, host, parser, last_run: None }
    }

    /// Cadence : `true` si l'intervalle est écoulé (ou 1re exécution).
    fn due(&self) -> bool {
        match self.last_run {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(self.cfg.interval.max(1)),
        }
    }
}

impl SourceReader for CommandReader {
    fn source_id(&self) -> &str { &self.cfg.name }
    fn wire(&self) -> Wire { Wire::Events }
    fn open(&mut self, _cursor: Cursor) {}

    /// `S36` — UNE COMMANDE QUI N'A PAS TOURNÉ N'EST PAS UNE COMMANDE SANS RÉSULTAT.
    ///
    /// TROIS CHEMINS MENAIENT AU LOT VIDE : le binaire introuvable ou non exécutable, la sortie
    /// coupée en cours de lecture, et — le plus discret — le CODE DE RETOUR jeté. Une commande qui
    /// échoue écrit sur l'erreur standard (redirigée vers le néant ici) et n'écrit RIEN sur sa sortie
    /// standard : le lecteur en tirait « aucun résultat », c'est-à-dire la valeur la plus calme.
    ///
    /// LE STATUT N'EST CONSULTÉ QUE SI LE PLAFOND DU LOT N'A PAS ÉTÉ ATTEINT : au-delà, c'est nous
    /// qui tuons l'enfant, et lire notre propre signal comme un échec produirait un aveu FAUX à
    /// chaque lot plein.
    fn next_batch(&mut self, max: usize) -> crate::lisibilite::Releve {
        use crate::lisibilite::{cause_io, Releve, CAUSE_SOURCE_ILLISIBLE, RAISON_DEPENDANCE_ABSENTE, RAISON_SOURCE_ABSENTE};
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        if max == 0 || !self.due() {
            // Cadence non échue : la source n'a pas été INTERROGÉE, donc rien n'a échoué.
            return Releve::rien_a_faire();
        }
        self.last_run = Some(Instant::now());
        let cap = max.min(self.cfg.max_lines);
        let mut child = match Command::new(&self.cfg.cmd)
            .args(&self.cfg.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return Releve::illisible(
                    RAISON_DEPENDANCE_ABSENTE,
                    cause_io(&e),
                    format!("[command:{}] `{}` non exécutable : {e}", self.cfg.name, self.cfg.cmd),
                )
            }
        };
        let mut out = Vec::with_capacity(cap.min(1024));
        let mut interrompu: Option<String> = None;
        if let Some(stdout) = child.stdout.take() {
            for ligne in BufReader::new(stdout).lines() {
                let line = match ligne {
                    Ok(l) => l,
                    Err(e) => {
                        interrompu = Some(format!(
                            "[command:{}] sortie de `{}` interrompue après {} ligne(s) : {e}",
                            self.cfg.name,
                            self.cfg.cmd,
                            out.len()
                        ));
                        break;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                out.push(NativeRecord { raw: line, cursor: None });
                if out.len() >= cap {
                    break;
                }
            }
        }
        let plafond_atteint = out.len() >= cap;
        let _ = child.kill();
        let statut = child.wait();
        if let Some(d) = interrompu {
            return Releve::partiel(out, RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ILLISIBLE, d);
        }
        if !plafond_atteint {
            if let Ok(st) = statut {
                if !st.success() {
                    return Releve::partiel(
                        out,
                        RAISON_SOURCE_ABSENTE,
                        CAUSE_SOURCE_ILLISIBLE,
                        format!(
                            "[command:{}] `{}` a terminé en échec ({st}) — un lot vide ne veut alors \
                             pas dire qu'il n'y avait rien à collecter",
                            self.cfg.name, self.cfg.cmd
                        ),
                    );
                }
            }
        }
        Releve::lu(out)
    }

    fn cursor(&self) -> Cursor { Cursor(None) }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        line_to_event(
            &self.cfg.name,
            &self.cfg.category,
            self.cfg.severity,
            &self.host,
            &self.parser,
            &rec.raw,
        )
    }
}

// ---------------------------------------------------------------------------------------------------
// http : GET d'une URL toutes les `interval` s ; chaque ligne du corps = event. Réutilise HttpTransport.
// ---------------------------------------------------------------------------------------------------
pub struct HttpReader {
    cfg: HttpCfg,
    host: String,
    parser: Parser,
    transport: Option<HttpTransport>,
    last_run: Option<Instant>,
}

impl HttpReader {
    pub fn new(cfg: HttpCfg, host: String, parser: Parser, tls: &TlsConfig) -> Self {
        // Transport construit sur les MÊMES options TLS que l'expédition (CA interne / mTLS de `[tls]`).
        // Échec de construction -> transport None -> lecteur inerte (warning au 1er poll).
        let transport = match HttpTransport::new(tls, Duration::from_secs(15)) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("[http:{}] transport TLS indisponible : {e}", cfg.name);
                None
            }
        };
        Self { cfg, host, parser, transport, last_run: None }
    }

    fn due(&self) -> bool {
        match self.last_run {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(self.cfg.interval.max(1)),
        }
    }
}

impl SourceReader for HttpReader {
    fn source_id(&self) -> &str { &self.cfg.name }
    fn wire(&self) -> Wire { Wire::Events }
    fn open(&mut self, _cursor: Cursor) {}

    /// `S36` — UN POINT D'ACCÈS QUI NE RÉPOND PAS N'EST PAS UN POINT D'ACCÈS SANS DONNÉE.
    ///
    /// TROIS CHEMINS MENAIENT AU LOT VIDE, dont le plus durable : un transport TLS qu'on n'a PAS SU
    /// CONSTRUIRE (CA interne illisible, certificat client absent) rendait le lecteur inerte POUR
    /// TOUTE LA VIE DU PROCESSUS, avec un unique avertissement à la construction — après quoi la
    /// source se lisait « calme » à chaque cycle, sans rien dire. Les deux autres : l'échec réseau et
    /// la réponse hors 2xx, tous deux réduits à « aucune ligne ».
    fn next_batch(&mut self, max: usize) -> crate::lisibilite::Releve {
        use crate::lisibilite::{
            Releve, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE, RAISON_CONFIG_ABSENTE, RAISON_INJOIGNABLE,
        };
        if max == 0 || !self.due() {
            return Releve::rien_a_faire();
        }
        let Some(transport) = &self.transport else {
            return Releve::illisible(
                RAISON_CONFIG_ABSENTE,
                CAUSE_SOURCE_ILLISIBLE,
                format!(
                    "[http:{}] transport TLS non construit au démarrage : cette source ne collectera \
                     RIEN tant que le processus vivra",
                    self.cfg.name
                ),
            );
        };
        self.last_run = Some(Instant::now());
        let resp = match transport.get(&self.cfg.url, &[]) {
            Ok(r) => r,
            Err(e) => {
                return Releve::illisible(
                    RAISON_INJOIGNABLE,
                    CAUSE_SOURCE_ILLISIBLE,
                    format!("[http:{}] GET {} échoué : {e}", self.cfg.name, self.cfg.url),
                )
            }
        };
        if !(200..300).contains(&resp.status) {
            // Le point d'accès a RÉPONDU, mais hors contrat : la source a été jointe et n'est pas
            // exploitable. C'est `forme_inconnue`, pas une absence — et surtout pas « rien à lire ».
            return Releve::illisible(
                RAISON_INJOIGNABLE,
                CAUSE_FORME_INCONNUE,
                format!("[http:{}] GET {} -> HTTP {}", self.cfg.name, self.cfg.url, resp.status),
            );
        }
        let cap = max.min(self.cfg.max_lines);
        let mut out = Vec::with_capacity(cap.min(1024));
        for line in resp.body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(NativeRecord { raw: line.to_string(), cursor: None });
            if out.len() >= cap {
                break;
            }
        }
        Releve::lu(out)
    }

    fn cursor(&self) -> Cursor { Cursor(None) }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        line_to_event(
            &self.cfg.name,
            &self.cfg.category,
            self.cfg.severity,
            &self.host,
            &self.parser,
            &rec.raw,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CommandCfg, FileCfg, ParserCfg};
    use std::io::Write;

    fn file_cfg(path: &str, parser: Option<ParserCfg>, from_start: bool) -> FileCfg {
        FileCfg {
            name: "applog".into(),
            path: path.into(),
            category: "application".into(),
            severity: 2,
            parser,
            from_start,
        }
    }

    #[test]
    fn regex_parser_extracts_named_groups() {
        let p = Parser::compile(&Some(ParserCfg {
            regex: Some(r"user=(?P<user>\w+) ip=(?P<ip>[0-9.]+)".into()),
            delimiter: None,
            fields: vec![],
        }))
        .unwrap();
        let e = line_to_event("s", "auth", 3, "h", &p, "login user=alice ip=10.0.0.9 ok").unwrap();
        assert_eq!(e.message, "login user=alice ip=10.0.0.9 ok", "message = ligne brute");
        assert_eq!(e.fields["user"], "alice");
        assert_eq!(e.fields["ip"], "10.0.0.9");
        assert_eq!(e.severity, 3);
        assert_eq!(e.source, "s");
    }

    #[test]
    fn regex_non_match_still_emits_with_empty_fields() {
        let p = Parser::compile(&Some(ParserCfg {
            regex: Some(r"user=(?P<user>\w+)".into()),
            delimiter: None,
            fields: vec![],
        }))
        .unwrap();
        let e = line_to_event("s", "", 1, "h", &p, "nothing matches here").unwrap();
        assert!(e.fields.as_object().unwrap().is_empty(), "aucun champ mais la ligne est expédiée");
        assert_eq!(e.message, "nothing matches here");
    }

    #[test]
    fn split_parser_names_columns() {
        let p = Parser::compile(&Some(ParserCfg {
            regex: None,
            delimiter: Some(",".into()),
            fields: vec!["ts".into(), "user".into(), "action".into()],
        }))
        .unwrap();
        let e = line_to_event("csvsrc", "", 1, "h", &p, "1700,bob,delete,extra").unwrap();
        assert_eq!(e.fields["ts"], "1700");
        assert_eq!(e.fields["user"], "bob");
        assert_eq!(e.fields["action"], "delete");
        assert!(e.fields.get("extra").is_none(), "colonne surnuméraire ignorée");
    }

    #[test]
    fn invalid_regex_fails_compile() {
        let r = Parser::compile(&Some(ParserCfg {
            regex: Some(r"(?P<bad>".into()),
            delimiter: None,
            fields: vec![],
        }));
        assert!(r.is_err(), "regex invalide -> Err (source ignorée en amont)");
    }

    #[test]
    fn severity_is_clamped() {
        let e = line_to_event("s", "", 99, "h", &Parser::None, "x").unwrap();
        assert_eq!(e.severity, 4, "severity clampée à 4");
        let e2 = line_to_event("s", "", -3, "h", &Parser::None, "x").unwrap();
        assert_eq!(e2.severity, 0, "severity clampée à 0");
    }

    #[test]
    fn empty_line_yields_no_event() {
        assert!(line_to_event("s", "", 1, "h", &Parser::None, "   ").is_none());
    }

    #[test]
    fn dedup_is_stable_within_hour_and_varies_by_line() {
        let a = line_to_event("s", "", 1, "h", &Parser::None, "same").unwrap();
        let b = line_to_event("s", "", 1, "h", &Parser::None, "same").unwrap();
        let c = line_to_event("s", "", 1, "h", &Parser::None, "diff").unwrap();
        assert_eq!(a.dedup, b.dedup, "même source+ligne+heure -> même dédup");
        assert_ne!(a.dedup, c.dedup, "ligne différente -> dédup différente");
    }

    #[test]
    fn file_reader_tails_new_lines_and_advances_cursor() {
        // fichier temp sur disque (dev box Linux) : teste le vrai chemin d'IO du tail.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("plume-agent-filetest-{}.log", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "ligne une").unwrap();
            writeln!(f, "ligne deux").unwrap();
        }
        let p = path.to_string_lossy().to_string();
        // from_start=true -> lit tout depuis le début.
        let mut r = FileReader::new(file_cfg(&p, None, true), "h".into(), Parser::None);
        r.open(Cursor(None));
        let batch = r.next_batch(100).records;
        assert_eq!(batch.len(), 2, "les 2 lignes existantes sont lues");
        assert_eq!(batch[0].raw, "ligne une");
        let cur = r.cursor();
        assert!(cur.0.is_some(), "curseur = offset d'octet");
        // rien de neuf -> lot vide.
        assert!(r.next_batch(100).records.is_empty());
        // append -> seule la nouvelle ligne est lue, curseur repris.
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "ligne trois").unwrap();
        }
        let batch2 = r.next_batch(100).records;
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].raw, "ligne trois");
        // mapping event via to_event.
        let ev = r.to_event(&batch2[0]).unwrap();
        assert_eq!(ev.source, "applog");
        assert_eq!(ev.category, "application");
        assert_eq!(ev.message, "ligne trois");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_reader_tail_mode_skips_existing_history() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("plume-agent-filetail-{}.log", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "vieux 1").unwrap();
            writeln!(f, "vieux 2").unwrap();
        }
        let p = path.to_string_lossy().to_string();
        // from_start=false (défaut tail) -> l'historique est ignoré, seul le nouveau est lu.
        let mut r = FileReader::new(file_cfg(&p, None, false), "h".into(), Parser::None);
        r.open(Cursor(None));
        assert!(r.next_batch(100).records.is_empty(), "tail : historique ignoré");
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "neuf").unwrap();
        }
        let b = r.next_batch(100).records;
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].raw, "neuf");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_reader_missing_file_is_inert() {
        let mut r = FileReader::new(
            file_cfg("/nonexistent/plume/nope.log", None, true),
            "h".into(),
            Parser::None,
        );
        r.open(Cursor(None));
        assert!(r.next_batch(100).records.is_empty(), "fichier absent -> aucun event, pas de panic");
        assert_eq!(r.wire(), Wire::Events);
    }

    #[test]
    fn command_reader_maps_stdout_lines() {
        // Commande portable émettant 2 lignes sur stdout : `printf` sur Unix, `cmd /C echo` sur Windows
        // (pas de `printf.exe` sur Windows -> le test échouait `left: 1`). Le reader lui-même est cross-OS
        // (BufRead::lines() gère \n ET \r\n) ; seul le CHOIX de commande du test devait être gardé par OS.
        #[cfg(not(target_os = "windows"))]
        let (cmd, args) = ("printf".to_string(), vec!["a\nb\n".to_string()]);
        #[cfg(target_os = "windows")]
        let (cmd, args) = ("cmd".to_string(), vec!["/C".to_string(), "echo a&echo b".to_string()]);
        let cfg = CommandCfg {
            name: "echosrc".into(),
            cmd,
            args,
            interval: 60,
            category: "custom".into(),
            severity: 1,
            parser: None,
            max_lines: 500,
        };
        let mut r = CommandReader::new(cfg, "h".into(), Parser::None);
        r.open(Cursor(None));
        let batch = r.next_batch(100).records;
        assert_eq!(batch.len(), 2, "2 lignes stdout -> 2 records");
        assert_eq!(batch[0].raw, "a");
        // interval non écoulé -> 2e appel vide (cadence respectée).
        assert!(r.next_batch(100).records.is_empty(), "interval non écoulé -> pas de ré-exécution");
        let ev = r.to_event(&batch[1]).unwrap();
        assert_eq!(ev.source, "echosrc");
        assert_eq!(ev.message, "b");
        assert_eq!(r.cursor(), Cursor(None), "command non-reprenable");
    }
}
