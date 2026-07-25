//! Parseurs d'ingestion : registre regex (PARSERS), extracteur générique (kv/logfmt/json) et
//! parseurs déclaratifs DSL (DPARSERS) + helpers fields_ip/dst/url. Statics OnceLock + accesseurs.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---- Registre de PARSERS (extraction de champs à l'ingestion, toutes sources) ----
// Regex compilées + cachées (rechargées depuis la table `parser` au boot et après CRUD). À l'ingestion,
// on applique les parsers de la source (+ '*') au message -> groupes nommés FUSIONNÉS dans les fields
// (sans écraser ceux du collecteur). Moteur regex Rust (linéaire, pas de ReDoS) + caps de longueur.
// MT-KEY: par db_path (R4). Le registre de parsers compilés est clé par base : parsers_reload charge
// l'entrée de SON db_path, et l'ingestion applique les parseurs du db_path EN COURS D'INGESTION (sinon les
// parseurs du dernier tenant rechargé transformeraient l'ingest de tous). En mono-tenant : une seule
// entrée -> comportement identique.
pub(crate) static PARSERS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Vec<(String, regex::Regex)>>>> = std::sync::OnceLock::new();
pub(crate) fn parsers_cell() -> &'static parking_lot::RwLock<HashMap<String, Vec<(String, regex::Regex)>>> {
    PARSERS.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
pub(crate) fn parsers_reload(conn: &Connection, db_path: &str) {
    let mut out: Vec<(String, regex::Regex)> = Vec::new();
    if let Ok(mut st) = conn.prepare("SELECT source, pattern FROM parser WHERE enabled=1") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (src, pat) in rows.flatten() {
                if pat.len() <= 1000 {
                    if let Ok(re) = regex::RegexBuilder::new(&pat).size_limit(1 << 20).build() { out.push((src, re)); }
                }
            }
        }
    }
    { let mut w = parsers_cell().write(); w.insert(db_path.to_string(), out); } // MT-KEY : registre de CE db_path
}
pub(crate) fn parsers_apply(db_path: &str, source: &str, message: &str, existing: Option<String>) -> Option<String> {
    let guard = parsers_cell().read();
    let list = match guard.get(db_path) { Some(l) if !l.is_empty() => l, _ => return existing }; // MT-KEY : parseurs de CE db_path
    let mut obj: serde_json::Map<String, Value> = existing.as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut added = false;
    let msg = if message.len() > 8192 { &message[..message.char_indices().take_while(|&(i, _)| i < 8192).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)] } else { message };
    for (src, re) in list.iter() {
        if src != "*" && src != source { continue; }
        if let Some(caps) = re.captures(msg) {
            for name in re.capture_names().flatten() {
                if let Some(mm) = caps.name(name) {
                    if !mm.as_str().is_empty() && !obj.contains_key(name) {
                        obj.insert(name.to_string(), Value::String(mm.as_str().to_string()));
                        added = true;
                    }
                }
            }
        }
    }
    if added { Some(Value::Object(obj).to_string()) } else { existing }
}

// ---- EXTRACTEUR GÉNÉRIQUE (kv/logfmt/json -> fields), OPT-IN par source (PARSER PHASE 1) ----
// Le registre `parsers_apply` est limité à des groupes regex FIXES (clés statiques). Pour les sources à
// clés DYNAMIQUES (logs k8s structurés : logfmt/json), `extract_generic` aplatit `key=value` /
// `key="val"` / objet JSON top-level dans les `fields`, SANS écraser (collecteur > parser > générique).
// BORNÉ DUR (budget 2 Go) : <=24 clés ajoutées/event, valeur <=256 c., clé doit passer soql_ident_ok
// (sinon non requêtable + risque d'injection -> skip), message tronqué à 8192 (comme parsers_apply).
pub(crate) const GENERIC_MAX_KEYS: usize = 24;
pub(crate) const GENERIC_MAX_VAL: usize = 256;
/// Sources opt-in pour `extract_generic` : env `PLUME_GENERIC_EXTRACT` (CSV, défaut `"k8s-log"`), mis
/// en cache au 1er appel. GARDE-FOU DUR : JAMAIS `*` (jamais toute source), JAMAIS `auditd` (volume +
/// auto-audit) — filtrés même si listés explicitement.
pub(crate) fn generic_sources() -> &'static [String] {
    static SRCS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    SRCS.get_or_init(|| {
        std::env::var("PLUME_GENERIC_EXTRACT")
            .unwrap_or_else(|_| "k8s-log".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "*" && s != "auditd")
            .collect()
    })
}
/// Tronque une valeur extraite sur frontière de caractère (<= GENERIC_MAX_VAL).
pub(crate) fn generic_trunc(s: &str) -> String {
    if s.len() <= GENERIC_MAX_VAL { return s.to_string(); }
    let mut end = GENERIC_MAX_VAL;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    s[..end].to_string()
}
/// Insertion BORNÉE (cap + soql_ident_ok + non-écrasement). Renvoie false UNIQUEMENT si le cap est
/// atteint (-> l'appelant ARRÊTE l'extraction) ; une clé non requêtable ou déjà présente est SAUTÉE
/// (renvoie true = continuer).
pub(crate) fn generic_put(obj: &mut serde_json::Map<String, Value>, added: &mut usize, k: &str, v: &str) -> bool {
    if *added >= GENERIC_MAX_KEYS { return false; }
    if soql_ident_ok(k) && !v.is_empty() && !obj.contains_key(k) {
        obj.insert(k.to_string(), Value::String(generic_trunc(v)));
        *added += 1;
    }
    true
}
/// Extracteur générique opt-in. Retourne le `fields` JSON ENRICHI, ou `None` si la source n'est pas
/// opt-in OU si rien n'a été ajouté. MERGE sans écrasement (même contrat que parsers_apply).
pub(crate) fn extract_generic(source: &str, message: &str, existing: &str) -> Option<String> {
    if !generic_sources().iter().any(|s| s == source) { return None; } // GATE opt-in (jamais * / auditd)
    let mut obj: serde_json::Map<String, Value> = serde_json::from_str::<Value>(existing)
        .ok().and_then(|v| v.as_object().cloned()).unwrap_or_default();
    let mut added = 0usize;
    // borne message (réutilise la troncature 8192 de parsers_apply, sur frontière de caractère).
    let msg = if message.len() > 8192 {
        &message[..message.char_indices().take_while(|&(i, _)| i < 8192).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)]
    } else { message };
    // 2. JSON-first : objet top-level -> aplati 1 niveau (scalaires `k` ; sous-objets `k.sub` qui sont
    //    ensuite SAUTÉS par soql_ident_ok car `.` n'y passe pas — tentés mais non requêtables).
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(msg) {
        'json: for (k, val) in &m {
            match val {
                Value::String(s) => { if !generic_put(&mut obj, &mut added, k, s) { break 'json; } }
                Value::Number(n) => { if !generic_put(&mut obj, &mut added, k, &n.to_string()) { break 'json; } }
                Value::Bool(b) => { if !generic_put(&mut obj, &mut added, k, &b.to_string()) { break 'json; } }
                Value::Object(sub) => {
                    for (sk, sv) in sub {
                        let key = format!("{k}.{sk}");
                        let sval = match sv {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            _ => continue,
                        };
                        if !generic_put(&mut obj, &mut added, &key, &sval) { break 'json; }
                    }
                }
                _ => {} // Array / Null -> ignorés
            }
        }
    } else {
        // 3. logfmt/kv : scan linéaire `key=value` / `key="value quoté"` (cheap, pas de regex lourde).
        let bytes = msg.as_bytes();
        let n = bytes.len();
        let mut i = 0;
        while i < n {
            if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') { i += 1; continue; } // début de clé
            let ks = i;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') { i += 1; }
            if i >= n || bytes[i] != b'=' { continue; } // mot non suivi de '=' -> pas un kv
            let key = &msg[ks..i];
            i += 1; // saute '='
            let val: &str = if i < n && bytes[i] == b'"' {
                i += 1;
                let vs = i;
                while i < n && bytes[i] != b'"' { i += 1; }
                let v = &msg[vs..i];
                if i < n { i += 1; } // saute le guillemet fermant
                v
            } else {
                let vs = i;
                while i < n && !bytes[i].is_ascii_whitespace() { i += 1; }
                &msg[vs..i]
            };
            if !generic_put(&mut obj, &mut added, key, val) { break; }
        }
    }
    if added > 0 { Some(Value::Object(obj).to_string()) } else { None }
}

// =====================================================================================
// PARSER DÉCLARATIF (DSL CIM) — Slice #7, pièce 2. PARSE / MAP / ENRICH, JAMAIS DROP.
//
// `parsers_apply` (registre legacy) ne fait qu'AJOUTER des champs (groupes nommés d'UNE regex) ; il ne
// peut PAS poser `category`/`severity`. `extract_generic` aplatit kv/json mais reste opt-in par source et
// n'affecte que `fields`. Ce module ajoute un parseur DÉCLARATIF, écrit en `config.d` (JSON, hot-reload,
// validé-ou-ignoré, managed), qui : (1) matche une `source` (+ un `match` regex optionnel), (2) EXTRAIT des
// valeurs (groupes regex nommés / key=value|logfmt / json), (3) les MAPPE vers les champs CIM
// (`category`, `severity`, `src_ip`, `dst_ip`, `url`, `action`, `fields.*`). Aucun rebuild Rust.
//
// INVARIANT (anti-angle-mort) : ENRICH/MAP uniquement. Une capture absente => AUCUN enrichissement (jamais
// une suppression d'event). Aucune primitive de ce module ne peut dropper/filtrer un event — un filtre de
// collecte relève des whitelists (#10), pas d'un parseur. MODE 0 : si AUCUN dparser n'est déclaré ou ne
// matche la source, `dparsers_apply` renvoie (fields inchangés, None, None) => ligne BYTE-IDENTIQUE.
//
// PROMOTION EN COLONNES : le map écrit `src_ip`/`dst_ip`/`url` DANS `fields` -> les promotions existantes
// (`fields_ip`/`fields_dst`/`fields_url`, appelées juste après à l'ingest) les remontent en colonnes. On
// réutilise donc l'infra de promotion telle quelle (aucune duplication).
// =====================================================================================

/// Bornes (budget cardinalité/RAM 2 Go) : steps d'extraction, captures retenues, longueur regex.
pub(crate) const DPARSER_MAX_STEPS: usize = 8;
pub(crate) const DPARSER_MAX_CAPS: usize = 32;
pub(crate) const DPARSER_MAX_RE_LEN: usize = 1000;
/// PLAFOND AGRÉGÉ : nombre de parseurs déclaratifs COMPILÉS chargés dans le registre chaud.
/// Les bornes par-parseur (steps/caps/regex len + linéarité du moteur regex) sont solides, mais le NOMBRE
/// était sans plafond -> coût CPU/RAM par event linéaire en N sans borne. Au-delà -> WARN + skip (jamais
/// fatal ; les parseurs n'arrivent que par config.d git-reviewé, ceci borde l'axe de croissance).
pub(crate) const DPARSER_MAX_TOTAL: usize = 256;

/// Une valeur de mapping : littérale (`"firewall"`, `2`) ou référence à une capture (`"$srcip"`).
#[derive(Debug, Clone)]
pub(crate) enum DMapVal { Lit(String), Cap(String) }
impl DMapVal {
    /// Parse une valeur JSON de map : `"$x"` -> Cap("x") ; toute autre string/number -> Lit ; sinon None.
    fn parse(v: &Value) -> Option<DMapVal> {
        match v {
            Value::String(s) if s.len() > 1 && s.starts_with('$') => Some(DMapVal::Cap(s[1..].to_string())),
            Value::String(s) => Some(DMapVal::Lit(s.clone())),
            Value::Number(n) => Some(DMapVal::Lit(n.to_string())),
            Value::Bool(b) => Some(DMapVal::Lit(b.to_string())),
            _ => None,
        }
    }
    /// Résout la valeur : littéral tel quel, ou capture (None si absente/vide -> AUCUN enrichissement).
    fn resolve(&self, caps: &std::collections::HashMap<String, String>) -> Option<String> {
        match self {
            DMapVal::Lit(s) => (!s.is_empty()).then(|| s.clone()),
            DMapVal::Cap(k) => caps.get(k).filter(|s| !s.is_empty()).cloned(),
        }
    }
}

/// Une étape d'extraction : groupes regex nommés, ou balayage kv/logfmt, ou objet JSON top-level.
#[derive(Debug, Clone)]
pub(crate) enum DExtract { Regex(regex::Regex), Kv, Json }

/// Le mapping vendeur -> CIM. Chaque cible est optionnelle ; `fields` = champs étendus arbitraires.
#[derive(Debug, Clone, Default)]
pub(crate) struct DMap {
    category: Option<DMapVal>,
    severity: Option<DMapVal>,
    src_ip: Option<DMapVal>,
    dst_ip: Option<DMapVal>,
    url: Option<DMapVal>,
    action: Option<DMapVal>,
    fields: Vec<(String, DMapVal)>,
}
impl DMap {
    fn is_empty(&self) -> bool {
        self.category.is_none() && self.severity.is_none() && self.src_ip.is_none()
            && self.dst_ip.is_none() && self.url.is_none() && self.action.is_none() && self.fields.is_empty()
    }
}

/// Un parseur déclaratif COMPILÉ (prêt pour l'ingest). `source='*'` = toutes.
#[derive(Debug, Clone)]
pub(crate) struct CompiledDParser {
    source: String,
    match_re: Option<regex::Regex>,
    extract: Vec<DExtract>,
    map: DMap,
}

/// Compile une spec JSON `{match?, extract?, map}` (+ `source`) en `CompiledDParser`. VALIDÉ-OU-IGNORÉ :
/// toute erreur -> `Err(raison)` et l'appelant SKIP le parseur (WARN, jamais fatal, jamais un drop d'event).
/// La présence d'un objet `map` est le DISCRIMINANT d'un parseur déclaratif (vs parseur regex legacy).
pub(crate) fn dparser_compile(source: &str, spec: &Value) -> Result<CompiledDParser, String> {
    let map_obj = spec.get("map").and_then(|m| m.as_object())
        .ok_or_else(|| "objet `map` manquant (requis pour un parseur déclaratif)".to_string())?;
    // `match` optionnel : regex de garde (le parseur ne s'applique qu'aux messages qui matchent).
    let match_re = match spec.get("match").and_then(|x| x.as_str()) {
        Some(p) if !p.is_empty() => {
            if p.len() > DPARSER_MAX_RE_LEN { return Err(format!("`match` trop long (>{DPARSER_MAX_RE_LEN})")); }
            Some(regex::RegexBuilder::new(p).size_limit(1 << 20).build().map_err(|e| format!("`match` regex invalide: {e}"))?)
        }
        _ => None,
    };
    // `extract` optionnel : liste ORDONNÉE d'étapes. Absent => map-only (littéraux).
    let mut extract = Vec::new();
    if let Some(arr) = spec.get("extract") {
        let arr = arr.as_array().ok_or_else(|| "`extract` doit être un tableau".to_string())?;
        if arr.len() > DPARSER_MAX_STEPS { return Err(format!("trop d'étapes `extract` (>{DPARSER_MAX_STEPS})")); }
        for (i, step) in arr.iter().enumerate() {
            let o = step.as_object().ok_or_else(|| format!("étape extract[{i}] doit être un objet"))?;
            if let Some(rx) = o.get("regex").and_then(|x| x.as_str()) {
                if rx.is_empty() || rx.len() > DPARSER_MAX_RE_LEN { return Err(format!("étape extract[{i}] : regex vide/trop longue")); }
                let re = regex::RegexBuilder::new(rx).size_limit(1 << 20).build().map_err(|e| format!("étape extract[{i}] regex invalide: {e}"))?;
                extract.push(DExtract::Regex(re));
            } else if o.get("kv").and_then(|x| x.as_bool()).unwrap_or(false)
                   || o.get("logfmt").and_then(|x| x.as_bool()).unwrap_or(false) {
                extract.push(DExtract::Kv);
            } else if o.get("json").and_then(|x| x.as_bool()).unwrap_or(false) {
                extract.push(DExtract::Json);
            } else {
                return Err(format!("étape extract[{i}] inconnue (attendu regex|kv|logfmt|json)"));
            }
        }
    }
    // `map` : cibles CIM. Clés cœur -> DMapVal ; `fields` (objet) -> champs étendus (clés soql_ident_ok).
    let mut map = DMap::default();
    for (k, dst) in [("category", 0), ("severity", 1), ("src_ip", 2), ("dst_ip", 3), ("url", 4), ("action", 5)] {
        if let Some(mv) = map_obj.get(k).and_then(DMapVal::parse) {
            match dst { 0 => map.category = Some(mv), 1 => map.severity = Some(mv), 2 => map.src_ip = Some(mv),
                        3 => map.dst_ip = Some(mv), 4 => map.url = Some(mv), _ => map.action = Some(mv) }
        }
    }
    if let Some(fo) = map_obj.get("fields").and_then(|x| x.as_object()) {
        for (k, v) in fo {
            if soql_ident_ok(k) {   // clé non requêtable -> ignorée (jamais un drop d'event)
                if let Some(mv) = DMapVal::parse(v) { map.fields.push((k.clone(), mv)); }
            }
        }
    }
    if map.is_empty() { return Err("`map` ne produit aucune cible CIM".to_string()); }
    Ok(CompiledDParser { source: source.to_string(), match_re, extract, map })
}

// Registre de parseurs déclaratifs COMPILÉS, clé par db_path (MÊME discipline MT-KEY que PARSERS : le
// registre de CE db_path est appliqué à l'ingest de CE db_path). Rechargé par `dparsers_reload` au boot
// (après les overlays) — mono-tenant : une seule entrée, comportement identique.
pub(crate) static DPARSERS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Vec<CompiledDParser>>>> = std::sync::OnceLock::new();
pub(crate) fn dparsers_cell() -> &'static parking_lot::RwLock<HashMap<String, Vec<CompiledDParser>>> {
    DPARSERS.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
/// Recharge le registre déclaratif de `db_path` depuis la table `dparser` (specs JSON -> compilées). Une
/// spec qui ne compile plus est SKIPPÉE (WARN) — jamais fatal. Miroir de `parsers_reload`.
pub(crate) fn dparsers_reload(conn: &Connection, db_path: &str) {
    let mut out: Vec<CompiledDParser> = Vec::new();
    if let Ok(mut st) = conn.prepare("SELECT source, spec FROM dparser WHERE enabled=1") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (src, spec) in rows.flatten() {
                // PLAFOND AGRÉGÉ : borne le nombre de parseurs appliqués par event.
                if out.len() >= DPARSER_MAX_TOTAL {
                    eprintln!("[dparser] WARN plafond de {DPARSER_MAX_TOTAL} parseurs déclaratifs atteint — parseurs supplémentaires IGNORÉS (à partir de source={src}) ; réduire le nombre de parseurs config.d");
                    break;
                }
                match serde_json::from_str::<Value>(&spec) {
                    Ok(v) => match dparser_compile(&src, &v) {
                        Ok(c) => out.push(c),
                        Err(e) => eprintln!("[dparser] WARN spec (source={src}) ne compile pas: {e} — ignorée"),
                    },
                    Err(e) => eprintln!("[dparser] WARN spec JSON invalide (source={src}): {e} — ignorée"),
                }
            }
        }
    }
    { let mut w = dparsers_cell().write(); w.insert(db_path.to_string(), out); }
}

/// Insère `k=v` dans le sac de captures, borné : cap atteint -> stop ; valeur vide/déjà présente -> SKIP
/// (first-writer-wins ; jamais d'écrasement d'une capture antérieure). Renvoie false quand le cap est plein.
pub(crate) fn dcap_put(caps: &mut std::collections::HashMap<String, String>, k: &str, v: &str) -> bool {
    if caps.len() >= DPARSER_MAX_CAPS && !caps.contains_key(k) { return false; }
    if !v.is_empty() && !caps.contains_key(k) { caps.insert(k.to_string(), generic_trunc(v)); }
    true
}
/// Exécute les étapes d'extraction sur `msg` -> sac de captures (nom -> valeur). BORNÉ (message 8192,
/// DPARSER_MAX_CAPS clés, valeur GENERIC_MAX_VAL). Réutilise le scan kv/json de `extract_generic`.
pub(crate) fn dparser_captures(msg: &str, steps: &[DExtract]) -> std::collections::HashMap<String, String> {
    let mut caps: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let msg = if msg.len() > 8192 {
        &msg[..msg.char_indices().take_while(|&(i, _)| i < 8192).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)]
    } else { msg };
    for step in steps {
        match step {
            DExtract::Regex(re) => {
                if let Some(c) = re.captures(msg) {
                    for name in re.capture_names().flatten() {
                        if let Some(mm) = c.name(name) {
                            if !dcap_put(&mut caps, name, mm.as_str()) { break; }
                        }
                    }
                }
            }
            DExtract::Json => {
                if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(msg) {
                    'json: for (k, val) in &m {
                        match val {
                            Value::String(s) => { if !dcap_put(&mut caps, k, s) { break 'json; } }
                            Value::Number(n) => { if !dcap_put(&mut caps, k, &n.to_string()) { break 'json; } }
                            Value::Bool(b) => { if !dcap_put(&mut caps, k, &b.to_string()) { break 'json; } }
                            Value::Object(sub) => {
                                for (sk, sv) in sub {
                                    let sval = match sv {
                                        Value::String(s) => s.clone(),
                                        Value::Number(n) => n.to_string(),
                                        Value::Bool(b) => b.to_string(),
                                        _ => continue,
                                    };
                                    if !dcap_put(&mut caps, &format!("{k}.{sk}"), &sval) { break 'json; }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            DExtract::Kv => {
                let bytes = msg.as_bytes();
                let n = bytes.len();
                let mut i = 0;
                while i < n {
                    if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') { i += 1; continue; }
                    let ks = i;
                    while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') { i += 1; }
                    if i >= n || bytes[i] != b'=' { continue; }
                    let key = &msg[ks..i];
                    i += 1;
                    let val: &str = if i < n && bytes[i] == b'"' {
                        i += 1;
                        let vs = i;
                        while i < n && bytes[i] != b'"' { i += 1; }
                        let v = &msg[vs..i];
                        if i < n { i += 1; }
                        v
                    } else {
                        let vs = i;
                        while i < n && !bytes[i].is_ascii_whitespace() { i += 1; }
                        &msg[vs..i]
                    };
                    if !dcap_put(&mut caps, key, val) { break; }
                }
            }
        }
    }
    caps
}

/// Écrit `k=v` dans le sac `fields` de sortie, borné et SANS écrasement (collecteur > parseur : une clé
/// déjà posée par le collecteur GAGNE). `added` passe à true dès qu'une clé est réellement ajoutée.
pub(crate) fn dfield_put(obj: &mut serde_json::Map<String, Value>, added: &mut bool, k: &str, v: &str) {
    if !v.is_empty() && !obj.contains_key(k) {
        obj.insert(k.to_string(), Value::String(generic_trunc(v)));
        *added = true;
    }
}

/// APPLIQUE les parseurs déclaratifs de `db_path` à un event `(source, message, fields)`. Renvoie
/// `(fields éventuellement enrichis, category override, severity override)`.
///
/// MODE 0 / BYTE-IDENTIQUE : si le registre de `db_path` est vide OU qu'aucun parseur ne cible `source`,
/// renvoie `(existing, None, None)` (aucune allocation, aucun changement). ENRICH-only : `fields` fusionne
/// SANS écraser (collecteur prioritaire) ; `category`/`severity` sont posés par le PREMIER parseur qui les
/// produit (first-writer-wins). Une capture absente => pas d'écriture (jamais un drop).
pub(crate) fn dparsers_apply(db_path: &str, source: &str, message: &str, existing: Option<String>) -> (Option<String>, Option<String>, Option<i64>) {
    let guard = dparsers_cell().read();
    let list = match guard.get(db_path) { Some(l) if !l.is_empty() => l, _ => return (existing, None, None) };
    // Y a-t-il au moins un parseur qui cible cette source ? Sinon -> no-op strict (ligne byte-identique).
    if !list.iter().any(|p| p.source == "*" || p.source == source) { return (existing, None, None); }
    let msg = if message.len() > 8192 {
        &message[..message.char_indices().take_while(|&(i, _)| i < 8192).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)]
    } else { message };
    let mut obj: serde_json::Map<String, Value> = existing.as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut added = false;
    let mut out_cat: Option<String> = None;
    let mut out_sev: Option<i64> = None;
    for p in list.iter() {
        if p.source != "*" && p.source != source { continue; }
        if let Some(re) = &p.match_re { if !re.is_match(msg) { continue; } }
        let caps = dparser_captures(msg, &p.extract);
        // category (first-writer-wins) : renvoyée comme OVERRIDE candidat ; l'ingest ne l'applique qu'en
        // ENRICH-only (si le collecteur n'a pas déjà posé une category). NB : seul le loader
        // AVERTIT sur une category LITTÉRALE hors taxonomie CIM ; une capture `$field` n'est pas re-validée ici.
        if out_cat.is_none() {
            if let Some(v) = p.map.category.as_ref().and_then(|mv| mv.resolve(&caps)) { out_cat = Some(v); }
        }
        // severity : littéral/capture -> i64 borné 0..4 ; hors plage/non numérique -> ignoré (pas d'override).
        if out_sev.is_none() {
            if let Some(v) = p.map.severity.as_ref().and_then(|mv| mv.resolve(&caps)) {
                if let Ok(s) = v.parse::<i64>() { if (0..=4).contains(&s) { out_sev = Some(s); } }
            }
        }
        // src_ip/dst_ip/url -> écrits DANS fields (promus en colonnes par fields_ip/dst/url en aval).
        if let Some(v) = p.map.src_ip.as_ref().and_then(|mv| mv.resolve(&caps)) { dfield_put(&mut obj, &mut added, "src_ip", &v); }
        if let Some(v) = p.map.dst_ip.as_ref().and_then(|mv| mv.resolve(&caps)) { dfield_put(&mut obj, &mut added, "dst_ip", &v); }
        if let Some(v) = p.map.url.as_ref().and_then(|mv| mv.resolve(&caps)) { dfield_put(&mut obj, &mut added, "url", &v); }
        if let Some(v) = p.map.action.as_ref().and_then(|mv| mv.resolve(&caps)) { dfield_put(&mut obj, &mut added, "action", &v); }
        for (k, mv) in &p.map.fields {
            if let Some(v) = mv.resolve(&caps) { dfield_put(&mut obj, &mut added, k, &v); }
        }
    }
    let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
    (fields, out_cat, out_sev)
}

/// IP SOURCE promue en colonne src_ip — UNIQUEMENT depuis des champs explicitement « source » :
/// `src_ip` (intention claire du parser) ou `rhost` (= l'hôte distant en convention auth). On NE promeut
/// PAS une clé ambiguë comme `ip` (pourrait être une destination) -> pas de faux sens src/dst.
pub(crate) fn fields_ip(fields: &Option<String>) -> Option<String> {
    let f: Value = serde_json::from_str(fields.as_deref()?).ok()?;
    for k in ["src_ip", "rhost"] {
        if let Some(s) = f.get(k).and_then(|x| x.as_str()) {
            if !s.is_empty() { return Some(s.to_string()); }
        }
    }
    None
}
/// IP DESTINATION promue en colonne dst_ip — uniquement depuis `dst_ip` (intention explicite du parser).
pub(crate) fn fields_dst(fields: &Option<String>) -> Option<String> {
    let f: Value = serde_json::from_str(fields.as_deref()?).ok()?;
    f.get("dst_ip").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string())
}
// NOTE (F6) : `fields_url` (promotion url standalone) a été RETIRÉE — son unique appelant (chemin event,
// ingest/mod.rs) est passé à la promotion groupée `fields_promote_src_dst_url` ci-dessous (parse unique).
// `fields_ip`/`fields_dst` restent (encore appelées par handlers/detection.rs et le chemin preauth).

/// PROMOTION GROUPÉE src_ip/dst_ip/url depuis les fields parsés — parse le blob JSON UNE SEULE FOIS (F6 :
/// au chemin event, `fields_ip`/`fields_dst`/`fields_url` refaisaient chacune un `from_str` du MÊME blob ->
/// 3 parses/event). Renvoie `(src_ip, dst_ip, url)` avec la MÊME précédence/fallback que les trois helpers
/// appelés séparément : src_ip = 1re clé non-vide parmi `["src_ip","rhost"]` ; dst_ip = clé `dst_ip` non-vide ;
/// url = clé `url` non-vide. JSON illisible/absent -> `(None,None,None)` (comme chaque helper qui renvoyait
/// None sur parse échoué). Valeurs promues BYTE-IDENTIQUES à l'appel séparé des trois fonctions.
pub(crate) fn fields_promote_src_dst_url(fields: &Option<String>) -> (Option<String>, Option<String>, Option<String>) {
    let f: Value = match fields.as_deref().and_then(|s| serde_json::from_str(s).ok()) {
        Some(v) => v,
        None => return (None, None, None),
    };
    // src_ip : même ordre/fallback que fields_ip -> 1re clé non-vide de ["src_ip","rhost"].
    let mut src = None;
    for k in ["src_ip", "rhost"] {
        if let Some(s) = f.get(k).and_then(|x| x.as_str()) {
            if !s.is_empty() { src = Some(s.to_string()); break; }
        }
    }
    // dst_ip : même règle que fields_dst.
    let dst = f.get("dst_ip").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    // url : même règle que fields_url.
    let url = f.get("url").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    (src, dst, url)
}
