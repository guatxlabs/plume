//! Importeur Sigma (Slice #7 pièce 3) : traduction Sigma YAML -> règle Plume (GXQL). Transforms
//! purs sur serde_json::Value + le handler HTTP sigma_import. Extrait de main.rs (refactor split
//! #25 — byte-identique).
use crate::*;

// =====================================================================================
//  SLICE #7 — PIÈCE 3 : IMPORTEUR SIGMA (Sigma YAML -> règle de détection Plume)
// =====================================================================================
//  Traduit une règle Sigma (standard ouvert de détection : logsource + detection{selection/
//  condition} + tags) en une RÈGLE PLUME : requête GXQL (`search … | stats count`) + métadonnées
//  (title -> name, level -> severity 0..4, tags attack.Txxxx -> MITRE). C'est le levier d'adoption #7
//  (absorbe la bibliothèque de détection open-source) et il est ADDITIF : une règle Sigma = des
//  lignes `rule` en plus, ZÉRO impact data-plane / mode 0.
//
//  PRINCIPE — JAMAIS de règle silencieusement fausse. Un construit non traduisible fidèlement est
//  SIGNALÉ+IGNORÉ avec une raison claire (`Err(String)`), jamais émis comme une règle qui SOUS-matche
//  (= angle mort) ou SUR-matche en silence. La couverture supportée est le sous-ensemble commun ;
//  l'INEXprimable en GXQL (OU inter-champs, `1 of them`, agrégations, encodages base64/cidr…) est rejeté.
//
//  SÉCURITÉ — INJECTION IMPOSSIBLE. Aucune valeur Sigma n'est interpolée « à cru » : chaque valeur
//  string devient un motif REGEXP construit par `sigma_re_literal`/`sigma_re_wildcard` qui n'ÉMET QUE
//  des caractères inertes pour le tokenizer GXQL (les caractères STRUCTURELS — espace, `|`, `"`, `()`,
//  `[]`, `,`, `'`, backtick — sont hex-échappés `\xNN`, décodés par le moteur regex mais invisibles au
//  découpage GXQL/pipe/`in`). La requête finale est de plus RECOMPILÉE par `rule_sql` (compilo GXQL du
//  cœur, `soql_to_sql_x`) AVANT tout stockage : échec de compilation -> rejet (garde-fou ultime).
//
//  COUVERTURE (cf. docs/SIGMA-IMPORTER.md) :
//   SUPPORTÉ  : logsource->category (table CIM) ; sélection (ET de champs) ; modificateurs
//               (=)/contains/startswith/endswith/re(|i)/all + comparateurs lt/lte/gt/gte ; jokers
//               Sigma `*`/`?` ; listes en OU d'égalités -> `field in (...)` ; condition conjonctive
//               (`and`, `and not <égalité simple/liste>`, `all of them`, `all of prefix*`, parenthèses).
//   NON SUP.  : OU inter-champs / `1 of …` / `or` ; agrégations (`| count()`) ; négation non-triviale ;
//               modificateurs base64*/utf16/wide/cidr/windash ; match `null` (existence) ; champs
//               imbriqués (nom non-ident). Chacun -> Err(raison) -> flag/skip.

/// Sigma `level` -> sévérité Plume 0..4 (cf. docs/CIM.md §3). Absent/inconnu -> 2 (warning).
pub(crate) fn sigma_level_to_sev(level: &str) -> i64 {
    match level.trim().to_ascii_lowercase().as_str() {
        "informational" | "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 2,
    }
}

/// Entier/décimal ? (miroir de `soql_num` du cœur -> le token émis suivra le MÊME chemin numérique).
pub(crate) fn sigma_is_num(s: &str) -> bool {
    let t = s.strip_prefix('-').unwrap_or(s);
    let mut parts = t.split('.');
    let i = parts.next().unwrap_or("");
    let f = parts.next();
    parts.next().is_none()
        && !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit())
        && f.map_or(true, |f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// Une valeur Sigma scalaire (string/nombre/bool) -> String. Objet/array/null -> None.
pub(crate) fn sigma_scalar_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// La valeur Sigma contient-elle un joker NON échappé (`*` / `?`) ? (`\*`,`\?`,`\\` = littéraux.)
pub(crate) fn sigma_has_wildcard(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' { i += 2; continue; }
        if chars[i] == '*' || chars[i] == '?' { return true; }
        i += 1;
    }
    false
}

/// Émet UN caractère littéral dans un motif regex de façon INERTE pour le tokenizer GXQL.
///   - alphanumérique / `_`                       -> verbatim.
///   - STRUCTUREL GXQL (espace,`|`,`"`,`()`,`[]`,`,`,`'`,backtick) -> `\xNN` (invisible au découpage
///     GXQL/pipe/`in`, décodé en littéral par le moteur regex).
///   - autre ponctuation ASCII imprimable (métacar. regex : `. * + ? ^ $ { } \ …`) -> `\c`
///     (échappement backslash — valide en regex Rust pour toute ponctuation ASCII, et GXQL-sûr).
///   - contrôle / non-ASCII -> `\xNN` / `\x{..}`.
pub(crate) fn sigma_push_literal_char(out: &mut String, c: char) {
    let u = c as u32;
    if c.is_ascii_alphanumeric() || c == '_' {
        out.push(c);
    } else if c.is_whitespace() || matches!(c, '"' | '|' | '(' | ')' | '[' | ']' | ',' | '\'' | '`') {
        // STRUCTUREL : DOIT être hex-échappé (un `\|` porterait encore le char `|` que soql_split_pipes voit).
        if u < 0x100 { out.push_str(&format!("\\x{u:02x}")); } else { out.push_str(&format!("\\x{{{u:x}}}")); }
    } else if (0x20..0x7f).contains(&u) {
        out.push('\\');
        out.push(c);
    } else if u < 0x100 {
        out.push_str(&format!("\\x{u:02x}"));
    } else {
        out.push_str(&format!("\\x{{{u:x}}}"));
    }
}

/// String LITTÉRALE Sigma -> fragment regex qui la matche EXACTEMENT et n'émet QUE des caractères
/// GXQL-inertes (cf. `sigma_push_literal_char`). Aucun joker interprété (usage : contains/startswith/…).
pub(crate) fn sigma_re_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() { sigma_push_literal_char(&mut out, c); }
    out
}

/// Valeur Sigma AVEC jokers -> fragment regex : `*` -> `.*`, `?` -> `.`, `\*`/`\?`/`\\` -> littéraux,
/// tout le reste hex/backslash-échappé (GXQL-inerte). Usage : égalité simple (les jokers y sont actifs).
pub(crate) fn sigma_re_wildcard(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                match chars.peek() {
                    Some(&n) if n == '*' || n == '?' || n == '\\' => { chars.next(); sigma_push_literal_char(&mut out, n); }
                    _ => sigma_push_literal_char(&mut out, '\\'),
                }
            }
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => sigma_push_literal_char(&mut out, other),
        }
    }
    out
}

/// Un motif `|re` brut est-il EMBARQUABLE tel quel dans un token GXQL ? (pas de caractère structurel
/// qui casserait le découpage : `|`,`"`,`()`,`[]`,`,`,`'`,backtick, espace). Sinon -> `re` non supporté
/// (on ne PEUT PAS hex-échapper un vrai regex sans en changer le sens : `|`=alternance, `[]`=classe…).
pub(crate) fn sigma_regex_embeddable(re: &str) -> bool {
    !re.is_empty()
        && !re.chars().any(|c| c.is_whitespace() || matches!(c, '|' | '"' | '(' | ')' | '[' | ']' | ',' | '\'' | '`'))
}

/// Valeur `field=value` / `field!=value` embarquable comme token NU (pas de structurel, pas d'espace) ?
pub(crate) fn sigma_bareword_safe(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || matches!(c, '|' | '"' | '(' | ')' | '[' | ']' | ',' | '\'' | '`'))
}

/// Valeur embarquable dans une liste `in (...)` ? (le pré-pass `in` extrait `[^()]*`, split sur `,` :
/// interdits = `,`,`(`,`)`,`|`,`"` ; les espaces internes sont préservés, `'` est ré-échappé côté SQL.)
pub(crate) fn sigma_in_safe(s: &str) -> bool {
    !s.trim().is_empty() && !s.chars().any(|c| matches!(c, ',' | '(' | ')' | '|' | '"'))
}

/// Assemble un token `field=~PATTERN` en bornant la longueur du motif à 512 (limite DURE de l'UDF
/// `regexp`) : au-delà, l'UDF renverrait une ERREUR à l'ÉVAL -> `eval_value=0` -> règle MUETTE (angle
/// mort SILENCIEUX). On préfère FLAGGER à la traduction (`Err`) qu'émettre une règle qui ne fire jamais.
pub(crate) fn sigma_regex_token(field: &str, pattern: &str) -> Result<String, String> {
    if pattern.len() > 512 {
        return Err(format!("champ '{field}' : motif regex généré trop long ({} > 512, limite UDF) — non supporté", pattern.len()));
    }
    Ok(format!("{field}=~{pattern}"))
}

/// Sigma `tags` -> 1re technique MITRE (`attack.t1059.001` -> `T1059.001`), validée par `norm_mitre`.
/// Plusieurs techniques : la colonne `rule.mitre` en porte UNE (la 1re valide) ; les autres restent
/// visibles dans le YAML source. Aucun tag technique -> "" (règle sans couverture MITRE, licite).
pub(crate) fn sigma_first_technique(tags: Option<&Value>) -> String {
    let arr = match tags.and_then(|v| v.as_array()) { Some(a) => a, None => return String::new() };
    for t in arr {
        if let Some(s) = t.as_str() {
            let s = s.trim();
            let rest = s.strip_prefix("attack.").or_else(|| s.strip_prefix("attack-"));
            if let Some(r) = rest {
                let up = r.to_ascii_uppercase();
                if up.starts_with('T') {
                    if let Some(m) = norm_mitre(&up) { if !m.is_empty() { return m; } }
                }
            }
        }
    }
    String::new()
}

/// #38 — alias courants de cadre (namespace de tag Sigma) -> id CANONIQUE du vocab. Un id déjà canonique
/// (ou un cadre client ajouté par config) passe tel quel s'il est connu. None = pas un cadre connu.
fn sigma_compliance_alias(token: &str) -> Option<String> {
    let canon = match token {
        "pci" | "pci_dss" | "pcidss" | "pci-dss" => "pci_dss",
        "hipaa" => "hipaa",
        "nist" | "nist_800_53" | "nist800_53" | "nist80053" | "nist-800-53" => "nist_800_53",
        "gdpr" => "gdpr",
        "tsc" | "soc2" => "tsc",
        "iso" | "iso_27001" | "iso27001" | "iso-27001" => "iso_27001",
        "cis" | "cis_csc" | "ciscsc" => "cis",
        other => other, // laisse passer un id potentiellement ajouté par config (compliance_framework_known tranche)
    };
    if compliance_framework_known(canon) { Some(canon.to_string()) } else { None }
}
/// Un tag Sigma unique -> entrée de conformité `cadre[:contrôle]` normalisée, ou None si le tag n'est pas un
/// tag de cadre reconnu (attack./cve./tlp./… -> None). Le namespace de tête est mappé sur l'id canonique ; le
/// reste (après le 1er `.`) devient l'id de CONTRÔLE libre. Validé unitairement via `norm_compliance`.
fn sigma_tag_to_compliance(tag: &str) -> Option<String> {
    let tag = tag.trim().to_ascii_lowercase();
    if tag.is_empty() { return None; }
    let (head, rest) = match tag.split_once('.') {
        Some((h, r)) => (h, Some(r)),
        None => (tag.as_str(), None),
    };
    let canon = sigma_compliance_alias(head)?;
    match rest {
        None => norm_compliance(&canon),
        Some(r) if !r.trim().is_empty() => norm_compliance(&format!("{canon}:{r}")),
        Some(_) => norm_compliance(&canon),
    }
}
/// Sigma `tags` -> CSV de conformité `cadre[:contrôle]` (multi-cadres). Balaie tous les tags, garde ceux dont le
/// namespace est un cadre connu (alias inclus), ignore le reste (attack/cve/tlp). Dédup + cap via `norm_compliance`.
/// Aucun tag de cadre -> "" (règle sans mapping conformité, licite). PUR (aucune DB) -> testable.
pub(crate) fn sigma_compliance_tags(tags: Option<&Value>) -> String {
    let arr = match tags.and_then(|v| v.as_array()) { Some(a) => a, None => return String::new() };
    let mut entries: Vec<String> = Vec::new();
    for t in arr {
        if let Some(s) = t.as_str() {
            if let Some(entry) = sigma_tag_to_compliance(s) {
                if !entry.is_empty() && !entries.iter().any(|e| e == &entry) { entries.push(entry); }
            }
        }
    }
    norm_compliance(&entries.join(",")).unwrap_or_default()
}

/// Table de mapping logsource Sigma -> catégorie CIM NEUTRE (docs/CIM.md §2). Sigma est très
/// endpoint/Windows-centré ; on rabat proprement sur la taxonomie Plume. Toute valeur de droite DOIT
/// être une catégorie CIM valide (garde de test `sigma_logsource_map_targets_are_cim`).
pub(crate) const SIGMA_LOGSOURCE_CATEGORY: &[(&str, &str)] = &[
    ("firewall", "firewall"),
    ("proxy", "web"), ("webserver", "web"), ("web", "web"),
    ("apache", "web"), ("nginx", "web"), ("modsecurity", "web"),
    ("dns", "dns"), ("dns_query", "dns"),
    ("antivirus", "malware"), ("av", "malware"), ("clamav", "malware"),
    ("authentication", "auth"), ("auth", "auth"), ("sshd", "auth"), ("sudo", "auth"),
    ("vpn", "vpn"),
    ("dlp", "dlp"),
    ("email", "mail"), ("smtp", "mail"),
    ("network_connection", "network"), ("netflow", "network"), ("firewall_traffic", "firewall"),
    // endpoint / Sysmon (rabattu sur les buckets CIM les plus proches)
    ("process_creation", "endpoint"), ("process_access", "endpoint"), ("ps_script", "endpoint"),
    ("image_load", "endpoint"), ("driver_load", "endpoint"), ("create_remote_thread", "endpoint"),
    ("file_event", "endpoint"), ("file_change", "endpoint"), ("file_delete", "endpoint"),
    ("registry_event", "endpoint"), ("registry_set", "endpoint"), ("registry_add", "endpoint"),
    ("registry_delete", "endpoint"),
    ("kubernetes", "k8s"), ("falco", "ebpf"), ("container", "container"),
    ("syslog", "syslog"), ("system", "system"),
];

/// logsource Sigma (bloc `{category?,service?,product?}`) -> catégorie CIM (priorité category>service>product).
/// None = non mappé (l'appelant AVERTIT et applique la règle à toutes les sources — sur-match signalé,
/// jamais un drop). ENRICH, jamais SUPPRESS.
pub(crate) fn sigma_logsource_category(ls: &Value) -> Option<&'static str> {
    let obj = ls.as_object()?;
    for key in ["category", "service", "product"] {
        if let Some(v) = obj.get(key).and_then(|x| x.as_str()) {
            let vl = v.trim().to_ascii_lowercase();
            for (k, c) in SIGMA_LOGSOURCE_CATEGORY {
                if *k == vl { return Some(c); }
            }
        }
    }
    None
}

/// Alias de champs Sigma courants -> champ Plume (colonne coeur si possible, cf. Schema::events).
const SIGMA_FIELD_ALIAS: &[(&str, &str)] = &[
    ("sourceip", "src_ip"), ("src_ip", "src_ip"), ("srcip", "src_ip"), ("source_ip", "src_ip"),
    ("sourceaddress", "src_ip"), ("clientip", "src_ip"), ("client_ip", "src_ip"), ("saddr", "src_ip"),
    ("destinationip", "dst_ip"), ("dst_ip", "dst_ip"), ("dstip", "dst_ip"), ("destination_ip", "dst_ip"),
    ("destinationaddress", "dst_ip"), ("dest_ip", "dst_ip"), ("daddr", "dst_ip"),
    ("destinationport", "dport"), ("dst_port", "dport"), ("dstport", "dport"), ("destination_port", "dport"),
    ("url", "url"), ("uri", "url"), ("requesturl", "url"), ("cs-uri", "url"), ("cs-uri-stem", "url"), ("c-uri", "url"),
    ("user", "user"), ("username", "user"), ("targetusername", "user"), ("account", "user"), ("user_name", "user"),
    ("host", "host"), ("hostname", "host"), ("computername", "host"), ("dvchost", "host"),
];

/// Champ Sigma -> champ Plume. Alias connu -> colonne/champ dédié ; sinon le nom brut S'IL est un
/// identifiant GXQL simple (`[A-Za-z0-9_]`, -> `fields.<Nom>` via json_extract, CASSE PRÉSERVÉE).
/// Nom imbriqué/à points/tiret (ex `winlog.event_data.X`) -> None (json_extract 1 niveau) -> flag.
pub(crate) fn sigma_field_to_plume(field: &str) -> Option<String> {
    let f = field.trim();
    if f.is_empty() { return None; }
    let fl = f.to_ascii_lowercase();
    for (k, plume) in SIGMA_FIELD_ALIAS {
        if *k == fl { return Some((*plume).to_string()); }
    }
    if f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') { Some(f.to_string()) } else { None }
}

/// ANTI-ANGLE-MORT (importeur Sigma) — un champ de sélection est-il ÉTENDU-INERTE ? = une fois TRADUIT en
/// champ plume, PLUME NE COLLECTE RIEN qui le peuple. La règle importée compile alors, mais reste INERTE.
/// On le SIGNALE (warning), on ne rejette JAMAIS (la donnée peut arriver plus tard). Sysmon/endpoint
/// (CommandLine, Image…) tombe ici -> un import en masse endpoint reste VISIBLEMENT distinct des règles qui
/// vont réellement fire.
///
/// DEUX RÔLES, DEUX TABLES (défaut fermé) — la traduction et l'inertie sont des questions DIFFÉRENTES :
///   * `sigma_field_to_plume` (via `SIGMA_FIELD_ALIAS`) répond « ce nom Sigma s'écrit COMMENT chez plume » ;
///   * `collected::plume_collects_field` répond « plume PEUPLE-t-il réellement ce champ » (inventaire des
///     collecteurs/parseurs/agent LIVRÉS, cf. `collected.rs`).
/// La version précédente court-circuitait sur `SIGMA_FIELD_ALIAS` (`if …any(k == fl) { return false; }`) :
/// AJOUTER UN ALIAS ÉTEIGNAIT donc l'avertissement d'inertie, sans qu'une seule donnée nouvelle soit
/// collectée — du faux vert à l'échelle du corpus. Le court-circuit est SUPPRIMÉ : un alias dont la CIBLE
/// n'est pas collectée laisse la règle signalée INERTE.
/// `HOT_FIELDS` a également été retiré de cet oracle : c'est une whitelist de PERFORMANCE (index-expression),
/// pas un inventaire de collecte — un champ y figurant n'est pas pour autant peuplé (`operation`, prévu pour
/// vault-audit, n'est émis par AUCUN collecteur livré). Ceux de ses membres réellement émis sont inventoriés
/// dans `collected.rs`, avec le fichier livré qui les émet.
pub(crate) fn sigma_field_is_inert_extended(raw: &str) -> bool {
    if raw.trim().is_empty() { return false; }
    match sigma_field_to_plume(raw) {
        None => false, // non mappable -> déjà Err à la génération de token (pas un warning ici)
        Some(p) => !crate::collected::plume_collects_field(&p),
    }
}

/// Collecte (récursif, sélections objet / liste-singleton) les noms de champs ÉTENDUS-INERTES d'une sélection.
pub(crate) fn sigma_collect_inert_fields(sel: &Value, out: &mut Vec<String>) {
    match sel {
        Value::Object(map) => {
            for k in map.keys() {
                let raw = k.split('|').next().unwrap_or("").trim();
                if sigma_field_is_inert_extended(raw) { out.push(raw.to_string()); }
            }
        }
        Value::Array(items) if items.len() == 1 => sigma_collect_inert_fields(&items[0], out),
        _ => {}
    }
}

/// Traduit UNE entrée `field[|mods]: value` de sélection en token(s) GXQL (tous en ET). Les modificateurs
/// de comparaison string sont CASSE-INSENSIBLE par défaut (`(?i)`, conforme Sigma — et sûr : sur-match
/// plutôt que sous-match). Err(raison) pour tout construit non exprimable (jamais un token faux).
pub(crate) fn sigma_field_tokens(key: &str, val: &Value) -> Result<Vec<String>, String> {
    let mut it = key.split('|');
    let raw_field = it.next().unwrap_or("");
    let mods: Vec<String> = it.map(|m| m.trim().to_ascii_lowercase()).collect();
    if val.is_null() {
        return Err(format!("champ '{key}' : match sur null (existence de champ) non exprimable en GXQL"));
    }
    let field = sigma_field_to_plume(raw_field)
        .ok_or_else(|| format!("champ '{raw_field}' non mappable (nom imbriqué / non-identifiant)"))?;
    for m in &mods {
        if !matches!(m.as_str(), "contains" | "startswith" | "endswith" | "re" | "all" | "i"
            | "lt" | "lte" | "gt" | "gte") {
            return Err(format!("champ '{key}' : modificateur '|{m}' non supporté (base64/utf16/wide/cidr/windash… inexprimables)"));
        }
    }
    let has = |m: &str| mods.iter().any(|x| x == m);

    // Comparateurs numériques.
    if has("lt") || has("lte") || has("gt") || has("gte") {
        let s = sigma_scalar_str(val).ok_or_else(|| format!("champ '{key}' : valeur numérique attendue"))?;
        if !sigma_is_num(&s) { return Err(format!("champ '{key}' : valeur '{s}' non numérique pour comparateur")); }
        let op = if has("lt") { "<" } else if has("lte") { "<=" } else if has("gt") { ">" } else { ">=" };
        return Ok(vec![format!("{field}{op}{s}")]);
    }

    let values: Vec<Value> = match val { Value::Array(a) => a.clone(), other => vec![other.clone()] };

    // `|re` : regex brut (respecté tel quel ; `|re|i` -> casse-insensible).
    if has("re") {
        let mut toks = Vec::new();
        for v in &values {
            let re = sigma_scalar_str(v).ok_or_else(|| format!("champ '{key}' : valeur '|re' non-string"))?;
            if !sigma_regex_embeddable(&re) {
                return Err(format!("champ '{key}' : le regex '|re' contient un caractère structurel GXQL (|, parenthèse, classe [], espace, guillemet) — non embarquable"));
            }
            let prefix = if has("i") { "(?i)" } else { "" };
            let pat = format!("{prefix}{re}");
            // Valider la COMPILATION pour le moteur regex de Rust DÈS L'IMPORT : un motif structurellement
            // embarquable mais invalide pour Rust (ex. quantificateur en tête `*foo`) échouerait à CHAQUE
            // éval de l'UDF `regexp` -> run_query Err -> eval_value=0 -> règle MUETTE (angle mort SILENCIEUX).
            // On préfère FLAGGER (Err, flag+skip) qu'émettre une règle qui ne fire jamais.
            regex::Regex::new(&pat).map_err(|e| format!("champ '{key}' : regex '|re' invalide pour le moteur Rust ({e}) — non importée"))?;
            toks.push(sigma_regex_token(&field, &pat)?);
        }
        if toks.len() > 1 && !has("all") {
            return Err(format!("champ '{key}' : liste de regex en OU non exprimable en GXQL (utiliser |all pour un ET)"));
        }
        return Ok(toks);
    }

    // Fragment regex pour UNE valeur string selon le modificateur (casse-insensible). Les jokers Sigma
    // `*`/`?` restent ACTIFS même sous contains/startswith/endswith (parité pySigma : le modificateur
    // enveloppe une SigmaString dont les jokers restent vivants) -> `sigma_re_wildcard` (les valeurs SANS
    // joker produisent une sortie identique au littéral, `\*`/`\?` restent littéraux).
    let frag = |s: &str| -> String {
        if has("contains")   { format!("(?i){}", sigma_re_wildcard(s)) }
        else if has("startswith") { format!("(?i)^{}", sigma_re_wildcard(s)) }
        else if has("endswith")   { format!("(?i){}$", sigma_re_wildcard(s)) }
        else                 { format!("(?i)^{}$", sigma_re_wildcard(s)) } // égalité : jokers Sigma actifs
    };

    if values.len() == 1 {
        let s = sigma_scalar_str(&values[0]).ok_or_else(|| format!("champ '{key}' : valeur non scalaire"))?;
        // Égalité pure sur un entier -> comparaison numérique exacte (chemin numérique du compilo).
        let string_mod = has("contains") || has("startswith") || has("endswith");
        if !string_mod && sigma_is_num(&s) && !sigma_has_wildcard(&s) {
            return Ok(vec![format!("{field}={s}")]);
        }
        return Ok(vec![sigma_regex_token(&field, &frag(&s))?]);
    }

    // LISTE de valeurs.
    let strs: Vec<String> = values.iter().map(sigma_scalar_str).collect::<Option<Vec<_>>>()
        .ok_or_else(|| format!("champ '{key}' : liste avec valeur non scalaire"))?;
    if has("all") {
        // ET : un token par valeur.
        let mut toks = Vec::new();
        for s in &strs { toks.push(sigma_regex_token(&field, &frag(s))?); }
        return Ok(toks);
    }
    let string_mod = has("contains") || has("startswith") || has("endswith");
    if string_mod {
        return Err(format!("champ '{key}' : liste (OU) de sous-chaînes non exprimable en GXQL (pas d'alternance possible) — utiliser |all pour un ET"));
    }
    // OU d'égalités -> `field in (...)` SI toutes les valeurs sont sans joker et embarquables.
    if strs.iter().all(|s| !sigma_has_wildcard(s) && sigma_in_safe(s)) {
        let list = strs.join(",");
        // CASSE : le compilo cœur émet un `in(...)` textuel positif en COLLATE NOCASE (casse-INSENSIBLE,
        // conforme au défaut Sigma) -> pas de sous-match sur des membres à casse variable (ex. cmd.exe vs
        // CMD.EXE). Cohérent avec l'égalité scalaire `(?i)`. (Négation `not in` reste BINARY = sur-inclut.)
        return Ok(vec![format!("{field} in ({list})")]);
    }
    Err(format!("champ '{key}' : liste de valeurs en OU avec jokers/caractères spéciaux non exprimable en GXQL — non supporté"))
}

/// Une sélection Sigma -> tokens (ET). Map = ET de champs ; liste singleton = son unique élément ;
/// liste multi (OU de sous-sélections / keywords) -> Err (OU inexprimable). String = keyword freetext.
pub(crate) fn sigma_selection_tokens(sel: &Value) -> Result<Vec<String>, String> {
    match sel {
        Value::Object(map) => {
            if map.is_empty() { return Err("sélection vide".into()); }
            let mut toks = Vec::new();
            for (k, v) in map { toks.extend(sigma_field_tokens(k, v)?); }
            Ok(toks)
        }
        Value::Array(items) => {
            if items.len() == 1 { return sigma_selection_item(&items[0]); }
            Err("sélection en liste (OU de sous-sélections / keywords) non exprimable en GXQL — non supporté".into())
        }
        Value::String(_) => sigma_selection_item(sel),
        _ => Err("forme de sélection non supportée".into()),
    }
}

/// Un élément de sélection : map -> ET de champs ; keyword string -> contains sur `message` (le
/// message porte la ligne brute lisible — approximation d'un match plein-texte inter-champs).
pub(crate) fn sigma_selection_item(v: &Value) -> Result<Vec<String>, String> {
    match v {
        Value::Object(_) | Value::Array(_) => sigma_selection_tokens(v),
        Value::String(s) => Ok(vec![sigma_regex_token("message", &format!("(?i){}", sigma_re_literal(s)))?]),
        _ => Err("élément de sélection non supporté".into()),
    }
}

/// NON(sélection). N'est exprimable en GXQL que pour une sélection MONO-champ en ÉGALITÉ (ou liste
/// d'égalités) : `field!=v` / `field not in (...)`. Multi-champs (= NON(a ET b) = OU de négations),
/// modificateurs (pas de NOT REGEXP), jokers -> Err. La négation en casse-sensible est SÛRE sur l'axe CASSE
/// (elle INCLUT plutôt qu'exclut si la casse diffère). ⚠️ AXE NULL : en logique SQL à 3 valeurs,
/// `field!=v`/`not in` sur un champ ABSENT (json_extract -> NULL) EXCLUT la ligne, alors que Sigma l'inclurait
/// (absence = ne matche pas le filtre) -> sous-match possible ; SIGNALÉ par un warning côté `sigma_translate`
/// (la forme NULL-tolérante `(field IS NULL OR …)` = un OU hors du sous-ensemble conjonctif figé du cœur).
pub(crate) fn sigma_selection_negated_tokens(sel: &Value) -> Result<Vec<String>, String> {
    let map = sel.as_object().ok_or("négation d'une sélection non-map non supportée")?;
    if map.len() != 1 {
        return Err("négation d'une sélection multi-champs (NON(a ET b) = OU de négations) non exprimable — non supporté".into());
    }
    let (k, v) = map.iter().next().unwrap();
    if k.contains('|') {
        return Err(format!("négation avec modificateur ('{k}') non supportée (pas de NOT REGEXP en GXQL)"));
    }
    let field = sigma_field_to_plume(k).ok_or_else(|| format!("champ '{k}' non mappable (négation)"))?;
    match v {
        Value::Array(items) => {
            let strs: Vec<String> = items.iter().map(sigma_scalar_str).collect::<Option<Vec<_>>>()
                .ok_or("négation : liste avec valeur non scalaire")?;
            if strs.iter().any(|s| sigma_has_wildcard(s) || !sigma_in_safe(s)) {
                return Err("négation d'une liste avec joker/caractère spécial non supportée".into());
            }
            Ok(vec![format!("{field} not in ({})", strs.join(","))])
        }
        _ => {
            let s = sigma_scalar_str(v).ok_or("négation : valeur non scalaire")?;
            if sigma_has_wildcard(&s) { return Err("négation d'une valeur avec joker non supportée".into()); }
            if sigma_is_num(&s) { return Ok(vec![format!("{field}!={s}")]); }
            if !sigma_bareword_safe(&s) { return Err("négation d'une valeur avec espace/caractère spécial non supportée".into()); }
            Ok(vec![format!("{field}!={s}")])
        }
    }
}

/// Résout un quantificateur de condition (`them` -> toutes ; `prefix*` -> préfixe ; sinon nom exact).
pub(crate) fn sigma_resolve_quantifier(target: &str, sel_names: &[String]) -> Result<Vec<String>, String> {
    let t = target.trim();
    if t.eq_ignore_ascii_case("them") { return Ok(sel_names.to_vec()); }
    if let Some(prefix) = t.strip_suffix('*') {
        let m: Vec<String> = sel_names.iter().filter(|n| n.starts_with(prefix)).cloned().collect();
        if m.is_empty() { return Err(format!("condition : aucun sélecteur ne matche '{t}'")); }
        return Ok(m);
    }
    if sel_names.iter().any(|n| n == t) { Ok(vec![t.to_string()]) }
    else { Err(format!("condition : sélection inconnue '{t}'")) }
}

/// Parse la CONDITION Sigma en une conjonction de `(negated, nom_de_sélection)`. Supporte le
/// sous-ensemble CONJONCTIF : `a`, `a and b`, `a and not b`, `all of them`, `all of prefix*`,
/// parenthèses. REJETTE tout OU (`or`, `1 of …`, `any of …`) et les agrégations (`|`).
pub(crate) fn sigma_parse_condition(cond: &str, sel_names: &[String]) -> Result<Vec<(bool, String)>, String> {
    if cond.contains('|') {
        return Err("condition avec agrégation Sigma (`| count() …`) non supportée".into());
    }
    let spaced = cond.replace('(', " ( ").replace(')', " ) ");
    let toks: Vec<String> = spaced.split_whitespace().map(|s| s.to_string()).collect();
    let lower: Vec<String> = toks.iter().map(|t| t.to_ascii_lowercase()).collect();
    if lower.iter().any(|w| w == "or") {
        return Err("condition avec 'or' (OU) non exprimable en GXQL (recherche conjonctive uniquement)".into());
    }
    let mut out: Vec<(bool, String)> = Vec::new();
    let mut negate = false;
    let mut i = 0;
    while i < toks.len() {
        match lower[i].as_str() {
            "(" => {
                // NÉGATION d'un GROUPE (`not (...)`) : NON(a ET b) = (NON a OU NON b) = un OU inexprimable
                // en GXQL conjonctif (et NON(a OU b) est déjà rejeté par le garde `or`). On REJETTE (flag+
                // skip) au lieu de mistranslater silencieusement en `NON a ET b` (De Morgan erroné, sous-match).
                if negate {
                    return Err("condition : négation d'un GROUPE entre parenthèses (`not (...)`) = NON(a ET b) = (NON a OU NON b) — OU non exprimable en GXQL conjonctif — non supporté".into());
                }
                i += 1;
            }
            ")" | "and" => { i += 1; }
            "not" => { negate = !negate; i += 1; }
            "1" | "any" => {
                return Err("condition : '1 of'/'any of' (OU) non exprimable en GXQL — non supporté".into());
            }
            "all" => {
                if lower.get(i + 1).map(|s| s.as_str()) != Some("of") {
                    return Err("condition : 'all' doit être suivi de 'of'".into());
                }
                let target = toks.get(i + 2).ok_or("condition : 'all of' incomplet")?;
                let names = sigma_resolve_quantifier(target, sel_names)?;
                // `not all of <multi>` = NON(a ET b) = (NON a OU NON b) : OU inexprimable -> REJET (flag+skip)
                // plutôt qu'un `NON a ET NON b` = NON(a OU b) silencieusement plus étroit (sous-match). Le cas
                // fidèle `not all of <un seul sélecteur>` = NON(single) reste exprimable.
                if negate && names.len() > 1 {
                    return Err("condition : `not all of <multi>` = NON(a ET b) = (NON a OU NON b) — OU non exprimable en GXQL conjonctif — non supporté".into());
                }
                for name in names { out.push((negate, name)); }
                negate = false;
                i += 3;
            }
            "of" | "them" => {
                return Err(format!("condition : '{}' inattendu (quantificateur mal formé)", toks[i]));
            }
            _ => {
                for name in sigma_resolve_quantifier(&toks[i], sel_names)? { out.push((negate, name)); }
                negate = false;
                i += 1;
            }
        }
    }
    if out.is_empty() { return Err("condition vide / non résolue".into()); }
    Ok(out)
}

/// Résultat d'une traduction Sigma -> règle Plume (prêt pour la table `rule`).
#[derive(Debug)]
pub(crate) struct SigmaTranslation {
    pub(crate) name: String,
    /// `id` (UUID) du document Sigma s'il est présent — CLÉ D'IDEMPOTENCE stable (dédup robuste à la dérive
    /// de titre). None -> dédup par le titre (comportement historique).
    pub(crate) sigma_id: Option<String>,
    pub(crate) query: String,
    pub(crate) severity: i64,
    pub(crate) mitre: String,
    /// #38 : tags de conformité mappés depuis `tags` Sigma (`pci_dss:8.7,hipaa:164.312`), déjà
    /// normalisés/validés (cadre ∈ vocab). "" si le doc Sigma ne porte aucun tag de cadre reconnu.
    pub(crate) compliance: String,
    pub(crate) interval_s: i64,
    pub(crate) window_s: i64,
    pub(crate) op: String,
    pub(crate) threshold: f64,
    pub(crate) warnings: Vec<String>,
}

/// `id` (UUID) d'un document Sigma -> clé de dédup stable. Chaîne non vide (trimée) -> Some ; sinon None
/// (repli titre, comportement historique). SigmaHQ garantit un `id` UUID par règle ; les rulesets custom
/// peuvent l'omettre -> repli sûr.
pub(crate) fn sigma_doc_id(doc: &Value) -> Option<String> {
    doc.get("id").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Recherche la règle EXISTANTE correspondant à une traduction : par `sigma_id` (UUID stable) D'ABORD — capte
/// une DÉRIVE de titre (même règle, titre changé) — sinon par nom (comportement historique quand aucun id, ou
/// première population de la colonne `sigma_id` sur une règle jadis importée par titre). Renvoie `(rowid, managed)`.
pub(crate) fn sigma_find_existing(conn: &Connection, t: &SigmaTranslation) -> Option<(i64, i64)> {
    if let Some(id) = &t.sigma_id {
        if let Ok(r) = conn.query_row("SELECT id,managed FROM rule WHERE sigma_id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))) {
            return Some(r);
        }
    }
    conn.query_row("SELECT id,managed FROM rule WHERE name=?1", params![t.name], |r| Ok((r.get(0)?, r.get(1)?))).ok()
}

/// TRADUCTEUR — une règle Sigma (serde_json::Value) -> `SigmaTranslation`, ou Err(raison claire) si un
/// construit n'est pas exprimable fidèlement. Le GXQL produit est `search <cat?> <champs…> | stats
/// count` + op `> 0` : fire s'il existe ≥1 event matchant dans la fenêtre. RECOMPILÉ par `rule_sql`
/// (chemin injection-safe du cœur) avant retour — un GXQL qui ne compile pas est REJETÉ (jamais stocké).
pub(crate) fn sigma_translate(doc: &Value) -> Result<SigmaTranslation, String> {
    let obj = doc.as_object().ok_or("document Sigma non-objet")?;
    let name = obj.get("title").and_then(|v| v.as_str()).map(|s| s.trim())
        .filter(|s| !s.is_empty()).ok_or("règle Sigma sans 'title'")?.to_string();
    let detection = obj.get("detection").and_then(|v| v.as_object())
        .ok_or("règle Sigma sans bloc 'detection'")?;
    let condition = match detection.get("condition") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) if a.len() == 1 => a[0].as_str().ok_or("condition (liste) non-string")?.to_string(),
        Some(Value::Array(_)) => return Err("bloc 'condition' multiple (liste) non supporté".into()),
        _ => return Err("règle Sigma sans 'condition'".into()),
    };
    // Sélections = clés de `detection` HORS 'condition' et 'timeframe' (agrégation temporelle).
    let sel_names: Vec<String> = detection.keys()
        .filter(|k| k.as_str() != "condition" && k.as_str() != "timeframe").cloned().collect();
    if sel_names.is_empty() { return Err("détection sans sélection".into()); }
    let refs = sigma_parse_condition(&condition, &sel_names)?;

    let mut warnings = Vec::new();
    let mut cat_token: Option<String> = None;
    if let Some(ls) = obj.get("logsource") {
        match sigma_logsource_category(ls) {
            Some(c) => {
                cat_token = Some(format!("category={c}"));
                // ANTI-ANGLE-MORT #1 : `endpoint` (Sysmon/EDR) est un bucket CIM sur lequel Plume RABAT le
                // gros de la bibliothèque Sigma, mais qu'un SOC réseau/syslog N'ALIMENTE PAS par défaut. La
                // règle s'importe (MITRE + sévérité) mais ne peut FIRE que si une source peuple category=endpoint.
                if c == "endpoint" {
                    warnings.push("category=endpoint (télémétrie hôte/EDR) : règle importée mais INERTE tant qu'une source n'alimente pas category=endpoint (Plume collecte typiquement réseau/syslog).".to_string());
                }
            }
            None => warnings.push("logsource non mappé sur une catégorie CIM : règle appliquée à TOUTES les sources (peut sur-matcher). Ajouter un mapping dans SIGMA_LOGSOURCE_CATEGORY si besoin.".to_string()),
        }
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut inert_fields: Vec<String> = Vec::new();
    let mut has_negation = false;
    for (neg, sname) in &refs {
        let sel = detection.get(sname).ok_or_else(|| format!("sélection '{sname}' absente"))?;
        sigma_collect_inert_fields(sel, &mut inert_fields);   // ANTI-ANGLE-MORT #1 (champs étendus inertes)
        let t = if *neg { has_negation = true; sigma_selection_negated_tokens(sel)? } else { sigma_selection_tokens(sel)? };
        tokens.extend(t);
    }
    if tokens.is_empty() {
        return Err("aucune condition de champ traduisible (la règle matcherait tous les événements)".into());
    }
    // ANTI-ANGLE-MORT #1 : les champs qui se résolvent en `fields.<X>` (json_extract) hors cœur/alias/HOT
    // sont INERTES tant qu'aucun parseur ne les peuple -> la règle compile mais ne peut pas fire.
    inert_fields.sort();
    inert_fields.dedup();
    if !inert_fields.is_empty() {
        warnings.push(format!("champ(s) étendu(s) [{}] lu(s) via fields.<X> (json_extract) : règle INERTE tant qu'un parseur/collecteur ne peuple pas ce(s) champ(s).", inert_fields.join(", ")));
    }
    // ANTI-ANGLE-MORT #7 : en logique NULL SQL, un `field!=v` / `field not in (...)` EXCLUT une ligne dont
    // le champ nié est ABSENT (NULL), alors que Sigma traite l'absence comme « ne matche pas le filtre »
    // (INCLURAIT). Sous-match possible si le champ n'est pas systématiquement peuplé. On le SIGNALE (la forme
    // NULL-tolérante `(field IS NULL OR …)` = un OU inexprimable dans le sous-ensemble GXQL conjonctif figé).
    if has_negation {
        warnings.push("négation (`not <filter>`) : un événement dont le champ nié est ABSENT est EXCLU (logique NULL SQL) là où Sigma l'inclurait — sous-match possible si le champ n'est pas toujours peuplé.".to_string());
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = &cat_token { parts.push(c.clone()); }
    parts.extend(tokens);
    let query = format!("search {} | stats count", parts.join(" "));
    let window_s = 3600i64;
    // Garde-fou ULTIME : la traduction DOIT compiler via le compilo GXQL du cœur (soql_to_sql_x).
    if let Err(e) = rule_sql(&query, true, window_s) {
        return Err(format!("échec de compilation GXQL (traduction non fiable, NON importée) : {e} — GXQL=«{query}»"));
    }
    let severity = sigma_level_to_sev(obj.get("level").and_then(|v| v.as_str()).unwrap_or(""));
    let mitre = sigma_first_technique(obj.get("tags"));
    let compliance = sigma_compliance_tags(obj.get("tags"));
    let sigma_id = sigma_doc_id(doc);
    Ok(SigmaTranslation { name, sigma_id, query, severity, mitre, compliance, interval_s: 300, window_s, op: ">".into(), threshold: 0.0, warnings })
}

/// yaml-rust `Yaml` -> serde_json::Value (front-end de l'importeur ; le cœur opère sur Value).
pub(crate) fn sigma_yaml_to_value(y: &yaml_rust::Yaml) -> Value {
    use yaml_rust::Yaml;
    match y {
        Yaml::Real(s) => s.parse::<f64>().ok().and_then(serde_json::Number::from_f64)
            .map(Value::Number).unwrap_or_else(|| Value::String(s.clone())),
        Yaml::Integer(i) => Value::Number((*i).into()),
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Array(a) => Value::Array(a.iter().map(sigma_yaml_to_value).collect()),
        Yaml::Hash(h) => {
            let mut m = serde_json::Map::new();
            for (k, v) in h {
                let key = match k {
                    Yaml::String(s) => s.clone(),
                    Yaml::Integer(i) => i.to_string(),
                    Yaml::Boolean(b) => b.to_string(),
                    Yaml::Real(s) => s.clone(),
                    _ => continue,
                };
                m.insert(key, sigma_yaml_to_value(v));
            }
            Value::Object(m)
        }
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Value::Null,
    }
}

/// Parse un texte Sigma (YAML multi-documents OU JSON) -> liste de documents `Value`. Les documents
/// null (séparateurs `---` vides) sont ignorés. Tolère JSON pur (front d'API/tests).
pub(crate) fn sigma_yaml_to_docs(text: &str) -> Result<Vec<Value>, String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("JSON invalide : {e}"))?;
        return Ok(match v { Value::Array(a) => a, other => vec![other] });
    }
    let docs = yaml_rust::YamlLoader::load_from_str(text).map_err(|e| format!("YAML invalide : {e}"))?;
    Ok(docs.iter().map(sigma_yaml_to_value).filter(|v| !v.is_null()).collect())
}

/// Disposition d'une règle Sigma importée face à une règle EXISTANTE de même nom (`managed`).
/// ADDITIF : les détections NATIVES (managed=0 builtin/seed) ET les overlays git (managed=1)
/// sont PROTÉGÉS (skip) — les seeds ne sont pas re-posés au reboot, donc un écrasement serait une perte
/// PERMANENTE d'une détection native. Seul `managed=2` (ad-hoc/déjà importé) est mis à jour (ré-import de
/// SA propre règle). Absente -> insert. -> l'import reste réellement ADDITIF sur collision de nom.
#[derive(Debug, PartialEq)]
pub(crate) enum SigmaDisp { Insert, Update, SkipManaged(i64) }
pub(crate) fn sigma_import_disposition(existing: Option<i64>) -> SigmaDisp {
    match existing {
        Some(1) => SigmaDisp::SkipManaged(1),
        Some(0) => SigmaDisp::SkipManaged(0),
        Some(_) => SigmaDisp::Update,
        None => SigmaDisp::Insert,
    }
}

/// SLICE #7 pièce 3 — ADMIN API : importe des règles Sigma. Corps : `{content:"<yaml|json>"}` (texte
/// Sigma, multi-docs OK) OU `{rules:[<sigma json>…]}`, + `{dry_run:bool}`. Gate RBAC : route sous
/// `/api/sigma/*` -> DEFAULT-DENY = ADMIN (route_min_role) : l'import en masse de détections externes est
/// une opération privilégiée. Les règles importées sont des overlays ad-hoc (`managed=2`), UPSERT par
/// nom, JAMAIS écrasant un overlay git (`managed=1`) NI une détection native (`managed=0`).
/// Traduction injection-safe (cf. sigma_translate) ; transaction fail-closed + audit #1b. dry_run -> RAS.
pub(crate) async fn sigma_import(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let dry = b.bool_field("dry_run", false);
    let docs: Vec<Value> = if let Some(txt) = b.get("content").and_then(|v| v.as_str()) {
        match sigma_yaml_to_docs(txt) {
            Ok(d) => d,
            Err(e) => return bad_req(format!("parse Sigma : {e}")),
        }
    } else if let Some(arr) = b.get("rules").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        return bad_req("corps attendu : {\"content\":\"<yaml|json>\"} ou {\"rules\":[…]}");
    };
    if docs.is_empty() {
        return bad_req("aucun document Sigma dans l'entrée");
    }
    // Traduction (pure) : sépare succès / rejets AVEC raison.
    let mut translations: Vec<SigmaTranslation> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for d in &docs {
        let title = d.get("title").and_then(|v| v.as_str()).unwrap_or("(sans titre)").to_string();
        match sigma_translate(d) {
            Ok(t) => translations.push(t),
            Err(e) => skipped.push(json!({ "title": title, "reason": e })),
        }
    }
    if dry {
        let would: Vec<Value> = translations.iter().map(|t| json!({
            "name": t.name, "query": t.query, "severity": t.severity, "mitre": t.mitre, "compliance": t.compliance,
            "op": t.op, "threshold": t.threshold, "window_s": t.window_s, "warnings": t.warnings
        })).collect();
        return Json(json!({ "dry_run": true, "would_import": would, "skipped": skipped })).into_response();
    }
    crate::req_conn!(st, au, conn);
    // Classification lecture seule (le verrou tenu empêche toute écriture concurrente) :
    // existe & managed=1 -> SKIP (ne pas écraser un overlay git) ; sinon INSERT/UPDATE en managed=2.
    let mut plan: Vec<(&SigmaTranslation, Option<i64>)> = Vec::new(); // (traduction, rowid existant à MAJ | None=insert)
    for t in &translations {
        // Dédup par sigma_id (UUID stable) d'abord (dérive de titre), sinon par nom (comportement historique).
        let existing = sigma_find_existing(&conn, t); // Option<(rowid, managed)>
        match sigma_import_disposition(existing.map(|(_, m)| m)) {
            SigmaDisp::SkipManaged(1) => skipped.push(json!({ "title": t.name, "reason": "existe déjà comme overlay géré (managed=1) — non écrasé (retirez-le côté git pour le remplacer)" })),
            // ADDITIF : une détection NATIVE (builtin/seed, managed=0) n'est JAMAIS écrasée par
            // un import Sigma sur collision de nom (les seeds ne sont pas re-posés au reboot -> perte permanente).
            SigmaDisp::SkipManaged(_) => skipped.push(json!({ "title": t.name, "reason": "existe déjà comme détection native (builtin/seed, managed=0) — NON écrasée par un import Sigma (protection des détections natives)" })),
            SigmaDisp::Update => plan.push((t, Some(existing.expect("Update -> existing présent").0))), // managed=2 (ad-hoc/importé) -> ré-import = MAJ de SA propre règle (rowid ciblé)
            SigmaDisp::Insert => plan.push((t, None)),
        }
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        for (t, target) in &plan {
            match target {
                // UPDATE ciblé par ROWID (résolu par sigma_id/nom) : rafraîchit la logique + `name` (titre
                // possiblement DÉRIVÉ) + `sigma_id` (back-fill). L'import unitaire (ré)active la règle (enabled=1).
                Some(rowid) => {
                    conn.execute(
                        "UPDATE rule SET name=?1, enabled=1, query=?2, is_soql=1, op=?3, threshold=?4, severity=?5, interval_s=?6, window_s=?7, mitre=?8, compliance=?9, sigma_id=?10, managed=2 WHERE id=?11",
                        params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.compliance, t.sigma_id, rowid],
                    )?;
                }
                None => {
                    conn.execute(
                        "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,compliance,sigma_id,managed) VALUES(?1,1,?2,1,?3,?4,?5,?6,?7,?8,?9,?10,2)",
                        params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.compliance, t.sigma_id],
                    )?;
                }
            }
        }
        // ANTI-ANGLE-MORT : les warnings PAR-RÈGLE (endpoint/champ étendu inerte, négation
        // NULL, logsource non mappé) sont enregistrés DURABLEMENT dans le ledger d'audit (pas seulement dans
        // la réponse HTTP éphémère) -> un import en masse de règles inertes reste traçable a posteriori.
        let warned: Vec<Value> = plan.iter()
            .filter(|(t, _)| !t.warnings.is_empty())
            .map(|(t, _)| json!({ "name": t.name, "warnings": t.warnings }))
            .collect();
        audit_config_change(
            &conn, "config.sigma.import",
            &format!("import Sigma par {} : {} règle(s) importée(s), {} ignorée(s), {} avec avertissement(s)", au.name, plan.len(), skipped.len(), warned.len()),
            2,
            &format!("import de règles de détection Sigma par {}", au.name),
            &json!({ "op": "sigma-import", "imported": plan.len(), "skipped": skipped.len(), "actor": au.name, "warnings": warned }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            let imported: Vec<Value> = plan.iter().map(|(t, _)| json!({
                "name": t.name, "query": t.query, "severity": t.severity, "mitre": t.mitre, "compliance": t.compliance, "warnings": t.warnings
            })).collect();
            Json(json!({ "imported": imported, "skipped": skipped, "managed": 2 })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification) : {e}"))
        }
    }
}

// =====================================================================================
//  SLICE #7 — IMPORT EN MASSE (BULK) : absorbe une BIBLIOTHÈQUE Sigma complète d'un coup.
// =====================================================================================
//  MULTIPLICATEUR de couverture : une communauté / un client fournit un ruleset Sigma (SigmaHQ, custom…),
//  Plume en fait des règles de détection managées et RESTITUE le DELTA DE COUVERTURE ATT&CK (blind-spots qui
//  se ferment). ADDITIF / mode 0 byte-identique (nouvel endpoint admin) / VENDOR-AGNOSTIC : AUCUN ruleset
//  n'est embarqué dans le daemon — l'admin/la communauté fournit le bundle.
//
//  DISCIPLINE « created-disabled » (miroir des connecteurs) : chaque règle est créée DÉSACTIVÉE par défaut.
//  L'import en masse de détections externes peut être bruyant/inerte/mal ciblé ; l'admin REVOIT puis ACTIVE.
//  Un flag `enable:true` permet l'activation immédiate (opt-in explicite). Le DELTA de couverture reflète la
//  couverture POTENTIELLE une fois les règles activées (cf. sigma_bulk_coverage_delta) — honnête et actionnable.
//
//  BORNÉ (budget mémoire 2 Go) : taille (octets) vérifiée AVANT parse + nombre de docs plafonné -> jamais
//  d'OOM. Overridable par PLUME_SIGMA_BULK_MAX / PLUME_SIGMA_BULK_MAX_BYTES.

/// Cap DOC-COUNT d'un import en masse (défaut 5000 — au-dessus d'un ruleset communautaire complet ~3k règles).
pub(crate) fn sigma_bulk_max_docs() -> usize {
    std::env::var("PLUME_SIGMA_BULK_MAX").ok().and_then(|v| v.parse().ok()).filter(|&n: &usize| n > 0).unwrap_or(5000)
}
/// Cap TAILLE (octets) du texte de bundle, vérifié AVANT parse (OOM-safe). Défaut 16 MiB.
pub(crate) fn sigma_bulk_max_bytes() -> usize {
    std::env::var("PLUME_SIGMA_BULK_MAX_BYTES").ok().and_then(|v| v.parse().ok()).filter(|&n: &usize| n > 0).unwrap_or(16 * 1024 * 1024)
}

/// Résout le BUNDLE d'entrée d'un import en masse -> liste de documents `Value`. Accepte (must-haves) :
///   - `{rules:[…]}`       : tableau JSON de docs Sigma déjà décodés.
///   - `{content:"…"}`     : texte Sigma — YAML MULTI-DOCUMENTS (`---`) OU tableau JSON (via sigma_yaml_to_docs).
///   - `{content_b64:"…"}` : base64 du MÊME texte (bundle transféré encodé — zéro dépendance archive/zip).
/// La TAILLE est bornée AVANT parse (`max_bytes`) : un bundle sur-cap est REJETÉ sans jamais être matérialisé
/// en structures parsées (jamais d'OOM). Réutilise `sigma_yaml_to_docs` (front-end existant, injection-safe).
pub(crate) fn sigma_bulk_docs_from_body(b: &Value) -> Result<Vec<Value>, String> {
    sigma_bulk_docs_from_body_capped(b, sigma_bulk_max_bytes())
}
/// Variante avec cap explicite (testable sans muter l'environnement du process).
pub(crate) fn sigma_bulk_docs_from_body_capped(b: &Value, max_bytes: usize) -> Result<Vec<Value>, String> {
    if let Some(arr) = b.get("rules").and_then(|v| v.as_array()) {
        return Ok(arr.clone());
    }
    let text: String = if let Some(txt) = b.get("content").and_then(|v| v.as_str()) {
        if txt.len() > max_bytes {
            return Err(format!("bundle trop volumineux ({} > {} octets ; ajuster PLUME_SIGMA_BULK_MAX_BYTES ou scinder l'import)", txt.len(), max_bytes));
        }
        txt.to_string()
    } else if let Some(b64) = b.get("content_b64").and_then(|v| v.as_str()) {
        // Borne la taille ENCODÉE avant même de décoder (base64 ~4/3 du clair -> cap*2 couvre largement).
        if b64.len() > max_bytes.saturating_mul(2) {
            return Err(format!("bundle base64 trop volumineux ({} octets encodés > {}) — scinder l'import", b64.len(), max_bytes.saturating_mul(2)));
        }
        let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim())
            .map_err(|e| format!("content_b64 : base64 invalide ({e})"))?;
        if raw.len() > max_bytes {
            return Err(format!("bundle décodé trop volumineux ({} > {} octets)", raw.len(), max_bytes));
        }
        String::from_utf8(raw).map_err(|e| format!("content_b64 : contenu décodé non-UTF8 ({e})"))?
    } else {
        return Err("corps attendu : {\"content\":\"<yaml|json>\"} | {\"content_b64\":\"<base64>\"} | {\"rules\":[…]}".into());
    };
    sigma_yaml_to_docs(&text)
}

/// Un doc écarté d'un import en masse, AVEC référence (`id` Sigma sinon `title`) et raison. `is_error` =
/// échec de TRADUCTION (construit non exprimable) vs faux = SKIP de protection (règle native/overlay non écrasée).
#[derive(Debug)]
pub(crate) struct SigmaBulkSkip {
    pub(crate) reference: String,
    pub(crate) reason: String,
    pub(crate) is_error: bool,
}

/// Traduit un LOT de docs Sigma -> (traductions réussies, skips {ref, reason, error}). PUR (aucune DB) donc
/// directement testable. Réutilise `sigma_translate` (injection-safe, unsupported->Err). IDEMPOTENT intra-bundle :
/// deux docs de MÊME titre -> UNE traduction (le DERNIER gagne — un ruleset qui redéfinit une règle prend effet,
/// pas de doublon). Un doc non traduisible = skip AVEC raison (jamais une règle silencieusement fausse), `is_error`.
pub(crate) fn sigma_bulk_translate(docs: &[Value]) -> (Vec<SigmaTranslation>, Vec<SigmaBulkSkip>) {
    let mut translations: Vec<SigmaTranslation> = Vec::new();
    let mut idx: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut skipped: Vec<SigmaBulkSkip> = Vec::new();
    for d in docs {
        let reference = d.get("id").and_then(|v| v.as_str())
            .or_else(|| d.get("title").and_then(|v| v.as_str()))
            .unwrap_or("(sans référence)").to_string();
        match sigma_translate(d) {
            Ok(t) => {
                // Clé de dédup intra-bundle : `sigma_id` (UUID stable) si présent — deux docs de MÊME id à
                // titres DIFFÉRENTS convergent en UNE traduction — sinon le titre (comportement historique).
                let key = match &t.sigma_id { Some(id) => format!("id:{id}"), None => format!("name:{}", t.name) };
                match idx.get(&key) {
                    Some(&i) => translations[i] = t, // re-définition intra-bundle : le dernier gagne (idempotent)
                    None => { idx.insert(key, translations.len()); translations.push(t); }
                }
            }
            Err(e) => skipped.push(SigmaBulkSkip { reference, reason: e, is_error: true }),
        }
    }
    (translations, skipped)
}

/// Techniques ATT&CK PARENTES couvertes par un jeu de tags MITRE — une technique est « couverte » dès qu'≥1
/// tag la cible (MÊME sémantique que build_attack_matrix : rule_count>0). Réutilise `mitre_parents` (le cœur de
/// l'agrégation /api/coverage/attack) : sous-techniques repliées sur la parente, tags hors-format ignorés.
pub(crate) fn sigma_covered_parents(tags: &[String]) -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    for t in tags { for p in mitre_parents(t) { s.insert(p); } }
    s
}

/// DELTA de couverture ATT&CK d'un import : `(couvertes_avant, couvertes_après, nouvellement_couvrables triées)`.
/// « avant » = techniques couvertes par les règles DÉJÀ ACTIVÉES (même requête que coverage_attack) ; « après »
/// = si l'on ACTIVAIT les règles importées. Comme l'import crée DÉSACTIVÉ, c'est la couverture POTENTIELLE
/// débloquée après revue+activation — l'admin voit exactement quels blind-spots se ferment. PUR / testable.
pub(crate) fn sigma_bulk_coverage_delta(before_tags: &[String], imported_mitre: &[String]) -> (i64, i64, Vec<String>) {
    let before = sigma_covered_parents(before_tags);
    let mut after_tags = before_tags.to_vec();
    after_tags.extend(imported_mitre.iter().cloned());
    let after = sigma_covered_parents(&after_tags);
    let newly: Vec<String> = after.difference(&before).cloned().collect();
    (before.len() as i64, after.len() as i64, newly)
}

/// Classe des traductions face à la BASE -> (plan `(traduction, update?)`, skips de PROTECTION). Réutilise
/// `sigma_import_disposition` : une détection NATIVE (managed=0) ou un OVERLAY git (managed=1) n'est JAMAIS
/// écrasé ; seul un ad-hoc (managed=2) est mis à jour (ré-import de SA propre règle). Absente -> insert.
pub(crate) fn sigma_bulk_classify<'a>(conn: &Connection, translations: &'a [SigmaTranslation]) -> (Vec<(&'a SigmaTranslation, Option<i64>)>, Vec<SigmaBulkSkip>) {
    let mut plan: Vec<(&SigmaTranslation, Option<i64>)> = Vec::new();
    let mut skipped: Vec<SigmaBulkSkip> = Vec::new();
    for t in translations {
        // Résolution par sigma_id (UUID stable) d'abord (dérive de titre), sinon par nom (historique).
        let existing = sigma_find_existing(conn, t); // Option<(rowid, managed)>
        match sigma_import_disposition(existing.map(|(_, m)| m)) {
            SigmaDisp::SkipManaged(1) => skipped.push(SigmaBulkSkip { reference: t.name.clone(), reason: "existe déjà comme overlay géré (managed=1) — non écrasé (retirez-le côté git pour le remplacer)".into(), is_error: false }),
            SigmaDisp::SkipManaged(_) => skipped.push(SigmaBulkSkip { reference: t.name.clone(), reason: "existe déjà comme détection native (builtin/seed, managed=0) — NON écrasée (protection des détections natives)".into(), is_error: false }),
            SigmaDisp::Update => plan.push((t, Some(existing.expect("Update -> existing présent").0))), // rowid ciblé (match sigma_id/nom)
            SigmaDisp::Insert => plan.push((t, None)),
        }
    }
    (plan, skipped)
}

/// Applique un PLAN d'import en masse. INSERT : crée la règle avec `enabled_flag` (0 = DÉSACTIVÉE par défaut,
/// discipline created-disabled). UPDATE (ré-import d'un managed=2) : rafraîchit la logique SANS toucher `enabled`
/// — préserve la décision de l'admin (ne ré-active pas une règle laissée off, ne désactive pas une règle activée).
pub(crate) fn sigma_bulk_apply(conn: &Connection, plan: &[(&SigmaTranslation, Option<i64>)], enable: bool) -> rusqlite::Result<()> {
    let enabled_flag: i64 = if enable { 1 } else { 0 };
    for (t, target) in plan {
        match target {
            // UPDATE ciblé par ROWID (résolu par sigma_id/nom) : rafraîchit la logique + `name` (le titre a pu
            // DÉRIVER) + `sigma_id` (back-fill d'une règle jadis importée par titre) SANS toucher `enabled`.
            Some(rowid) => {
                conn.execute(
                    "UPDATE rule SET name=?1, query=?2, is_soql=1, op=?3, threshold=?4, severity=?5, interval_s=?6, window_s=?7, mitre=?8, compliance=?9, sigma_id=?10, managed=2 WHERE id=?11",
                    params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.compliance, t.sigma_id, rowid],
                )?;
            }
            None => {
                conn.execute(
                    "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,compliance,sigma_id,managed) VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,?9,?10,?11,2)",
                    params![t.name, enabled_flag, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.compliance, t.sigma_id],
                )?;
            }
        }
    }
    Ok(())
}

/// SLICE #7 — ADMIN API : `POST /api/sigma/import-bulk`. Importe une BIBLIOTHÈQUE Sigma (bundle multi-docs) et
/// restitue le DELTA de couverture ATT&CK. Gate RBAC : mutation sous `/api/sigma/*` -> DEFAULT-DENY = ADMIN.
/// Règles créées DÉSACTIVÉES (sauf `enable:true`), UPSERT idempotent par titre (managed=2), JAMAIS écrasant un
/// overlay git (managed=1) ni une détection native (managed=0). Transaction fail-closed + audit. `dry_run` -> RAS.
/// Réponse : `{imported, updated, skipped:[{ref,reason}], errors, coverage_before, coverage_after,
/// techniques_newly_covered, disabled_on_import}`.
pub(crate) async fn sigma_import_bulk(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let dry = b.bool_field("dry_run", false);
    let enable = b.bool_field("enable", false); // DÉFAUT : créées DÉSACTIVÉES (l'admin revoit puis active).
    let docs = match sigma_bulk_docs_from_body(&b) {
        Ok(d) => d,
        Err(e) => return bad_req(e),
    };
    // MODE 0 / no-op : bundle vide -> AUCUNE règle créée, réponse neutre (idempotent).
    if docs.is_empty() {
        return Json(json!({
            "imported": 0, "updated": 0, "skipped": [], "errors": 0,
            "coverage_before": 0, "coverage_after": 0, "techniques_newly_covered": [],
            "disabled_on_import": !enable, "note": "bundle vide : no-op (aucune règle créée)"
        })).into_response();
    }
    let max_docs = sigma_bulk_max_docs();
    if docs.len() > max_docs {
        return bad_req(format!("bundle : {} documents dépasse le cap {} (PLUME_SIGMA_BULK_MAX) — scinder l'import", docs.len(), max_docs));
    }
    // Traduction (pure) : succès + rejets AVEC raison (skip-with-reason, jamais une règle silencieusement fausse).
    let (translations, mut skipped) = sigma_bulk_translate(&docs);

    crate::req_conn!(st, au, conn);
    // Couverture AVANT = tags MITRE des règles ACTIVÉES (MÊME requête que coverage_attack).
    let before_tags: Vec<String> = {
        let mut v = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT mitre FROM rule WHERE enabled=1 AND mitre IS NOT NULL AND mitre<>''") {
            if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) { v = rows.flatten().collect(); }
        }
        v
    };
    // Classification managed (protège natif/overlay) : ajoute ses skips à ceux de traduction.
    let (plan, managed_skips) = sigma_bulk_classify(&conn, &translations);
    skipped.extend(managed_skips);
    let errors = skipped.iter().filter(|s| s.is_error).count() as i64;
    let n_insert = plan.iter().filter(|(_, target)| target.is_none()).count() as i64;
    let n_update = plan.iter().filter(|(_, target)| target.is_some()).count() as i64;
    // DELTA de couverture : couverture potentielle une fois les règles importées ACTIVÉES.
    let imported_mitre: Vec<String> = plan.iter().map(|(t, _)| t.mitre.clone()).collect();
    let (cov_before, cov_after, newly) = sigma_bulk_coverage_delta(&before_tags, &imported_mitre);
    let skipped_json: Vec<Value> = skipped.iter().map(|s| json!({ "ref": s.reference, "reason": s.reason })).collect();

    if dry {
        return Json(json!({
            "dry_run": true, "imported": n_insert, "updated": n_update,
            "skipped": skipped_json, "errors": errors,
            "coverage_before": cov_before, "coverage_after": cov_after, "techniques_newly_covered": newly,
            "disabled_on_import": !enable,
            "note": "dry_run : rien écrit. 'coverage_after' = couverture POTENTIELLE une fois les règles activées (créées désactivées)."
        })).into_response();
    }

    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        sigma_bulk_apply(&conn, &plan, enable)?;
        // ANTI-ANGLE-MORT : les warnings par-règle (endpoint inerte / champ étendu / négation NULL) + le delta
        // de couverture sont journalisés DURABLEMENT dans le ledger (traçabilité d'un import en masse).
        let warned: Vec<Value> = plan.iter().filter(|(t, _)| !t.warnings.is_empty())
            .map(|(t, _)| json!({ "name": t.name, "warnings": t.warnings })).collect();
        audit_config_change(
            &conn, "config.sigma.import-bulk",
            &format!("import Sigma EN MASSE par {} : {} insérée(s), {} mise(s) à jour, {} ignorée(s) ({} erreur(s)), créées {} ; couverture ATT&CK {}→{} techniques (+{})",
                au.name, n_insert, n_update, skipped.len(), errors, if enable { "ACTIVÉES" } else { "désactivées" }, cov_before, cov_after, newly.len()),
            2,
            &format!("import en masse de règles de détection Sigma par {}", au.name),
            &json!({ "op": "sigma-import-bulk", "imported": n_insert, "updated": n_update, "skipped": skipped.len(),
                "errors": errors, "enabled_on_import": enable, "coverage_before": cov_before, "coverage_after": cov_after,
                "techniques_newly_covered": newly, "actor": au.name, "warnings": warned }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({
                "imported": n_insert, "updated": n_update, "skipped": skipped_json, "errors": errors,
                "coverage_before": cov_before, "coverage_after": cov_after, "techniques_newly_covered": newly,
                "disabled_on_import": !enable, "managed": 2,
                "note": "règles créées DÉSACTIVÉES (l'admin revoit puis active) ; 'coverage_after' = couverture une fois activées."
            })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction (aucune modification) : {e}"))
        }
    }
}
