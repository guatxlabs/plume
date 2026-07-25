//! Overlays versionnés (config.d) : charge parsers/dparsers/règles/playbooks/sigma déclarés en JSON.
//! Sur &Connection. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// =====================================================================================
// PERSONNALISATION PHASE 1 — OVERLAYS VERSIONNÉS (config.d). Charge les parsers/règles/playbooks
// déclarés en fichiers JSON sous ${PLUME_CONFIG_DIR}/{parsers,rules,playbooks}/*.json
// (DÉFAUT /usr/local/share/plume/config.d — répertoire BAKED dans l'image, comme web/, car le pod
// tourne en readOnlyRootFilesystem : PAS de chemin hôte writable type /etc/plume). Appelé au boot
// APRÈS migrate() + TOUS les seed_* -> un overlay GAGNE sur un builtin/seed du même `name` (override
// opérateur durable, survit au re-seed). Chaque entrée est posée avec managed=1 (source = git ;
// managed=2 = CRUD UI ; managed=0 = builtin/seed). IDEMPOTENT : UPSERT keyé par `name` -> re-jouer
// donne le MÊME état. Fichier invalide (JSON cassé, regex/SOQL qui ne compile pas) -> WARNING + skip,
// JAMAIS de crash du boot.
// =====================================================================================

/// Liste triée des `*.json` d'un sous-dossier d'overlays (ordre déterministe). Dossier absent -> vide.
pub(crate) fn overlay_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("json") {
                v.push(p);
            }
        }
    }
    v.sort();
    v
}

/// Lit + parse un fichier overlay en JSON. Erreur de lecture/parse -> WARNING + None (skip gracieux).
/// Les clés inconnues (ex `_comment` de documentation) sont simplement ignorées en aval.
pub(crate) fn overlay_read_json(path: &std::path::Path) -> Option<Value> {
    let txt = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => { eprintln!("[overlays] WARN lecture {} échouée: {e} — ignoré", path.display()); return None; }
    };
    match serde_json::from_str::<Value>(&txt) {
        Ok(v) => Some(v),
        Err(e) => { eprintln!("[overlays] WARN JSON invalide {}: {e} — ignoré", path.display()); None }
    }
}

/// Parsers d'overlay : MÊME validation que parser_create (motif non vide, ≤1000, regex qui compile),
/// puis UPSERT keyé par name avec managed=1 (un overlay écrase un builtin du même nom : builtin=0).
pub(crate) fn load_overlay_parsers(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() {
            eprintln!("[overlays] WARN parser {} sans 'name' — ignoré", path.display());
            continue;
        }
        // DISCRIMINANT : un fichier AVEC un objet `map` est un PARSEUR DÉCLARATIF (DSL CIM, pièce 2) traité
        // par load_overlay_dparsers, PAS ici (il n'a pas de `pattern` legacy). On le saute SILENCIEUSEMENT
        // (sans le WARN « motif vide ») — chaque fichier va à exactement un loader.
        if v.get("map").map(|m| m.is_object()).unwrap_or(false) { continue; }
        let pattern = v.get("pattern").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if pattern.is_empty() || pattern.len() > 1000 || regex::Regex::new(&pattern).is_err() {
            eprintln!("[overlays] WARN parser '{name}' ({}) : motif vide/trop long/regex invalide — ignoré", path.display());
            continue;
        }
        let source = v.get("source").and_then(|x| x.as_str()).unwrap_or("*");
        // CIM (Slice #7, pièce 1) — VALIDATION, jamais un rejet : si un parser overlay DÉCLARE
        // une `category` (clé forward-looking pour le DSL de mapping, aujourd'hui non consommée à
        // l'ingest), la valider contre la taxonomie CIM. WARN-only — le parser est chargé quoi
        // qu'il arrive (ENRICH, pas SUPPRESS). N'affecte AUCUNE ligne existante (aucun overlay ne
        // déclare `category` aujourd'hui) : purement additif/observabilité, data-plane inchangé.
        if let Some(cat) = v.get("category").and_then(|x| x.as_str()) {
            if !cat.is_empty() && !cim_category_ok(cat) {
                eprintln!("[cim] WARN parser '{name}' ({}) : category='{cat}' hors taxonomie CIM v{CIM_VERSION} — acceptée mais NON canonique (cf. docs/CIM.md)", path.display());
            }
        }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let exists = conn.query_row("SELECT 1 FROM parser WHERE name=?1", params![name], |_| Ok(())).is_ok();
        if exists {
            let _ = conn.execute(
                "UPDATE parser SET source=?1, pattern=?2, enabled=?3, builtin=0, managed=1 WHERE name=?4",
                params![source, pattern, enabled, name],
            );
        } else {
            let _ = conn.execute(
                "INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES(?1,?2,?3,?4,0,1,?5)",
                params![name, source, pattern, enabled, now()],
            );
        }
        n += 1;
    }
    n
}

/// Parseurs DÉCLARATIFS d'overlay (DSL CIM, pièce 2) : les fichiers `config.d/parsers/*.json` qui portent un
/// objet `map`. MÊME contrat que les autres loaders : VALIDÉ-OU-IGNORÉ (dparser_compile ; spec/regex/map
/// invalides -> WARN + skip, jamais un crash boot) ; UPSERT keyé par `name` avec managed=1 (source git). La
/// spec stockée = le JSON figé du fichier (recompilé par dparsers_reload). Une `category` littérale hors
/// taxonomie CIM est ACCEPTÉE mais SIGNALÉE (warn) — ENRICH, jamais SUPPRESS. Data-plane inchangé tant que
/// dparsers_reload n'a pas rechargé le registre.
pub(crate) fn load_overlay_dparsers(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        // Seuls les fichiers AVEC un objet `map` sont des parseurs déclaratifs (les autres -> load_overlay_parsers).
        if !v.get("map").map(|m| m.is_object()).unwrap_or(false) { continue; }
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() {
            eprintln!("[overlays] WARN parseur déclaratif {} sans 'name' — ignoré", path.display());
            continue;
        }
        let source = v.get("source").and_then(|x| x.as_str()).unwrap_or("*").to_string();
        // VALIDATION = compilation réelle (mêmes bornes/regex que l'ingest). Échec -> skip (jamais fatal).
        if let Err(e) = dparser_compile(&source, &v) {
            eprintln!("[overlays] WARN parseur déclaratif '{name}' ({}) : {e} — ignoré", path.display());
            continue;
        }
        // CIM (warn-only) : une `category` LITTÉRALE hors taxonomie est acceptée mais signalée (cf. docs/CIM.md).
        if let Some(cat) = v.get("map").and_then(|m| m.get("category")).and_then(|x| x.as_str()) {
            if !cat.is_empty() && !cat.starts_with('$') && !cim_category_ok(cat) {
                eprintln!("[cim] WARN parseur déclaratif '{name}' : category='{cat}' hors taxonomie CIM v{CIM_VERSION} — acceptée mais NON canonique (cf. docs/CIM.md)");
            }
        }
        // SEVERITY (warn-only) : parité avec la validation de `category`. Une `severity` LITTÉRALE
        // (hors capture `$x`) hors 0..4 / non numérique est SILENCIEUSEMENT no-op à l'ingest (le clamp runtime
        // la rejette) -> on AVERTIT ici pour que l'opérateur voie sa mauvaise config (les captures `$x` gardent
        // le clamp runtime, leur valeur n'étant pas connue au chargement).
        if let Some(sv) = v.get("map").and_then(|m| m.get("severity")) {
            let is_capture = sv.as_str().map(|s| s.starts_with('$')).unwrap_or(false);
            if !is_capture {
                let in_range = sv.as_i64().map(|n| (0..=4).contains(&n))
                    .or_else(|| sv.as_str().and_then(|s| s.parse::<i64>().ok()).map(|n| (0..=4).contains(&n)))
                    .unwrap_or(false);
                if !in_range {
                    eprintln!("[cim] WARN parseur déclaratif '{name}' : severity={sv} invalide (littéral entier 0..4 attendu) — override IGNORÉ à l'ingest");
                }
            }
        }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let spec = v.to_string();
        let exists = conn.query_row("SELECT 1 FROM dparser WHERE name=?1", params![name], |_| Ok(())).is_ok();
        if exists {
            let _ = conn.execute(
                "UPDATE dparser SET source=?1, spec=?2, enabled=?3, builtin=0, managed=1 WHERE name=?4",
                params![source, spec, enabled, name],
            );
        } else {
            let _ = conn.execute(
                "INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,?2,?3,?4,0,1,?5)",
                params![name, source, spec, enabled, now()],
            );
        }
        n += 1;
    }
    n
}

/// Règles d'overlay : la requête soql/SQL doit COMPILER (rule_sql, même chemin que l'éval/test) + MITRE
/// normalisé/validé (norm_mitre, comme rule_create). UPSERT keyé par name avec managed=1. INVARIANT :
/// les overlays sont SOQL-ONLY -> une règle en SQL brut (is_soql=false) est REFUSÉE au chargement (elle
/// contournerait sinon le gate admin `raw_sql_allowed` + le ledger d'audit ; le raw SQL reste admin-only via l'API).
pub(crate) fn load_overlay_rules(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() {
            eprintln!("[overlays] WARN règle {} sans 'name' — ignorée", path.display());
            continue;
        }
        let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let is_soql = v.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
        let window_s = v.get("window_s").and_then(|x| x.as_i64()).unwrap_or(3600);
        // INVARIANT : les overlays config.d sont SOQL-ONLY. Une règle managed=1 en SQL brut
        // (is_soql=false) contournerait le gate admin `raw_sql_allowed` du CRUD ET le ledger d'audit plume
        // (seul un commit git la tracerait). On la REFUSE au chargement (skip + WARN + event config-source, PAS
        // un crash). Le SQL brut reste une action admin-authorée, gatée et auditée, via l'API SEULEMENT.
        if !is_soql {
            eprintln!("[overlays] refus règle raw-SQL managed=1 '{name}' — SOQL requis");
            let _ = audit_config_change(
                conn, "config.overlay.reject",
                &format!("règle overlay '{name}' refusée : SQL brut interdit (SOQL requis)"), 3,
                &format!("overlay config.d : règle raw-SQL '{name}' refusée au chargement (SOQL-only)"),
                &json!({ "op": "reject", "kind": "rule", "name": name, "reason": "raw-sql-overlay-forbidden" }).to_string(),
            );
            continue;
        }
        if let Err(e) = rule_sql(&query, is_soql, window_s) {
            eprintln!("[overlays] WARN règle '{name}' ({}) : requête invalide ({e}) — ignorée", path.display());
            continue;
        }
        let mitre = match norm_mitre(v.get("mitre").and_then(|x| x.as_str()).unwrap_or("")) {
            Some(m) => m,
            None => { eprintln!("[overlays] WARN règle '{name}' : MITRE invalide (attendu Txxxx[.yyy]) — ignorée"); continue; }
        };
        // #38 COMPLIANCE RULE-TAGS (observability-as-code) : tag de conformité DÉCLARATIF sur la règle. MÊME
        // validation que rule_create (norm_compliance : chaque cadre validé contre le vocabulaire effectif,
        // contrôle charset-borné ; vide -> "" licite). Un tag hors vocabulaire -> WARN + skip (validé-ou-ignoré).
        let compliance = match norm_compliance(v.get("compliance").and_then(|x| x.as_str()).unwrap_or("")) {
            Some(c) => c,
            None => { eprintln!("[overlays] WARN règle '{name}' : compliance invalide (cadre hors vocabulaire / contrôle invalide) — ignorée"); continue; }
        };
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let op = v.get("op").and_then(|x| x.as_str()).unwrap_or(">");
        let threshold = v.get("threshold").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let severity = v.get("severity").and_then(|x| x.as_i64()).unwrap_or(2);
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(300);
        let exists = conn.query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(())).is_ok();
        if exists {
            let _ = conn.execute(
                "UPDATE rule SET enabled=?1, query=?2, is_soql=?3, op=?4, threshold=?5, severity=?6, interval_s=?7, window_s=?8, mitre=?9, compliance=?10, managed=1 WHERE name=?11",
                params![enabled, query, is_soql as i64, op, threshold, severity, interval_s, window_s, mitre, compliance, name],
            );
        } else {
            let _ = conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,compliance,managed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,1)",
                params![name, enabled, query, is_soql as i64, op, threshold, severity, interval_s, window_s, mitre, compliance],
            );
        }
        n += 1;
    }
    n
}

/// Playbooks d'overlay : la requête doit COMPILER (rule_sql). UPSERT keyé par name avec managed=1.
pub(crate) fn load_overlay_playbooks(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in overlay_files(dir) {
        let v = match overlay_read_json(&path) { Some(v) => v, None => continue };
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() {
            eprintln!("[overlays] WARN playbook {} sans 'name' — ignoré", path.display());
            continue;
        }
        let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let is_soql = v.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
        let window_s = v.get("window_s").and_then(|x| x.as_i64()).unwrap_or(3600);
        // INVARIANT : même frontière SOQL-only sur les playbooks overlay (query exécutée ->
        // même classe de contournement du gate raw-SQL + audit). Raw-SQL managed=1 -> refus (skip + WARN + event).
        if !is_soql {
            eprintln!("[overlays] refus playbook raw-SQL managed=1 '{name}' — SOQL requis");
            let _ = audit_config_change(
                conn, "config.overlay.reject",
                &format!("playbook overlay '{name}' refusé : SQL brut interdit (SOQL requis)"), 3,
                &format!("overlay config.d : playbook raw-SQL '{name}' refusé au chargement (SOQL-only)"),
                &json!({ "op": "reject", "kind": "playbook", "name": name, "reason": "raw-sql-overlay-forbidden" }).to_string(),
            );
            continue;
        }
        if let Err(e) = rule_sql(&query, is_soql, window_s) {
            eprintln!("[overlays] WARN playbook '{name}' ({}) : requête invalide ({e}) — ignoré", path.display());
            continue;
        }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let action_kind = v.get("action_kind").and_then(|x| x.as_str()).unwrap_or("ban_ip");
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(300);
        let exists = conn.query_row("SELECT 1 FROM playbook WHERE name=?1", params![name], |_| Ok(())).is_ok();
        if exists {
            let _ = conn.execute(
                "UPDATE playbook SET enabled=?1, query=?2, is_soql=?3, action_kind=?4, interval_s=?5, window_s=?6, managed=1 WHERE name=?7",
                params![enabled, query, is_soql as i64, action_kind, interval_s, window_s, name],
            );
        } else {
            let _ = conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed) VALUES(?1,?2,?3,?4,?5,?6,?7,1)",
                params![name, enabled, query, is_soql as i64, action_kind, interval_s, window_s],
            );
        }
        n += 1;
    }
    n
}

/// Fichiers Sigma d'un dossier overlay (`*.yml` / `*.yaml` / `*.json`), triés. Un fichier peut porter
/// PLUSIEURS documents YAML (`---`). Distinct de `overlay_files` (JSON-only) : Sigma est du YAML.
pub(crate) fn sigma_overlay_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    if matches!(ext, "yml" | "yaml" | "json") { v.push(p); }
                }
            }
        }
    }
    v.sort();
    v
}

/// SLICE #7 pièce 3 — overlays SIGMA (`config.d/sigma/*.yml|yaml|json`). Chaque document est TRADUIT
/// (sigma_translate) puis, en cas de succès, UPSERT dans `rule` avec `managed=1` (source git, comme
/// load_overlay_rules). MÊME contrat VALIDÉ-OU-IGNORÉ : un doc non traduisible est WARN + skip (jamais
/// fatal) ; les warnings de traduction (logsource non mappé, casse d'un `in`) sont journalisés (NOTE).
pub(crate) fn load_overlay_sigma(conn: &Connection, dir: &std::path::Path) -> u32 {
    let mut n = 0;
    for path in sigma_overlay_files(dir) {
        let txt = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => { eprintln!("[overlays] WARN Sigma lecture {} échouée : {e} — ignoré", path.display()); continue; }
        };
        let docs = match sigma_yaml_to_docs(&txt) {
            Ok(d) => d,
            Err(e) => { eprintln!("[overlays] WARN Sigma {} : {e} — ignoré", path.display()); continue; }
        };
        for d in &docs {
            let title = d.str_field("title").to_string();
            match sigma_translate(d) {
                Ok(t) => {
                    for w in &t.warnings { eprintln!("[sigma] NOTE règle '{}' : {w}", t.name); }
                    let exists = conn.query_row("SELECT 1 FROM rule WHERE name=?1", params![t.name], |_| Ok(())).is_ok();
                    if exists {
                        let _ = conn.execute(
                            "UPDATE rule SET enabled=1, query=?1, is_soql=1, op=?2, threshold=?3, severity=?4, interval_s=?5, window_s=?6, mitre=?7, managed=1 WHERE name=?8",
                            params![t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.name],
                        );
                    } else {
                        let _ = conn.execute(
                            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed) VALUES(?1,1,?2,1,?3,?4,?5,?6,?7,?8,1)",
                            params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre],
                        );
                    }
                    n += 1;
                }
                Err(e) => {
                    let who = if title.is_empty() { "(sans titre)".to_string() } else { title };
                    eprintln!("[overlays] WARN règle Sigma '{who}' ({}) : {e} — ignorée", path.display());
                }
            }
        }
    }
    n
}

/// #1c-toggle — RÉAPPLIQUE les overrides d'activation ADMIN (detection_override) PAR-DESSUS l'état posé par les
/// overlays config.d. Le contrat : git (le fichier config.d) définit le CONTENU (query/regex/action) ET pose
/// un `enabled` au boot ; l'admin décide de l'ACTIVATION via l'UI, écrite dans detection_override, et CET
/// override GAGNE ici (dernier appliqué au boot) -> l'`enabled` du fichier ne ré-impose plus l'état, le choix
/// de l'admin SURVIT au reboot. Ne touche QUE la colonne `enabled` (jamais query/is_soql -> aucune élévation).
/// Set-based, keyé par (kind,name) : `kind`/`table` sont des LITTÉRAUX d'un tableau fixe (jamais une entrée
/// utilisateur -> pas d'injection) ; `name` via corrélation SQL paramétrée. MODE 0 (aucune ligne d'override) ->
/// 0 UPDATE sur chaque table -> byte-identique au boot historique. Couvre règles + parseurs + playbooks (les
/// trois portent le pattern managed=1 overlay).
pub(crate) fn apply_content_overrides(conn: &Connection) {
    for (kind, table) in [("rule", "rule"), ("parser", "parser"), ("playbook", "playbook")] {
        // UPDATE <table> SET enabled = (override.enabled) WHERE name a un override du bon kind.
        // FIX HIGH-2 : le système d'override ne gouverne QUE le contenu overlay config.d (managed=1). Sans
        // UNIQUE(name), un editor peut pré-positionner un ad-hoc managed=2 du MÊME nom qu'un overlay admin ;
        // sans ce scope, l'override admin ferait aussi basculer la ligne managed=2 de l'editor au boot. On scope
        // DONC les DEUX côtés à managed=1 (corrélation interne + WHERE externe). `{table}`/`kind` restent des
        // LITTÉRAUX d'un tableau fixe (pas d'injection). MODE 0 (aucun override) -> 0 UPDATE -> byte-identique.
        let _ = conn.execute(
            &format!(
                "UPDATE {table} SET enabled=(SELECT o.enabled FROM detection_override o WHERE o.kind=?1 AND o.name={table}.name AND {table}.managed=1) \
                 WHERE {table}.managed=1 AND name IN (SELECT name FROM detection_override WHERE kind=?1)"
            ),
            params![kind],
        );
    }
}

/// Applique tous les overlays d'un répertoire racine `config.d` (sous-dossiers parsers/rules/playbooks/sigma).
/// Racine absente -> no-op gracieux. Séparé de load_overlays pour être testable sans env/cfg.
pub(crate) fn load_overlays_dir(conn: &Connection, root: &std::path::Path) {
    if !root.is_dir() {
        return;
    }
    let np = load_overlay_parsers(conn, &root.join("parsers"));
    let nd = load_overlay_dparsers(conn, &root.join("parsers"));   // pièce 2 : mêmes fichiers, ceux à objet `map`
    let nr = load_overlay_rules(conn, &root.join("rules"));
    // CATALOGUE DE DÉTECTION (#22 — starter pack curé) : sous-dossier dédié `rules/catalog/` chargé par le
    // MÊME loader (managed=1, MÊME validation « compile-ou-ignore »). Séparé de `rules/` pour distinguer la
    // BIBLIOTHÈQUE curée (large, la plupart enabled=false, activée par l'opérateur selon sa télémétrie) des
    // quelques règles « actives » posées à la racine. overlay_files ne récurse pas -> chemin explicite.
    let ncat = load_overlay_rules(conn, &root.join("rules").join("catalog"));
    let nr = nr + ncat;
    let nb = load_overlay_playbooks(conn, &root.join("playbooks"));
    let ns = load_overlay_sigma(conn, &root.join("sigma"));        // pièce 3 : règles Sigma (YAML) -> rule
    // #1c-toggle : l'override d'activation admin GAGNE sur l'`enabled` du fichier config.d — réappliqué APRÈS
    // TOUS les upserts d'overlay (rules JSON + Sigma + parsers + playbooks) -> le dernier écrit l'emporte, le
    // choix de l'admin survit au reboot. VIDE en mode 0 -> 0 UPDATE -> byte-identique.
    apply_content_overrides(conn);
    if np + nd + nr + nb + ns > 0 {
        eprintln!("[overlays] config.d appliqué : {np} parser(s) regex, {nd} parser(s) déclaratif(s), {nr} règle(s) (dont {ncat} catalogue), {nb} playbook(s), {ns} règle(s) Sigma — managed=1 (source git)");
    }
    // #55 OBSERVABILITY-AS-CODE — objets de config (dashboards/notifiers/destinations/connecteurs/index-policies/
    // field-filters/library-panels/notification-policies). MÊME racine config.d, sous-dossiers dédiés. No-op si
    // aucun sous-dossier -> mode 0 byte-identique.
    load_oac_overlays_dir(conn, root);
}

/// Point d'entrée boot : résout ${PLUME_CONFIG_DIR} (défaut /usr/local/share/plume/config.d, BAKED).
pub(crate) fn load_overlays(conn: &Connection, conf: &HashMap<String, String>) {
    let base = cfg(conf, "PLUME_CONFIG_DIR", "/usr/local/share/plume/config.d");
    load_overlays_dir(conn, std::path::Path::new(&base));
}

// =====================================================================================
// #26 — CYCLE DE VIE des overlays config.d : PRUNE des overlays ORPHELINS. Un overlay chargé (managed=1) le
// reste EN BASE même après SUPPRESSION de son fichier config.d (load_overlays ne fait qu'UPSERT, jamais de
// DELETE) : une règle/parseur retiré côté git SURVIT en base -> angle mort de gouvernance. Le prune supprime
// les lignes managed=1 dont le `name` n'est PLUS adossé à un fichier config.d courant. NE TOUCHE JAMAIS
// managed=0 (builtin/seed) ni managed=2 (ad-hoc UI) : chirurgical. Idempotent. Admin-only + audité. Après
// prune on RECHARGE les registres parsers/dparsers (état cohérent). Cf. delete_managed_row qui REFUSE (409)
// un managed=1 individuel « car le fichier git le ré-imposerait au boot » : ce prune est le pendant légitime
// APRÈS retrait du fichier (l'overlay n'est plus adossé -> il peut être élagué sans qu'un re-seed le recrée).
// =====================================================================================

/// Noms d'overlays ACTUELLEMENT adossés à un fichier config.d, par catégorie (mêmes discriminants que les
/// loaders). Pour `rule` : union des règles JSON et des règles Sigma TRADUITES (mêmes noms qu'à l'insertion).
#[derive(Default)]
pub(crate) struct OverlayBackedNames {
    pub(crate) parser: std::collections::HashSet<String>,
    pub(crate) dparser: std::collections::HashSet<String>,
    pub(crate) rule: std::collections::HashSet<String>,
    pub(crate) playbook: std::collections::HashSet<String>,
}
pub(crate) fn overlay_backed_names(root: &std::path::Path) -> OverlayBackedNames {
    let mut o = OverlayBackedNames::default();
    if !root.is_dir() {
        return o;
    }
    // parsers/*.json : `map` objet -> dparser (déclaratif) ; sinon parser (regex). Même clé que les loaders.
    for path in overlay_files(&root.join("parsers")) {
        if let Some(v) = overlay_read_json(&path) {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if name.is_empty() {
                continue;
            }
            if v.get("map").map(|m| m.is_object()).unwrap_or(false) {
                o.dparser.insert(name);
            } else {
                o.parser.insert(name);
            }
        }
    }
    // Racine `rules/` + sous-dossier `rules/catalog/` (catalogue de détection curé) : MÊMES clés `name`
    // adossées que les deux appels load_overlay_rules -> le prune #26 ne considère PAS les règles catalogue
    // comme orphelines (symétrie loader/prune ; sans ceci le prune supprimerait les managed=1 du catalogue).
    for dir in [root.join("rules"), root.join("rules").join("catalog")] {
        for path in overlay_files(&dir) {
            if let Some(v) = overlay_read_json(&path) {
                let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                if !name.is_empty() {
                    o.rule.insert(name);
                }
            }
        }
    }
    // Sigma -> `rule` : le NOM adossé est celui produit par la TRADUCTION (identique à load_overlay_sigma).
    for path in sigma_overlay_files(&root.join("sigma")) {
        if let Ok(txt) = std::fs::read_to_string(&path) {
            if let Ok(docs) = sigma_yaml_to_docs(&txt) {
                for d in &docs {
                    if let Ok(t) = sigma_translate(d) {
                        o.rule.insert(t.name);
                    }
                }
            }
        }
    }
    for path in overlay_files(&root.join("playbooks")) {
        if let Some(v) = overlay_read_json(&path) {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if !name.is_empty() {
                o.playbook.insert(name);
            }
        }
    }
    o
}

/// Comptes d'overlays orphelins élagués, par table.
#[derive(Default, Debug, PartialEq)]
pub(crate) struct PruneCounts {
    pub(crate) parser: i64,
    pub(crate) dparser: i64,
    pub(crate) rule: i64,
    pub(crate) playbook: i64,
}

/// Supprime les lignes managed=1 dont le `name` n'est PLUS dans `keep` (adossé à un fichier). Collecte les id
/// orphelins puis DELETE par id (le re-check `managed=1` sur le DELETE = défense en profondeur ; jamais un
/// nom interpolé dans le SQL). `table` est un littéral fixe de l'appelant (aucune injection).
fn prune_table_orphans(conn: &Connection, table: &str, keep: &std::collections::HashSet<String>) -> rusqlite::Result<i64> {
    let orphan_ids: Vec<i64> = {
        let mut st = conn.prepare(&format!("SELECT id,name FROM {table} WHERE managed=1"))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        rows.flatten().filter(|(_, n)| !keep.contains(n)).map(|(id, _)| id).collect()
    };
    let mut n = 0i64;
    for id in &orphan_ids {
        n += conn.execute(&format!("DELETE FROM {table} WHERE id=?1 AND managed=1"), params![id])? as i64;
    }
    Ok(n)
}

/// PRUNE des overlays config.d orphelins (parser/dparser/rule/playbook) contre l'état COURANT des fichiers de
/// `root`. Ne touche JAMAIS managed=0/2. Renvoie les comptes par table. PUR côté décision (adossement = lecture
/// des fichiers) + DELETE ciblés — testable avec un répertoire temporaire.
pub(crate) fn prune_orphan_overlays(conn: &Connection, root: &std::path::Path) -> rusqlite::Result<PruneCounts> {
    let backed = overlay_backed_names(root);
    Ok(PruneCounts {
        parser: prune_table_orphans(conn, "parser", &backed.parser)?,
        dparser: prune_table_orphans(conn, "dparser", &backed.dparser)?,
        rule: prune_table_orphans(conn, "rule", &backed.rule)?,
        playbook: prune_table_orphans(conn, "playbook", &backed.playbook)?,
    })
}

/// POST /api/config-overlays/prune — élague les overlays config.d ORPHELINS (managed=1 sans fichier adossé).
/// ADMIN-only (serveur default-deny + re-check) + PAR-TENANT (req_db). Transaction fail-closed + AUDIT
/// (audit_config_change, sévérité 3 = mutation de config). Recharge les registres parsers/dparsers après
/// coup. Renvoie les comptes élagués par table. Idempotent (re-appel = 0 si plus d'orphelin).
pub(crate) async fn config_overlays_prune(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let conf = load_config();
    let base = cfg(&conf, "PLUME_CONFIG_DIR", "/usr/local/share/plume/config.d");
    let root = std::path::PathBuf::from(&base);
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<(PruneCounts, OacPruneCounts)> = (|| {
        let c = prune_orphan_overlays(&conn, &root)?;
        // #55 — prune AUSSI les OBJETS DE CONFIG OAC orphelins (notifiers/destinations/…) — même discipline.
        let o = prune_oac_orphans(&conn, &root)?;
        let total = c.parser + c.dparser + c.rule + c.playbook
            + o.notifier + o.destination + o.connector + o.index_policy + o.field_filter
            + o.library_panel + o.notification_policy + o.dashboard + o.panel;
        audit_config_change(
            &conn,
            "config.overlay.prune",
            &format!("prune overlays config.d orphelins : {total} ligne(s) par {}", au.name),
            3,
            &format!(
                "prune config.d par {} : {} parser regex, {} parseur(s) déclaratif(s), {} règle(s), {} playbook(s) + OAC ({} notifier, {} destination, {} connecteur, {} index-policy, {} field-filter, {} library-panel, {} notif-policy, {} dashboard, {} panel) ORPHELIN(S) élagué(s) (managed=1 sans fichier adossé)",
                au.name, c.parser, c.dparser, c.rule, c.playbook,
                o.notifier, o.destination, o.connector, o.index_policy, o.field_filter, o.library_panel, o.notification_policy, o.dashboard, o.panel
            ),
            &json!({ "parser": c.parser, "dparser": c.dparser, "rule": c.rule, "playbook": c.playbook,
                     "notifier": o.notifier, "destination": o.destination, "connector": o.connector, "index_policy": o.index_policy,
                     "field_filter": o.field_filter, "library_panel": o.library_panel, "notification_policy": o.notification_policy,
                     "dashboard": o.dashboard, "panel": o.panel, "actor": au.name }).to_string(),
        )?;
        Ok((c, o))
    })();
    match outcome {
        Ok((c, o)) => {
            let _ = conn.execute_batch("COMMIT");
            // Recharge les registres compilés depuis les fichiers RESTANTS -> état runtime cohérent.
            parsers_reload(&conn, &db_path);
            dparsers_reload(&conn, &db_path);
            field_filters_reload(&conn, &db_path); // #45/#55 : le prune a pu retirer des field-filters overlay
            Json(json!({ "pruned": { "parser": c.parser, "dparser": c.dparser, "rule": c.rule, "playbook": c.playbook,
                "notifier": o.notifier, "destination": o.destination, "connector": o.connector, "index_policy": o.index_policy,
                "field_filter": o.field_filter, "library_panel": o.library_panel, "notification_policy": o.notification_policy,
                "dashboard": o.dashboard, "panel": o.panel } })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction prune (aucune modification): {e}"))
        }
    }
}
