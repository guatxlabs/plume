//! Normalisation CIM des télémétries de SÉCURITÉ ENDPOINT (#57) — BYO-agent (bring-your-own-agent).
//!
//! DÉCISION STRATÉGIQUE (honorée) : Plume NE reconstruit PAS un agent endpoint (pas de moteur natif
//! SCA/CVE/rootcheck — ce serait re-bâtir OSSEC, contre la charte souveraine/2 Go/vendor-agnostic).
//! À la place : SUR-ENSEMBLE-PAR-INGESTION — on ingère + normalise en CIM la télémétrie endpoint des
//! agents que le client fait DÉJÀ tourner (Wazuh, osquery, EDR) et on la surface en vues natives Plume.
//!
//! Ce module reconnaît le schéma d'ALERTE JSON Wazuh (le format BYO-agent le plus répandu) et mappe ses
//! familles endpoint-sécurité vers le CIM (`docs/CIM.md`) :
//!   - `data.sca.*`            (Security Configuration Assessment / CIS) -> category `posture`
//!   - `data.vulnerability.*`  (vulnerability-detector)                  -> category `vuln`
//!   - `syscheck.*`            (FIM / integrité fichiers)                -> category `integrity`
//!   - `data.*` (syscollector) (inventaire paquets/ports/processus)     -> category `inventory`
//!
//! MODE 0 / BYTE-IDENTIQUE (invariant DUR) : le normaliseur est GATE PAR SOURCE (`PLUME_ENDPOINT_NORMALIZE`,
//! défaut `"wazuh"`). Tant qu'aucun event de cette source ne circule, `endpoint_normalize` renvoie
//! `(existing, None, None)` en UN test d'appartenance (`iter().any`) — AUCUNE allocation, AUCUN parse JSON,
//! ligne stockée BYTE-IDENTIQUE. Le parse JSON du message n'a lieu QUE pour les sources opt-in.
//!
//! ENRICH / MAP, jamais DROP (même contrat que les parseurs déclaratifs) : on n'AJOUTE que des champs
//! `fields.*` absents (le collecteur GAGNE) et on renvoie `category`/`severity` comme OVERRIDES CANDIDATS
//! (l'ingest ne les applique qu'en ENRICH-only : si le collecteur ne les a pas déjà posés). Aucun event
//! n'est jamais supprimé ni filtré. Tout passe par le sac `fields` -> chemin INSERT bindé (injection-safe).
//!
//! VENDOR-AGNOSTIC : c'est un PRESET BUILT-IN mince pour le schéma Wazuh. Un AUTRE vendeur (openscap, un EDR)
//! s'ajoute SANS rebuild via le DSL de parseur déclaratif (`docs/PARSER-DSL.md`, `config.d/parsers/`) en
//! ciblant les MÊMES champs/catégories CIM (cf. `config.d/parsers/example-endpoint-fim.json`).
use crate::*;

/// Sources opt-in du normaliseur endpoint : env `PLUME_ENDPOINT_NORMALIZE` (CSV, défaut `"wazuh"`), mise
/// en cache au 1er appel (même patron que `generic_sources`). Vide/absent -> `["wazuh"]`. Le gate `*` est
/// interdit (jamais TOUTE source : le parse JSON par event coûterait, et casserait le mode 0 byte-identique).
pub(crate) fn endpoint_sources() -> &'static [String] {
    static SRCS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    SRCS.get_or_init(|| {
        std::env::var("PLUME_ENDPOINT_NORMALIZE")
            .unwrap_or_else(|_| "wazuh".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "*")
            .collect()
    })
}

/// Accès à une sous-clé d'objet (None si absente ou non-objet).
fn sub<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|o| o.get(k))
}
/// Accès imbriqué par chemin pointé (`["data","sca","check","id"]`).
fn nested<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for k in path {
        cur = sub(cur, k)?;
    }
    Some(cur)
}
/// Valeur scalaire -> String (string telle quelle, nombre/bool stringifiés). Array/objet/null -> None.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
/// Lit un scalaire à un chemin imbriqué (borné en longueur via `generic_trunc`).
fn get_str(root: &Value, path: &[&str]) -> Option<String> {
    nested(root, path).and_then(scalar).map(|s| generic_trunc(&s)).filter(|s| !s.is_empty())
}

/// Insertion ENRICH bornée dans le sac `fields` de sortie : n'écrit QUE si la clé est absente et la valeur
/// non vide (collecteur > normaliseur, first-writer-wins). Passe `added` à true dès qu'une clé est ajoutée.
/// Réutilise `dfield_put` (même contrat que les parseurs déclaratifs).
fn put(obj: &mut serde_json::Map<String, Value>, added: &mut bool, k: &str, v: Option<String>) {
    if let Some(v) = v {
        dfield_put(obj, added, k, &v);
    }
}

/// Aplatit `data.sca.check.compliance` (cadres de conformité). Wazuh l'émet soit en TABLEAU d'objets
/// mono-clé (`[{"cis":["1.1.1"]},{"pci_dss":["2.2.4"]}]`) soit en OBJET (`{"cis":"1.1.1",...}`). Renvoie
/// `(cadres, paires)` : `cadres` = liste des noms de cadres (`"cis,pci_dss"`), `paires` = `"cis:1.1.1,..."`.
/// Bornes : au plus 16 entrées collectées (cardinalité) ; valeurs jointes puis tronquées par l'appelant.
fn flatten_compliance(v: &Value) -> (String, String) {
    let mut frameworks: Vec<String> = Vec::new();
    let mut pairs: Vec<String> = Vec::new();
    let mut push = |fw: &str, val: &Value| {
        if frameworks.len() >= 16 {
            return;
        }
        let fw = fw.trim();
        if fw.is_empty() {
            return;
        }
        let joined = match val {
            Value::Array(a) => a.iter().filter_map(scalar).collect::<Vec<_>>().join("/"),
            other => scalar(other).unwrap_or_default(),
        };
        if !frameworks.iter().any(|f| f == fw) {
            frameworks.push(fw.to_string());
        }
        pairs.push(if joined.is_empty() { fw.to_string() } else { format!("{fw}:{joined}") });
    };
    match v {
        Value::Array(items) => {
            for it in items {
                if let Some(o) = it.as_object() {
                    for (fw, val) in o {
                        push(fw, val);
                    }
                }
            }
        }
        Value::Object(o) => {
            for (fw, val) in o {
                push(fw, val);
            }
        }
        _ => {}
    }
    (frameworks.join(","), pairs.join(","))
}

/// Normalise un résultat SCA Wazuh (`passed`/`failed`/`not applicable`) -> vocabulaire neutre `pass`/`fail`/`na`.
fn norm_result(r: &str) -> &'static str {
    match r.trim().to_ascii_lowercase().as_str() {
        "passed" | "pass" => "pass",
        "failed" | "fail" => "fail",
        _ => "na", // "not applicable" / inconnu
    }
}

/// Sévérité CVE Wazuh -> échelle Plume 0..4. `critical`->4, `high`->3, `medium`->2, `low`->1, sinon 0.
fn cve_sev(sev: &str) -> i64 {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// NORMALISE un event endpoint (schéma d'alerte Wazuh) vers le CIM. Renvoie
/// `(fields éventuellement enrichis, category override, severity override)` — MÊME forme que
/// `dparsers_apply`, pour se brancher au MÊME point de l'ingest.
///
/// MODE 0 : source hors `endpoint_sources()` OU message non-objet-JSON OU aucune famille reconnue
/// => `(existing, None, None)` (ligne BYTE-IDENTIQUE). Sinon : détecte la famille par présence de clé
/// (`data.sca` / `data.vulnerability` / `syscheck` / syscollector), aplatit les champs imbriqués en
/// `fields.*` (bornés, ENRICH-only) et pose category/severity.
pub(crate) fn endpoint_normalize(source: &str, message: &str, existing: Option<String>) -> (Option<String>, Option<String>, Option<i64>) {
    // GATE opt-in par source — le SEUL coût en mode 0 (aucun parse JSON tant que la source n'est pas listée).
    if !endpoint_sources().iter().any(|s| s == source) {
        return (existing, None, None);
    }
    // Borne message (même troncature caractère-safe 8192 que les autres parseurs).
    let msg = if message.len() > 8192 {
        &message[..message.char_indices().take_while(|&(i, _)| i < 8192).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0)]
    } else {
        message
    };
    // Le message DOIT être un objet JSON (l'alerte Wazuh complète). Sinon -> no-op strict (byte-identique).
    let root: Value = match serde_json::from_str::<Value>(msg) {
        Ok(v) if v.is_object() => v,
        _ => return (existing, None, None),
    };

    let mut obj: serde_json::Map<String, Value> = existing.as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut added = false;
    let mut out_cat: Option<String> = None;
    let mut out_sev: Option<i64> = None;

    // Identité de l'ENDPOINT (agent Wazuh) — utile car un forwarder central relaie plusieurs hôtes : la
    // colonne `host` peut être le forwarder, tandis que `agent_name` est le vrai endpoint (surface dans les vues).
    put(&mut obj, &mut added, "agent_name", get_str(&root, &["agent", "name"]));
    put(&mut obj, &mut added, "agent_id", get_str(&root, &["agent", "id"]));
    put(&mut obj, &mut added, "agent_ip", get_str(&root, &["agent", "ip"]));

    // --- Famille 1 : SCA (Security Configuration Assessment / CIS) -> category `posture` ---
    if let Some(sca) = nested(&root, &["data", "sca"]) {
        out_cat = Some("posture".to_string());
        put(&mut obj, &mut added, "posture_policy", get_str(sca, &["policy"]));
        put(&mut obj, &mut added, "posture_policy_id", get_str(sca, &["policy_id"]));
        let is_summary = get_str(sca, &["type"]).as_deref() == Some("summary")
            || sca.as_object().map(|o| o.contains_key("score") && !o.contains_key("check")).unwrap_or(false);
        if is_summary {
            // Event de SYNTHÈSE de scan : score + compteurs pass/fail par politique (pas un contrôle unique).
            put(&mut obj, &mut added, "posture_kind", Some("summary".to_string()));
            put(&mut obj, &mut added, "posture_score", get_str(sca, &["score"]));
            put(&mut obj, &mut added, "posture_passed", get_str(sca, &["passed"]));
            put(&mut obj, &mut added, "posture_failed", get_str(sca, &["failed"]));
        } else {
            // Event de CONTRÔLE : id/titre/résultat/remédiation + cadres de conformité.
            put(&mut obj, &mut added, "posture_kind", Some("check".to_string()));
            put(&mut obj, &mut added, "posture_check_id", get_str(sca, &["check", "id"]));
            put(&mut obj, &mut added, "posture_check_title", get_str(sca, &["check", "title"]));
            if let Some(r) = get_str(sca, &["check", "result"]) {
                put(&mut obj, &mut added, "posture_result", Some(norm_result(&r).to_string()));
                // failed = signal notable (warning) ; passed/na = info. ENRICH-only (le collecteur gagne).
                out_sev = Some(if norm_result(&r) == "fail" { 2 } else { 0 });
            }
            put(&mut obj, &mut added, "posture_remediation", get_str(sca, &["check", "remediation"]));
            if let Some(comp) = nested(sca, &["check", "compliance"]) {
                let (fw, pairs) = flatten_compliance(comp);
                put(&mut obj, &mut added, "posture_framework", (!fw.is_empty()).then(|| generic_trunc(&fw)));
                put(&mut obj, &mut added, "posture_compliance", (!pairs.is_empty()).then(|| generic_trunc(&pairs)));
            }
        }
        let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
        return (fields, out_cat, out_sev);
    }

    // --- Famille 2 : Vulnerability-detector -> category `vuln` ---
    if let Some(vln) = nested(&root, &["data", "vulnerability"]) {
        out_cat = Some("vuln".to_string());
        put(&mut obj, &mut added, "cve", get_str(vln, &["cve"]));
        put(&mut obj, &mut added, "vuln_title", get_str(vln, &["title"]));
        // package : Wazuh a varié entre `package.{name,version}` et `package_name`/`package_version`.
        let pkg = get_str(vln, &["package", "name"]).or_else(|| get_str(vln, &["package_name"]));
        let pver = get_str(vln, &["package", "version"]).or_else(|| get_str(vln, &["package_version"]));
        put(&mut obj, &mut added, "vuln_package", pkg);
        put(&mut obj, &mut added, "vuln_package_version", pver);
        put(&mut obj, &mut added, "vuln_status", get_str(vln, &["status"]));
        // CVSS3 base score (chemins Wazuh connus).
        let cvss = get_str(vln, &["cvss", "cvss3", "base_score"])
            .or_else(|| get_str(vln, &["cvss3", "base_score"]))
            .or_else(|| get_str(vln, &["cvss3_score"]));
        put(&mut obj, &mut added, "vuln_cvss", cvss);
        if let Some(sv) = get_str(vln, &["severity"]) {
            put(&mut obj, &mut added, "vuln_severity", Some(sv.to_ascii_lowercase()));
            out_sev = Some(cve_sev(&sv));
        }
        let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
        return (fields, out_cat, out_sev);
    }

    // --- Famille 3 : FIM / syscheck -> category `integrity` (étend la catégorie existante) ---
    if let Some(sc) = sub(&root, "syscheck") {
        out_cat = Some("integrity".to_string());
        put(&mut obj, &mut added, "fim_path", get_str(sc, &["path"]));
        let event = get_str(sc, &["event"]); // added|modified|deleted
        put(&mut obj, &mut added, "fim_event", event.clone());
        put(&mut obj, &mut added, "fim_mode", get_str(sc, &["mode"])); // scheduled|realtime|whodata
        // Empreinte APRÈS (détecte la trojanisation in-place) + attributs clés.
        put(&mut obj, &mut added, "fim_sha256", get_str(sc, &["sha256_after"]));
        put(&mut obj, &mut added, "fim_md5", get_str(sc, &["md5_after"]));
        put(&mut obj, &mut added, "fim_size", get_str(sc, &["size_after"]));
        put(&mut obj, &mut added, "fim_uname", get_str(sc, &["uname_after"]));
        // whodata : QUI a modifié le fichier (si Wazuh l'a capté).
        put(&mut obj, &mut added, "fim_actor", get_str(sc, &["audit", "effective_user", "name"]));
        if let Some(ev) = event.as_deref() {
            // Outcome neutre CIM (réutilise le vocabulaire d'action) : modified->modify, deleted->delete.
            let act = match ev { "modified" => Some("modify"), "deleted" => Some("delete"), _ => None };
            put(&mut obj, &mut added, "action", act.map(|s| s.to_string()));
            out_sev = Some(match ev { "deleted" => 3, "modified" => 2, _ => 1 });
        }
        let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
        return (fields, out_cat, out_sev);
    }

    // --- Famille 4 : syscollector (inventaire) -> category `inventory` ---
    // Détection PRUDENTE (évite les faux positifs sur d'autres alertes) : marqueur explicite syscollector
    // (rule.groups / location) OU présence d'un sous-objet d'inventaire connu sous `data`.
    let is_syscollector = get_str(&root, &["location"]).map(|l| l.contains("syscollector")).unwrap_or(false)
        || nested(&root, &["rule", "groups"]).and_then(|g| g.as_array())
            .map(|a| a.iter().any(|x| x.as_str() == Some("syscollector"))).unwrap_or(false)
        || ["program", "package", "port", "process", "hotfix"].iter().any(|k| nested(&root, &["data", k]).is_some());
    if is_syscollector {
        if let Some(data) = sub(&root, "data") {
            out_cat = Some("inventory".to_string());
            // Type d'inventaire + champs saillants selon le sous-objet présent (paquet / port / processus).
            if let Some(p) = sub(data, "program").or_else(|| sub(data, "package")) {
                put(&mut obj, &mut added, "inv_type", Some("package".to_string()));
                put(&mut obj, &mut added, "inv_name", get_str(p, &["name"]));
                put(&mut obj, &mut added, "inv_version", get_str(p, &["version"]));
                put(&mut obj, &mut added, "inv_vendor", get_str(p, &["vendor"]));
            } else if let Some(p) = sub(data, "port") {
                put(&mut obj, &mut added, "inv_type", Some("port".to_string()));
                put(&mut obj, &mut added, "inv_port", get_str(p, &["local", "port"]).or_else(|| get_str(p, &["local_port"])));
                put(&mut obj, &mut added, "inv_protocol", get_str(p, &["protocol"]));
                put(&mut obj, &mut added, "inv_process", get_str(p, &["process"]));
            } else if let Some(p) = sub(data, "process") {
                put(&mut obj, &mut added, "inv_type", Some("process".to_string()));
                put(&mut obj, &mut added, "inv_name", get_str(p, &["name"]));
                put(&mut obj, &mut added, "inv_pid", get_str(p, &["pid"]));
                put(&mut obj, &mut added, "inv_cmd", get_str(p, &["cmd"]));
            } else if let Some(p) = sub(data, "hotfix") {
                put(&mut obj, &mut added, "inv_type", Some("hotfix".to_string()));
                put(&mut obj, &mut added, "inv_name", get_str(p, &["hotfix"]).or_else(|| scalar(p)));
            }
            out_sev = Some(0); // télémétrie d'inventaire = info
        }
        let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
        return (fields, out_cat, out_sev);
    }

    // Aucune famille reconnue -> on rend les fields (les 3 champs agent_* ci-dessus peuvent avoir enrichi),
    // sans catégorie. Si RIEN n'a été ajouté -> `existing` intact (byte-identique).
    let fields = if added { Some(Value::Object(obj).to_string()) } else { existing };
    (fields, None, None)
}
