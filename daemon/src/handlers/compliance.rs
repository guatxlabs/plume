//! #38 — MAPPING DE CONFORMITÉ : tags de cadre réglementaire PAR RÈGLE + rollup de posture PAR CADRE
//! + rapport de posture exportable. HONNÊTETÉ (invariant DUR) : Plume expose une POSTURE / COUVERTURE de
//! conformité (contrôles couverts + preuve adossée au ledger), il ne CERTIFIE PAS. Toute étiquette dit
//! « posture / couverture », jamais « conforme / certifié » (cf. docs/COMPLIANCE.md).
//!
//! DEUX sources composées (sur-ensemble-par-ingestion, #57) :
//!   (a) POSTURE ingérée : events `category=posture` (SCA/CIS via BYO-agent) portant `posture_compliance`
//!       (`pci_dss:2.2.4,hipaa:164.312`) + `posture_result` (pass|fail|na) -> pass/fail PAR contrôle.
//!   (b) RÈGLES de détection : colonne `rule.compliance` (v88) -> quelles détections COUVRENT quel cadre.
//!
//! VENDOR-AGNOSTIC : le vocabulaire de cadres est un SOCLE (`guatx_core::cim::COMPLIANCE_FRAMEWORKS`)
//! UNIONNÉ avec une liste de config (`PLUME_COMPLIANCE_FRAMEWORKS`, CSV) -> ajouter un cadre client ne
//! demande pas de rebuild. Les IDs sont alignés Wazuh -> la posture ingérée et le tag de règle JOIGNENT.
//!
//! INJECTION-SAFE : le cadre est VALIDÉ contre le vocab (jamais interpolé) ; l'id de contrôle est un charset
//! borné, STOCKÉ en valeur (jamais interpolé dans le SQL) ; le rollup lit la posture via le chemin GXQL
//! MASQUÉ (#45 field-filters + RBAC hérités) et agrège les cadres/contrôles EN RUST (aucune concat SQL).
use crate::*;

/// Longueur max d'un id de contrôle (borne mémoire/affichage). Un contrôle réel (`8.7`, `164.312(a)(1)`,
/// `AU-2(3)`) tient largement.
const COMPLIANCE_CTRL_MAX: usize = 64;
/// Nombre max d'entrées `cadre:contrôle` dans un tag de règle (borne d'affichage/stockage ; un ruleset
/// Sigma en porte typiquement < 10).
const COMPLIANCE_MAX_ENTRIES: usize = 64;
/// Plafond de lignes de posture lues par le rollup (anti-OOM ; volume posture modeste, cf. seed_sca_dashboard).
const COMPLIANCE_POSTURE_ROW_CAP: i64 = 100_000;

/// Vocabulaire EFFECTIF de cadres = SOCLE core (`COMPLIANCE_FRAMEWORKS`) UNIONNÉ avec l'ADDITIF de config
/// (`PLUME_COMPLIANCE_FRAMEWORKS`, CSV, minuscule, `_` séparateur). Mis en cache au 1er appel (même patron que
/// `endpoint_sources`/`generic_sources`). Le socle est TOUJOURS présent (un cadre client S'AJOUTE, ne remplace
/// pas). Extensible SANS rebuild -> vendor-agnostic.
pub(crate) fn compliance_frameworks() -> &'static [String] {
    static FWS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    FWS.get_or_init(|| {
        let mut v: Vec<String> = COMPLIANCE_FRAMEWORKS.iter().map(|s| s.to_string()).collect();
        if let Ok(extra) = std::env::var("PLUME_COMPLIANCE_FRAMEWORKS") {
            for item in extra.split(',') {
                let fw = compliance_norm_fw(item);
                if !fw.is_empty() && !v.iter().any(|x| x == &fw) {
                    v.push(fw);
                }
            }
        }
        v
    })
}
/// Un cadre est-il connu (socle + additif de config) ? Validation PARSE (jamais interpolé). Casse/vide -> false.
pub(crate) fn compliance_framework_known(fw: &str) -> bool {
    let fw = compliance_norm_fw(fw);
    !fw.is_empty() && compliance_frameworks().iter().any(|x| x == &fw)
}
/// Normalise un nom de cadre : trim + minuscule (les IDs canoniques sont en minuscule/`_`). N'implique PAS
/// la validité (cf. `compliance_framework_known`).
fn compliance_norm_fw(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}
/// Un id de contrôle est-il SÛR ? charset borné (alphanumérique + `. _ - / ( ) space`) et longueur bornée.
/// PAS d'interpolation SQL (stocké en valeur, lu via GXQL/params) — on borne le charset pour éviter le bruit
/// et fermer toute surface d'injection par principe. Vide -> false (un contrôle vide = tag « cadre seul »,
/// géré à part).
fn compliance_ctrl_ok(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= COMPLIANCE_CTRL_MAX
        && c.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/' | '(' | ')' | ' '))
}

/// NORMALISE + VALIDE un tag de conformité de règle : CSV d'entrées `cadre[:contrôle]`. Le CADRE est validé
/// contre le vocab EFFECTIF (inconnu -> `None`, fail-closed : vocabulaire CONTRÔLÉ) ; le CONTRÔLE est libre mais
/// charset-borné (invalide -> `None`). Vide -> `Some("")` (règle non taguée, licite -> mode 0). Dédup + cap.
/// Sortie canonique : `cadre` (cadre seul) ou `cadre:contrôle`, jointe par `,` (même forme que `posture_compliance`).
pub(crate) fn norm_compliance(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return Some(String::new());
    }
    let mut out: Vec<String> = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (fw_raw, ctrl_raw) = match part.split_once(':') {
            Some((f, c)) => (f, Some(c)),
            None => (part, None),
        };
        let fw = compliance_norm_fw(fw_raw);
        if !compliance_framework_known(&fw) {
            return None; // cadre hors-vocab -> rejet (vocabulaire contrôlé)
        }
        let entry = match ctrl_raw.map(|c| c.trim()).filter(|c| !c.is_empty()) {
            None => fw, // cadre seul
            Some(ctrl) => {
                // Un contrôle peut porter plusieurs sous-ids joints par `/` (miroir de flatten_compliance).
                for one in ctrl.split('/').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                    if !compliance_ctrl_ok(one) {
                        return None;
                    }
                }
                format!("{fw}:{ctrl}")
            }
        };
        if !out.iter().any(|e| e == &entry) {
            out.push(entry);
        }
        if out.len() >= COMPLIANCE_MAX_ENTRIES {
            break;
        }
    }
    Some(out.join(","))
}

/// Parse une chaîne de conformité (`rule.compliance` OU `posture_compliance`) -> paires `(cadre, contrôle)`.
/// `contrôle` = "" pour un tag « cadre seul ». Un contrôle multi-id (`pci_dss:1.1/1.2`) -> une paire par id.
/// PUR (aucune DB) : partagé entre le tag de règle et la posture ingérée -> ils joignent sur le MÊME token.
pub(crate) fn compliance_pairs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once(':') {
            None => out.push((compliance_norm_fw(part), String::new())),
            Some((f, c)) => {
                let fw = compliance_norm_fw(f);
                let c = c.trim();
                if c.is_empty() {
                    out.push((fw, String::new()));
                } else {
                    for one in c.split('/').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                        out.push((fw.clone(), one.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// Compteur pass/fail/na d'un contrôle (posture). PUR/testable.
#[derive(Default, Clone, Debug, PartialEq)]
pub(crate) struct CtrlCount {
    pub pass: i64,
    pub fail: i64,
    pub na: i64,
}
impl CtrlCount {
    fn bump(&mut self, result: &str) {
        match result {
            "pass" => self.pass += 1,
            "fail" => self.fail += 1,
            _ => self.na += 1,
        }
    }
}

/// AGRÉGE la posture ingérée en compteurs pass/fail/na PAR `(cadre, contrôle)`. Entrée = itérateur de
/// `(posture_compliance, posture_framework, posture_result)`. Si `posture_compliance` est absente/masquée mais
/// que `posture_framework` liste des cadres, on rabat en niveau CADRE (contrôle=""). `target` filtre à un cadre
/// (None = tous). PUR (aucune DB) -> directement testable.
pub(crate) fn posture_aggregate<I>(rows: I, target: Option<&str>) -> std::collections::BTreeMap<(String, String), CtrlCount>
where
    I: IntoIterator<Item = (String, String, String)>,
{
    let mut agg: std::collections::BTreeMap<(String, String), CtrlCount> = std::collections::BTreeMap::new();
    for (comp, fw_field, result) in rows {
        let result = result.trim().to_ascii_lowercase();
        let mut pairs = compliance_pairs(&comp);
        // Repli : aucune paire détaillée mais des cadres listés -> niveau cadre.
        if pairs.is_empty() && !fw_field.trim().is_empty() {
            for fw in fw_field.split(',').map(|x| compliance_norm_fw(x)).filter(|x| !x.is_empty()) {
                pairs.push((fw, String::new()));
            }
        }
        for (fw, ctrl) in pairs {
            if let Some(t) = target {
                if fw != t {
                    continue;
                }
            }
            agg.entry((fw, ctrl)).or_default().bump(&result);
        }
    }
    agg
}

/// Lit la colonne `rule.compliance` (règles ACTIVÉES) -> map `cadre -> map(contrôle -> [noms de règles])`.
/// "" = règle mappée au cadre sans contrôle précis (couverture cadre-générale). Lecture directe de la table
/// `rule` (métadonnée de détection, viewer-visible comme `rule.mitre` dans coverage_attack) — pas la table event.
fn rule_compliance_map(conn: &Connection) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> {
    let mut map: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> = std::collections::BTreeMap::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT name, COALESCE(compliance,'') FROM rule WHERE enabled=1 AND compliance IS NOT NULL AND compliance<>''",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for (name, comp) in rows.flatten() {
                for (fw, ctrl) in compliance_pairs(&comp) {
                    let e = map.entry(fw).or_default().entry(ctrl).or_default();
                    if !e.contains(&name) {
                        e.push(name.clone());
                    }
                }
            }
        }
    }
    map
}

/// GXQL (fixe, littéral) de lecture de la posture pour le rollup : contrôles SCA détaillés, projetés en
/// `posture_compliance`/`posture_framework`/`posture_result`. Head cap -> anti-OOM. Les tokens sont des
/// CONSTANTES (aucune entrée utilisateur) ; la compilation passe par le chemin GXQL masqué (#45).
pub(crate) fn compliance_posture_soql() -> String {
    format!(
        "search category=posture posture_kind=check | table posture_compliance,posture_framework,posture_result | head {COMPLIANCE_POSTURE_ROW_CAP}"
    )
}

/// Extrait la colonne `col` d'un résultat run_query (`{columns:[…],rows:[[…]]}`) en Vec<String> par ligne.
fn col_of(res: &Value, col: &str) -> Vec<String> {
    let cols = res.get("columns").and_then(|c| c.as_array());
    let idx = cols.and_then(|c| c.iter().position(|x| x.as_str() == Some(col)));
    let rows = res.get("rows").and_then(|r| r.as_array());
    match (idx, rows) {
        (Some(i), Some(rows)) => rows
            .iter()
            .map(|row| row.as_array().and_then(|a| a.get(i)).map(cell_to_string).unwrap_or_default())
            .collect(),
        _ => Vec::new(),
    }
}
fn cell_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// GET `/api/compliance/frameworks` — vocabulaire EFFECTIF des cadres (socle + additif config). viewer+.
pub(crate) async fn compliance_frameworks_list(Extension(_au): Extension<AuthUser>) -> Json<Value> {
    Json(json!({ "frameworks": compliance_frameworks() }))
}

/// GET `/api/compliance/posture[?framework=<id>][&since=<epoch_s>]` — ROLLUP de posture de conformité. viewer+,
/// lecture seule. Compose (a) pass/fail SCA PAR contrôle (posture ingérée, chemin GXQL masqué #45) et (b) les
/// règles de détection qui MAPPENT ce cadre (`rule.compliance`). Sans `framework` : synthèse par cadre. ADDITIF
/// / mode-0 : aucune posture + aucune règle taguée -> tout à zéro (jamais d'erreur). Le cadre est VALIDÉ (vocab).
pub(crate) async fn compliance_posture(
    State(st): State<AppState>,
    Extension(au): Extension<AuthUser>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let target: Option<String> = q.get("framework").map(|s| compliance_norm_fw(s)).filter(|s| !s.is_empty());
    if let Some(fw) = &target {
        if !compliance_framework_known(fw) {
            return Json(json!({ "error": "cadre de conformité inconnu", "frameworks": compliance_frameworks() }));
        }
    }
    let since: i64 = q.get("since").and_then(|s| s.parse().ok()).filter(|&n: &i64| n >= 0).unwrap_or(0);
    let empty = json!({ "framework": target, "controls": [], "rules": [], "totals": {}, "frameworks": compliance_frameworks() });
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(crate::handlers::portillon::corps_de_refus(empty)),
    };
    let db_path = req_db_path(&st, &au);
    let env = au.env_filter();
    // FIELD FILTERS (#45) : masques EFFECTIFS du rôle/tenant/env -> la posture est lue MASQUÉE (RBAC hérité).
    let masks = effective_masks(&db_path, &au.role, &au.tenant, env);
    let sql = match soql_to_sql_masked_x(&compliance_posture_soql(), since, 0, env, &masks) {
        Ok(s) => s,
        Err(_) => return Json(empty),
    };
    let target2 = target.clone();
    let out = tokio::task::spawn_blocking(move || {
        // (a) posture ingérée.
        let res = run_query(&db_path, &sql).unwrap_or_else(|_| json!({ "columns": [], "rows": [] }));
        let comp = col_of(&res, "posture_compliance");
        let fwc = col_of(&res, "posture_framework");
        let rez = col_of(&res, "posture_result");
        let n = comp.len().max(fwc.len()).max(rez.len());
        let rows_iter = (0..n).map(|i| {
            (
                comp.get(i).cloned().unwrap_or_default(),
                fwc.get(i).cloned().unwrap_or_default(),
                rez.get(i).cloned().unwrap_or_default(),
            )
        });
        let agg = posture_aggregate(rows_iter, target2.as_deref());
        // (b) règles mappées.
        let rules = read_with_watchdog(&db_path, std::collections::BTreeMap::new(), rule_compliance_map);
        (agg, rules, res.get("rows").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0))
    })
    .await
    .unwrap_or_else(|_| (std::collections::BTreeMap::new(), std::collections::BTreeMap::new(), 0));
    let (agg, rules, scanned) = out;
    let truncated = scanned as i64 >= COMPLIANCE_POSTURE_ROW_CAP;

    match &target {
        // ---- Un cadre : détail par contrôle (posture) + règles couvrant le cadre. ----
        Some(fw) => {
            let rule_ctrls = rules.get(fw);
            // Union des contrôles vus en posture ET en règles.
            let mut controls: std::collections::BTreeSet<String> = agg.keys().filter(|(f, _)| f == fw).map(|(_, c)| c.clone()).collect();
            if let Some(rc) = rule_ctrls {
                for c in rc.keys() {
                    controls.insert(c.clone());
                }
            }
            let (mut tp, mut tf, mut tn) = (0i64, 0i64, 0i64);
            let ctrl_json: Vec<Value> = controls
                .iter()
                .map(|c| {
                    let cc = agg.get(&(fw.clone(), c.clone())).cloned().unwrap_or_default();
                    tp += cc.pass;
                    tf += cc.fail;
                    tn += cc.na;
                    let covering: Vec<&String> = rule_ctrls.and_then(|rc| rc.get(c)).map(|v| v.iter().collect()).unwrap_or_default();
                    json!({
                        "control": if c.is_empty() { Value::Null } else { json!(c) },
                        "pass": cc.pass, "fail": cc.fail, "na": cc.na,
                        "covered": !covering.is_empty(),
                        "rules": covering,
                    })
                })
                .collect();
            let rules_mapped: Vec<Value> = rule_ctrls
                .map(|rc| {
                    let mut names: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
                    for v in rc.values() {
                        for n in v {
                            names.insert(n);
                        }
                    }
                    names.into_iter().map(|n| json!(n)).collect()
                })
                .unwrap_or_default();
            let n_controls = ctrl_json.len();
            let n_rules = rules_mapped.len();
            Json(json!({
                "framework": fw,
                "since": since,
                "controls": ctrl_json,
                "rules": rules_mapped,
                "totals": { "pass": tp, "fail": tf, "na": tn, "controls": n_controls, "rules_mapped": n_rules },
                "truncated": truncated,
                "frameworks": compliance_frameworks(),
            }))
        }
        // ---- Synthèse : une ligne par cadre (posture + nb de règles mappées). ----
        None => {
            let mut per_fw: std::collections::BTreeMap<String, (CtrlCount, std::collections::BTreeSet<String>)> = std::collections::BTreeMap::new();
            for ((fw, ctrl), cc) in &agg {
                let e = per_fw.entry(fw.clone()).or_default();
                e.0.pass += cc.pass;
                e.0.fail += cc.fail;
                e.0.na += cc.na;
                e.1.insert(ctrl.clone());
            }
            // fusionne les cadres présents UNIQUEMENT en règles.
            for fw in rules.keys() {
                per_fw.entry(fw.clone()).or_default();
            }
            let summary: Vec<Value> = per_fw
                .iter()
                .map(|(fw, (cc, ctrls))| {
                    let n_rules = rules.get(fw).map(|rc| {
                        let mut s: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
                        for v in rc.values() {
                            for n in v {
                                s.insert(n);
                            }
                        }
                        s.len()
                    }).unwrap_or(0);
                    json!({
                        "framework": fw,
                        "pass": cc.pass, "fail": cc.fail, "na": cc.na,
                        "controls": ctrls.iter().filter(|c| !c.is_empty()).count(),
                        "rules_mapped": n_rules,
                    })
                })
                .collect();
            Json(json!({
                "framework": Value::Null,
                "since": since,
                "summary": summary,
                "truncated": truncated,
                "frameworks": compliance_frameworks(),
            }))
        }
    }
}

/// GET `/api/compliance/report?framework=<id>` — RAPPORT DE POSTURE exportable (JSON), read-only. Compose le
/// rollup (`compliance_posture`) + un ANCRAGE DE PREUVE en LECTURE SEULE sur le ledger (tête de chaîne + dernier
/// checkpoint signé) -> adossé au journal d'intégrité tamper-evident SANS l'exporter (export/streaming du ledger
/// = DIFFÉRÉ, revue sécu séparée). HONNÊTE : c'est une POSTURE / COUVERTURE, PAS une certification. viewer+.
pub(crate) async fn compliance_report(
    State(st): State<AppState>,
    Extension(au): Extension<AuthUser>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let target: Option<String> = q.get("framework").map(|s| compliance_norm_fw(s)).filter(|s| !s.is_empty());
    if let Some(fw) = &target {
        if !compliance_framework_known(fw) {
            return Json(json!({ "error": "cadre de conformité inconnu", "frameworks": compliance_frameworks() }));
        }
    }
    // Réutilise le rollup (même chemin masqué / RBAC).
    let rollup = compliance_posture(State(st.clone()), Extension(au.clone()), Query(q.clone())).await.0;
    // ANCRAGE DE PREUVE (lecture seule) : tête du ledger + dernier checkpoint signé. AUCUNE écriture, AUCUN
    // export d'entrées (différé). Le ledger prouve que la config de détection auditée est adossée à une chaîne
    // tamper-evident — la posture n'est PAS une certification, c'est de la couverture prouvable.
    let db_path = req_db_path(&st, &au);
    let evidence = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({}), |conn| {
            let head: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap_or_default();
            let entries: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap_or(0);
            let cp_ts: Option<i64> = conn.query_row("SELECT ts FROM checkpoint ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).ok();
            json!({
                "ledger_head": head,
                "ledger_entries": entries,
                "last_checkpoint_ts": cp_ts,
                "note": "ancrage lecture-seule sur le ledger d'intégrité (Ed25519). L'export/stream du ledger est un chantier séparé (revue sécu).",
            })
        })
    })
    .await
    .unwrap_or_else(|_| json!({}));
    Json(json!({
        "report": "compliance-posture",
        "framework": target,
        "generated": now(),
        "cim_version": CIM_VERSION,
        "disclaimer": "Rapport de POSTURE / COUVERTURE de conformité. Plume montre la couverture des contrôles (pass/fail SCA ingérés) et les détections mappées à un cadre, adossées au ledger d'intégrité. Ce N'EST PAS une certification de conformité ni un audit certifié.",
        "posture": rollup,
        "evidence": evidence,
    }))
}
