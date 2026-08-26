//! #48 + #53 — MATURITÉ DE L'ALERTING : largeur de canaux + suppression avancée + politiques de
//! notification (arbre de routage) + silences temporisés (mute par label-matcher), ledgerisés.
//!
//! INVARIANT MODE 0 (byte-identique) : tant qu'AUCUNE politique (`notification_policy` vide), AUCUN
//! silence actif, AUCUN canal des nouveaux types ET aucune règle « avancée » (throttle/per-result/
//! fenêtre) n'existe, le dispatch se comporte EXACTEMENT comme l'historique (fan-out plat vers tous les
//! canaux `enabled` selon `min_severity`, dédup `rule-{id}`). Les nouveaux comportements s'activent PAR LA
//! DONNÉE (une ligne posée), JAMAIS par un flag — miroir des chantiers correlation/connector/engagement.
//!
//! SÉCURITÉ :
//!  - Les endpoints/clés sensibles des nouveaux canaux (webhook Slack, routing key PagerDuty, en-tête
//!    d'auth du canal générique) vivent dans `notifier.config` (JAMAIS projeté ; miroir `has_auth`).
//!  - Les matchers de label sont validés contre une ALLOWLIST de champs et évalués EN RUST sur une map de
//!    labels (aucune construction de SQL, aucun paramètre non borné) -> injection-safe.
//!  - Le canal générique ne fait QUE substituer des placeholders `{{champ}}` connus (pas de commande, pas
//!    de SSRF au-delà de l'URL configurée). Aucun `run-script` / exécution de commande arbitraire.
//!  - Création/suppression de silence + toute mutation de politique -> `audit_config_change` (ledger
//!    ed25519 hash-chaîné + event plume-config alertable). Un silence NE PEUT PAS être permanent (TTL max).
use crate::*;
use std::collections::BTreeSet;

// ======================================================================================
// 1) CANAUX (#48) — CONSTRUCTEURS DE PAYLOAD (purs, testables)
// ======================================================================================

/// Payload Slack (incoming webhook, format « blocks » + fallback texte). Le titre/détail sont du TEXTE
/// (Slack échappe côté rendu) ; on neutralise quand même les CR/LF (miroir `oneline`).
pub(crate) fn slack_payload(sev: i64, title: &str, detail: &str, host: &str, ts: i64) -> Value {
    let emoji = match sev { 4 => ":rotating_light:", 3 => ":warning:", 2 => ":large_yellow_circle:", 1 => ":large_blue_circle:", _ => ":white_circle:" };
    let sevname = sev_name(sev);
    let header = format!("{emoji} [Plume/{sevname}] {}", oneline(title));
    let ctx = format!("ts={ts}{}", if host.is_empty() { String::new() } else { format!(" · host={}", oneline(host)) });
    json!({
        "text": header,
        "blocks": [
            { "type": "header", "text": { "type": "plain_text", "text": header, "emoji": true } },
            { "type": "section", "text": { "type": "mrkdwn", "text": oneline(detail) } },
            { "type": "context", "elements": [ { "type": "mrkdwn", "text": ctx } ] }
        ]
    })
}

/// Payload PagerDuty Events API v2 (action `trigger`). `dedup_key` -> corrélation/résolution côté PD.
/// `severity` PD ∈ {info,warning,error,critical}. La `routing_key` est fournie À PART (secret).
pub(crate) fn pagerduty_payload(routing_key: &str, dedup_key: &str, sev: i64, title: &str, detail: &str, host: &str, ts: i64) -> Value {
    let pd_sev = match sev { 4 => "critical", 3 => "error", 2 => "warning", _ => "info" };
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": oneline(title),
            "source": if host.is_empty() { "plume".to_string() } else { oneline(host) },
            "severity": pd_sev,
            "timestamp": ts,
            "custom_details": { "detail": oneline(detail), "plume_severity": sev }
        }
    })
}

/// Nom lisible d'une sévérité (0..4).
pub(crate) fn sev_name(sev: i64) -> &'static str {
    match sev { 4 => "critical", 3 => "high", 2 => "medium", 1 => "low", _ => "info" }
}

/// Rendu SÛR d'un gabarit texte pour le canal générique : substitue UNIQUEMENT les placeholders connus
/// `{{severity}} {{sev_name}} {{title}} {{detail}} {{host}} {{ts}}`. Aucune évaluation, aucune commande,
/// aucun accès hors de ces champs. Un placeholder inconnu est laissé tel quel (pas d'erreur silencieuse).
pub(crate) fn render_template(tmpl: &str, sev: i64, title: &str, detail: &str, host: &str, ts: i64) -> String {
    tmpl.replace("{{severity}}", &sev.to_string())
        .replace("{{sev_name}}", sev_name(sev))
        .replace("{{title}}", &oneline(title))
        .replace("{{detail}}", &oneline(detail))
        .replace("{{host}}", &oneline(host))
        .replace("{{ts}}", &ts.to_string())
}

// ======================================================================================
// 2) CANAL output-to-lookup (#48 ↔ #36) — écrit l'alerte dans une table lookup enrichissable
// ======================================================================================

/// Écrit UNE alerte dans le lookup `name` (réutilise `lookup_kv`/`lookup_meta` de #36) sous la clé `key`
/// (valeur du champ-clé, ex `host`/`src_ip`). Le `val` est le JSON des champs de l'alerte -> une détection
/// ultérieure peut faire `... | lookup <name> <keyfield>` pour s'enrichir. Idempotent (INSERT OR REPLACE).
pub(crate) fn write_alert_to_lookup(conn: &Connection, name: &str, key_field: &str, key: &str, fields: &Value) -> rusqlite::Result<()> {
    let cols = fields.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    conn.execute(
        "INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES(?1,?2,?3)",
        params![name, key, fields.to_string()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO lookup_meta(name,key_field,cols,updated) VALUES(?1,?2,?3,?4)",
        params![name, key_field, json!(cols).to_string(), now()],
    )?;
    Ok(())
}

// ======================================================================================
// 3) SUPPRESSION AVANCÉE (#48) — fenêtre / throttle-by-field / per-result (purs, testables)
// ======================================================================================

/// Une « unité de tir » : une alerte candidate. `key` = clé de dédup/throttle (valeur de champ ou index) ;
/// `label` = texte affiché (valeur du champ matché) pour le titre.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FireUnit {
    pub(crate) key: String,
    pub(crate) label: String,
}

/// True si la fenêtre de suppression n'est PAS encore écoulée depuis le dernier tir de cette clé.
/// `window_s<=0` -> jamais supprimé (pas de fenêtre). `last_fire=None` -> jamais tiré -> autorisé.
pub(crate) fn window_suppressed(last_fire: Option<i64>, now_ts: i64, window_s: i64) -> bool {
    if window_s <= 0 {
        return false;
    }
    match last_fire {
        Some(t) => now_ts - t < window_s,
        None => false,
    }
}

/// Extrait la valeur (texte) d'un champ nommé d'une ligne (`columns` = noms, `row` = tableau de valeurs).
/// Renvoie "" si le champ est absent ou nul. Aucune évaluation : simple lecture par index.
pub(crate) fn extract_field_by_name(columns: &[Value], row: &Value, field: &str) -> String {
    let idx = columns.iter().position(|c| c.as_str() == Some(field));
    let Some(i) = idx else { return String::new(); };
    match row.get(i) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// Planifie les unités de tir d'une règle selon son mode :
///  - `per_result`  -> UNE unité par ligne matchée (fire-one-per-result) ;
///  - `throttle_field` (sans per_result) -> UNE unité par VALEUR DISTINCTE du champ (throttle-by-field) ;
///  - sinon -> UNE unité globale (clé "" = dédup `rule-{id}`, comportement historique).
pub(crate) fn plan_fire_units(throttle_field: &str, per_result: bool, columns: &[Value], rows: &[Value]) -> Vec<FireUnit> {
    let tf = throttle_field.trim();
    if per_result {
        return rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                if tf.is_empty() {
                    FireUnit { key: format!("r{i}"), label: format!("#{}", i + 1) }
                } else {
                    let fv = extract_field_by_name(columns, row, tf);
                    // per-result + throttle_field : la clé reste unique par ligne (index) pour NE PAS fusionner
                    // deux résultats partageant la même valeur ; le label porte la valeur du champ.
                    FireUnit { key: format!("r{i}"), label: fv }
                }
            })
            .collect();
    }
    if !tf.is_empty() {
        let mut seen = BTreeSet::new();
        let mut units = Vec::new();
        for row in rows {
            let fv = extract_field_by_name(columns, row, tf);
            if fv.is_empty() {
                continue;
            }
            if seen.insert(fv.clone()) {
                units.push(FireUnit { key: fv.clone(), label: fv });
            }
        }
        return units;
    }
    vec![FireUnit { key: String::new(), label: String::new() }]
}

// ======================================================================================
// 4) MATCHERS DE LABEL (allowlist, injection-safe) + LABELS D'ALERTE
// ======================================================================================

/// Champs de label AUTORISÉS pour les matchers (politiques + silences). Fermé : tout autre champ est refusé
/// à la validation -> pas de champ arbitraire, pas de construction SQL (l'évaluation est en Rust sur la map).
pub(crate) const MATCHER_FIELDS: &[&str] = &["severity", "mitre", "host", "source", "env", "tag"];

pub(crate) fn valid_matcher_field(f: &str) -> bool {
    MATCHER_FIELDS.contains(&f)
}

/// Parse + VALIDE des matchers depuis un JSON objet `{champ: valeur, ...}` (valeurs texte ou nombre).
/// Rejette : non-objet, champ hors allowlist, valeur non scalaire, valeur vide, plus de 8 matchers.
/// Renvoie une liste TRIÉE par champ (déterminisme d'affichage/stockage/spécificité).
pub(crate) fn parse_matchers(v: &Value) -> Result<Vec<(String, String)>, String> {
    let obj = v.as_object().ok_or_else(|| "matchers doit être un objet {champ:valeur}".to_string())?;
    if obj.len() > 8 {
        return Err("trop de matchers (max 8)".into());
    }
    let mut out = Vec::new();
    for (k, val) in obj {
        if !valid_matcher_field(k) {
            return Err(format!("champ de matcher non autorisé: '{k}' (autorisés: {})", MATCHER_FIELDS.join(",")));
        }
        let sval = match val {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return Err(format!("valeur de matcher invalide pour '{k}' (texte/nombre attendu)")),
        };
        if sval.trim().is_empty() {
            return Err(format!("valeur de matcher vide pour '{k}'"));
        }
        if sval.len() > 256 {
            return Err(format!("valeur de matcher trop longue pour '{k}'"));
        }
        out.push((k.clone(), sval));
    }
    out.sort();
    Ok(out)
}

/// Sérialise des matchers en JSON objet canonique (pour stockage/affichage).
pub(crate) fn matchers_to_json(m: &[(String, String)]) -> String {
    let map: serde_json::Map<String, Value> = m.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    Value::Object(map).to_string()
}

/// Recharge des matchers depuis leur JSON stocké (tolérant : un blob invalide -> aucun matcher).
pub(crate) fn matchers_from_json(s: &str) -> Vec<(String, String)> {
    serde_json::from_str::<Value>(s).ok().and_then(|v| parse_matchers(&v).ok()).unwrap_or_default()
}

/// True si TOUS les matchers sont satisfaits par la map de labels (AND). Un matcher `{}` (vide) matche tout.
pub(crate) fn matchers_match(m: &[(String, String)], labels: &HashMap<String, String>) -> bool {
    m.iter().all(|(k, v)| labels.get(k).map(|lv| lv == v).unwrap_or(false))
}

/// Construit la map de labels d'une alerte pour le routage/silence. `source` = identifiant de règle/source
/// (colonne `alert.rule`). `env` = env_id (axe intra-tenant). Le tenant est IMPLICITE (une base par tenant).
pub(crate) fn alert_labels(severity: i64, mitre: &str, host: &str, source: &str, env: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("severity".to_string(), severity.to_string());
    if !mitre.is_empty() {
        m.insert("mitre".to_string(), mitre.to_string());
    }
    if !host.is_empty() {
        m.insert("host".to_string(), host.to_string());
    }
    if !source.is_empty() {
        m.insert("source".to_string(), source.to_string());
    }
    if !env.is_empty() {
        m.insert("env".to_string(), env.to_string());
    }
    m
}

// ======================================================================================
// 5) POLITIQUES DE NOTIFICATION (#53) — arbre de routage most-specific-wins + route par défaut
// ======================================================================================

#[derive(Debug, Clone)]
pub(crate) struct Policy {
    pub(crate) id: i64,
    pub(crate) matchers: Vec<(String, String)>,
    pub(crate) contacts: Vec<i64>,
    /// `continue` : après avoir matché, on ÉVALUE AUSSI les routes moins spécifiques (union des contacts).
    pub(crate) cont: bool,
}

/// Route une alerte (via ses labels) vers des points de contact (ids de canaux). Sémantique :
///  - on ne garde que les politiques dont les matchers matchent les labels ;
///  - la PLUS SPÉCIFIQUE gagne (plus grand nombre de matchers ; départage par id croissant) ;
///  - si elle porte `continue`, on cumule aussi les contacts de la suivante (moins spécifique), et ainsi de
///    suite tant que la route courante est `continue` ;
///  - une politique `{}` (0 matcher) = ROUTE PAR DÉFAUT (matche tout, la moins spécifique).
/// Aucune correspondance -> aucun contact (routage explicite : à l'opérateur de poser une route par défaut).
pub(crate) fn route_contacts(policies: &[Policy], labels: &HashMap<String, String>) -> Vec<i64> {
    let mut matched: Vec<&Policy> = policies.iter().filter(|p| matchers_match(&p.matchers, labels)).collect();
    // plus spécifique d'abord (nb de matchers desc), départage id croissant (déterministe).
    matched.sort_by(|a, b| b.matchers.len().cmp(&a.matchers.len()).then(a.id.cmp(&b.id)));
    let mut out: Vec<i64> = Vec::new();
    for p in matched {
        for c in &p.contacts {
            if !out.contains(c) {
                out.push(*c);
            }
        }
        if !p.cont {
            break;
        }
    }
    out
}

// ======================================================================================
// 6) SILENCES (#53) — mute temporisé par label-matcher
// ======================================================================================

/// True si l'alerte (labels) est mutée par AU MOINS un silence actif (liste de jeux de matchers).
pub(crate) fn alert_is_silenced(silences: &[Vec<(String, String)>], labels: &HashMap<String, String>) -> bool {
    silences.iter().any(|m| matchers_match(m, labels))
}

/// TTL maximal d'un silence (secondes). Un silence NE PEUT PAS être permanent (gouvernance). Défaut 30 j ;
/// borne configurable par l'admin via `PLUME_SILENCE_MAX_TTL_S` (>=60). Un create au-delà est rejeté.
pub(crate) fn silence_max_ttl_s() -> i64 {
    std::env::var("PLUME_SILENCE_MAX_TTL_S").ok().and_then(|v| v.parse().ok()).filter(|&n: &i64| n >= 60).unwrap_or(2_592_000)
}

// ======================================================================================
// 7) PLAN DE DISPATCH (mode-0 preserving) — silence + routage, ou fan-out plat
// ======================================================================================

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DispatchPlan {
    pub(crate) silenced: bool,
    pub(crate) target_ids: Vec<i64>,
}

/// Décide, pour une alerte, si elle est mutée et vers QUELS canaux la router.
///  - AUCUNE politique -> `target_ids` = TOUS les canaux `enabled` (FAN-OUT PLAT = comportement historique) ;
///  - politiques présentes -> routage most-specific-wins, borné aux canaux réellement `enabled`.
/// Le filtre `severity>=min_severity` reste appliqué PAR CANAL dans la boucle d'envoi (inchangé).
pub(crate) fn plan_dispatch(labels: &HashMap<String, String>, policies: &[Policy], silences: &[Vec<(String, String)>], enabled_ids: &[i64]) -> DispatchPlan {
    let silenced = alert_is_silenced(silences, labels);
    let target_ids = if policies.is_empty() {
        enabled_ids.to_vec()
    } else {
        route_contacts(policies, labels).into_iter().filter(|id| enabled_ids.contains(id)).collect()
    };
    DispatchPlan { silenced, target_ids }
}

// ======================================================================================
// 8) FIRING AVANCÉ — run_advanced_rules (isolé, comme run_risk_rules ; mode-0 = 0 ligne due)
// ======================================================================================

/// Évalue les règles « avancées » (fenêtre de suppression / throttle-by-field / per-result) EXCLUES de
/// `run_due_rules`. INERTE en mode 0 : aucune règle ne porte ces réglages -> le SELECT ne rend 0 ligne ->
/// retour immédiat (run_due_rules reste byte-identique car son WHERE exclut ces mêmes règles).
/// REND SON BILAN (`P4.1-r`, même contrat que `run_due_rules`) : `Illisible` si la liste des règles
/// avancées dues n'a pas pu être lue, `Lue(n)` = règles dues abandonnées ce tick.
pub(crate) fn run_advanced_rules(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnees = 0u32;
    let due: Vec<(i64, String, String, bool, String, f64, i64, i64, String, i64, String, bool)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id,name,query,is_soql,op,threshold,severity,window_s,COALESCE(mitre,''), \
                    COALESCE(suppress_window_s,0),COALESCE(throttle_field,''),COALESCE(per_result,0) \
             FROM rule \
             WHERE enabled=1 AND COALESCE(risk_score,0)=0 \
               AND (COALESCE(suppress_window_s,0)>0 OR COALESCE(throttle_field,'')<>'' OR COALESCE(per_result,0)<>0) \
               AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles avancées", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0,
                r.get::<_, String>(4)?, r.get::<_, f64>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?, r.get::<_, String>(8)?,
                r.get::<_, i64>(9)?, r.get::<_, String>(10)?, r.get::<_, i64>(11)? != 0,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles avancées", &e),
        };
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(x) => due.push(x),
                Err(_) => abandonnees += 1, // ligne indécodable : une règle non évaluée, comptée
            }
        }
        due
    };
    for (id, name, query, is_soql, op, threshold, severity, window_s, mitre, suppress_window_s, throttle_field, per_result) in due {
        let sql = match rule_sql(&query, is_soql, window_s) {
            Ok(s) => s,
            Err(_) => {
                abandonnees += 1;
                let conn = db.lock();
                let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now_ts, id]);
                continue;
            }
        };
        // scalaire décide s'il y a franchissement (comme run_due_rules) — fail-closed si éval échoue.
        let scalar = eval_value_budget(db_path, &sql, query_budget_interactive_ms());
        let Some(val) = scalar else {
            abandonnees += 1;
            let conn = db.lock();
            let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now_ts, id]);
            continue;
        };
        {
            let conn = db.lock();
            let _ = conn.execute("UPDATE rule SET last_run=?1, last_value=?2 WHERE id=?3", params![now_ts, val, id]);
        }
        if !cmp_op(val, &op, threshold) {
            // retour sous le seuil -> résout les alertes ouvertes de CETTE règle (préfixe de dédup) et purge le throttle.
            let conn = db.lock();
            let like = format!("rule-{id}::%");
            let _ = conn.execute("UPDATE alert SET status='resolved', dedup=NULL WHERE dedup LIKE ?1 AND status IN ('new','ack')", params![like]);
            let _ = conn.execute("DELETE FROM alert_throttle WHERE rule_id=?1", params![id]);
            continue;
        }
        // fenêtre de throttle : suppress_window_s si posé, sinon la fenêtre d'évaluation de la règle.
        let win = if suppress_window_s > 0 { suppress_window_s } else { window_s };
        // per-result/throttle-by-field ont besoin des LIGNES ; fenêtre-seule n'en a pas besoin (unité globale).
        let units = if per_result || !throttle_field.is_empty() {
            match run_query_ex(db_path, &sql, query_budget_interactive_ms(), None) {
                Ok(v) => {
                    let cols = v.get("columns").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                    let rows = v.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                    plan_fire_units(&throttle_field, per_result, &cols, &rows)
                }
                Err(_) => {
                    abandonnees += 1; // fail-closed : pas de fabrication d'unités sur éval en erreur — et c'est COMPTÉ
                    continue;
                }
            }
        } else {
            plan_fire_units("", false, &[], &[])
        };
        let conn = db.lock();
        for unit in units {
            let last_fire: Option<i64> = conn
                .query_row("SELECT last_fire FROM alert_throttle WHERE rule_id=?1 AND throttle_key=?2", params![id, unit.key], |r| r.get(0))
                .ok();
            if window_suppressed(last_fire, now_ts, win) {
                continue; // muté par la fenêtre de suppression
            }
            let dedup = format!("rule-{id}::{}", unit.key);
            let title = if unit.label.is_empty() {
                format!("{name} : {val} {op} {threshold}")
            } else {
                format!("{name} [{}] : {val} {op} {threshold}", unit.label)
            };
            // #3 P3-A — CAPTURE STRUCTURÉE BEST-EFFORT (additif, mode-0 byte-identique quand NULL). `unit.label`
            // porte la VALEUR du champ de throttle (throttle-only : key==label==valeur ; per_result : key="r{i}"
            // mais label==valeur -> on prend TOUJOURS `label`, jamais `key`, sinon on stockerait un index "r0").
            // On NE MAPPE QUE des noms de colonne CIM sans ambiguïté (src_ip/pid/host) -> AUCUN mislabel : un
            // group-by arbitraire (rule/source/user…) laisse les trois colonnes NULL (repli blanc au wizard).
            // La cible n'est jamais auto-jouée : re-validée par action_valid_ctx au wizard PUIS à /api/actions.
            let ent = unit.label.trim();
            let (a_src, a_pid, a_host): (Option<&str>, Option<&str>, Option<&str>) = if ent.is_empty() {
                (None, None, None)
            } else {
                match throttle_field.as_str() {
                    "src_ip" => (Some(ent), None, None),
                    "pid" => (None, Some(ent), None),
                    "host" => (None, None, Some(ent)),
                    _ => (None, None, None),
                }
            };
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre,src_ip,pid,host) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![now_ts, format!("rule.{id}"), severity, title, query, dedup, mitre, a_src, a_pid, a_host],
            );
            let _ = conn.execute(
                "INSERT OR REPLACE INTO alert_throttle(rule_id,throttle_key,last_fire) VALUES(?1,?2,?3)",
                params![id, unit.key, now_ts],
            );
        }
        let _ = conn.execute("UPDATE rule SET last_fired=?1 WHERE id=?2", params![now_ts, id]);
    }
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

// ======================================================================================
// 9) HANDLERS — politiques de notification (editor+ ; GET viewer+)
// ======================================================================================

pub(crate) async fn policies_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare("SELECT id,matchers,contact_points,continue_,enabled,COALESCE(created_by,'') FROM notification_policy ORDER BY id") {
        Ok(s) => s,
        Err(_) => return Json(json!({ "policies": [] })),
    };
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            let matchers: String = r.get(1)?;
            let contacts: String = r.get(2)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "matchers": serde_json::from_str::<Value>(&matchers).unwrap_or_else(|_| json!({})),
                "contact_points": contacts.split(',').filter(|s| !s.is_empty()).filter_map(|s| s.parse::<i64>().ok()).collect::<Vec<_>>(),
                "continue": r.get::<_, i64>(3)? != 0,
                "enabled": r.get::<_, i64>(4)? != 0,
                "created_by": r.get::<_, String>(5)?,
            }))
        })
        .map(|x| x.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "policies": rows }))
}

/// Parse + valide {matchers, contact_points[], continue, enabled} -> (matchers_json, contacts_csv, cont, enabled).
fn policy_body(b: &Value) -> Result<(String, String, i64, i64), String> {
    let matchers = parse_matchers(b.get("matchers").unwrap_or(&json!({})))?;
    let contacts: Vec<i64> = match b.get("contact_points") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_i64()).collect(),
        _ => return Err("contact_points doit être un tableau d'ids de canaux".into()),
    };
    if contacts.is_empty() {
        return Err("au moins un point de contact requis".into());
    }
    if contacts.len() > 32 {
        return Err("trop de points de contact (max 32)".into());
    }
    let csv = contacts.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let cont = b.bool_field("continue", false) as i64;
    let enabled = b.bool_field("enabled", true) as i64;
    Ok((matchers_to_json(&matchers), csv, cont, enabled))
}

pub(crate) async fn policy_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let (matchers, csv, cont, enabled) = match policy_body(&b) {
        Ok(x) => x,
        Err(e) => return bad_req(e),
    };
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO notification_policy(matchers,contact_points,continue_,enabled,created,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
            params![matchers, csv, cont, enabled, now(), au.name],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.notification-policy.create",
            &format!("politique de notification #{id} créée par {} (matchers={matchers} -> canaux {csv})", au.name), 2,
            &format!("route de notification #{id} créée par {}", au.name),
            &json!({ "op": "create", "kind": "notification-policy", "id": id, "matchers": matchers, "contacts": csv, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn policy_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let (matchers, csv, cont, enabled) = match policy_body(&b) {
        Ok(x) => x,
        Err(e) => return bad_req(e),
    };
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM notification_policy WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("politique introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(
            "UPDATE notification_policy SET matchers=?1, contact_points=?2, continue_=?3, enabled=?4 WHERE id=?5",
            params![matchers, csv, cont, enabled, id],
        )?;
        audit_config_change(
            &conn, "config.notification-policy.update",
            &format!("politique de notification #{id} modifiée par {}", au.name), 2,
            &format!("route de notification #{id} modifiée par {}", au.name),
            &json!({ "op": "update", "kind": "notification-policy", "id": id, "matchers": matchers, "contacts": csv, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn policy_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM notification_policy WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("politique introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM notification_policy WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.notification-policy.delete",
            &format!("politique de notification #{id} supprimée par {}", au.name), 2,
            &format!("route de notification #{id} supprimée par {}", au.name),
            &json!({ "op": "delete", "kind": "notification-policy", "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// ======================================================================================
// 10) HANDLERS — silences (editor+ ; GET viewer+). Create/update/delete LEDGERISÉS. TTL borné.
// ======================================================================================

pub(crate) async fn silences_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let now_ts = now();
    let mut stmt = match conn.prepare("SELECT id,matchers,expires_at,COALESCE(reason,''),created,COALESCE(created_by,'') FROM silence ORDER BY id DESC") {
        Ok(s) => s,
        Err(_) => return Json(json!({ "silences": [] })),
    };
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            let matchers: String = r.get(1)?;
            let expires: i64 = r.get(2)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "matchers": serde_json::from_str::<Value>(&matchers).unwrap_or_else(|_| json!({})),
                "expires_at": expires,
                "active": expires > now_ts,
                "reason": r.get::<_, String>(3)?,
                "created": r.get::<_, i64>(4)?,
                "created_by": r.get::<_, String>(5)?,
            }))
        })
        .map(|x| x.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "silences": rows }))
}

pub(crate) async fn silence_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let matchers = match parse_matchers(b.get("matchers").unwrap_or(&json!({}))) {
        Ok(m) => m,
        Err(e) => return bad_req(e),
    };
    if matchers.is_empty() {
        return bad_req("un silence doit porter au moins un matcher (mute par label)");
    }
    let dur = b.i64_field("duration_s", 3600);
    if dur <= 0 {
        return bad_req("duration_s doit être > 0");
    }
    let max = silence_max_ttl_s();
    if dur > max {
        return bad_req(format!("durée de silence trop longue (max {max}s) — un silence ne peut être permanent"));
    }
    let reason = b.str_field("reason").trim().to_string();
    let now_ts = now();
    let expires = now_ts + dur;
    let matchers_json = matchers_to_json(&matchers);
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES(?1,?2,?3,?4,?5)",
            params![matchers_json, expires, reason, now_ts, au.name],
        )?;
        let id = conn.last_insert_rowid();
        // sévérité 3 : muter des alertes pendant un incident est un ÉVÉNEMENT DE GOUVERNANCE notable.
        audit_config_change(
            &conn, "config.silence.create",
            &format!("silence #{id} créé par {} (matchers={matchers_json}, expire={expires}, raison='{reason}')", au.name), 3,
            &format!("silence de notification #{id} créé par {} (expire à {expires})", au.name),
            &json!({ "op": "create", "kind": "silence", "id": id, "matchers": matchers_json, "expires_at": expires, "reason": reason, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "expires_at": expires })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

/// PUT|POST /api/silences/{id} — MODIFIE un silence existant (P11.5-a : le troisième geste de l'administrateur,
/// entre créer et lever). Corps partiel : `matchers` (objet, re-validé par `parse_matchers`), `duration_s`
/// (nouvelle durée COMPTÉE DEPUIS MAINTENANT, bornée par le même TTL maximal que la création : un silence
/// ne devient pas permanent par modification), `reason`. Rôle : editor+ (même classe que create/delete,
/// section 7 de `route_min_role`). Audit : `config.silence.update` (ledger + event plume-config, sévérité 3,
/// fail-closed : rien n'est persisté si l'audit échoue) — MÊME mécanisme que create/delete.
pub(crate) async fn silence_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let Ok((old_matchers, old_expires, old_reason)) = conn.query_row(
        "SELECT matchers, expires_at, COALESCE(reason,'') FROM silence WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)),
    ) else {
        return not_found("silence introuvable");
    };
    // Validation COMPLÈTE avant toute écriture : un corps invalide ne modifie rien.
    let matchers_json = match b.get("matchers") {
        Some(m) => match parse_matchers(m) {
            Ok(list) if !list.is_empty() => matchers_to_json(&list),
            Ok(_) => return bad_req("un silence doit porter au moins un matcher (mute par label)"),
            Err(e) => return bad_req(e),
        },
        None => old_matchers.clone(),
    };
    let now_ts = now();
    let expires = match b.get("duration_s").and_then(|v| v.as_i64()) {
        Some(dur) if dur <= 0 => return bad_req("duration_s doit être > 0"),
        Some(dur) => {
            let max = silence_max_ttl_s();
            if dur > max {
                return bad_req(format!("durée de silence trop longue (max {max}s) — un silence ne peut être permanent"));
            }
            now_ts + dur
        }
        None => old_expires,
    };
    let reason = match b.get("reason").and_then(|v| v.as_str()) {
        Some(r) => r.trim().to_string(),
        None => old_reason.clone(),
    };
    if matchers_json == old_matchers && expires == old_expires && reason == old_reason {
        return Json(json!({ "ok": true, "id": id, "expires_at": expires, "changed": false })).into_response();
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(
            "UPDATE silence SET matchers=?1, expires_at=?2, reason=?3 WHERE id=?4",
            params![matchers_json, expires, reason, id],
        )?;
        audit_config_change(
            &conn, "config.silence.update",
            &format!("silence #{id} modifié par {} (matchers={matchers_json}, expire={expires}, raison='{reason}')", au.name), 3,
            &format!("silence de notification #{id} modifié par {} (expire à {expires})", au.name),
            &json!({ "op": "update", "kind": "silence", "id": id, "matchers": matchers_json, "expires_at": expires, "reason": reason, "old": { "matchers": old_matchers, "expires_at": old_expires, "reason": old_reason }, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true, "id": id, "expires_at": expires, "changed": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn silence_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM silence WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("silence introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM silence WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.silence.delete",
            &format!("silence #{id} levé par {}", au.name), 3,
            &format!("silence de notification #{id} levé (supprimé) par {}", au.name),
            &json!({ "op": "delete", "kind": "silence", "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// ======================================================================================
// 11) CHARGEMENTS pour le dispatch (politiques + silences actifs)
// ======================================================================================

/// Charge les politiques (vide si la table n'existe pas / est vide -> le dispatch retombe en fan-out plat).
pub(crate) fn load_policies(conn: &Connection) -> Vec<Policy> {
    let mut stmt = match conn.prepare("SELECT id,matchers,contact_points,continue_ FROM notification_policy WHERE enabled=1") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| {
        let matchers: String = r.get(1)?;
        let contacts: String = r.get(2)?;
        Ok(Policy {
            id: r.get(0)?,
            matchers: matchers_from_json(&matchers),
            contacts: contacts.split(',').filter(|s| !s.is_empty()).filter_map(|s| s.parse::<i64>().ok()).collect(),
            cont: r.get::<_, i64>(3)? != 0,
        })
    })
    .map(|x| x.flatten().collect())
    .unwrap_or_default()
}

/// Charge les jeux de matchers des silences ACTIFS (expires_at>now) — un silence expiré est ignoré (auto-expiry).
pub(crate) fn load_active_silences(conn: &Connection, now_ts: i64) -> Vec<Vec<(String, String)>> {
    let mut stmt = match conn.prepare("SELECT matchers FROM silence WHERE expires_at>?1") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map(params![now_ts], |r| {
        let m: String = r.get(0)?;
        Ok(matchers_from_json(&m))
    })
    .map(|x| x.flatten().filter(|m| !m.is_empty()).collect())
    .unwrap_or_default()
}

// ======================================================================================
// TESTS
// ======================================================================================
#[cfg(test)]
mod alerting_tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(crate::migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn
    }

    // ---- #48 canaux : forme de payload ----
    #[test]
    fn slack_payload_shape() {
        let p = slack_payload(4, "Brute force SSH", "50 échecs", "web-01", 1000);
        assert!(p.get("blocks").and_then(|b| b.as_array()).map(|a| a.len() == 3).unwrap_or(false));
        assert!(p["text"].as_str().unwrap().contains("rotating_light"));
        assert!(p["blocks"][1]["text"]["text"].as_str().unwrap().contains("50 échecs"));
    }

    #[test]
    fn pagerduty_payload_shape() {
        let p = pagerduty_payload("RK-SECRET", "rule-7::1.2.3.4", 3, "Exfil", "détail", "db-01", 42);
        assert_eq!(p["routing_key"], "RK-SECRET");
        assert_eq!(p["event_action"], "trigger");
        assert_eq!(p["dedup_key"], "rule-7::1.2.3.4");
        assert_eq!(p["payload"]["severity"], "error");
        assert_eq!(p["payload"]["source"], "db-01");
        assert_eq!(p["payload"]["summary"], "Exfil");
    }

    #[test]
    fn generic_template_is_safe_and_substitutes() {
        let out = render_template("[{{sev_name}}] {{title}} on {{host}} @ {{ts}} — {{detail}}", 3, "T", "D", "h1", 99);
        assert_eq!(out, "[high] T on h1 @ 99 — D");
        // placeholder inconnu laissé tel quel (pas d'exécution) ; CR/LF neutralisés dans les valeurs.
        // oneline() neutralise CHAQUE CR/LF en espace -> "a\r\nb" devient "a  b" (deux espaces) : pas
        // d'injection d'en-tête/ligne possible dans le corps rendu, et placeholder inconnu laissé tel quel.
        let inj = render_template("{{title}}|{{unknown}}", 2, "a\r\nb", "", "", 0);
        assert_eq!(inj, "a  b|{{unknown}}");
    }

    // ---- #48 output-to-lookup ----
    #[test]
    fn output_to_lookup_writes_and_reads_back() {
        let conn = mem();
        let fields = json!({ "host": "web-01", "severity": 3, "title": "SSH brute" });
        write_alert_to_lookup(&conn, "alerts", "host", "web-01", &fields).unwrap();
        let val: String = conn.query_row("SELECT val FROM lookup_kv WHERE name='alerts' AND \"key\"='web-01'", [], |r| r.get(0)).unwrap();
        assert!(val.contains("SSH brute"));
        let kf: String = conn.query_row("SELECT key_field FROM lookup_meta WHERE name='alerts'", [], |r| r.get(0)).unwrap();
        assert_eq!(kf, "host");
    }

    // ---- #48 suppression window ----
    #[test]
    fn suppression_window_mutes_within_n_minutes() {
        // fenêtre 300 s : re-tir à +100 s muté, re-tir à +400 s autorisé, jamais-tiré autorisé.
        assert!(window_suppressed(Some(1000), 1100, 300), "re-tir dans la fenêtre = muté");
        assert!(!window_suppressed(Some(1000), 1400, 300), "au-delà de la fenêtre = autorisé");
        assert!(!window_suppressed(None, 1100, 300), "jamais tiré = autorisé");
        assert!(!window_suppressed(Some(1000), 1100, 0), "pas de fenêtre = jamais muté");
    }

    // ---- #48 throttle-by-field : un tir par valeur distincte ----
    #[test]
    fn throttle_by_field_one_unit_per_distinct_value() {
        let cols = vec![json!("src_ip"), json!("n")];
        let rows = vec![
            json!(["1.1.1.1", 5]),
            json!(["1.1.1.1", 9]),
            json!(["2.2.2.2", 3]),
        ];
        let units = plan_fire_units("src_ip", false, &cols, &rows);
        assert_eq!(units.len(), 2, "une unité par src_ip distinct");
        let keys: Vec<&str> = units.iter().map(|u| u.key.as_str()).collect();
        assert!(keys.contains(&"1.1.1.1") && keys.contains(&"2.2.2.2"));
    }

    // ---- #48 per-result firing : un tir par ligne ----
    #[test]
    fn per_result_one_unit_per_row() {
        let cols = vec![json!("src_ip")];
        let rows = vec![json!(["a"]), json!(["a"]), json!(["b"])];
        let units = plan_fire_units("src_ip", true, &cols, &rows);
        assert_eq!(units.len(), 3, "une unité par ligne (même valeur non fusionnée)");
        // clés uniques par ligne
        let keys: BTreeSet<&str> = units.iter().map(|u| u.key.as_str()).collect();
        assert_eq!(keys.len(), 3);
    }

    // ---- #53 routage : most-specific-wins + défaut ----
    #[test]
    fn policy_routes_most_specific_wins_and_default() {
        let policies = vec![
            Policy { id: 1, matchers: vec![], contacts: vec![10], cont: false }, // défaut
            Policy { id: 2, matchers: vec![("severity".into(), "4".into())], contacts: vec![20], cont: false },
            Policy { id: 3, matchers: vec![("severity".into(), "4".into()), ("mitre".into(), "T1110".into())], contacts: vec![30], cont: false },
        ];
        // crit + T1110 -> la plus spécifique (#3)
        let l = alert_labels(4, "T1110", "", "", "");
        assert_eq!(route_contacts(&policies, &l), vec![30]);
        // crit sans mitre -> #2
        let l2 = alert_labels(4, "", "", "", "");
        assert_eq!(route_contacts(&policies, &l2), vec![20]);
        // low -> route par défaut #1
        let l3 = alert_labels(1, "", "", "", "");
        assert_eq!(route_contacts(&policies, &l3), vec![10]);
    }

    #[test]
    fn policy_continue_unions_less_specific() {
        let policies = vec![
            Policy { id: 1, matchers: vec![], contacts: vec![10], cont: false },
            Policy { id: 2, matchers: vec![("severity".into(), "4".into())], contacts: vec![20], cont: true },
        ];
        let l = alert_labels(4, "", "", "", "");
        assert_eq!(route_contacts(&policies, &l), vec![20, 10], "continue cumule la route par défaut");
    }

    // ---- #53 silence : matche + auto-expiry + ledger ----
    #[test]
    fn silence_matches_and_auto_expires_and_is_ledgerised() {
        let conn = mem();
        let now_ts = now();
        // silence actif sur host=web-01
        conn.execute(
            "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES(?1,?2,'maint',?3,'alice')",
            params![matchers_to_json(&[("host".into(), "web-01".into())]), now_ts + 600, now_ts],
        ).unwrap();
        // silence EXPIRÉ sur host=db-01
        conn.execute(
            "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES(?1,?2,'old',?3,'alice')",
            params![matchers_to_json(&[("host".into(), "db-01".into())]), now_ts - 10, now_ts],
        ).unwrap();
        // ledger d'un create (simule le handler)
        audit_config_change(&conn, "config.silence.create", "silence test", 3, "silence test", "{}").unwrap();

        let active = load_active_silences(&conn, now_ts);
        assert_eq!(active.len(), 1, "seul le silence non expiré est actif (auto-expiry)");
        let l = alert_labels(3, "", "web-01", "", "");
        assert!(alert_is_silenced(&active, &l), "alerte host=web-01 mutée");
        let l2 = alert_labels(3, "", "db-01", "", "");
        assert!(!alert_is_silenced(&active, &l2), "alerte host=db-01 NON mutée (silence expiré)");
        // ledgerisation
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.silence.create'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "création de silence ledgerisée (tamper-evident)");
    }

    // ---- MODE 0 : aucune politique/silence -> fan-out plat identique ----
    #[test]
    fn mode0_no_policy_no_silence_is_flat_fanout() {
        let l = alert_labels(3, "T1110", "web-01", "rule.5", "prod");
        let enabled = vec![1i64, 2, 3];
        let plan = plan_dispatch(&l, &[], &[], &enabled);
        assert!(!plan.silenced);
        assert_eq!(plan.target_ids, enabled, "sans politique -> TOUS les canaux enabled (fan-out plat historique)");
    }

    #[test]
    fn dispatch_routes_and_silences_when_configured() {
        let l = alert_labels(4, "", "web-01", "", "");
        let policies = vec![
            Policy { id: 1, matchers: vec![], contacts: vec![1], cont: false },
            Policy { id: 2, matchers: vec![("severity".into(), "4".into())], contacts: vec![2, 99], cont: false },
        ];
        let enabled = vec![1i64, 2, 3];
        let plan = plan_dispatch(&l, &policies, &[], &enabled);
        assert_eq!(plan.target_ids, vec![2], "route la crit vers le canal 2 (99 filtré: non enabled)");
        // avec silence host=web-01
        let sil = vec![vec![("host".to_string(), "web-01".to_string())]];
        let plan2 = plan_dispatch(&l, &policies, &sil, &enabled);
        assert!(plan2.silenced, "alerte mutée par silence host=web-01");
    }

    // ---- matchers injection-safe (allowlist) ----
    #[test]
    fn matchers_reject_unknown_field() {
        assert!(parse_matchers(&json!({ "severity": "4" })).is_ok());
        assert!(parse_matchers(&json!({ "host": "web-01", "mitre": "T1110" })).is_ok());
        assert!(parse_matchers(&json!({ "drop table": "x" })).is_err(), "champ hors allowlist refusé");
        assert!(parse_matchers(&json!({ "severity": "" })).is_err(), "valeur vide refusée");
        assert!(parse_matchers(&json!("not an object")).is_err());
    }

    // ---- migration v89 : tables + colonnes présentes, mode-0 inerte ----
    #[test]
    fn migration_v89_tables_and_columns() {
        let conn = mem();
        let ver: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert!(ver.parse::<i64>().unwrap() >= 89);
        // tables créées + vides (mode 0)
        for t in ["notification_policy", "silence", "alert_throttle"] {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "table {t} vide en mode 0");
        }
        // colonnes additives sur rule
        conn.execute("INSERT INTO rule(name) VALUES('r')", []).unwrap();
        let (sw, tf, pr): (i64, String, i64) = conn
            .query_row("SELECT COALESCE(suppress_window_s,0),COALESCE(throttle_field,''),COALESCE(per_result,0) FROM rule", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!((sw, tf.as_str(), pr), (0, "", 0), "défauts inertes -> règle traitée par run_due_rules (mode 0)");
    }
}
