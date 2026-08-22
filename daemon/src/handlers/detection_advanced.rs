//! #37 DÉTECTION AVANCÉE — deux moteurs ADDITIFS, INERTES en mode 0 (tables vides -> zéro travail, zéro
//! écriture, détection/ingest byte-identiques) :
//!
//!  1. CORRÉLATION MULTI-ÉVÉNEMENTS STATEFUL (Finding-Groups) — `correlation` : une séquence ORDONNÉE
//!     d'étapes GXQL keyée sur UNE entité (src_ip/user/host…). Chaque étape sélectionne des events (au moins
//!     `ts` + la colonne de clé) ; l'entité MATCHE si l'on trouve, dans la fenêtre W, `min_count` events de
//!     l'étape 1 PUIS de l'étape 2 … PUIS de l'étape N, chaque étape survenant AU-DELÀ de l'ancre de la
//!     précédente (« failed-auth ×N puis success même IP », « recon -> exploit -> C2 »). Un match clôt le
//!     groupe en UNE alerte (`corr-<id>-<entity>`) qui AGRÈGE les N events -> incident/finding-group. Fenêtré,
//!     keyé-entité, mémoire BORNÉE (LIMIT par étape via run_query_ex).
//!
//!  2. BASELINING STATISTIQUE = ON-RAMP UEBA — `baseline` : par entité, une baseline glissante (moyenne +
//!     écart-type des buckets passés) + score de DÉVIATION (z-score). SANS ML (plafond HONNÊTE : statistique,
//!     pas de modèle). Une déviation >= z_threshold alimente le chemin RBA (risk_event) si `risk_score>0`,
//!     sinon lève une alerte discrète `baseline-<id>-<entity>-<bucket>`.
//!
//! SÉMANTIQUE FAIL-CLOSED (miroir de run_due_rules) : une évaluation qui ERRE ou TIMEOUT ne fabrique JAMAIS
//! un « tout clair » — elle N'écrit rien et NE RÉSOUT PAS de groupe ouvert (elle avance seulement last_run
//! et re-tentera). Concurrence bornée par `PLUME_DETECT_CONCURRENCY` (mutualisé avec run_due_rules).
//!
//! SÉCU : étapes de corrélation & requête de baseline = GXQL UNIQUEMENT (langage borné read-only sur `event`,
//! identifiants allowlistés, injection-safe — mêmes garanties que les règles GXQL, éditeur+). Aucun SQL brut,
//! aucune surface d'exécution custom, aucun contrôle hôte.
use crate::*;
use std::collections::HashMap;

// ============================================================================================
// MODÈLE — étapes de corrélation (JSON) + validation pure (testable sans AppState).
// ============================================================================================

/// Une étape ordonnée d'une corrélation : un filtre GXQL + un compte minimal d'events requis.
#[derive(Clone, Debug)]
pub(crate) struct CorrStep {
    pub(crate) name: String,
    pub(crate) query: String,
    pub(crate) min_count: i64,
}

/// Parse le champ `steps` (JSON array de {name,query,min_count}) en étapes typées. Chaîne vide / non-array /
/// étape sans `query` -> Err (surface l'erreur au test/CRUD ; JAMAIS un angle mort silencieux).
pub(crate) fn parse_corr_steps(steps_json: &str) -> Result<Vec<CorrStep>, String> {
    let v: Value = serde_json::from_str(steps_json).map_err(|e| format!("steps JSON invalide : {e}"))?;
    let arr = v.as_array().ok_or_else(|| "steps doit être un tableau JSON".to_string())?;
    if arr.is_empty() {
        return Err("au moins une étape est requise".into());
    }
    if arr.len() > 16 {
        return Err("trop d'étapes (max 16)".into());
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, s) in arr.iter().enumerate() {
        let query = s.get("query").and_then(|q| q.as_str()).unwrap_or("").trim().to_string();
        if query.is_empty() {
            return Err(format!("étape {} : requête GXQL vide", i + 1));
        }
        let min_count = s.get("min_count").and_then(|m| m.as_i64()).unwrap_or(1).max(1);
        let name = s.get("name").and_then(|n| n.as_str()).unwrap_or("").trim().to_string();
        out.push(CorrStep { name: if name.is_empty() { format!("étape {}", i + 1) } else { name }, query, min_count });
    }
    Ok(out)
}

/// Un nom de colonne de clé/champ d'entité est-il un identifiant SÛR ? (défense en profondeur : la colonne est
/// recherchée par NOM dans les résultats, jamais interpolée en SQL, mais on borne quand même la surface.)
pub(crate) fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Valide le CONTENU d'une corrélation à l'enregistrement (fail-closed) : clé/type d'entité = identifiants
/// sûrs, étapes non vides qui COMPILENT toutes en GXQL (même chemin que l'éval -> zéro angle mort).
pub(crate) fn validate_correlation(key_field: &str, entity_type: &str, steps_json: &str, window_s: i64) -> Result<(), (StatusCode, String)> {
    if !ident_ok(key_field) {
        return Err((StatusCode::BAD_REQUEST, "champ de clé (key_field) invalide (alphanumérique/_ ≤64)".into()));
    }
    if !ident_ok(entity_type) {
        return Err((StatusCode::BAD_REQUEST, "type d'entité (entity_type) invalide".into()));
    }
    let steps = parse_corr_steps(steps_json).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    for (i, st) in steps.iter().enumerate() {
        // étape = GXQL borné (is_soql=true) qui DOIT compiler (rule_sql -> guatx_core::soql).
        if let Err(e) = rule_sql(&st.query, true, window_s) {
            return Err((StatusCode::BAD_REQUEST, format!("étape {} : requête invalide : {e}", i + 1)));
        }
    }
    Ok(())
}

// ============================================================================================
// ALGORITHME PUR — appariement de séquence par entité (testable directement).
// ============================================================================================

/// `step_ts[i]` = horodatages (TRIÉS ASC) des events de l'étape i pour UNE entité. `min_counts[i]` = compte
/// minimal requis à l'étape i. Renvoie true s'il existe une chaîne ORDONNÉE : `min_counts[0]` events de
/// l'étape 0, puis (au niveau de l'ancre = le n-ième) `min_counts[1]` events de l'étape 1 survenant AU-DELÀ,
/// etc. La fenêtre W est déjà appliquée en amont (chaque requête d'étape est scopée [now-W, now]) -> seul
/// l'ORDRE est vérifié ici. Mémoire O(events), déterministe.
pub(crate) fn correlation_match(step_ts: &[Vec<i64>], min_counts: &[i64]) -> bool {
    if step_ts.is_empty() {
        return false;
    }
    let mut floor: Option<i64> = None; // ancre de l'étape précédente ; None = pas encore de plancher
    for (i, ts_list) in step_ts.iter().enumerate() {
        let need = (*min_counts.get(i).unwrap_or(&1)).max(1) as usize;
        let mut cnt = 0usize;
        let mut anchor: Option<i64> = None;
        for &t in ts_list.iter() {
            // AU-DELÀ (>=) de l'ancre précédente : autorise le même seconde-tick entre 2 étapes distinctes.
            if floor.map(|f| t >= f).unwrap_or(true) {
                cnt += 1;
                if cnt == need {
                    anchor = Some(t);
                    break;
                }
            }
        }
        match anchor {
            Some(a) => floor = Some(a),
            None => return false, // pas assez d'events ordonnés pour cette étape -> pas de séquence
        }
    }
    true
}

// ============================================================================================
// ÉVALUATION D'UNE CORRÉLATION (hors lock) — renvoie (entités matchées, ok). ok=false = ÉCHEC D'ÉVAL
// (compile/exécution/colonne absente) -> le chemin planifié NE RÉSOUT PAS de groupe (fail-closed).
// ============================================================================================

struct CorrEval {
    id: i64,
    name: String,
    entity_type: String,
    /// #3 P3-A — nom RÉEL de la colonne CIM keyée (src_ip/user/host/…) : sert au mapping entité->colonne
    /// structurée d'alerte (jamais à mislabeler ; `entity_type` est un LIBELLÉ opérateur, `key_field` est la
    /// colonne effectivement interrogée -> on mappe sur `key_field`, plus fiable).
    key_field: String,
    severity: i64,
    mitre: String,
    risk_score: i64,
    window_s: i64,
    matched: Vec<(String, String)>, // (entity, detail)
    ok: bool,
}

/// Évalue une corrélation : exécute chaque étape (connexion lecture read-only, budget interactif), extrait
/// (entité, ts) par étape, puis apparie la séquence par entité. FAIL-CLOSED : toute étape en erreur / sans
/// colonne `ts` / sans la colonne de clé -> ok=false (l'appelant N'écrit rien et NE RÉSOUT rien).
fn eval_correlation(
    db_path: &str, id: i64, name: &str, key_field: &str, entity_type: &str, steps_json: &str,
    window_s: i64, severity: i64, mitre: &str, risk_score: i64,
) -> CorrEval {
    let mut fail = CorrEval {
        id, name: name.to_string(), entity_type: entity_type.to_string(), key_field: key_field.to_string(),
        severity, mitre: mitre.to_string(), risk_score, window_s, matched: Vec::new(), ok: false,
    };
    let steps = match parse_corr_steps(steps_json) {
        Ok(s) => s,
        Err(_) => return fail, // config cassée -> échec d'éval (jamais un « tout clair »)
    };
    // Par étape : map entité -> timestamps triés. Toute étape en échec -> abandon fail-closed.
    let mut per_step: Vec<HashMap<String, Vec<i64>>> = Vec::with_capacity(steps.len());
    for st in &steps {
        let sql = match rule_sql(&st.query, true, window_s) {
            Ok(s) => s,
            Err(_) => return fail,
        };
        let v = match run_query_ex(db_path, &sql, query_budget_interactive_ms(), None) {
            Ok(v) => v,
            Err(_) => return fail, // erreur SQL / watchdog budget -> échec d'éval (fail-closed)
        };
        let cols = match v.get("columns").and_then(|c| c.as_array()) { Some(c) => c, None => return fail };
        let rows = match v.get("rows").and_then(|r| r.as_array()) { Some(r) => r, None => return fail };
        let ts_idx = match cols.iter().position(|c| c.as_str() == Some("ts")) { Some(i) => i, None => return fail };
        let key_idx = match cols.iter().position(|c| c.as_str() == Some(key_field)) { Some(i) => i, None => return fail };
        let mut m: HashMap<String, Vec<i64>> = HashMap::new();
        for row in rows {
            let arr = match row.as_array() { Some(a) => a, None => continue };
            let ts = match arr.get(ts_idx).and_then(|c| c.as_i64().or_else(|| c.as_f64().map(|f| f as i64))) {
                Some(t) => t, None => continue,
            };
            let ent = match arr.get(key_idx) {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => continue, // entité vide/nulle -> ignorée
            };
            m.entry(ent).or_default().push(ts);
        }
        for v in m.values_mut() {
            v.sort_unstable();
        }
        per_step.push(m);
    }
    // Appariement : une entité doit apparaître dans l'étape 0 (première) ; on teste la chaîne complète.
    let min_counts: Vec<i64> = steps.iter().map(|s| s.min_count).collect();
    let mut matched = Vec::new();
    if let Some(first) = per_step.first() {
        for entity in first.keys() {
            let step_ts: Vec<Vec<i64>> = per_step.iter().map(|m| m.get(entity).cloned().unwrap_or_default()).collect();
            if correlation_match(&step_ts, &min_counts) {
                let detail = steps.iter().enumerate().map(|(i, s)| {
                    let n = per_step[i].get(entity).map(|v| v.len()).unwrap_or(0);
                    format!("{}×{}", n, s.name)
                }).collect::<Vec<_>>().join(" → ");
                matched.push((entity.clone(), detail));
            }
        }
    }
    fail.matched = matched;
    fail.ok = true;
    fail
}

// ============================================================================================
// ORDONNANCEUR — run_correlations (à côté de run_due_rules dans la boucle de détection).
// ============================================================================================

/// Évalue les corrélations DUES (enabled + intervalle écoulé) en parallélisme BORNÉ (detect_concurrency),
/// puis écrit les finding-groups sous un seul verrou. MODE 0 : `correlation` vide -> `due` vide -> retour
/// immédiat (0 travail, byte-identique).
/// REND SON BILAN (`P4.1-r`, même contrat que `run_due_rules`) : `Illisible` si la liste des corrélations
/// dues n'a pas pu être lue (table absente comprise : une base non migrée n'évalue RIEN, et le dire vaut
/// mieux qu'un « no-op strict » indiscernable d'un tick calme), `Lue(n)` = corrélations dues abandonnées.
pub(crate) fn run_correlations(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnees = 0u32;
    // Phase 1 : collecte des corrélations dues.
    let due: Vec<(i64, String, String, String, String, i64, i64, String, i64)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id,name,key_field,entity_type,steps,window_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0) \
             FROM correlation WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("corrélations", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?, r.get::<_, i64>(8)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("corrélations", &e),
        };
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(x) => due.push(x),
                Err(_) => abandonnees += 1, // ligne indécodable : une corrélation non évaluée, comptée
            }
        }
        due
    };
    if due.is_empty() {
        return crate::mesure_environnement::Mesure::Lue(abandonnees);
    }
    // Phase 2 : éval hors lock, par tranches de detect_concurrency (miroir run_due_rules).
    let cc = detect_concurrency();
    let mut results: Vec<CorrEval> = Vec::with_capacity(due.len());
    for chunk in due.chunks(cc) {
        let chunk_res: Vec<CorrEval> = std::thread::scope(|s| {
            chunk.iter()
                .map(|(id, name, key_field, etype, steps, window_s, severity, mitre, risk_score)| {
                    s.spawn(move || eval_correlation(db_path, *id, name, key_field, etype, steps, *window_s, *severity, mitre, *risk_score))
                })
                .collect::<Vec<_>>()
                .into_iter()
                // DURCISSEMENT (#25) : un worker EMPOISONNÉ (panic dans eval_correlation) ne doit PAS avorter
                // TOUT le balayage. On le traite comme un ÉCHEC D'ÉVAL (ok=false, id=0 -> UPDATE no-op en
                // phase 3) : aucun groupe ouvert résolu, aucune contribution risk fabriquée (fail-closed).
                .map(|h| h.join().unwrap_or_else(|_| CorrEval { id: 0, name: String::new(), entity_type: String::new(), key_field: String::new(), severity: 0, mitre: String::new(), risk_score: 0, window_s: 0, matched: Vec::new(), ok: false }))
                .collect()
        });
        results.extend(chunk_res);
    }
    // Phase 3 : écritures groupées sous verrou.
    let conn = db.lock();
    for ev in results {
        // last_run avance TOUJOURS (même en échec -> re-tentera au prochain intervalle).
        let _ = conn.execute("UPDATE correlation SET last_run=?1 WHERE id=?2", params![now_ts, ev.id]);
        if !ev.ok {
            // ÉCHEC D'ÉVAL : ne rien écrire, NE PAS résoudre de groupe ouvert (fail-closed) — et COMPTER.
            abandonnees += 1;
            continue;
        }
        if !ev.matched.is_empty() {
            let _ = conn.execute("UPDATE correlation SET last_fired=?1 WHERE id=?2", params![now_ts, ev.id]);
        }
        if ev.risk_score > 0 {
            // MODE RISK : chaque entité matchée CONTRIBUE au RBA (dédup par bucket-de-fenêtre) — pas d'alerte
            // scalaire directe. L'accumulation/décroissance/alerte est gérée par rollup_risk (#24).
            let bucket = if ev.window_s > 0 { now_ts / ev.window_s } else { now_ts };
            for (entity, detail) in &ev.matched {
                let dedup = format!("risk:corr{}:{}:{}", ev.id, entity, bucket);
                let reason = format!("corrélation « {} » : {}", ev.name, detail);
                risk_event_insert(&conn, now_ts, &ev.entity_type, entity, ev.risk_score, "correlation", Some(ev.id), &reason, &ev.mitre, ev.severity, "prod", Some(&dedup));
            }
            continue;
        }
        // MODE ALERTE : un finding-group DÉDUPLIQUÉ par (corrélation, entité). INSERT OR IGNORE (no-op si déjà
        // ouvert) + refresh sans renotif ; puis résolution des groupes ouverts dont l'entité ne matche plus.
        // #3 P3-A — CAPTURE STRUCTURÉE BEST-EFFORT (additif). La corrélation est keyée sur UNE entité (`entity` =
        // valeur de `key_field`) -> on la range dans la colonne CIM correspondante SI key_field est sans ambiguïté
        // (src_ip/pid/host). Tout autre key_field (user, session…) laisse les colonnes NULL (A2 : `user` différé ;
        // conservateur = NULL plutôt que mislabeler). Re-validée au wizard puis à /api/actions — jamais auto-jouée.
        let mut crossing: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (entity, detail) in &ev.matched {
            let dedup = format!("corr-{}-{}", ev.id, entity);
            crossing.insert(dedup.clone());
            let title = format!("Corrélation : {} — {} ({})", ev.name, entity, ev.entity_type);
            let detail_full = format!("séquence appariée : {detail}");
            let (e_src, e_pid, e_host): (Option<&str>, Option<&str>, Option<&str>) = match ev.key_field.as_str() {
                "src_ip" => (Some(entity.as_str()), None, None),
                "pid" => (None, Some(entity.as_str()), None),
                "host" => (None, None, Some(entity.as_str())),
                _ => (None, None, None),
            };
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre,src_ip,pid,host) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![now_ts, format!("corr.{}", ev.id), ev.severity, title, detail_full, dedup, ev.mitre, e_src, e_pid, e_host],
            );
            let _ = conn.execute(
                "UPDATE alert SET ts=?1, title=?2, severity=?3, detail=?4 WHERE dedup=?5 AND status IN ('new','ack')",
                params![now_ts, title, ev.severity, detail_full, dedup],
            );
        }
        // Résolution : SEULEMENT parce que l'éval a RÉUSSI (ok=true) -> les groupes ouverts de CETTE corrélation
        // dont l'entité n'apparaît plus dans `crossing` sont résolus (retombée). Fail-closed : jamais sur échec.
        // Les groupes ouverts qu'on ne sait pas LIRE ne sont pas résolus (fail-closed), et chaque lecture
        // manquée est comptée : une résolution qui n'a pas eu lieu n'est pas un groupe « toujours actif ».
        let open: Vec<String> = {
            let like = format!("corr-{}-%", ev.id);
            match conn.prepare("SELECT dedup FROM alert WHERE dedup LIKE ?1 AND status IN ('new','ack')") {
                Ok(mut st) => match st.query_map(params![like], |r| r.get::<_, String>(0)) {
                    Ok(it) => it
                        .filter_map(|r| match r {
                            Ok(d) => Some(d),
                            Err(_) => {
                                abandonnees += 1;
                                None
                            }
                        })
                        .collect(),
                    Err(_) => {
                        abandonnees += 1;
                        Vec::new()
                    }
                },
                Err(_) => {
                    abandonnees += 1;
                    Vec::new()
                }
            }
        };
        for d in open {
            if !crossing.contains(&d) {
                let _ = conn.execute(
                    "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                    params![d],
                );
            }
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

// ============================================================================================
// BASELINING STATISTIQUE — scoring pur (z-score) + ordonnanceur run_baselines.
// ============================================================================================

/// Moyenne + écart-type ÉCHANTILLON (n-1) d'une série. None si <2 points ou variance nulle (pas de baseline
/// exploitable -> jamais de division par zéro / jamais un z-score fabriqué).
pub(crate) fn mean_std(history: &[f64]) -> Option<(f64, f64)> {
    if history.len() < 2 {
        return None;
    }
    let n = history.len() as f64;
    let mean = history.iter().sum::<f64>() / n;
    let var = history.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let std = var.sqrt();
    if std <= 0.0 {
        None
    } else {
        Some((mean, std))
    }
}

/// Score de DÉVIATION (z-score) de `current` vs la baseline `history`. None si historique insuffisant
/// (< min_samples) ou variance nulle. Positif = au-dessus de la normale (le cas qui nous intéresse pour une
/// anomalie de volume/rate/distinct). Sans ML : plafond HONNÊTE (statistique pure).
pub(crate) fn deviation_score(current: f64, history: &[f64], min_samples: usize) -> Option<f64> {
    if history.len() < min_samples.max(2) {
        return None;
    }
    let (mean, std) = mean_std(history)?;
    Some((current - mean) / std)
}

/// Une observation est-elle ANORMALE (déviation POSITIVE >= z_threshold) ? Renvoie Some(z) si oui.
pub(crate) fn baseline_anomaly(current: f64, history: &[f64], min_samples: usize, z_threshold: f64) -> Option<f64> {
    let z = deviation_score(current, history, min_samples)?;
    if z >= z_threshold {
        Some(z)
    } else {
        None
    }
}

struct BaselineHit {
    entity: String,
    value: f64,
    z: f64,
}

struct BaselineEval {
    id: i64,
    name: String,
    entity_type: String,
    severity: i64,
    mitre: String,
    risk_score: i64,
    z_threshold: f64,
    bucket: i64,
    observations: Vec<(String, f64)>, // (entity, value) à persister pour CE bucket
    hits: Vec<BaselineHit>,
    ok: bool,
}

/// Évalue une baseline pour le DERNIER bucket CLOS : calcule la valeur par entité sur [bstart,bend), puis le
/// z-score vs les observations passées (déjà persistées). FAIL-CLOSED : requête en erreur / colonnes absentes
/// -> ok=false (l'appelant N'écrit ni observation ni alerte et N'avance PAS last_bucket).
#[allow(clippy::too_many_arguments)]
fn eval_baseline(
    conn: &Connection, db_path: &str, id: i64, name: &str, query: &str, entity_field: &str, value_field: &str,
    entity_type: &str, bucket_s: i64, min_samples: i64, z_threshold: f64, window_s: i64,
    severity: i64, mitre: &str, risk_score: i64, now_ts: i64,
) -> BaselineEval {
    let mut out = BaselineEval {
        id, name: name.to_string(), entity_type: entity_type.to_string(), severity, mitre: mitre.to_string(),
        risk_score, z_threshold, bucket: 0, observations: Vec::new(), hits: Vec::new(), ok: false,
    };
    let bucket_s = bucket_s.max(60);
    let cur = now_ts / bucket_s; // bucket courant (incomplet)
    let closed = cur - 1; // dernier bucket COMPLET
    out.bucket = closed;
    let bstart = closed * bucket_s;
    let bend = cur * bucket_s - 1; // borne HAUTE inclusive (soql_to_sql_x -> ts <= bend) = fin du bucket clos
    // Compile la requête bornée AU bucket clos [bstart, bend]. GXQL uniquement (borné, read-only).
    let sql = match soql_to_sql_x(query, bstart, bend, None) {
        Ok(s) => s,
        Err(_) => return out,
    };
    let v = match run_query_ex(db_path, &sql, query_budget_interactive_ms(), None) {
        Ok(v) => v,
        Err(_) => return out, // erreur / budget -> fail-closed
    };
    let cols = match v.get("columns").and_then(|c| c.as_array()) { Some(c) => c, None => return out };
    let rows = match v.get("rows").and_then(|r| r.as_array()) { Some(r) => r, None => return out };
    let ent_idx = match cols.iter().position(|c| c.as_str() == Some(entity_field)) { Some(i) => i, None => return out };
    // value_field vide -> dernière colonne (convention `… | stats count by entity` : count = dernière col).
    let val_idx = if value_field.is_empty() {
        cols.len().saturating_sub(1)
    } else {
        match cols.iter().position(|c| c.as_str() == Some(value_field)) { Some(i) => i, None => return out }
    };
    let window_buckets = (window_s / bucket_s).max(2);
    let min_bucket = closed - window_buckets;
    for row in rows {
        let arr = match row.as_array() { Some(a) => a, None => continue };
        let entity = match arr.get(ent_idx) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => continue,
        };
        let value = match arr.get(val_idx).and_then(|c| c.as_f64().or_else(|| c.as_i64().map(|n| n as f64))) {
            Some(x) => x, None => continue,
        };
        out.observations.push((entity.clone(), value));
        // Historique = observations passées de CETTE entité dans la fenêtre (EXCLUT le bucket courant).
        let hist: Vec<f64> = {
            match conn.prepare(
                "SELECT value FROM ueba_baseline_obs WHERE baseline_id=?1 AND entity=?2 AND bucket>=?3 AND bucket<?4 ORDER BY bucket",
            ) {
                Ok(mut st) => st.query_map(params![id, entity, min_bucket, closed], |r| r.get::<_, f64>(0)).map(|x| x.flatten().collect()).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        };
        if let Some(z) = baseline_anomaly(value, &hist, min_samples.max(2) as usize, z_threshold) {
            out.hits.push(BaselineHit { entity, value, z });
        }
    }
    out.ok = true;
    out
}

/// Évalue les baselines DUES (enabled + intervalle écoulé + bucket clos non encore traité). Persiste les
/// observations du bucket, lève les anomalies (RBA si risk_score>0, sinon alerte discrète), élague les
/// observations hors fenêtre. MODE 0 : `baseline` vide -> `due` vide -> retour immédiat.
/// REND SON BILAN (`P4.1-r`, même contrat que `run_due_rules`) : `Illisible` si la liste des lignes de
/// base dues n'a pas pu être lue, `Lue(n)` = lignes de base dues abandonnées ce tick (ligne indécodable,
/// évaluation en échec, ou au-delà du plafond de traitement par tick — cette dernière est RE-TENTÉE au
/// tick suivant mais n'en est pas moins non évaluée ici).
pub(crate) fn run_baselines(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnees = 0u32;
    // Phase 1 : collecte des baselines dues (sous lock — lecture rapide).
    struct Due {
        id: i64, name: String, query: String, entity_field: String, value_field: String, entity_type: String,
        bucket_s: i64, min_samples: i64, z_threshold: f64, window_s: i64, severity: i64, mitre: String, risk_score: i64,
    }
    let due: Vec<Due> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id,name,query,entity_field,value_field,entity_type,bucket_s,min_samples,z_threshold,window_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0),COALESCE(last_bucket,-1) \
             FROM ueba_baseline WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("lignes de base", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?,
                r.get::<_, f64>(8)?, r.get::<_, i64>(9)?, r.get::<_, i64>(10)?, r.get::<_, String>(11)?,
                r.get::<_, i64>(12)?, r.get::<_, i64>(13)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("lignes de base", &e),
        };
        let mut all = Vec::new();
        for r in rows {
            match r {
                Ok(x) => all.push(x),
                Err(_) => abandonnees += 1, // ligne indécodable : une ligne de base non évaluée, comptée
            }
        }
        // Filtre : ne traite que si le bucket clos n'a pas déjà été traité (last_bucket < closed).
        all.into_iter().filter_map(|(id, name, query, ef, vf, et, bs, ms, zt, ws, sev, mi, rs, last_bucket)| {
            let closed = now_ts / bs.max(60) - 1;
            if last_bucket >= closed {
                return None; // déjà traité ce bucket -> avance juste last_run (fait en phase 3)
            }
            Some(Due { id, name, query, entity_field: ef, value_field: vf, entity_type: et, bucket_s: bs, min_samples: ms, z_threshold: zt, window_s: ws, severity: sev, mitre: mi, risk_score: rs })
        }).collect()
    };
    // Toujours avancer last_run des baselines dues (même celles dont le bucket est déjà traité) -> évite un
    // recalcul serré à chaque tick. On récupère la liste des ids dus (indépendamment du bucket) pour cela.
    let due_ids_all: Vec<i64> = {
        let conn = db.lock();
        let mut st = match conn.prepare("SELECT id FROM ueba_baseline WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)") {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("lignes de base", &e),
        };
        let it = match st.query_map(params![now_ts], |r| r.get::<_, i64>(0)) {
            Ok(it) => it,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("lignes de base", &e),
        };
        let mut ids: Vec<i64> = Vec::new();
        for r in it {
            match r {
                Ok(id) => ids.push(id),
                Err(_) => abandonnees += 1,
            }
        }
        ids
    };
    if due_ids_all.is_empty() {
        return crate::mesure_environnement::Mesure::Lue(abandonnees);
    }
    // Phase 2 : éval (chaque baseline lit ses observations passées -> connexion writer sous lock court par
    // baseline ; l'éval elle-même exécute la requête via le pool read-only). Séquentiel (peu de baselines,
    // budget 2 Go) mais on borne le nombre traité par tick à detect_concurrency*4 pour rester prévisible.
    let cap = detect_concurrency().saturating_mul(4).max(4);
    // Au-delà du plafond : non évaluées CE tick (re-tentées au suivant) — comptées, pas tues.
    abandonnees += u32::try_from(due.len().saturating_sub(cap)).unwrap_or(u32::MAX);
    let mut evals: Vec<BaselineEval> = Vec::new();
    {
        let conn = db.lock();
        for d in due.iter().take(cap) {
            let ev = eval_baseline(
                &conn, db_path, d.id, &d.name, &d.query, &d.entity_field, &d.value_field, &d.entity_type,
                d.bucket_s, d.min_samples, d.z_threshold, d.window_s, d.severity, &d.mitre, d.risk_score, now_ts,
            );
            evals.push(ev);
        }
    }
    // Phase 3 : écritures groupées sous verrou.
    let conn = db.lock();
    for id in &due_ids_all {
        let _ = conn.execute("UPDATE ueba_baseline SET last_run=?1 WHERE id=?2", params![now_ts, id]);
    }
    for ev in evals {
        if !ev.ok {
            abandonnees += 1;
            continue; // fail-closed : n'avance PAS last_bucket, ne persiste rien — et c'est COMPTÉ
        }
        // Persiste les observations du bucket (INSERT OR IGNORE -> idempotent si le tick rejoue).
        for (entity, value) in &ev.observations {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value,env_id) VALUES(?1,?2,?3,?4,?5,'prod')",
                params![ev.id, ev.entity_type, entity, ev.bucket, value],
            );
        }
        // Anomalies.
        for hit in &ev.hits {
            let reason = format!("baseline « {} » : {:.1} (z={:.2})", ev.name, hit.value, hit.z);
            if ev.risk_score > 0 {
                let dedup = format!("risk:baseline{}:{}:{}", ev.id, hit.entity, ev.bucket);
                risk_event_insert(&conn, now_ts, &ev.entity_type, &hit.entity, ev.risk_score, "baseline", Some(ev.id), &reason, &ev.mitre, ev.severity, "prod", Some(&dedup));
            } else {
                // Alerte discrète PAR BUCKET (dédup inclut le bucket -> une anomalie = un finding, pas de renotif).
                let dedup = format!("baseline-{}-{}-{}", ev.id, hit.entity, ev.bucket);
                let title = format!("Anomalie baseline : {} — {} ({})", ev.name, hit.entity, ev.entity_type);
                let detail = format!("valeur {:.1} au bucket {} — déviation z={:.2} ≥ seuil {:.1}", hit.value, ev.bucket, hit.z, ev.z_threshold);
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![now_ts, format!("baseline.{}", ev.id), ev.severity, title, detail, dedup, ev.mitre],
                );
            }
        }
        // Avance last_bucket + élague les observations hors fenêtre (borne la table).
        let _ = conn.execute("UPDATE ueba_baseline SET last_bucket=?1 WHERE id=?2", params![ev.bucket, ev.id]);
    }
    // Élagage global des observations hors fenêtre (une passe cheap, bornée) — après avancée des buckets.
    let _ = conn.execute(
        "DELETE FROM ueba_baseline_obs WHERE bucket < (SELECT (?1/MAX(bucket_s,60)) - (window_s/MAX(bucket_s,60)) - 2 FROM ueba_baseline b WHERE b.id=ueba_baseline_obs.baseline_id)",
        params![now_ts],
    );
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

// ============================================================================================
// CRUD + TEST (interactif / dry-run) — CORRÉLATIONS. Mutations éditeur+ (Write), lecture viewer+.
// ============================================================================================

fn corr_row_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? != 0,
        "key_field": r.get::<_, String>(3)?, "entity_type": r.get::<_, String>(4)?, "steps": r.get::<_, String>(5)?,
        "window_s": r.get::<_, i64>(6)?, "interval_s": r.get::<_, i64>(7)?, "severity": r.get::<_, i64>(8)?,
        "mitre": r.get::<_, String>(9)?, "risk_score": r.get::<_, i64>(10)?, "last_run": r.get::<_, Option<i64>>(11)?,
        "last_fired": r.get::<_, Option<i64>>(12)?, "managed": r.get::<_, i64>(13)?
    }))
}

pub(crate) async fn correlations_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare(
        "SELECT id,name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0),last_run,last_fired,managed FROM correlation ORDER BY id",
    ) {
        Ok(s) => s,
        Err(_) => return Json(json!({ "correlations": [] })),
    };
    let rows: Vec<Value> = stmt.query_map([], corr_row_json).map(|x| x.flatten().collect()).unwrap_or_default();
    Json(json!({ "correlations": rows }))
}

pub(crate) async fn correlation_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Corrélation").to_string();
    let key_field = b.get("key_field").and_then(|v| v.as_str()).unwrap_or("src_ip").trim().to_string();
    let entity_type = b.get("entity_type").and_then(|v| v.as_str()).unwrap_or("ip").trim().to_string();
    let steps = match b.get("steps") {
        Some(Value::Array(_)) => b.get("steps").unwrap().to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => "[]".to_string(),
    };
    let window_s = b.i64_field("window_s", 3600);
    let interval_s = b.i64_field("interval_s", 300);
    let severity = b.i64_field("severity", 3);
    let risk_score = b.i64_field("risk_score", 0).max(0);
    if let Err((code, msg)) = validate_correlation(&key_field, &entity_type, &steps, window_s) {
        return err_json(code, msg);
    }
    let mitre = match norm_mitre(b.str_field("mitre")) {
        Some(m) => m,
        None => return bad_req("MITRE invalide : format attendu Txxxx ou Txxxx.yyy"),
    };
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO correlation(name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,managed,created) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,2,?11)",
            params![name, enabled, key_field, entity_type, steps, window_s, interval_s, severity, mitre, risk_score, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.correlation.create",
            &format!("corrélation '{name}' (#{id}) créée par {}", au.name), 2,
            &format!("corrélation de détection '{name}' créée par {}", au.name),
            &json!({ "op": "create", "kind": "correlation", "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "managed": 2 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn correlation_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT key_field,entity_type,steps,window_s,managed FROM correlation WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)),
    );
    let (cur_key, cur_etype, cur_steps, cur_window, cur_managed) = match cur {
        Ok(x) => x,
        Err(_) => return not_found("corrélation introuvable"),
    };
    let eff_key = b.get("key_field").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).unwrap_or(cur_key);
    let eff_etype = b.get("entity_type").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).unwrap_or(cur_etype);
    let eff_steps = match b.get("steps") {
        Some(Value::Array(_)) => b.get("steps").unwrap().to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => cur_steps,
    };
    let eff_window = b.get("window_s").and_then(|x| x.as_i64()).unwrap_or(cur_window);
    if let Err((code, msg)) = validate_correlation(&eff_key, &eff_etype, &eff_steps, eff_window) {
        return err_json(code, msg);
    }
    // FIX HIGH-1b (port sibling — corrélation) : identique à rule_update/parser_update. Modifier une détection
    // BASELINE (seed/builtin managed=0) est RÉSERVÉ ADMIN. La route /api/correlations est editor+ (rbac §7), donc
    // c'est un TROU LIVE : sans cette garde, l'effet de bord d'adoption managed=0->2 ci-dessous rend `managed`
    // editor-inscriptible, et l'écriture inconditionnelle de `enabled` laissait un editor désactiver/neutraliser
    // une corrélation seedée en UNE requête. Évalué sur le managed COURANT, AVANT toute adoption. Fail-closed :
    // on refuse tout le PATCH. Frontière : seed(0)/overlay(1)=admin-managés ; l'editor garde le CRUD sur SON ad-hoc(2).
    // INVARIANT : `cur_managed != 2` — overlay(1) admin-managé au même titre que le seed(0) (neuter-via-steps).
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier une détection managée (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre règle");
    }
    // FIX HIGH-1 (défense-en-profondeur) : basculer `enabled` sur une détection MANAGÉE (seed=0/overlay=1) =
    // ADMIN. Un non-admin ne toggle `enabled` QUE sur son propre ad-hoc managed=2. Évalué sur le managed COURANT.
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE correlation SET name=?1 WHERE id=?2", params![v, id])?; }
        conn.execute("UPDATE correlation SET key_field=?1, entity_type=?2, steps=?3, window_s=?4 WHERE id=?5", params![eff_key, eff_etype, eff_steps, eff_window, id])?;
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE correlation SET interval_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("severity").and_then(|x| x.as_i64()) { conn.execute("UPDATE correlation SET severity=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("risk_score").and_then(|x| x.as_i64()) { conn.execute("UPDATE correlation SET risk_score=?1 WHERE id=?2", params![v.max(0), id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE correlation SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        if let Some(v) = b.get("mitre").and_then(|x| x.as_str()) {
            if let Some(m) = norm_mitre(v) { conn.execute("UPDATE correlation SET mitre=?1 WHERE id=?2", params![m, id])?; }
        }
        if cur_managed == 0 { conn.execute("UPDATE correlation SET managed=2 WHERE id=?1", params![id])?; }
        audit_config_change(
            &conn, "config.correlation.update",
            &format!("corrélation #{id} modifiée par {}", au.name), 2,
            &format!("corrélation de détection #{id} modifiée par {}", au.name),
            &json!({ "op": "update", "kind": "correlation", "id": id, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn correlation_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM correlation WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("corrélation introuvable"),
    };
    delete_managed_row(&conn, "correlation", "config.correlation", id, managed, &au.name)
}

/// POST /api/correlations/:id/test — BACKTEST/dry-run : évalue la séquence sur la fenêtre courante SANS écrire.
/// Renvoie les entités matchées + le détail par étape (aperçu avant activation).
pub(crate) async fn correlation_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row(
            "SELECT name,key_field,entity_type,steps,window_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0) FROM correlation WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, String>(6)?, r.get::<_, i64>(7)?)),
        ).ok()
    };
    let (name, key_field, entity_type, steps, window_s, severity, mitre, risk_score) = match row {
        Some(x) => x,
        None => return Json(json!({ "error": "corrélation introuvable" })),
    };
    // #45 — DRY-RUN = SURFACE D'APPELANT : cette route est EDITOR+ et RENVOIE les ENTITÉS (`key_field`)
    // en clair. `eval_correlation` est PARTAGÉ avec l'ordonnanceur et doit rester tenant-wide/non masqué
    // (D7 : ne jamais rendre une corrélation aveugle) -> on garde la SURFACE, pas l'évaluateur.
    let step_qs: Vec<String> = parse_corr_steps(&steps).map(|v| v.into_iter().map(|s| s.query).collect()).unwrap_or_default();
    if let Err(e) = caller_dryrun_guard(&st, &au, &step_qs.iter().map(|s| s.as_str()).collect::<Vec<_>>(), &[&key_field], window_s) {
        return Json(json!({ "error": e }));
    }
    let db_path = req_db_path(&st, &au);
    let ev = tokio::task::spawn_blocking(move || eval_correlation(&db_path, id, &name, &key_field, &entity_type, &steps, window_s, severity, &mitre, risk_score)).await;
    match ev {
        Ok(ev) if ev.ok => Json(json!({
            "ok": true, "matched": ev.matched.len(),
            "entities": ev.matched.iter().map(|(e, d)| json!({ "entity": e, "detail": d })).collect::<Vec<_>>(),
        })),
        Ok(_) => Json(json!({ "error": "évaluation échouée (étape en erreur, ou colonne ts/clé absente d'une étape)" })),
        Err(_) => Json(json!({ "error": "exécution échouée" })),
    }
}

// ============================================================================================
// CRUD + TEST — BASELINES. Mutations éditeur+ (Write), lecture viewer+.
// ============================================================================================

pub(crate) async fn baselines_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare(
        "SELECT id,name,enabled,query,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0),last_run,last_bucket,managed FROM ueba_baseline ORDER BY id",
    ) {
        Ok(s) => s,
        Err(_) => return Json(json!({ "baselines": [] })),
    };
    let rows: Vec<Value> = stmt.query_map([], |r| Ok(json!({
        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? != 0,
        "query": r.get::<_, String>(3)?, "entity_type": r.get::<_, String>(4)?, "entity_field": r.get::<_, String>(5)?,
        "value_field": r.get::<_, String>(6)?, "bucket_s": r.get::<_, i64>(7)?, "min_samples": r.get::<_, i64>(8)?,
        "z_threshold": r.get::<_, f64>(9)?, "window_s": r.get::<_, i64>(10)?, "interval_s": r.get::<_, i64>(11)?,
        "severity": r.get::<_, i64>(12)?, "mitre": r.get::<_, String>(13)?, "risk_score": r.get::<_, i64>(14)?,
        "last_run": r.get::<_, Option<i64>>(15)?, "last_bucket": r.get::<_, Option<i64>>(16)?, "managed": r.get::<_, i64>(17)?
    }))).map(|x| x.flatten().collect()).unwrap_or_default();
    Json(json!({ "baselines": rows }))
}

/// Valide le contenu d'une baseline (fail-closed) : query GXQL non vide qui compile, champs = identifiants sûrs.
fn validate_baseline(query: &str, entity_field: &str, value_field: &str, entity_type: &str) -> Result<(), (StatusCode, String)> {
    if query.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "requête GXQL vide".into()));
    }
    if !ident_ok(entity_field) {
        return Err((StatusCode::BAD_REQUEST, "champ d'entité (entity_field) invalide".into()));
    }
    if !value_field.is_empty() && !ident_ok(value_field) {
        return Err((StatusCode::BAD_REQUEST, "champ de valeur (value_field) invalide".into()));
    }
    if !ident_ok(entity_type) {
        return Err((StatusCode::BAD_REQUEST, "type d'entité (entity_type) invalide".into()));
    }
    // La requête doit compiler bornée (from/to arbitraires -> on teste avec la même couture que l'éval).
    if let Err(e) = soql_to_sql_x(query, 0, 0, None) {
        return Err((StatusCode::BAD_REQUEST, format!("requête invalide : {e}")));
    }
    Ok(())
}

pub(crate) async fn baseline_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Baseline").to_string();
    let query = b.str_field("query").to_string();
    let entity_field = b.get("entity_field").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let value_field = b.get("value_field").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let entity_type = b.get("entity_type").and_then(|v| v.as_str()).unwrap_or("host").trim().to_string();
    if let Err((code, msg)) = validate_baseline(&query, &entity_field, &value_field, &entity_type) {
        return err_json(code, msg);
    }
    let mitre = match norm_mitre(b.str_field("mitre")) {
        Some(m) => m,
        None => return bad_req("MITRE invalide : format attendu Txxxx ou Txxxx.yyy"),
    };
    let bucket_s = b.i64_field("bucket_s", 3600).max(60);
    let min_samples = b.i64_field("min_samples", 5).max(2);
    let z_threshold = b.get("z_threshold").and_then(|v| v.as_f64()).unwrap_or(3.0).max(0.5);
    let window_s = b.i64_field("window_s", 604800).max(bucket_s * 2);
    let interval_s = b.i64_field("interval_s", 3600).max(60);
    let severity = b.i64_field("severity", 2);
    let risk_score = b.i64_field("risk_score", 0).max(0);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed,created) \
             VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,2,?15)",
            params![name, enabled, query, entity_type, entity_field, value_field, bucket_s, min_samples, z_threshold, window_s, interval_s, severity, mitre, risk_score, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.baseline.create",
            &format!("baseline '{name}' (#{id}) créée par {}", au.name), 2,
            &format!("baseline UEBA '{name}' créée par {}", au.name),
            &json!({ "op": "create", "kind": "baseline", "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "managed": 2 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn baseline_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT query,entity_field,value_field,entity_type,managed FROM ueba_baseline WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)),
    );
    let (cur_q, cur_ef, cur_vf, cur_et, cur_managed) = match cur {
        Ok(x) => x,
        Err(_) => return not_found("baseline introuvable"),
    };
    let eff_q = b.get("query").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_q);
    let eff_ef = b.get("entity_field").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).unwrap_or(cur_ef);
    let eff_vf = b.get("value_field").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).unwrap_or(cur_vf);
    let eff_et = b.get("entity_type").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).unwrap_or(cur_et);
    if let Err((code, msg)) = validate_baseline(&eff_q, &eff_ef, &eff_vf, &eff_et) {
        return err_json(code, msg);
    }
    // FIX HIGH-1b (port sibling — baseline UEBA) : identique à rule_update/parser_update/correlation_update.
    // Modifier une détection BASELINE (seed/builtin managed=0) = ADMIN. Route /api/baselines editor+ (rbac §7) =>
    // TROU LIVE : sans garde, l'adoption managed=0->2 + l'écriture inconditionnelle de `enabled` laissent un editor
    // désactiver/neutraliser une baseline seedée en UNE requête. Évalué sur le managed COURANT, AVANT toute adoption.
    // INVARIANT : `cur_managed != 2` — overlay(1) admin-managé au même titre que le seed(0) (neuter-via-query).
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier une détection managée (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre règle");
    }
    // FIX HIGH-1 (défense-en-profondeur) : toggle `enabled` sur une détection MANAGÉE (seed=0/overlay=1) = ADMIN ;
    // un non-admin ne toggle que son ad-hoc managed=2. Évalué sur le managed COURANT.
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE ueba_baseline SET name=?1 WHERE id=?2", params![v, id])?; }
        conn.execute("UPDATE ueba_baseline SET query=?1, entity_field=?2, value_field=?3, entity_type=?4 WHERE id=?5", params![eff_q, eff_ef, eff_vf, eff_et, id])?;
        if let Some(v) = b.get("bucket_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET bucket_s=?1 WHERE id=?2", params![v.max(60), id])?; }
        if let Some(v) = b.get("min_samples").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET min_samples=?1 WHERE id=?2", params![v.max(2), id])?; }
        if let Some(v) = b.get("z_threshold").and_then(|x| x.as_f64()) { conn.execute("UPDATE ueba_baseline SET z_threshold=?1 WHERE id=?2", params![v.max(0.5), id])?; }
        if let Some(v) = b.get("window_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET window_s=?1 WHERE id=?2", params![v.max(120), id])?; }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET interval_s=?1 WHERE id=?2", params![v.max(60), id])?; }
        if let Some(v) = b.get("severity").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET severity=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("risk_score").and_then(|x| x.as_i64()) { conn.execute("UPDATE ueba_baseline SET risk_score=?1 WHERE id=?2", params![v.max(0), id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE ueba_baseline SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        if let Some(v) = b.get("mitre").and_then(|x| x.as_str()) {
            if let Some(m) = norm_mitre(v) { conn.execute("UPDATE ueba_baseline SET mitre=?1 WHERE id=?2", params![m, id])?; }
        }
        if cur_managed == 0 { conn.execute("UPDATE ueba_baseline SET managed=2 WHERE id=?1", params![id])?; }
        audit_config_change(
            &conn, "config.baseline.update",
            &format!("baseline #{id} modifiée par {}", au.name), 2,
            &format!("baseline UEBA #{id} modifiée par {}", au.name),
            &json!({ "op": "update", "kind": "baseline", "id": id, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn baseline_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM ueba_baseline WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("baseline introuvable"),
    };
    // Nettoie aussi les observations rattachées (best-effort) avant la suppression gérée.
    if managed == 2 {
        let _ = conn.execute("DELETE FROM ueba_baseline_obs WHERE baseline_id=?1", params![id]);
    }
    delete_managed_row(&conn, "ueba_baseline", "config.baseline", id, managed, &au.name)
}

/// POST /api/baselines/:id/test — dry-run : calcule les valeurs du dernier bucket clos + le z-score par entité
/// SANS persister d'observation ni lever d'alerte. Aperçu pour régler seuil/fenêtre.
pub(crate) async fn baseline_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    // #45 — DRY-RUN = SURFACE D'APPELANT : cette route est EDITOR+ et RENVOIE les ÉCHANTILLONS
    // (entité, valeur) en clair. `eval_baseline` est PARTAGÉ avec l'ordonnanceur et doit rester
    // tenant-wide/non masqué (D7) -> on garde la SURFACE, pas l'évaluateur. Pré-lecture des seuls champs
    // nécessaires à la garde (la lecture complète reste DANS le bloc bloquant, inchangée).
    {
        let pre: Option<(String, String, String, i64)> = {
            crate::req_conn!(st, au, conn);
            conn.query_row(
                "SELECT query,entity_field,value_field,window_s FROM ueba_baseline WHERE id=?1",
                params![id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)),
            ).ok()
        };
        if let Some((q, ef, vf, ws)) = pre {
            if let Err(e) = caller_dryrun_guard(&st, &au, &[q.as_str()], &[&ef, &vf], ws) {
                return Json(json!({ "error": e }));
            }
        }
    }
    let db = req_db(&st, &au);
    let db_path = req_db_path(&st, &au);
    let out = tokio::task::spawn_blocking(move || -> Value {
        let conn = db.lock();
        let row = conn.query_row(
            "SELECT name,query,entity_field,value_field,entity_type,bucket_s,min_samples,z_threshold,window_s,severity,COALESCE(mitre,''),COALESCE(risk_score,0) FROM ueba_baseline WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, f64>(7)?, r.get::<_, i64>(8)?, r.get::<_, i64>(9)?, r.get::<_, String>(10)?, r.get::<_, i64>(11)?)),
        );
        let (name, query, ef, vf, et, bs, ms, zt, ws, sev, mi, rs) = match row {
            Ok(x) => x, Err(_) => return json!({ "error": "baseline introuvable" }),
        };
        let ev = eval_baseline(&conn, &db_path, id, &name, &query, &ef, &vf, &et, bs, ms, zt, ws, sev, &mi, rs, now());
        if !ev.ok {
            return json!({ "error": "évaluation échouée (requête en erreur, ou colonne entité/valeur absente)" });
        }
        json!({
            "ok": true, "bucket": ev.bucket, "observed": ev.observations.len(), "anomalies": ev.hits.len(),
            "samples": ev.observations.iter().map(|(e, v)| json!({ "entity": e, "value": v })).take(200).collect::<Vec<_>>(),
            "hits": ev.hits.iter().map(|h| json!({ "entity": h.entity, "value": h.value, "z": h.z })).collect::<Vec<_>>(),
        })
    }).await.unwrap_or_else(|_| json!({ "error": "exécution échouée" }));
    Json(out)
}
