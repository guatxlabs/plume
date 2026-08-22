//! Risk-Based Alerting (#24, modèle Splunk ES RBA) — FONDATION. Au lieu d'UNE alerte par détection, les
//! détections CONTRIBUENT du RISQUE à des ENTITÉS (user/host/ip/…) via `risk_event` ; le risque S'ACCUMULE
//! par entité sur une fenêtre, matérialisé PAR ENTITÉ dans `risk_rollup` (score cumulé, tactiques MITRE
//! distinctes, vélocité) ; quand une entité franchit un seuil (cumul, ≥N tactiques, ou vélocité) on lève
//! UNE alerte risk-based DÉDUPLIQUÉE pour cette entité -> réduit la fatigue d'alerte sans perdre le signal.
//!
//! DISCIPLINE (miroir host_rollup / IOC_SET) : `risk_rollup` est RECONSTRUIT dans la boucle rollup depuis la
//! PETITE table `risk_event` (dédup + rétention -> bornée), JAMAIS depuis un scan de `event`. La LECTURE
//! (/api/risk/entities) sert le rollup en O(entités-risquées), ZÉRO scan. La reconstruction FENÊTRÉE gère le
//! DECAY (les vieilles contributions sortent de la fenêtre) sans purge de ligne — servie à la lecture.
//!
//! INVARIANT ABSOLU mode 0 (comme #23) : aucune règle risk seedée + IOC store vide -> AUCUN `risk_event`
//! n'est jamais émis -> `risk_rollup` vide -> AUCUNE alerte risk -> détection/ingest byte-identiques. RBA
//! s'ACTIVE par la DONNÉE (une règle passée en mode risk, ou un IOC importé), jamais par un flag.
use crate::*;
use std::collections::{HashMap, HashSet};

// ============================================================================================
// CONFIG (tuning — tous surchargables par l'environnement ; défauts CONSERVATEURS pour la fondation).
// Décisions à confirmer par l'opérateur : seuils par défaut, score d'une contribution ti, politique de sévérité.
// ============================================================================================

/// Fenêtre d'ACCUMULATION du risque (s) : le rollup n'agrège que `risk_event` de [now-window, now] -> decay.
fn risk_window_s(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_WINDOW_S", "86400").parse().unwrap_or(86400).max(60)
}
/// Sous-fenêtre de VÉLOCITÉ (s) : score « chaud » = somme des contributions des dernières `vel_window` s.
fn risk_velocity_window_s(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_VELOCITY_WINDOW_S", "3600").parse().unwrap_or(3600).max(60)
}
/// Seuil de CUMUL : entité dont le score cumulé sur la fenêtre >= ce seuil -> alerte risk.
fn risk_score_threshold(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_SCORE_THRESHOLD", "100").parse().unwrap_or(100).max(1)
}
/// Seuil de TACTIQUES distinctes : entité touchée par >= N techniques MITRE distinctes -> alerte. 0 = off.
fn risk_tactics_threshold(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_TACTICS_THRESHOLD", "3").parse().unwrap_or(3).max(0)
}
/// Seuil de VÉLOCITÉ : score chaud (sous-fenêtre) >= ce seuil -> alerte (rafale). 0 = off.
fn risk_velocity_threshold(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_VELOCITY", "50").parse().unwrap_or(50).max(0)
}
/// Score d'une contribution THREAT-INTEL (composition #23->#24). 0 = composition ti->risk DÉSACTIVÉE.
fn risk_ti_score(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_TI_SCORE", "20").parse().unwrap_or(20).max(0)
}
/// Granularité de dédup d'une contribution ti (s) : une entité reçoit AU PLUS une contribution ti par bucket
/// -> un scanner qui matche un IOC = ~1 apport/heure, pas 10 000 (émission bornée sous attaque bruyante).
fn risk_ti_bucket_s(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_RISK_TI_BUCKET_S", "3600").parse().unwrap_or(3600).max(1)
}

// ============================================================================================
// STORE — insertion d'une contribution de risque (dédup borné via INSERT OR IGNORE).
// ============================================================================================

/// Insère UNE contribution de risque. `dedup` (Some) -> INSERT OR IGNORE (déjà posée = no-op, borne
/// l'émission) ; None -> insertion toujours (l'index UNIQUE est PARTIEL WHERE dedup IS NOT NULL). Renvoie
/// true si une ligne a été écrite. `rule_id` None pour les contributions ti/manuelles.
#[allow(clippy::too_many_arguments)]
pub(crate) fn risk_event_insert(
    conn: &Connection, ts: i64, entity_type: &str, entity: &str, score: i64, source: &str,
    rule_id: Option<i64>, reason: &str, mitre: &str, severity: i64, env_id: &str, dedup: Option<&str>,
) -> bool {
    conn.execute(
        "INSERT OR IGNORE INTO risk_event(ts,entity_type,entity,risk_score,source,rule_id,reason,mitre,severity,env_id,dedup) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![ts, entity_type, entity, score, source, rule_id, reason, mitre, severity, env_id, dedup],
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// COMPOSITION #23->#24 — un match threat-intel (à l'ingest, sous le lock writer, DANS la transaction du
/// batch) CONTRIBUE du risque à l'entité de l'IOC. Dédup par (entity, bucket horaire) -> émission bornée.
/// INERTE en mode 0 : jamais appelée (aucun IOC -> aucun hit). `PLUME_RISK_TI_SCORE=0` désactive la compo.
pub(crate) fn ti_risk_contribution(conn: &Connection, hit: &TiHit, ts: i64, env_id: &str) {
    let conf = load_config();
    let score = risk_ti_score(&conf);
    if score == 0 {
        return; // composition ti->risk explicitement désactivée
    }
    let bucket = ts / risk_ti_bucket_s(&conf);
    let dedup = format!("risk:ti:{}:{}:{}", hit.entity_type, hit.entity, bucket);
    let reason = format!("threat-intel match ({})", hit.source);
    risk_event_insert(conn, ts, &hit.entity_type, &hit.entity, score, "ti", None, &reason, "", hit.severity, env_id, Some(&dedup));
}

// ============================================================================================
// ANNOTATION RISK sur les RÈGLES — run_risk_rules (planificateur, à côté de run_due_rules ; les règles
// risk sont EXCLUES de run_due_rules -> elles ne lèvent PAS d'alerte scalaire par tir : « instead of »).
// ============================================================================================

/// Évalue les règles DUES en MODE RISK (risk_score>0) : exécute la requête (attendue en `… | stats count by
/// <entity>`) et CONTRIBUE risk_score points à CHAQUE entité de la colonne `risk_entity_field`, typée
/// `risk_entity_type`. Dédup par (règle, entité, bucket-de-fenêtre) -> une contribution par entité/fenêtre.
/// 3 phases (calquées sur run_due_rules) : collecte sous lock -> éval hors lock (pool lecture) -> écriture
/// groupée sous lock. MODE 0 : aucune règle risk -> `due` vide -> retour immédiat (0 travail).
/// REND SON BILAN (`P4.1-r`, même contrat que `run_due_rules`) : `Illisible` si la liste des règles de
/// risque dues n'a pas pu être lue, `Lue(n)` = règles dues qui n'ont PAS contribué ce tick faute d'avoir
/// pu être évaluées (ligne indécodable, sans entité cible, compilation refusée, requête en échec, champ
/// d'entité absent du résultat). Avant : chacune était sautée en avançant `last_run`, indiscernable
/// d'une règle évaluée qui ne rapporte rien.
pub(crate) fn run_risk_rules(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnees = 0u32;
    // Phase 1 : collecte des règles risk DUES (enabled + risk_score>0 + intervalle écoulé).
    let due: Vec<(i64, String, String, bool, i64, i64, i64, String, String, String)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id,name,query,is_soql,window_s,severity,risk_score,COALESCE(mitre,''),\
                    COALESCE(risk_entity_type,''),COALESCE(risk_entity_field,'') \
             FROM rule WHERE enabled=1 AND COALESCE(risk_score,0)>0 \
               AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles de risque", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0,
                r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?,
                r.get::<_, String>(8)?, r.get::<_, String>(9)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles de risque", &e),
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
    if due.is_empty() {
        return crate::mesure_environnement::Mesure::Lue(abandonnees);
    }
    // Phase 2 : évalue chaque règle (connexion lecture, hors lock) -> liste de contributions.
    struct Contrib { rule_id: i64, entity_type: String, entity: String, score: i64, reason: String, mitre: String, severity: i64, window_s: i64 }
    let mut contribs: Vec<Contrib> = Vec::new();
    let ran: Vec<i64> = due.iter().map(|d| d.0).collect();
    for (id, name, query, is_soql, window_s, severity, risk_score, mitre, etype, efield) in &due {
        // Sans entité cible (type/champ), impossible d'attribuer le risque -> aucune contribution (fail-safe),
        // mais une règle de risque sans cible est une règle qui ne contribuera JAMAIS : comptée.
        if etype.is_empty() || efield.is_empty() {
            abandonnees += 1;
            continue;
        }
        let sql = match rule_sql(query, *is_soql, *window_s) {
            Ok(s) => s,
            Err(_) => {
                abandonnees += 1;
                continue;
            }
        };
        let v = match run_query(db_path, &sql) {
            Ok(v) => v,
            Err(_) => {
                abandonnees += 1;
                continue;
            }
        };
        // `run_query` rend TOUJOURS `columns` et `rows` ; une réponse sans l'un des deux est une forme
        // inconnue, donc une évaluation qu'on n'a pas su lire — comptée comme telle.
        let (cols, rows) = match (v.get("columns").and_then(|c| c.as_array()), v.get("rows").and_then(|r| r.as_array())) {
            (Some(c), Some(r)) => (c, r),
            _ => {
                abandonnees += 1;
                continue;
            }
        };
        // Index de la colonne entité (par NOM = risk_entity_field). Absente du résultat -> la règle ne peut
        // attribuer AUCUN risque, et ce n'est pas « rien à signaler » : c'est une règle mal configurée, comptée.
        let idx = match cols.iter().position(|c| c.as_str() == Some(efield.as_str())) {
            Some(i) => i,
            None => {
                abandonnees += 1;
                continue;
            }
        };
        for row in rows {
            let cell = row.as_array().and_then(|a| a.get(idx));
            // Une cellule vide ou nulle n'est pas un échec d'évaluation : c'est une ligne SANS entité, à
            // laquelle aucun risque ne peut être attribué. La branche rend une VALEUR (vide), le filtre suit.
            let entity = match cell {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => String::new(),
            };
            if entity.is_empty() {
                continue; // entité vide/nulle -> aucune contribution (ce n'est pas un abandon de la règle)
            }
            contribs.push(Contrib {
                rule_id: *id, entity_type: etype.clone(), entity, score: *risk_score,
                reason: name.clone(), mitre: mitre.clone(), severity: *severity, window_s: *window_s,
            });
        }
    }
    // Phase 3 : écritures groupées sous un seul verrou (contributions dédupliquées + avance de last_run).
    let conn = db.lock();
    for c in &contribs {
        let bucket = if c.window_s > 0 { now_ts / c.window_s } else { now_ts };
        let dedup = format!("risk:rule{}:{}:{}", c.rule_id, c.entity, bucket);
        risk_event_insert(&conn, now_ts, &c.entity_type, &c.entity, c.score, "rule", Some(c.rule_id), &c.reason, &c.mitre, c.severity, "prod", Some(&dedup));
    }
    for id in &ran {
        let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now_ts, id]);
    }
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

// ============================================================================================
// #3 — MAPPING TECHNIQUE->TACTIQUE ATT&CK (exposé en SQL). Enregistre la fonction scalaire
// `attack_tactic(technique) -> tactique` sur la connexion (idempotent : create_scalar_function REMPLACE).
// Le mapping curé vit dans guatx_core::attack (pur, testé côté cœur, partagé Plume/Forge). Fallback :
// technique NON curée -> l'ID technique brut (jamais un sous-comptage des tactiques distinctes) ; entrée
// vide/NULL -> '' (exclue par NULLIF). DÉTERMINISTE -> utilisable dans GROUP BY / COUNT(DISTINCT).
// ============================================================================================
fn register_attack_tactic(conn: &Connection) {
    use rusqlite::functions::FunctionFlags;
    let _ = conn.create_scalar_function(
        "attack_tactic",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let tid = match ctx.get_raw(0) {
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                _ => return Ok(String::new()), // NULL / non-texte -> vide (NULLIF l'exclut du DISTINCT)
            };
            if tid.trim().is_empty() {
                return Ok(String::new());
            }
            Ok(guatx_core::attack::tactic_for_technique(&tid)
                .map(|s| s.to_string())
                .unwrap_or(tid)) // technique non curée -> ID brut (bucket distinct, jamais un sous-comptage)
        },
    );
}

// ============================================================================================
// ACCUMULATION + DÉCLENCHEMENT — rollup_risk (piggyback rollup_events / retention_run).
// ============================================================================================

/// MATÉRIALISE `risk_rollup` (agrégat par entité sur la fenêtre) puis évalue les incidents de risque.
/// RECONSTRUCTION à blanc depuis `risk_event` (petite table) : gère le DECAY (fenêtre glissante) sans purge.
/// FAST PATH mode 0 : ni risk_event, ni risk_rollup, ni alerte risk ouverte -> retour immédiat (1 point-read).
/// REND LE BILAN de l'évaluation des incidents de risque (`P4.1-r`) : `Illisible` si `risk_rollup` ou les
/// alertes ouvertes n'ont pas pu être lues (aucun seuil n'a été jugé), `Lue(n)` = lignes du rollup
/// indécodables, donc des entités dont le risque n'a PAS été jugé ce tick. Mode 0 : `Lue(0)`.
pub(crate) fn rollup_risk(conn: &Connection) -> crate::bilan_de_tick::BilanDeTick {
    register_attack_tactic(conn);   // #3 : SQL scalar attack_tactic(technique)->tactique (idempotent, cheap)
    let has_events: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM risk_event)", [], |r| r.get(0)).unwrap_or(false);
    let has_rollup: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM risk_rollup)", [], |r| r.get(0)).unwrap_or(false);
    if !has_events && !has_rollup {
        // Aucune donnée de risque : ne reste que le cas-limite d'une alerte risk ouverte à résoudre.
        let has_alert: bool = conn
            .query_row("SELECT EXISTS(SELECT 1 FROM alert WHERE dedup LIKE 'risk-%' AND status IN ('new','ack'))", [], |r| r.get(0))
            .unwrap_or(false);
        if !has_alert {
            return crate::mesure_environnement::Mesure::Lue(0); // mode 0 : NO-OP strict, et c'est un VRAI zéro
        }
    }
    let conf = load_config();
    let n = now();
    let from = n - risk_window_s(&conf);
    let hot_from = n - risk_velocity_window_s(&conf);
    // Reconstruction : DELETE (petite table) puis INSERT...SELECT agrégé (bornes i64 formatées, pas
    // d'injection). distinct_tactics = TACTIQUES ATT&CK distinctes (#3 : `attack_tactic(mitre)` mappe la
    // technique -> sa tactique primaire ; deux techniques d'une même tactique ne comptent qu'UNE fois =
    // vraie largeur de kill-chain). Fallback dans attack_tactic : technique non curée -> l'ID technique
    // lui-même (jamais un sous-comptage vs. la fondation). `tactics` reste la liste des TECHNIQUES (jointure
    // couverture /api/coverage/detections sur `mitre` + first_mitre de l'alerte inchangés). score_hot/
    // contrib_hot = vélocité.
    let _ = conn.execute("DELETE FROM risk_rollup", []);
    let _ = conn.execute(
        &format!(
            "INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
             SELECT entity_type, entity, COALESCE(env_id,'prod'), \
                    SUM(risk_score), COUNT(*), \
                    COUNT(DISTINCT NULLIF(attack_tactic(mitre),'')), \
                    COALESCE(GROUP_CONCAT(DISTINCT NULLIF(mitre,'')),''), \
                    SUM(CASE WHEN ts >= {hot_from} THEN risk_score ELSE 0 END), \
                    SUM(CASE WHEN ts >= {hot_from} THEN 1 ELSE 0 END), \
                    MAX(severity), MIN(ts), MAX(ts), {n} \
             FROM risk_event WHERE ts >= {from} \
             GROUP BY entity_type, entity, COALESCE(env_id,'prod')"
        ),
        [],
    );
    risk_incidents_eval(conn, &conf, n)
}

/// Sévérité (0..4) d'une alerte risk : palier haut (4) si score très au-delà du seuil OU tactiques largement
/// dépassées ; sinon 3 ; toujours >= la sévérité max des contributions. Politique à confirmer par l'opérateur.
fn risk_alert_severity(score: i64, distinct_tactics: i64, score_thr: i64, tactics_thr: i64, max_sev: i64) -> i64 {
    let base = if score >= 2 * score_thr || (tactics_thr > 0 && distinct_tactics >= tactics_thr + 2) { 4 } else { 3 };
    base.max(max_sev).min(4)
}

/// Évalue les incidents de risque depuis `risk_rollup` : pour chaque entité franchissant un seuil (cumul,
/// tactiques distinctes, ou vélocité), lève UNE alerte DÉDUPLIQUÉE (`risk-<type>-<entity>`) via INSERT OR
/// IGNORE (mécanique run_due_rules) ; rafraîchit une alerte ouverte SANS renotifier ; RÉSOUT les alertes
/// risk ouvertes dont l'entité ne franchit plus aucun seuil (retombée sous la fenêtre / le seuil).
fn risk_incidents_eval(conn: &Connection, conf: &HashMap<String, String>, n: i64) -> crate::bilan_de_tick::BilanDeTick {
    let score_thr = risk_score_threshold(conf);
    let tactics_thr = risk_tactics_threshold(conf);
    let vel_thr = risk_velocity_threshold(conf);
    let mut abandonnees = 0u32;
    let rows: Vec<(String, String, i64, i64, i64, i64, String, i64)> = {
        let mut st = match conn.prepare(
            "SELECT entity_type,entity,score,contrib,distinct_tactics,score_hot,tactics,max_severity FROM risk_rollup",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("incidents de risque", &e),
        };
        let it = match st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, String>(6)?, r.get::<_, i64>(7)?,
            ))
        }) {
            Ok(x) => x,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("incidents de risque", &e),
        };
        let mut lues = Vec::new();
        for r in it {
            match r {
                Ok(x) => lues.push(x),
                Err(_) => abandonnees += 1, // une entité dont le risque n'est PAS jugé ce tick, comptée
            }
        }
        lues
    };
    let mut crossing: HashSet<String> = HashSet::new();
    for (etype, entity, score, contrib, dt, score_hot, tactics, max_sev) in &rows {
        let trig_score = *score >= score_thr;
        let trig_tactics = tactics_thr > 0 && *dt >= tactics_thr;
        let trig_vel = vel_thr > 0 && *score_hot >= vel_thr;
        if !(trig_score || trig_tactics || trig_vel) {
            continue;
        }
        let dedup = format!("risk-{}-{}", etype, entity);
        crossing.insert(dedup.clone());
        let mut why: Vec<String> = Vec::new();
        if trig_score { why.push(format!("score {score}≥{score_thr}")); }
        if trig_tactics { why.push(format!("{dt} tactiques≥{tactics_thr}")); }
        if trig_vel { why.push(format!("vélocité {score_hot}≥{vel_thr}")); }
        let sev = risk_alert_severity(*score, *dt, score_thr, tactics_thr, *max_sev);
        let title = format!("Risque : {entity} ({etype}) — score {score}, {contrib} contributions, {dt} tactiques");
        let detail = format!("déclencheur: {}. tactiques MITRE: {}", why.join(", "), if tactics.is_empty() { "—" } else { tactics });
        let first_mitre = tactics.split(',').next().unwrap_or("").to_string();
        let rule_tag = format!("risk.{etype}.{entity}");
        // no-op si une alerte ouverte porte déjà la clé (INSERT OR IGNORE sur dedup UNIQUE) -> pas de renotif.
        let _ = conn.execute(
            "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![n, rule_tag, sev, title, detail, dedup, first_mitre],
        );
        // rafraîchit l'affichage (ts/score/sévérité montent) SANS toucher `notified` -> pas de renotif.
        let _ = conn.execute(
            "UPDATE alert SET ts=?1, title=?2, severity=?3, detail=?4 WHERE dedup=?5 AND status IN ('new','ack')",
            params![n, title, sev, detail, dedup],
        );
    }
    // Résolution : toute alerte risk OUVERTE dont l'entité ne franchit plus aucun seuil -> resolved + dedup
    // libéré (ré-arme un futur épisode). Miroir de la branche « retour sous le seuil » de run_due_rules.
    let open: Vec<String> = {
        let mut st = match conn.prepare("SELECT dedup FROM alert WHERE dedup LIKE 'risk-%' AND status IN ('new','ack')") {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("incidents de risque (résolution)", &e),
        };
        let it = match st.query_map([], |r| r.get::<_, String>(0)) {
            Ok(x) => x,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("incidents de risque (résolution)", &e),
        };
        let mut lues = Vec::new();
        for r in it {
            match r {
                Ok(x) => lues.push(x),
                Err(_) => abandonnees += 1, // une alerte ouverte dont la résolution n'a pas été jugée, comptée
            }
        }
        lues
    };
    for d in open {
        if !crossing.contains(&d) {
            let _ = conn.execute(
                "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                params![d],
            );
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

// ============================================================================================
// SURFACING — GET /api/risk/entities (top-risque, servi du rollup, ZÉRO scan event) + timeline par entité.
// viewer+ (donnée de posture, pas un secret) via route_min_role (GET -> Read).
// ============================================================================================

/// GET /api/risk/entities — entités les plus à risque (score cumulé, contributions, tactiques distinctes,
/// vélocité), SERVIES DEPUIS `risk_rollup` (aucun scan de `event`). Renvoie aussi les seuils courants pour
/// que l'UI marque les entités over-threshold. Mode 0 : rollup vide -> `entities:[]`.
pub(crate) async fn risk_entities(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let conf = load_config();
    let score_thr = risk_score_threshold(&conf);
    let tactics_thr = risk_tactics_threshold(&conf);
    let vel_thr = risk_velocity_threshold(&conf);
    let window = risk_window_s(&conf);
    crate::req_conn!(st, au, conn);
    let entities: Vec<Value> = match conn.prepare(
        "SELECT entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts \
         FROM risk_rollup ORDER BY score DESC, last_ts DESC LIMIT 200",
    ) {
        Ok(mut s) => s
            .query_map([], |r| {
                let score: i64 = r.get(3)?;
                let dt: i64 = r.get(5)?;
                let score_hot: i64 = r.get(7)?;
                Ok(json!({
                    "entity_type": r.get::<_, String>(0)?,
                    "entity": r.get::<_, String>(1)?,
                    "env_id": r.get::<_, String>(2)?,
                    "score": score,
                    "contrib": r.get::<_, i64>(4)?,
                    "distinct_tactics": dt,
                    "tactics": r.get::<_, String>(6)?,
                    "score_hot": score_hot,
                    "contrib_hot": r.get::<_, i64>(8)?,
                    "max_severity": r.get::<_, i64>(9)?,
                    "first_ts": r.get::<_, i64>(10)?,
                    "last_ts": r.get::<_, i64>(11)?,
                    "over_threshold": score >= score_thr || (tactics_thr > 0 && dt >= tactics_thr) || (vel_thr > 0 && score_hot >= vel_thr)
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(json!({
        "entities": entities,
        "thresholds": { "score": score_thr, "distinct_tactics": tactics_thr, "velocity": vel_thr, "window_s": window },
    }))
}

/// GET /api/risk/entity/:etype/:entity — SYNTHÈSE (rollup) + TIMELINE horaire + contributions récentes d'UNE
/// entité. La timeline/les contributions lisent la PETITE table `risk_event` INDEXÉE par (entity_type,entity)
/// -> lookup ciblé, PAS un scan de `event`. viewer+.
pub(crate) async fn risk_entity_timeline(
    State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((etype, entity)): Path<(String, String)>,
) -> Json<Value> {
    let conf = load_config();
    let from = now() - risk_window_s(&conf);
    crate::req_conn!(st, au, conn);
    let summary = conn
        .query_row(
            "SELECT score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts \
             FROM risk_rollup WHERE entity_type=?1 AND entity=?2",
            params![etype, entity],
            |r| {
                Ok(json!({
                    "score": r.get::<_, i64>(0)?, "contrib": r.get::<_, i64>(1)?,
                    "distinct_tactics": r.get::<_, i64>(2)?, "tactics": r.get::<_, String>(3)?,
                    "score_hot": r.get::<_, i64>(4)?, "contrib_hot": r.get::<_, i64>(5)?,
                    "max_severity": r.get::<_, i64>(6)?, "first_ts": r.get::<_, i64>(7)?, "last_ts": r.get::<_, i64>(8)?
                }))
            },
        )
        .ok();
    let timeline: Vec<Value> = match conn.prepare(
        "SELECT (ts/3600)*3600 AS bucket, SUM(risk_score), COUNT(*) FROM risk_event \
         WHERE entity_type=?1 AND entity=?2 AND ts>=?3 GROUP BY bucket ORDER BY bucket",
    ) {
        Ok(mut s) => s
            .query_map(params![etype, entity, from], |r| Ok(json!({ "ts": r.get::<_, i64>(0)?, "score": r.get::<_, i64>(1)?, "contrib": r.get::<_, i64>(2)? })))
            .map(|x| x.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let contributions: Vec<Value> = match conn.prepare(
        "SELECT ts,risk_score,source,rule_id,reason,mitre,severity FROM risk_event \
         WHERE entity_type=?1 AND entity=?2 ORDER BY ts DESC LIMIT 200",
    ) {
        Ok(mut s) => s
            .query_map(params![etype, entity], |r| {
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "risk_score": r.get::<_, i64>(1)?, "source": r.get::<_, String>(2)?,
                    "rule_id": r.get::<_, Option<i64>>(3)?, "reason": r.get::<_, String>(4)?,
                    "mitre": r.get::<_, String>(5)?, "severity": r.get::<_, i64>(6)?
                }))
            })
            .map(|x| x.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(json!({ "entity_type": etype, "entity": entity, "summary": summary, "timeline": timeline, "contributions": contributions }))
}
