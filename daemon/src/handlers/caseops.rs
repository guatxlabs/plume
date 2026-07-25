//! #39 TEAM CASE-OPS (readiness P1) — extension NON DESTRUCTIVE du système de cases first-class (#4a/#4a-bis).
//! Cinq leviers, tous ADDITIFS et INERTES en mode 0 (aucune politique SLA, aucune fusion, aucun lien) :
//!   1. PER-ASSIGNEE QUEUES  : résumé de charge par propriétaire (`case_queues_json`) — compte open/overdue/
//!      ack-pending/breach par assignee, + « my queue ». La LISTE reste `cases_list_json_paged` (#4a, déjà
//!      filtrée assignee + paginée serveur) : on n'ajoute qu'un agrégat de tête.
//!   2. MERGE (soft)         : `case_merge` marque la SOURCE `merged_into=<dst>` + la clôt, SANS supprimer sa
//!      timeline (append-only) ; `case_get_json` combine les items des sources fusionnées dans la cible. Ledger.
//!   3. LINK (non destructif): `case_link_add` associe deux cases (related/duplicate/blocks) sans rien fusionner.
//!   4. MULTI-LEVEL SLA      : table `sla_policy` (ack + resolve par priorité). VIDE -> SLA legacy (#4a) INCHANGÉ.
//!      Chrono ancré sur des timestamps IMMUABLES (`ts`) + un cumul de PAUSE (`sla_pause_accum`) ; pause/reprise
//!      sur le statut 'waiting'. Le tick `sla_multilevel_tick` pose les breach (early-return si 0 politique).
//!   5. MTTA/MTTR DASHBOARD  : `case_metrics_json` agrège mean/p50 MTTA (first_response_ts-ts) & MTTR
//!      (closed_ts-ts-pause) sur une fenêtre, par assignee/severity. Lecture pure sur `incident` (human-scale).
//!   6. CLIENT-READ API      : surface EXTERNE read-only, tenant-scopée, MASQUÉE — un client MSSP voit SES cases
//!      (statut/sévérité/cycle de vie), JAMAIS les identités analystes, les notes internes, ni les refs
//!      alert/event. Auth = jeton `kind='client'` (seam dédié) OU rôle résolu `client`. Cf. INVARIANT plus bas.
//!
//! INVARIANT SÉCU CLIENT-READ :
//!   - TENANT-SCOPE : les handlers lisent la base via `req_db_path`/`req_db` du tenant de l'appelant -> en mode 0
//!     l'unique base ; en mode 1 la base du tenant résolu par auth_guard. AUCUN cross-tenant possible (isolation
//!     par-base, comme /api/query & scheduled-reports #60). On passe le VRAI tenant à effective_masks, jamais "".
//!   - MASQUÉ : `effective_masks(role,tenant,env)` du RÔLE de l'appelant est appliqué aux champs textuels
//!     exposés. Rôle `client` -> role_rank 0 (fail-closed) -> masqué par TOUTE règle field-filter.
//!   - PROJECTION FERMÉE : la sortie est une allowlist de colonnes `incident` (aucune colonne de la denylist de
//!     secrets n'existe sur `incident`) ; owner/assignee/summary interne + refs alert/event NE SONT PAS exposés.
//!   - READ-ONLY : les handlers n'exécutent que des SELECT paramétrés (jamais de SQL brut, jamais /api/query,
//!     jamais une route mutante) ; le jeton client ne s'authentifie QUE sur `client_bearer_path`.
//!
//! ⚠⚠ ISOLATION CLIENT — #3 PHASE 3 Part B (ÉLARGIT LA PROJECTION CLIENT) ⚠⚠
//!   La projection client (`client_case_row`) gagne TROIS champs ADDITIFS, closed-allowlist, tous dérivés de
//!   colonnes NON secrètes déjà tenant-scopées, approuvés par l'opérateur (« minimal safe view ») :
//!     • `is_incident` (bool) = `incident_tier IS NOT NULL` — le BOOLÉEN seul (le SELECT calcule IS NOT NULL en
//!       SQL : le tier BRUT 1..4 ne rentre jamais dans Rust ; `incident_type`/`commander` jamais lus).
//!     • `phase` (enum coarse FERMÉ) — dérivé du SEUL `status` (client_phase), JAMAIS d'une étape/runbook.
//!     • `acknowledged` (bool) = `first_response_ts IS NOT NULL` — timing MTTA-style coarse (pas de timestamp/durée).
//!   DENYLIST DURE INCHANGÉE (jamais exposé, ni valeur ni chaîne dérivable) : `incident_tier` brut,
//!   `incident_type`, `commander`, tout runbook (nom/id/key), tout `case_step` (titre/guidance/status/count/
//!   target/host), tout SOQL/search, tout `action_kind`, notes/commentaires internes, identité analyste/assignee,
//!   cross-tenant. La timeline client garde son allowlist de kinds INCHANGÉE (jamais 'incident'/'runbook'/'step').
use crate::*;

// ================================================================================================
// MULTI-LEVEL SLA — politiques configurables (ack + resolve par priorité). VIDE = SLA legacy #4a.
// ================================================================================================

/// Politique SLA ACTIVE pour une priorité (1..4) : (policy_id, ack_target_s, resolve_target_s). None si la
/// table est vide ou aucune politique activée pour ce tier -> l'appelant retombe sur le SLA legacy (sla_due).
pub(crate) fn sla_policy_for(conn: &Connection, priority: i64) -> Option<(i64, i64, i64)> {
    conn.query_row(
        "SELECT id, ack_target_s, resolve_target_s FROM sla_policy WHERE priority=?1 AND enabled=1",
        params![priority],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
    )
    .ok()
}

/// (Ré)applique la politique SLA multi-niveau à un case : pose `sla_policy_id`, `ack_due` (si PAS encore
/// acquitté : first_response_ts NULL), `resolve_due`, à partir du `ts` IMMUABLE + cibles + cumul de pause.
/// INERTE si aucune politique pour la priorité courante (mode 0 : dues restent NULL -> SLA legacy). Ne touche
/// JAMAIS un case terminal (resolved/closed). Idempotent. Appelée à la création et sur changement de priorité.
pub(crate) fn sla_apply_policy(conn: &Connection, id: i64) {
    let row: Option<(i64, i64, String, i64, Option<i64>)> = conn
        .query_row(
            "SELECT ts, priority, status, COALESCE(sla_pause_accum,0), first_response_ts FROM incident WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .ok();
    let Some((ts, priority, status, pause_accum, first_resp)) = row else { return };
    if matches!(status.as_str(), "resolved" | "closed" | "contained") {
        return; // terminal : le chrono est arrêté, on ne recompute pas.
    }
    let Some((pid, ack_s, res_s)) = sla_policy_for(conn, priority) else { return }; // pas de politique -> legacy
    let resolve_due = ts + res_s + pause_accum;
    // ack_due n'est (re)posé que tant que le case n'est PAS acquitté (first_response_ts NULL) : après ack, le
    // chrono d'acquittement est arrêté et son échéance figée.
    if first_resp.is_none() {
        let ack_due = ts + ack_s + pause_accum;
        let _ = conn.execute(
            "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?3 WHERE id=?4",
            params![pid, ack_due, resolve_due, id],
        );
    } else {
        let _ = conn.execute(
            "UPDATE incident SET sla_policy_id=?1, resolve_due=?2 WHERE id=?3",
            params![pid, resolve_due, id],
        );
    }
}

/// PAUSE/REPRISE du chrono SLA multi-niveau sur transition de statut. INERTE si le case n'est pas gouverné par
/// une politique (`sla_policy_id` NULL) -> mode 0 byte-identique. Modèle ancré sur des TIMESTAMPS IMMUABLES :
///   - entrée en 'waiting' (on-hold) : mémorise `sla_paused_since=t` (le chrono s'arrête) ;
///   - sortie de 'waiting' vers un statut ACTIF : cumule (t - paused_since) dans `sla_pause_accum` et DÉCALE
///     ack_due/resolve_due d'autant (le temps « en attente » ne consomme pas le SLA), efface paused_since.
/// Le breach reste calculé depuis (ts immuable + cumul) — un analyste ne peut PAS reculer `ts` pour tricher.
pub(crate) fn sla_on_status_change(conn: &Connection, id: i64, new_status: &str, t: i64) {
    let row: Option<(Option<i64>, Option<i64>)> = conn
        .query_row(
            "SELECT sla_policy_id, sla_paused_since FROM incident WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let Some((policy_id, paused_since)) = row else { return };
    if policy_id.is_none() {
        return; // pas de politique multi-niveau -> aucune comptabilité de pause (legacy inchangé)
    }
    match (paused_since, new_status == "waiting") {
        (None, true) => {
            // le chrono passe EN PAUSE.
            let _ = conn.execute("UPDATE incident SET sla_paused_since=?1 WHERE id=?2", params![t, id]);
        }
        (Some(since), false) => {
            // REPRISE : cumule la durée de pause + décale les échéances d'autant.
            let delta = (t - since).max(0);
            let _ = conn.execute(
                "UPDATE incident SET sla_pause_accum = COALESCE(sla_pause_accum,0)+?1, sla_paused_since=NULL, \
                 ack_due = CASE WHEN ack_due IS NULL THEN NULL ELSE ack_due+?1 END, \
                 resolve_due = CASE WHEN resolve_due IS NULL THEN NULL ELSE resolve_due+?1 END WHERE id=?2",
                params![delta, id],
            );
        }
        _ => {} // déjà dans l'état visé -> no-op
    }
}

/// #39 — TICK SLA MULTI-NIVEAU : marque les breach d'ACQUITTEMENT (now>ack_due, pas encore acquitté) et de
/// RÉSOLUTION (now>resolve_due, non terminal), une seule fois (ack_breached/resolve_breached anti re-notif),
/// trace un item 'sla' + ledger, et notifie via les notifiers du tenant (min_severity respecté). SKIP les
/// cases EN PAUSE (sla_paused_since NOT NULL). EARLY-RETURN si `sla_policy` VIDE -> ZÉRO travail mode 0
/// (miroir de escalate_overdue_cases). Séquentiel + LIMIT (budget 2 Go). Appelé dans la boucle de fond.
pub(crate) fn sla_multilevel_tick(db: &Arc<Mutex<Connection>>) {
    let now_i = now();
    let (ack_b, res_b, notifiers): (Vec<(i64, String, i64)>, Vec<(i64, String, i64)>, Vec<(String, String, i64, String)>) = {
        let conn = db.lock();
        // GATE : aucune politique -> on ne fait RIEN (pas même un scan de la table incident).
        let has_policy: i64 = conn.query_row("SELECT EXISTS(SELECT 1 FROM sla_policy WHERE enabled=1)", [], |r| r.get(0)).unwrap_or(0);
        if has_policy == 0 {
            return;
        }
        let ack_b: Vec<(i64, String, i64)> = conn
            .prepare(
                "SELECT id,COALESCE(title,''),priority FROM incident \
                 WHERE ack_due IS NOT NULL AND ack_breached=0 AND first_response_ts IS NULL \
                   AND sla_paused_since IS NULL AND merged_into IS NULL \
                   AND status NOT IN ('resolved','closed','contained') AND ?1 > ack_due \
                 ORDER BY ack_due LIMIT 20",
            )
            .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|x| x.flatten().collect()))
            .unwrap_or_default();
        let res_b: Vec<(i64, String, i64)> = conn
            .prepare(
                "SELECT id,COALESCE(title,''),priority FROM incident \
                 WHERE resolve_due IS NOT NULL AND resolve_breached=0 \
                   AND sla_paused_since IS NULL AND merged_into IS NULL \
                   AND status NOT IN ('resolved','closed','contained') AND ?1 > resolve_due \
                 ORDER BY resolve_due LIMIT 20",
            )
            .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|x| x.flatten().collect()))
            .unwrap_or_default();
        if ack_b.is_empty() && res_b.is_empty() {
            return;
        }
        let notifiers: Vec<(String, String, i64, String)> = conn
            .prepare("SELECT kind,url,min_severity,config FROM notifier WHERE enabled=1")
            .and_then(|mut s| s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).map(|x| x.flatten().collect()))
            .unwrap_or_default();
        (ack_b, res_b, notifiers)
    };
    let fire = |db: &Arc<Mutex<Connection>>, id: i64, title: &str, priority: i64, col: &str, kind: &str, what: &str| {
        let sev = match priority { 1 => 4, 2 => 3, 3 => 2, _ => 1 };
        let detail = format!("Case #{id} « {title} » : SLA {what} P{priority} dépassé.");
        for (nk, url, minsev, cfg) in &notifiers {
            if sev >= *minsev {
                let config: Value = serde_json::from_str(cfg).unwrap_or_else(|_| json!({}));
                let _ = notify_send(nk, url, &config, sev, &format!("SLA {what} : {title}"), &detail, "", now_i);
            }
        }
        let conn = db.lock();
        let _ = conn.execute(&format!("UPDATE incident SET {col}=1 WHERE id=?1"), params![id]);
        case_add_item(&conn, id, now_i, "sla", "system", &detail, None);
        ledger_append(&conn, kind, &format!("#{id} P{priority} {what}"));
    };
    for (id, title, pr) in &ack_b {
        fire(db, *id, title, *pr, "ack_breached", "case.sla_ack_breach", "acquittement (MTTA)");
    }
    for (id, title, pr) in &res_b {
        fire(db, *id, title, *pr, "resolve_breached", "case.sla_resolve_breach", "résolution (MTTR)");
    }
}

// ================================================================================================
// MERGE (soft, non destructif) + LINK (association)
// ================================================================================================

/// FUSION SOFT #39 : marque la SOURCE `merged_into=dst` + la clôt ('closed'), SANS supprimer sa ligne ni sa
/// timeline (append-only, audit préservé, réversible via case_unmerge). Trace un item 'merge' sur la source ET
/// la cible + ledger `case.merge`. Refuse : case inexistant, src==dst, source déjà fusionnée, ou fusion CIBLE
/// -> SOURCE (anti-cycle direct). `case_get_json(dst)` combinera les items des sources fusionnées.
pub(crate) fn case_merge(conn: &Connection, src_id: i64, dst_id: i64, author: &str) -> bool {
    if src_id == dst_id {
        return false;
    }
    // les deux doivent exister ; la source ne doit pas être DÉJÀ fusionnée ailleurs.
    let src_ok: Option<Option<i64>> = conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![src_id], |r| r.get(0)).ok();
    let dst_ok: Option<Option<i64>> = conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![dst_id], |r| r.get(0)).ok();
    let (Some(src_merged), Some(_)) = (src_ok, dst_ok) else { return false };
    if src_merged.is_some() {
        return false; // source déjà fusionnée -> refus (pas de re-fusion silencieuse)
    }
    // #39 CORRECTIVE — ANTI-CYCLE de TOUTE longueur (pas seulement le 2-cycle direct). On REMONTE la chaîne
    // `merged_into` depuis dst ; si src y apparaît, la fusion fermerait un cycle (ex. merge(A,B);merge(B,C);
    // merge(C,A)) qui poserait merged_into sur TOUS les cases -> aucun survivant listable (WHERE merged_into IS
    // NULL) = disparition totale + audit cassé. Boucle BORNÉE (≤50 sauts, jamais de récursion non bornée).
    let mut cursor = dst_id;
    for _ in 0..50 {
        if cursor == src_id {
            return false; // src est en AMONT de dst -> fusionner fermerait le cycle : refus
        }
        match conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![cursor], |r| r.get::<_, Option<i64>>(0)) {
            Ok(Some(next)) => cursor = next, // maillon suivant de la chaîne
            _ => break,                      // racine non fusionnée (fin de chaîne) ou case absent
        }
    }
    let t = now();
    let _ = conn.execute(
        "UPDATE incident SET merged_into=?1, status='closed', closed_ts=?2, updated=?2 WHERE id=?3",
        params![dst_id, t, src_id],
    );
    case_add_item(conn, src_id, t, "merge", author, &format!("fusionné dans #{dst_id}"), Some(&format!("case:{dst_id}")));
    case_add_item(conn, dst_id, t, "merge", author, &format!("#{src_id} fusionné ici (timeline combinée)"), Some(&format!("case:{src_id}")));
    ledger_append(conn, "case.merge", &format!("#{src_id} -> #{dst_id} by {author}"));
    true
}

/// RÉVERSIBILITÉ de la fusion : dé-fusionne la source (merged_into=NULL) + la rouvre ('triage'). Trace + ledger.
/// false si le case n'existe pas ou n'est pas fusionné. Preuve que la fusion NE DÉTRUIT rien (#39, exigence revue).
pub(crate) fn case_unmerge(conn: &Connection, src_id: i64, author: &str) -> bool {
    let cur: Option<Option<i64>> = conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![src_id], |r| r.get(0)).ok();
    let Some(Some(dst)) = cur else { return false };
    let t = now();
    let _ = conn.execute("UPDATE incident SET merged_into=NULL, status='triage', closed_ts=NULL, updated=?1 WHERE id=?2", params![t, src_id]);
    case_add_item(conn, src_id, t, "merge", author, &format!("dé-fusionné de #{dst} (ré-ouvert)"), None);
    ledger_append(conn, "case.unmerge", &format!("#{src_id} <- #{dst} by {author}"));
    true
}

/// LIEN NON DESTRUCTIF #39 : associe deux cases (kind ∈ related|duplicate|blocks) sans les fusionner. Dédup par
/// UNIQUE(src,dst,kind). Trace item 'link' des deux côtés + ledger. false si un case manque ou src==dst.
pub(crate) fn case_link_add(conn: &Connection, src_id: i64, dst_id: i64, kind: &str, note: &str, author: &str) -> bool {
    if src_id == dst_id {
        return false;
    }
    let kind = match kind {
        "duplicate" | "blocks" | "related" => kind,
        _ => "related",
    };
    for cid in [src_id, dst_id] {
        if conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![cid], |_| Ok(())).is_err() {
            return false;
        }
    }
    let t = now();
    let n = conn.execute(
        "INSERT OR IGNORE INTO case_link(src_id,dst_id,kind,note,created,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
        params![src_id, dst_id, kind, note, t, author],
    ).unwrap_or(0);
    if n == 0 {
        return true; // déjà lié (idempotent) — pas de double trace
    }
    case_add_item(conn, src_id, t, "link", author, &format!("lié à #{dst_id} ({kind})"), Some(&format!("case:{dst_id}")));
    case_add_item(conn, dst_id, t, "link", author, &format!("lié à #{src_id} ({kind})"), Some(&format!("case:{src_id}")));
    ledger_append(conn, "case.link", &format!("#{src_id} <-{kind}-> #{dst_id} by {author}"));
    true
}

/// Supprime un lien (les deux sens) entre deux cases. Trace + ledger. Le lien est une pure ASSOCIATION -> sa
/// suppression ne détruit AUCUNE donnée de case. false si aucun lien.
pub(crate) fn case_link_remove(conn: &Connection, a: i64, b: i64, author: &str) -> bool {
    let n = conn.execute(
        "DELETE FROM case_link WHERE (src_id=?1 AND dst_id=?2) OR (src_id=?2 AND dst_id=?1)",
        params![a, b],
    ).unwrap_or(0);
    if n == 0 {
        return false;
    }
    ledger_append(conn, "case.unlink", &format!("#{a} x #{b} by {author}"));
    true
}

/// Liens d'un case (dans les deux sens) résolus en (id, titre, statut, kind). Point-lookups bornés (budget 2 Go).
pub(crate) fn case_links_json(conn: &Connection, id: i64) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT CASE WHEN l.src_id=?1 THEN l.dst_id ELSE l.src_id END AS other, l.kind, l.note, \
                COALESCE(i.title,''), COALESCE(i.status,'') \
         FROM case_link l JOIN incident i ON i.id = (CASE WHEN l.src_id=?1 THEN l.dst_id ELSE l.src_id END) \
         WHERE l.src_id=?1 OR l.dst_id=?1 ORDER BY l.created DESC LIMIT 200",
    ) {
        if let Ok(rows) = stmt.query_map(params![id], |r| {
            Ok(json!({ "id": r.get::<_,i64>(0)?, "kind": r.get::<_,String>(1)?, "note": r.get::<_,String>(2)?,
                       "title": r.get::<_,String>(3)?, "status": r.get::<_,String>(4)? }))
        }) {
            out = rows.flatten().collect();
        }
    }
    out
}

// ================================================================================================
// PER-ASSIGNEE QUEUES — agrégat de charge par propriétaire (la liste reste cases_list_json_paged #4a).
// ================================================================================================

/// Résumé de file par ASSIGNEE : open (actifs non fusionnés), overdue (SLA legacy dépassé), ack_pending (SLA
/// multi-niveau : ack_due dépassé, pas acquitté), breach (ack/resolve breach), waiting (en pause). Un bucket
/// `(none)` agrège les non-assignés. Lecture pure agrégée (GROUP BY) sur `incident` (human-scale). #39.
pub(crate) fn case_queues_json(conn: &Connection, now_i: i64) -> Value {
    let sql = "SELECT COALESCE(NULLIF(assignee,''),'(none)') AS who, \
               COUNT(*) AS open, \
               SUM(CASE WHEN sla_due IS NOT NULL AND ?1>sla_due THEN 1 ELSE 0 END) AS overdue, \
               SUM(CASE WHEN ack_due IS NOT NULL AND ?1>ack_due AND first_response_ts IS NULL AND sla_paused_since IS NULL THEN 1 ELSE 0 END) AS ack_pending, \
               SUM(CASE WHEN ack_breached=1 OR resolve_breached=1 THEN 1 ELSE 0 END) AS breach, \
               SUM(CASE WHEN status='waiting' THEN 1 ELSE 0 END) AS waiting \
               FROM incident \
               WHERE archived=0 AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained') \
               GROUP BY who ORDER BY open DESC, who LIMIT 500";
    let rows: Vec<Value> = conn
        .prepare(sql)
        .and_then(|mut s| {
            s.query_map(params![now_i], |r| {
                Ok(json!({ "assignee": r.get::<_,String>(0)?, "open": r.get::<_,i64>(1)?, "overdue": r.get::<_,i64>(2)?,
                           "ack_pending": r.get::<_,i64>(3)?, "breach": r.get::<_,i64>(4)?, "waiting": r.get::<_,i64>(5)? }))
            }).map(|x| x.flatten().collect())
        })
        .unwrap_or_default();
    json!({ "queues": rows })
}

// ================================================================================================
// MTTA / MTTR DASHBOARD — agrégation sur `incident` (mean/p50, par assignee/severity).
// ================================================================================================

/// p50 (médiane) d'un vecteur trié-able, en Rust (les cases sont human-scale : quelques milliers, pas des
/// millions -> pas de scan chiffré massif). Vecteur vide -> None.
fn p50(mut v: Vec<i64>) -> Option<i64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// TABLEAU DE BORD MTTA/MTTR #39 : agrège sur une FENÊTRE [from,to] (bornée sur closed_ts pour MTTR/MTTA des
/// cases résolus dans la fenêtre) :
///   - MTTA = first_response_ts - ts (temps d'acquittement) ; MTTR = closed_ts - ts - pause (temps de résolution).
///   - overall {resolved, mtta_mean, mtta_p50, mttr_mean, mttr_p50, ack_breaches, resolve_breaches} + open_now,
///     overdue_now (instantanés) ; by_assignee & by_severity (mean MTTA/MTTR + résolus + breach).
/// Lecture pure. `to<=0` -> now. Fenêtre par défaut = 30 j si from<=0.
pub(crate) fn case_metrics_json(conn: &Connection, from_in: i64, to_in: i64) -> Value {
    let to = if to_in > 0 { to_in } else { now() };
    let from = if from_in > 0 { from_in } else { to - 30 * 86400 };
    // Valeurs individuelles (résolus dans la fenêtre) pour mean + p50 (Rust). Borné LIMIT (garde-fou mémoire).
    let mut mtta: Vec<i64> = Vec::new();
    let mut mttr: Vec<i64> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT first_response_ts, closed_ts, ts, COALESCE(sla_pause_accum,0) FROM incident \
         WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL LIMIT 50000",
    ) {
        if let Ok(rows) = stmt.query_map(params![from, to], |r| {
            Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
        }) {
            for (fr, closed, ts, pause) in rows.flatten() {
                if let Some(fr) = fr {
                    if fr >= ts {
                        mtta.push(fr - ts);
                    }
                }
                let r = closed - ts - pause;
                if r >= 0 {
                    mttr.push(r);
                }
            }
        }
    }
    let mean = |v: &[i64]| -> Option<i64> {
        if v.is_empty() { None } else { Some(v.iter().sum::<i64>() / v.len() as i64) }
    };
    let resolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL",
        params![from, to], |r| r.get(0)).unwrap_or(0);
    let now_i = now();
    let open_now: i64 = conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE archived=0 AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained')",
        [], |r| r.get(0)).unwrap_or(0);
    let overdue_now: i64 = conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE sla_due IS NOT NULL AND ?1>sla_due AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained')",
        params![now_i], |r| r.get(0)).unwrap_or(0);
    let ack_breaches: i64 = conn.query_row("SELECT COUNT(*) FROM incident WHERE ack_breached=1 AND ts>=?1 AND ts<=?2", params![from, to], |r| r.get(0)).unwrap_or(0);
    let resolve_breaches: i64 = conn.query_row("SELECT COUNT(*) FROM incident WHERE resolve_breached=1 AND ts>=?1 AND ts<=?2", params![from, to], |r| r.get(0)).unwrap_or(0);
    // by_assignee : mean MTTA/MTTR + résolus + breach (SQL agrégé ; mean SQL suffit par groupe).
    let by_assignee: Vec<Value> = conn.prepare(
        "SELECT COALESCE(NULLIF(assignee,''),'(none)') AS who, COUNT(*), \
                AVG(CASE WHEN first_response_ts IS NOT NULL AND first_response_ts>=ts THEN first_response_ts-ts END), \
                AVG(CASE WHEN closed_ts-ts-COALESCE(sla_pause_accum,0)>=0 THEN closed_ts-ts-COALESCE(sla_pause_accum,0) END), \
                SUM(CASE WHEN ack_breached=1 OR resolve_breached=1 THEN 1 ELSE 0 END) \
         FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL \
         GROUP BY who ORDER BY COUNT(*) DESC LIMIT 200")
        .and_then(|mut s| s.query_map(params![from, to], |r| {
            Ok(json!({ "assignee": r.get::<_,String>(0)?, "resolved": r.get::<_,i64>(1)?,
                       "mtta_mean": r.get::<_,Option<f64>>(2)?.map(|x| x as i64),
                       "mttr_mean": r.get::<_,Option<f64>>(3)?.map(|x| x as i64),
                       "breach": r.get::<_,i64>(4)? }))
        }).map(|x| x.flatten().collect())).unwrap_or_default();
    let by_severity: Vec<Value> = conn.prepare(
        "SELECT severity, COUNT(*), \
                AVG(CASE WHEN first_response_ts IS NOT NULL AND first_response_ts>=ts THEN first_response_ts-ts END), \
                AVG(CASE WHEN closed_ts-ts-COALESCE(sla_pause_accum,0)>=0 THEN closed_ts-ts-COALESCE(sla_pause_accum,0) END) \
         FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL \
         GROUP BY severity ORDER BY severity DESC LIMIT 20")
        .and_then(|mut s| s.query_map(params![from, to], |r| {
            Ok(json!({ "severity": r.get::<_,i64>(0)?, "resolved": r.get::<_,i64>(1)?,
                       "mtta_mean": r.get::<_,Option<f64>>(2)?.map(|x| x as i64),
                       "mttr_mean": r.get::<_,Option<f64>>(3)?.map(|x| x as i64) }))
        }).map(|x| x.flatten().collect())).unwrap_or_default();
    json!({
        "window": { "from": from, "to": to },
        "overall": {
            "resolved": resolved, "open_now": open_now, "overdue_now": overdue_now,
            "mtta_mean": mean(&mtta), "mtta_p50": p50(mtta.clone()),
            "mttr_mean": mean(&mttr), "mttr_p50": p50(mttr.clone()),
            "ack_breaches": ack_breaches, "resolve_breaches": resolve_breaches,
        },
        "by_assignee": by_assignee,
        "by_severity": by_severity,
    })
}

// ================================================================================================
// CLIENT-READ API (external, read-only, tenant-scoped, masked). Cf. INVARIANT en tête de module.
// ================================================================================================

/// Statut CLIENT-FACING (mappe le vocabulaire interne vers un cycle de vie neutre pour l'externe) : on n'expose
/// PAS 'triage'/'in_progress' bruts si l'on veut ; ici on garde un mapping lisible sans fuite d'info interne.
fn client_status(internal: &str) -> &'static str {
    match internal {
        "new" => "open",
        "triage" => "open",
        "in_progress" => "in_progress",
        "waiting" => "waiting",
        "resolved" | "contained" => "resolved",
        "closed" => "closed",
        _ => "open",
    }
}

/// #3 PHASE 3 — Part B : PHASE CLIENT COARSE. Étiquette humaine, neutre, dérivée UNIQUEMENT de la colonne
/// `status` (cycle de vie du case) — JAMAIS de `case_step` (aucun titre/nombre/guidance/target d'étape n'entre
/// ici), JAMAIS du runbook, JAMAIS du `incident_tier`/`incident_type`/`commander`. C'est un enum FERMÉ contrôlé
/// serveur (littéraux fixes) : rien de dérivé du client/case en texte libre -> pas de masquage requis (INVARIANT
/// #2 : les enum dérivés de colonnes NON secrètes ne sont pas masqués). 'contained' est un état de cycle de vie
/// du case (pas une étape) -> bucket coarse « contenu ». Le client apprend OÙ EN EST son case, jamais COMMENT.
fn client_phase(internal: &str) -> &'static str {
    match internal {
        "new" | "triage" => "ouvert",
        "in_progress" => "en cours de traitement",
        "waiting" => "en attente",
        "contained" => "contenu",
        "resolved" => "résolu",
        "closed" => "clôturé",
        _ => "ouvert",
    }
}

/// PROJECTION CLIENT d'une ligne de case — ALLOWLIST FERMÉE de colonnes `incident` (aucun secret, aucun
/// owner/assignee, aucune note interne). Titre passé au masque du rôle appelant (défense en profondeur #45).
/// `overdue` calculé au read. C'est le SEUL point où des données de case sortent vers un client.
///
/// #3 PHASE 3 — Part B (⚠ ÉLARGIT LA PROJECTION CLIENT — cf. INVARIANT en tête de module ; surface
/// d'isolation sensible) : trois champs ADDITIFS, tous dérivés de colonnes NON secrètes déjà tenant-scopées, sans
/// aucune colonne interne d'incident/runbook/step :
///   - `is_incident` (bool) = `incident_tier IS NOT NULL`. Le BOOLÉEN seul ; le tier BRUT (1..4), `incident_type`
///     et `commander` NE sont JAMAIS lus ici (le SELECT calcule `IS NOT NULL` en SQL -> l'entier ne rentre même
///     pas dans Rust).
///   - `phase` (string) = enum coarse FERMÉ dérivé du seul `status` (cf. client_phase) — jamais une étape.
///   - `acknowledged` (bool) = `first_response_ts IS NOT NULL` (timing MTTA-style : « quelqu'un a pris le case »).
///     Le timestamp brut / la durée MTTA ne sont PAS exposés (coarse only).
/// Ces trois champs sont des bool/enum contrôlés serveur -> non masqués (INVARIANT #2). Aucun `case_step`,
/// `search_soql`, `action_kind`, note, ref alert/event, identité analyste n'est ajouté : allowlist TOUJOURS fermée.
#[allow(clippy::too_many_arguments)]
fn client_case_row(db_path: &str, masks: &guatx_core::soql::FieldMaskSet, id: i64, ts: i64, updated: i64, title: &str, status: &str, severity: i64, priority: i64, closed_ts: Option<i64>, overdue: bool, is_incident: bool, acknowledged: bool) -> Value {
    let title_v = if masks.is_empty() { json!(title) } else { mask_field_value(db_path, masks, "title", &json!(title)) };
    json!({
        "id": id, "opened": ts, "updated": updated, "title": title_v,
        "status": client_status(status), "severity": severity,
        "priority": priority, "priority_label": priority_label(priority),
        "closed": closed_ts, "overdue": overdue,
        "is_incident": is_incident, "phase": client_phase(status), "acknowledged": acknowledged,
    })
}

/// LISTE CLIENT paginée des cases du tenant appelant : projection fermée, filtre par statut ouvert/résolu
/// optionnel, tri updated DESC. `total` = COUNT après filtre (pager serveur). MASQUE appliqué au titre.
/// EXCLUT les cases archivés ET fusionnés (vue client propre). Lecture pure sur `incident`.
pub(crate) fn client_cases_list_json(conn: &Connection, db_path: &str, masks: &guatx_core::soql::FieldMaskSet, now_i: i64, state: &str, limit: i64, offset: i64) -> Value {
    // filtre de PÉRIMÈTRE client : "open" = actifs, "resolved" = terminaux, "" = tous. Toujours non-archivé,
    // non-fusionné. Littéraux -> pas d'injection.
    let where_state = match state {
        "open" => "AND status NOT IN ('resolved','closed','contained')",
        "resolved" => "AND status IN ('resolved','closed','contained')",
        _ => "",
    };
    let base = format!("FROM incident WHERE archived=0 AND merged_into IS NULL {where_state}");
    let total: i64 = conn.query_row(&format!("SELECT COUNT(*) {base}"), [], |r| r.get(0)).unwrap_or(0);
    // Part B : `is_incident`/`acknowledged` calculés en SQL comme BOOLÉENS (IS NOT NULL) -> le tier brut et le
    // timestamp MTTA ne sont JAMAIS matérialisés côté Rust. Allowlist fermée : deux colonnes bool ajoutées, rien d'autre.
    let sql = format!(
        "SELECT id,ts,updated,COALESCE(title,''),status,severity,priority,closed_ts, \
                (sla_due IS NOT NULL AND ?1>sla_due AND status NOT IN ('resolved','closed','contained')) AS overdue, \
                (incident_tier IS NOT NULL) AS is_incident, (first_response_ts IS NOT NULL) AS acknowledged \
         {base} ORDER BY updated DESC LIMIT ?2 OFFSET ?3");
    let rows: Vec<Value> = conn
        .prepare(&sql)
        .and_then(|mut s| {
            s.query_map(params![now_i, limit, offset], |r| {
                Ok(client_case_row(db_path, masks, r.get(0)?, r.get(1)?, r.get(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get::<_, i64>(8)? != 0, r.get::<_, i64>(9)? != 0, r.get::<_, i64>(10)? != 0))
            }).map(|x| x.flatten().collect())
        })
        .unwrap_or_default();
    json!({ "cases": rows, "total": total })
}

/// DÉTAIL CLIENT d'un case : la projection fermée + une timeline RESTREINTE aux événements de CYCLE DE VIE
/// (created/status/sla/merge) — JAMAIS les notes internes, actions, ni les refs alert/event (télémétrie interne).
/// Les auteurs analystes sont ANONYMISÉS ('SOC'). None si le case n'existe pas / est archivé / fusionné.
pub(crate) fn client_case_get_json(conn: &Connection, db_path: &str, masks: &guatx_core::soql::FieldMaskSet, id: i64, now_i: i64) -> Option<Value> {
    let mut c = conn.query_row(
        "SELECT id,ts,updated,COALESCE(title,''),status,severity,priority,closed_ts, \
                (sla_due IS NOT NULL AND ?2>sla_due AND status NOT IN ('resolved','closed','contained')), \
                (incident_tier IS NOT NULL), (first_response_ts IS NOT NULL) \
         FROM incident WHERE id=?1 AND archived=0 AND merged_into IS NULL",
        params![id, now_i],
        |r| Ok(client_case_row(db_path, masks, r.get(0)?, r.get(1)?, r.get(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get::<_, i64>(8)? != 0, r.get::<_, i64>(9)? != 0, r.get::<_, i64>(10)? != 0)),
    ).ok()?;
    // Timeline CYCLE DE VIE uniquement (allowlist de kinds ; auteurs anonymisés ; body des notes/alertes EXCLU).
    let items: Vec<Value> = conn
        .prepare("SELECT ts,kind FROM incident_item WHERE incident_id=?1 AND kind IN ('created','status','sla','merge') ORDER BY ts,id LIMIT 500")
        .and_then(|mut s| s.query_map(params![id], |r| {
            let kind: String = r.get(1)?;
            Ok(json!({ "ts": r.get::<_,i64>(0)?, "event": kind, "by": "SOC" }))
        }).map(|x| x.flatten().collect()))
        .unwrap_or_default();
    c["timeline"] = json!(items);
    Some(c)
}

// ================================================================================================
// HANDLERS AXUM
// ================================================================================================

/// GET /api/cases/queues — résumé de charge par assignee (+ « my queue » côté UI via le filtre assignee de
/// /api/cases). Lecture (viewer+). Read-pool + watchdog (comme cases_list).
pub(crate) async fn case_queues(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({ "queues": [] })),
    };
    let db_path = req_db_path(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "queues": [] }), move |conn| case_queues_json(conn, now_i)))
        .await
        .unwrap_or_else(|_| json!({ "queues": [] }));
    Json(res)
}

/// GET /api/cases/metrics[?from=&to=] — tableau de bord MTTA/MTTR (fenêtre, par assignee/severity). Lecture.
pub(crate) async fn case_metrics(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let from = q.get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({})),
    };
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({}), move |conn| case_metrics_json(conn, from, to)))
        .await
        .unwrap_or_else(|_| json!({}));
    Json(res)
}

/// POST /api/cases/:id/merge {into} — fusion SOFT du case :id DANS `into`. Mutating (editor+). Ledgerisé,
/// non destructif (source conservée + réversible). 404 si un case manque / refus (déjà fusionné / cycle).
pub(crate) async fn case_merge_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    let into = b.get("into").and_then(|v| v.as_i64()).unwrap_or(0);
    if into <= 0 {
        return StatusCode::BAD_REQUEST;
    }
    with_write(&st, &au, |conn| {
        if case_merge(&conn, id, into, &au.name) { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }
    })
}

/// POST /api/cases/:id/unmerge — dé-fusionne (réversibilité). Mutating (editor+).
pub(crate) async fn case_unmerge_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    with_write(&st, &au, |conn| {
        if case_unmerge(&conn, id, &au.name) { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }
    })
}

/// GET /api/cases/:id/links — liens du case. POST /api/cases/:id/links {to,kind,note} — ajoute un lien.
pub(crate) async fn case_links_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "links": [] }), move |conn| json!({ "links": case_links_json(conn, id) })))
        .await
        .unwrap_or_else(|_| json!({ "links": [] }));
    Json(res)
}

pub(crate) async fn case_link_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    let to = b.get("to").and_then(|v| v.as_i64()).unwrap_or(0);
    let kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("related").to_string();
    let note = b.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if to <= 0 {
        return StatusCode::BAD_REQUEST;
    }
    with_write(&st, &au, |conn| {
        if case_link_add(&conn, id, to, &kind, &note, &au.name) { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }
    })
}

pub(crate) async fn case_unlink_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, other)): Path<(i64, i64)>) -> StatusCode {
    with_write(&st, &au, |conn| {
        if case_link_remove(&conn, id, other, &au.name) { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }
    })
}

// ---------- SLA policy CRUD (editor+ ; destructive delete = admin re-check dans le handler) ----------

/// GET /api/sla-policies — liste des politiques SLA multi-niveau. Lecture (viewer+).
pub(crate) async fn sla_policies_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "policies": [] }), |conn| {
        let rows: Vec<Value> = conn
            .prepare("SELECT id,name,priority,ack_target_s,resolve_target_s,enabled FROM sla_policy ORDER BY priority")
            .and_then(|mut s| {
                s.query_map([], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "priority": r.get::<_, i64>(2)?,
                        "ack_target_s": r.get::<_, i64>(3)?, "resolve_target_s": r.get::<_, i64>(4)?, "enabled": r.get::<_, i64>(5)? != 0
                    }))
                })
                .map(|x| x.flatten().collect())
            })
            .unwrap_or_default();
        json!({ "policies": rows })
    })).await.unwrap_or_else(|_| json!({ "policies": [] }));
    Json(res)
}

/// POST /api/sla-policies {name,priority,ack_target_s,resolve_target_s,enabled?} — upsert par priorité. editor+.
/// Ledgerisé. Recompute les dues des cases ACTIFS de cette priorité (borné). priority hors 1..4 -> 400.
pub(crate) async fn sla_policy_upsert(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> StatusCode {
    let priority = b.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
    if !(1..=4).contains(&priority) {
        return StatusCode::BAD_REQUEST;
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let ack_s = b.get("ack_target_s").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let res_s = b.get("resolve_target_s").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let enabled = b.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as i64;
    if ack_s == 0 || res_s == 0 {
        return StatusCode::BAD_REQUEST;
    }
    with_write(&st, &au, |conn| {
        let t = now();
        let _ = conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?6) \
             ON CONFLICT(priority) DO UPDATE SET name=?1,ack_target_s=?3,resolve_target_s=?4,enabled=?5,updated=?6",
            params![name, priority, ack_s, res_s, enabled, t, au.name],
        );
        ledger_append(&conn, "sla_policy.upsert", &format!("P{priority} ack={ack_s}s resolve={res_s}s by {}", au.name));
        // recompute borné : cases ACTIFS de cette priorité non fusionnés (human-scale).
        let ids: Vec<i64> = conn.prepare("SELECT id FROM incident WHERE priority=?1 AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained') LIMIT 5000")
            .and_then(|mut s| s.query_map(params![priority], |r| r.get(0)).map(|x| x.flatten().collect())).unwrap_or_default();
        for cid in ids {
            sla_apply_policy(&conn, cid);
        }
        StatusCode::NO_CONTENT
    })
}

/// DELETE /api/sla-policies/:id — supprime une politique. ADMIN-ONLY (config gouvernante) : re-check handler.
pub(crate) async fn sla_policy_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    if !au.is_admin() {
        return StatusCode::FORBIDDEN;
    }
    with_write(&st, &au, |conn| {
        let n = conn.execute("DELETE FROM sla_policy WHERE id=?1", params![id]).unwrap_or(0);
        if n == 0 {
            return StatusCode::NOT_FOUND;
        }
        ledger_append(&conn, "sla_policy.delete", &format!("#{id} by {}", au.name));
        StatusCode::NO_CONTENT
    })
}

// ---------- CLIENT-READ API handlers ----------

/// Masques EFFECTIFS de l'appelant client — VRAI tenant/role/env (jamais ""), comme /api/query & #60.
fn client_masks(st: &AppState, au: &AuthUser) -> guatx_core::soql::FieldMaskSet {
    effective_masks(req_db_path(st, au).as_str(), &au.role, &au.tenant, au.env_filter())
}

/// GET /api/client/cases[?state=open|resolved&limit=&offset=] — LISTE client read-only, tenant-scopée, masquée.
/// Cf. INVARIANT SÉCU en tête de module. Read-pool + watchdog. Jamais de mutation ni de SQL brut.
pub(crate) async fn client_cases_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let state = q.get("state").cloned().unwrap_or_default();
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(100).clamp(1, 500);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({ "cases": [], "total": 0 })),
    };
    let db_path = req_db_path(&st, &au);
    let masks = client_masks(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || {
        let dbp = db_path.clone();
        read_with_watchdog(&db_path, json!({ "cases": [], "total": 0 }), move |conn| client_cases_list_json(conn, &dbp, &masks, now_i, &state, limit, offset))
    })
    .await
    .unwrap_or_else(|_| json!({ "cases": [], "total": 0 }));
    Json(res)
}

/// GET /api/client/cases/:id — DÉTAIL client (projection fermée + timeline cycle-de-vie anonymisée). 404 si
/// absent/archivé/fusionné. Tenant-scopé + masqué (INVARIANT).
pub(crate) async fn client_case_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    let db_path = req_db_path(&st, &au);
    let masks = client_masks(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || {
        let dbp = db_path.clone();
        read_with_watchdog(&db_path, None, move |conn| client_case_get_json(conn, &dbp, &masks, id, now_i))
    })
    .await
    .unwrap_or(None);
    match res {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, "case introuvable").into_response(),
    }
}
