//! Gestion d'incident (cases) : cœur testable pur sur &Connection (SLA `sla_target_s`, priorités
//! `parse_priority`/`priority_label`, statuts, `resolve_case_ref`, CRUD row `case_create_row`/
//! `case_apply_update`/`case_get_json`, listing paginé `cases_list_json_paged`, timeline, archivage,
//! escalade `escalate_overdue_cases`), les handlers CRUD cases et `ack`/`ack_all`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- gestion d'incident (cases) : table `incident` + `incident_item` (timeline) ----------
// ---- #4a CASES FIRST-CLASS — cœur TESTABLE (fonctions pures / sur &Connection, sans AppState) ----------

/// Cible SLA (secondes) par priorité (1=critique .. 4=bas). Sert au calcul de sla_due (création/priorisation)
/// ET de MIROIR au backfill SQL de la migration v69 (garder les deux en phase). Toute valeur hors 1..4 -> P3.
pub(crate) fn sla_target_s(priority: i64) -> i64 {
    match priority {
        1 => 3600,    // P1 critique : 1 h
        2 => 14400,   // P2 haut : 4 h
        3 => 86400,   // P3 moyen : 24 h
        _ => 259200,  // P4 bas : 72 h
    }
}

/// Normalise une priorité entrante — entier 1..4 OU libellé texte (critical/high/med/low, alias p1..p4/1..4)
/// -> entier BORNÉ 1..4. None si absente/invalide (l'appelant garde la valeur courante). Bridge des deux
/// vocabulaires demandés (#4a : priority low/med/high/critical côté produit, stockée en entier ordonnable).
pub(crate) fn parse_priority(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n.clamp(1, 4));
    }
    if let Some(s) = v.as_str() {
        return match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" | "p1" | "1" => Some(1),
            "high" | "p2" | "2" => Some(2),
            "med" | "medium" | "p3" | "3" => Some(3),
            "low" | "p4" | "4" => Some(4),
            _ => None,
        };
    }
    None
}

/// Libellé texte d'une priorité entière (miroir de parse_priority) exposé à l'API/UI (low/med/high/critical).
pub(crate) fn priority_label(p: i64) -> &'static str {
    match p {
        1 => "critical",
        2 => "high",
        3 => "med",
        _ => "low",
    }
}

/// Normalise un statut de case vers le vocabulaire CANONIQUE first-class (#4a),
/// new -> triage -> in_progress -> resolved -> closed, en TOLÉRANT les alias LEGACY (open/investigating/
/// contained) posés avant la v69. None si le statut est inconnu (l'appelant refuse le changement). NB : la
/// migration ne réécrit JAMAIS le statut stocké ; cette normalisation ne s'applique qu'aux ENTRÉES d'update.
pub(crate) fn norm_case_status(v: &str) -> Option<&'static str> {
    match v.trim() {
        "new" | "open" => Some("new"),
        "triage" => Some("triage"),
        "in_progress" | "investigating" => Some("in_progress"),
        // #39 — statut ACTIF « en attente / on-hold » : NON terminal, mais METS EN PAUSE le chrono SLA
        // multi-niveau (cf. sla_on_status_change). Additif : aucun case ne le porte en mode 0.
        "waiting" | "on_hold" | "pending" => Some("waiting"),
        "resolved" | "contained" => Some("resolved"),
        "closed" => Some("closed"),
        _ => None,
    }
}

/// #4a case-ops — VERDICTS DE DISPOSITION FERMÉS (source unique de vérité). Le verdict porté par l'analyste à
/// la clôture d'un case. NULL/'' = non-défini. Toute autre valeur est REJETÉE (400) au bord de l'API. Les
/// labels s'accumulent pour un futur apprentissage supervisé (DIFFÉRÉ — ce n'est PAS du ML). Verdict INTERNE :
/// JAMAIS projeté au client MSSP (hors `client_case_row`).
pub(crate) const DISPOSITION_VALUES: &[&str] = &["true_positive", "false_positive", "benign", "duplicate"];

/// Vrai si `s` est un verdict de disposition VALIDE (membre de l'allowlist fermée). La chaîne vide (non-défini)
/// n'est PAS un membre : l'appelant la traite à part (unset), elle n'est pas un 400.
pub(crate) fn disposition_valid(s: &str) -> bool {
    DISPOSITION_VALUES.contains(&s)
}

/// Résolution INVERSE d'une ref d'item de timeline ('alert:<id>' | 'event:<id>') -> (titre, sévérité), pour
/// afficher un libellé lisible au lieu de la ref brute. Point-lookup par PK (JAMAIS de scan : budget 2 Go).
/// (None, None) si ref vide/inconnue ou cible supprimée (rétention).
pub(crate) fn resolve_case_ref(conn: &Connection, rf: &str) -> (Option<String>, Option<i64>) {
    if let Some(ids) = rf.strip_prefix("alert:") {
        if let Ok(id) = ids.parse::<i64>() {
            if let Ok(r) = conn.query_row(
                "SELECT COALESCE(title,''),severity FROM alert WHERE id=?1",
                params![id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            ) {
                return (Some(r.0), Some(r.1));
            }
        }
    } else if let Some(ids) = rf.strip_prefix("event:") {
        if let Ok(id) = ids.parse::<i64>() {
            if let Ok(r) = conn.query_row(
                "SELECT COALESCE(message,''),severity FROM event WHERE id=?1",
                params![id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            ) {
                return (Some(r.0), Some(r.1));
            }
        }
    }
    (None, None)
}

/// Insère un item de timeline horodaté + auteur, bump `incident.updated`, et fige first_response_ts (MTTA) au
/// 1er item de RÉPONSE analyste (ni 'note', ni 'created', ni 'sla' système). CŒUR COMMUN des mutations de case :
/// chaque action laisse une trace d'audit datée dans la timeline (#4a).
pub(crate) fn case_add_item(conn: &Connection, incident_id: i64, t: i64, kind: &str, author: &str, body: &str, rf: Option<&str>) {
    let _ = conn.execute(
        "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,?2,?3,?4,?5,?6)",
        params![incident_id, t, kind, author, body, rf],
    );
    let _ = conn.execute("UPDATE incident SET updated=?1 WHERE id=?2", params![t, incident_id]);
    // MTTA : archive/unarchive sont des gestes ADMIN de rangement (#4a-bis), PAS une réponse analyste ->
    // exclus, comme note/created/sla, pour ne pas figer un faux first_response_ts.
    if !matches!(kind, "note" | "created" | "sla" | "archive" | "unarchive") {
        let _ = conn.execute(
            "UPDATE incident SET first_response_ts=?1 WHERE id=?2 AND first_response_ts IS NULL",
            params![t, incident_id],
        );
    }
}

/// Crée un case first-class : statut canonique 'new', priorité bornée 1..4, sla_due = ts + cible(priority),
/// item 'created', audit ledger (case.create). owner = créateur (immuable ensuite). Renvoie l'id. #4a.
pub(crate) fn case_create_row(conn: &Connection, author: &str, title: &str, sev: i64, summary: &str, assignee: Option<&str>, priority: i64) -> i64 {
    let t = now();
    let pr = priority.clamp(1, 4);
    let sla_due = t + sla_target_s(pr);
    let _ = conn.execute(
        "INSERT INTO incident(ts,updated,title,status,severity,owner,summary,priority,assignee,sla_due) \
         VALUES(?1,?1,?2,'new',?3,?4,?5,?6,?7,?8)",
        params![t, title, sev, author, summary, pr, assignee, sla_due],
    );
    let id = conn.last_insert_rowid();
    case_add_item(conn, id, t, "created", author, "Incident créé", None);
    ledger_append(conn, "case.create", &format!("#{id} '{title}' by {author}"));
    // #39 — pose les échéances SLA MULTI-NIVEAU (ack_due/resolve_due) si une politique gouverne cette priorité.
    // INERTE si `sla_policy` VIDE (mode 0 : sla_apply_policy retourne sans écrire -> SLA legacy sla_due inchangé).
    sla_apply_policy(conn, id);
    id
}

/// Applique un patch de case (title/severity/owner/summary/priority/assignee/status). Chaque changement
/// SÉMANTIQUE écrit un item de timeline TYPÉ (assign/priority/status) + bump `updated` ; recalcule sla_due
/// depuis la priorité courante tant que le case n'est pas TERMINAL (resolved/closed/contained) ; audit ledger
/// (case.assign / case.status). closed/resolved posent closed_ts ; un reopen (statut non terminal) le remet à
/// NULL et ré-arme escalated. Statuts LEGACY tolérés en entrée (alias canoniques). false si le case n'existe
/// pas. couvre assign / close / reopen / priorisation. #4a.
pub(crate) fn case_apply_update(conn: &Connection, id: i64, author: &str, b: &Value) -> bool {
    let cur: Option<(i64, String)> = conn
        .query_row("SELECT priority, status FROM incident WHERE id=?1", params![id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })
        .ok();
    let Some((mut cur_priority, cur_status)) = cur else { return false; };
    let t = now();
    if let Some(v) = b.get("title").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE incident SET title=?1 WHERE id=?2", params![v.trim(), id]);
    }
    if let Some(v) = b.get("severity").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE incident SET severity=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("owner").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE incident SET owner=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("summary").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE incident SET summary=?1 WHERE id=?2", params![v, id]);
    }
    // ASSIGNATION dédiée (owner reste le créateur). Chaîne vide -> désassignation.
    if let Some(v) = b.get("assignee") {
        let a = v.as_str().unwrap_or("").trim().to_string();
        let stored: Option<String> = if a.is_empty() { None } else { Some(a.clone()) };
        let _ = conn.execute("UPDATE incident SET assignee=?1 WHERE id=?2", params![stored, id]);
        let body = if a.is_empty() { "désassigné".to_string() } else { format!("assigné à {a}") };
        case_add_item(conn, id, t, "assign", author, &body, None);
        ledger_append(conn, "case.assign", &format!("#{id} -> {} by {author}", if a.is_empty() { "(aucun)" } else { &a }));
    }
    // PRIORITÉ 1..4 (entier ou libellé) -> item 'priority' ; recalcul sla_due plus bas.
    if let Some(pr) = b.get("priority").and_then(parse_priority) {
        cur_priority = pr;
        let _ = conn.execute("UPDATE incident SET priority=?1 WHERE id=?2", params![pr, id]);
        case_add_item(conn, id, t, "priority", author, &format!("priorité -> P{pr} ({})", priority_label(pr)), None);
    }
    // STATUT canonique (+ alias legacy). closed/resolved -> closed_ts=t ; reopen (non terminal) -> closed_ts=NULL.
    let mut new_status: Option<&str> = None;
    if let Some(v) = b.get("status").and_then(|v| v.as_str()) {
        if let Some(s) = norm_case_status(v) {
            new_status = Some(s);
            let closed = if matches!(s, "closed" | "resolved") { Some(t) } else { None };
            let _ = conn.execute("UPDATE incident SET status=?1, closed_ts=?2 WHERE id=?3", params![s, closed, id]);
            case_add_item(conn, id, t, "status", author, &format!("statut -> {s}"), None);
            ledger_append(conn, "case.status", &format!("#{id} -> {s} by {author}"));
        }
    }
    // DISPOSITION (#4a) — VERDICT analyste posé à la clôture (ou changé). Optionnel. Valeur FERMÉE (l'API rejette
    // 400 en amont ; ici garde fail-closed : une valeur non-membre est un NO-OP, jamais écrite). '' -> unset (NULL).
    // Trace timeline TYPÉE ('disposition') + audit ledger (case.disposition) comme case.status/case.assign. Pose
    // disposition_ts=now + disposition_by=author. RESTE HORS de la projection client-read (verdict interne).
    if let Some(dv) = b.get("disposition") {
        let d = dv.as_str().unwrap_or("").trim();
        if d.is_empty() {
            let _ = conn.execute(
                "UPDATE incident SET disposition=NULL, disposition_ts=NULL, disposition_by=NULL WHERE id=?1",
                params![id],
            );
            case_add_item(conn, id, t, "disposition", author, "verdict effacé", None);
            ledger_append(conn, "case.disposition", &format!("#{id} -> (aucun) by {author}"));
        } else if disposition_valid(d) {
            let _ = conn.execute(
                "UPDATE incident SET disposition=?1, disposition_ts=?2, disposition_by=?3 WHERE id=?4",
                params![d, t, author, id],
            );
            case_add_item(conn, id, t, "disposition", author, &format!("verdict -> {d}"), None);
            ledger_append(conn, "case.disposition", &format!("#{id} -> {d} by {author}"));
        }
        // valeur non-vide et non-membre : ignorée (fail-closed ; l'API a déjà renvoyé 400).
    }
    // RECALCUL sla_due = ts + cible(priorité courante) tant que le case n'est pas TERMINAL. Idempotent si la
    // priorité n'a pas changé (même résultat) ; ré-arme escalated si l'échéance repart dans le futur.
    let effective_status = new_status.map(|s| s.to_string()).unwrap_or(cur_status);
    if !matches!(effective_status.as_str(), "resolved" | "closed" | "contained") {
        let _ = conn.execute("UPDATE incident SET sla_due = ts + ?1 WHERE id=?2", params![sla_target_s(cur_priority), id]);
        let _ = conn.execute("UPDATE incident SET escalated=0 WHERE id=?1 AND sla_due > ?2", params![id, t]);
    }
    // #39 SLA MULTI-NIVEAU (INERTE si `sla_policy_id` NULL -> mode 0 byte-identique) : pause/reprise du chrono
    // sur transition de statut (entrée/sortie 'waiting') ; recalcul des échéances si la priorité a changé.
    if new_status.is_some() {
        sla_on_status_change(conn, id, &effective_status, t);
    }
    if b.get("priority").and_then(parse_priority).is_some() {
        sla_apply_policy(conn, id);
    }
    let _ = conn.execute("UPDATE incident SET updated=?1 WHERE id=?2", params![t, id]);
    true
}

/// Métadonnées + timeline (refs alert/event RÉSOLUES en titre+sévérité) d'un case, avec overdue calculé AU
/// READ (now > sla_due ET statut non terminal). None si introuvable. #4a.
pub(crate) fn case_get_json(conn: &Connection, id: i64, now_i: i64) -> Option<Value> {
    let mut c = conn
        .query_row(
            "SELECT id,ts,updated,title,status,severity,COALESCE(owner,''),COALESCE(summary,''),closed_ts,\
                    priority,COALESCE(assignee,''),sla_due,first_response_ts,\
                    (sla_due IS NOT NULL AND ?2 > sla_due AND status NOT IN ('resolved','closed','contained')),\
                    archived,archived_ts,COALESCE(archived_by,''),\
                    merged_into,ack_due,resolve_due,ack_breached,resolve_breached,sla_paused_since,\
                    disposition,disposition_ts,COALESCE(disposition_by,'') \
             FROM incident WHERE id=?1",
            params![id, now_i],
            |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "updated": r.get::<_, i64>(2)?,
                    "title": r.get::<_, String>(3)?, "status": r.get::<_, String>(4)?, "severity": r.get::<_, i64>(5)?,
                    "owner": r.get::<_, String>(6)?, "summary": r.get::<_, String>(7)?, "closed_ts": r.get::<_, Option<i64>>(8)?,
                    "priority": r.get::<_, i64>(9)?, "priority_label": priority_label(r.get::<_, i64>(9)?),
                    "assignee": r.get::<_, String>(10)?, "sla_due": r.get::<_, Option<i64>>(11)?,
                    "first_response_ts": r.get::<_, Option<i64>>(12)?, "overdue": r.get::<_, i64>(13)? != 0,
                    "archived": r.get::<_, i64>(14)? != 0, "archived_ts": r.get::<_, Option<i64>>(15)?,
                    "archived_by": r.get::<_, String>(16)?,
                    // #39 team case-ops (additifs ; NULL/0 en mode 0 -> parité)
                    "merged_into": r.get::<_, Option<i64>>(17)?,
                    "ack_due": r.get::<_, Option<i64>>(18)?, "resolve_due": r.get::<_, Option<i64>>(19)?,
                    "ack_breached": r.get::<_, i64>(20)? != 0, "resolve_breached": r.get::<_, i64>(21)? != 0,
                    "sla_paused": r.get::<_, Option<i64>>(22)?.is_some(),
                    // #4a disposition (verdict analyste ; NULL/'' = non-défini en mode 0 -> parité). INTERNE.
                    "disposition": r.get::<_, Option<String>>(23)?, "disposition_ts": r.get::<_, Option<i64>>(24)?,
                    "disposition_by": r.get::<_, String>(25)?
                }))
            },
        )
        .ok()?;
    // #39 — la timeline d'un case CIBLE combine les items des cases fusionnés DEDANS (merged_into=?1). En mode 0
    // (aucune fusion) le sous-SELECT est vide -> items STRICTEMENT identiques (parité).
    let mut stmt = conn
        .prepare("SELECT id,ts,kind,COALESCE(author,''),COALESCE(body,''),COALESCE(ref,'') FROM incident_item \
                  WHERE incident_id=?1 OR incident_id IN (SELECT id FROM incident WHERE merged_into=?1) ORDER BY ts,id")
        .ok()?;
    let rows: Vec<(i64, i64, String, String, String, String)> = stmt
        .query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .ok()?
        .flatten()
        .collect();
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(iid, its, kind, author, body, rf)| {
            let (ref_title, ref_severity) = resolve_case_ref(conn, &rf);
            json!({ "id": iid, "ts": its, "kind": kind, "author": author, "body": body, "ref": rf,
                    "ref_title": ref_title, "ref_severity": ref_severity })
        })
        .collect();
    c["items"] = json!(items);
    Some(c)
}

/// Liste filtrée (status/assignee/priority/overdue) + tri OVERDUE-FIRST puis actifs avant terminaux puis
/// updated DESC. Filtres neutres : status/assignee='' = tous, priority=0 = toutes, overdue_only=false. #4a.
/// #4a-bis : `archived` sélectionne le PÉRIMÈTRE — false = cases ACTIFS (archived=0, défaut : les archives sont
/// MASQUÉES) ; true = UNIQUEMENT les archives (vue dédiée). Jamais de mélange -> l'archive masque sans supprimer.
/// Fold du TRI côté serveur (BATCH 1 scalabilité) : mappe la clé de tri front -> clause ORDER BY. Vide ou
/// inconnue -> tri par défaut (overdue-first, historique inchangé). `caseSortRows` (client) reste un repli
/// idempotent (re-trie la page renvoyée par la même clé -> même ordre). Colonnes littérales -> pas d'injection.
pub(crate) fn case_order_clause(sort: &str) -> &'static str {
    match sort {
        "updated" => "updated DESC",
        "priority" => "priority ASC, updated DESC",
        "sla" => "(sla_due IS NULL), sla_due ASC, updated DESC",
        _ => "overdue DESC, (status IN ('closed','resolved','contained')), updated DESC",
    }
}

/// Liste PAGINÉE + triée + comptée des cases (BATCH 1). Renvoie `{cases,total}` : `total` = COUNT des cases
/// APRÈS filtres (même WHERE, sans LIMIT) -> le pager front borne le DOM sans jamais tout charger. Les
/// filtres (status/assignee/priority/overdue/archived) sont PRÉSERVÉS. `limit`/`offset` bornent la page ;
/// `sort` replie le tri serveur (cf. case_order_clause). Rétro-compat : cf. wrapper `cases_list_json`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cases_list_json_paged(conn: &Connection, now_i: i64, status: &str, assignee: &str, priority: i64, overdue_only: bool, archived: bool, sort: &str, limit: i64, offset: i64) -> Value {
    // WHERE partagé COUNT/SELECT : ?1=now ?2=status ?3=assignee ?4=priority ?5=overdue_only ?6=archived.
    // #39 — les cases fusionnés (SOURCE d'un merge) sont MASQUÉS de la liste (comme un archivage) : `merged_into
    // IS NULL`. En mode 0 (aucune fusion) ce prédicat ne retire RIEN -> COUNT/lignes identiques (parité).
    let where_clause = "WHERE archived=?6 AND merged_into IS NULL \
                 AND (?2='' OR status=?2) \
                 AND (?3='' OR COALESCE(assignee,'')=?3) \
                 AND (?4=0 OR priority=?4) \
                 AND (?5=0 OR (sla_due IS NOT NULL AND ?1 > sla_due AND status NOT IN ('resolved','closed','contained')))";
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM incident {where_clause}"),
            params![now_i, status, assignee, priority, overdue_only as i64, archived as i64],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let sql = format!(
        "SELECT id,ts,updated,title,status,severity,COALESCE(owner,''),\
               priority,COALESCE(assignee,''),sla_due,\
               (sla_due IS NOT NULL AND ?1 > sla_due AND status NOT IN ('resolved','closed','contained')) AS overdue,\
               (SELECT COUNT(*) FROM incident_item WHERE incident_id=incident.id),archived,\
               disposition \
               FROM incident {where_clause} ORDER BY {order} LIMIT ?7 OFFSET ?8",
        order = case_order_clause(sort)
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return json!({ "cases": [], "total": total }),
    };
    let rows: Vec<Value> = stmt
        .query_map(params![now_i, status, assignee, priority, overdue_only as i64, archived as i64, limit, offset], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "updated": r.get::<_, i64>(2)?,
                "title": r.get::<_, String>(3)?, "status": r.get::<_, String>(4)?, "severity": r.get::<_, i64>(5)?,
                "owner": r.get::<_, String>(6)?, "priority": r.get::<_, i64>(7)?,
                "priority_label": priority_label(r.get::<_, i64>(7)?),
                "assignee": r.get::<_, String>(8)?, "sla_due": r.get::<_, Option<i64>>(9)?,
                "overdue": r.get::<_, i64>(10)? != 0, "items": r.get::<_, i64>(11)?,
                "archived": r.get::<_, i64>(12)? != 0,
                // #4a disposition (verdict analyste ; NULL = non-défini). INTERNE — hors projection client.
                "disposition": r.get::<_, Option<String>>(13)?
            }))
        })
        .map(|x| x.flatten().collect())
        .unwrap_or_default();
    json!({ "cases": rows, "total": total })
}

/// Wrapper rétro-compat : tri par défaut (overdue-first), page unique bornée à 300 (comportement historique).
/// Le champ `total` additionnel est ignoré par les appelants existants (qui ne lisent que `["cases"]`).
pub(crate) fn cases_list_json(conn: &Connection, now_i: i64, status: &str, assignee: &str, priority: i64, overdue_only: bool, archived: bool) -> Value {
    cases_list_json_paged(conn, now_i, status, assignee, priority, overdue_only, archived, "", 300, 0)
}

/// Détache un item de timeline d'un case (anti-IDOR : borné à incident_id) et trace le geste (item 'note'
/// « détaché … »). false si l'item n'existe pas / n'appartient pas au case. #4a.
pub(crate) fn case_detach_item(conn: &Connection, id: i64, item_id: i64, author: &str) -> bool {
    let rf: String = match conn.query_row(
        "SELECT COALESCE(ref,'') FROM incident_item WHERE id=?1 AND incident_id=?2",
        params![item_id, id],
        |r| r.get(0),
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let _ = conn.execute("DELETE FROM incident_item WHERE id=?1 AND incident_id=?2", params![item_id, id]);
    let body = if rf.is_empty() { "élément détaché".to_string() } else { format!("détaché {rf}") };
    case_add_item(conn, id, now(), "note", author, &body, None);
    true
}

/// #4a — ESCALADE SLA : notifie (via les notifiers du tenant, min_severity respecté) les cases dont le SLA est
/// DÉPASSÉ et pas encore escaladés, puis marque escalated=1 (anti re-notif) + trace un item 'sla' + ledger.
/// Appelée dans la boucle de fond PAR-TENANT (à côté de dispatch_notifications). INERTE tant qu'aucun case
/// overdue (0 ligne -> 0 réseau, 0 écriture). Séquentiel + LIMIT (budget 2 Go). Réutilise notify_send tel quel.
pub(crate) fn escalate_overdue_cases(db: &Arc<Mutex<Connection>>) {
    let now_i = now();
    let (cases, notifiers): (Vec<(i64, String, i64, i64)>, Vec<(String, String, i64, String)>) = {
        let conn = db.lock();
        let cases: Vec<(i64, String, i64, i64)> = match conn.prepare(
            "SELECT id,COALESCE(title,''),priority,sla_due FROM incident \
             WHERE sla_due IS NOT NULL AND escalated=0 \
               AND status NOT IN ('resolved','closed','contained') AND ?1 > sla_due \
             ORDER BY sla_due LIMIT 20",
        ) {
            Ok(mut s) => s
                .query_map(params![now_i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .map(|x| x.flatten().collect())
                .unwrap_or_default(),
            Err(_) => return,
        };
        if cases.is_empty() {
            return;
        }
        let notifiers: Vec<(String, String, i64, String)> = match conn.prepare("SELECT kind,url,min_severity,config FROM notifier WHERE enabled=1") {
            Ok(mut s) => s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).map(|x| x.flatten().collect()).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        (cases, notifiers)
    };
    for (id, title, priority, sla_due) in &cases {
        // sévérité de notif dérivée de la priorité (P1->sev4 .. P4->sev1) pour respecter min_severity du canal.
        let sev = match *priority { 1 => 4, 2 => 3, 3 => 2, _ => 1 };
        let detail = format!("Case #{id} « {title} » : SLA P{priority} dépassé (échéance {sla_due}).");
        for (kind, url, minsev, cfg) in &notifiers {
            if sev >= *minsev {
                let config: Value = serde_json::from_str(cfg).unwrap_or_else(|_| json!({}));
                let _ = notify_send(kind, url, &config, sev, &format!("SLA dépassé : {title}"), &detail, "", now_i);
            }
        }
        let conn = db.lock();
        let _ = conn.execute("UPDATE incident SET escalated=1 WHERE id=?1", params![id]);
        case_add_item(&conn, *id, now_i, "sla", "system", &detail, None);
        ledger_append(&conn, "case.sla_escalate", &format!("#{id} P{priority} sla_due={sla_due}"));
    }
}

/// GET /api/cases[?status=&assignee=&priority=&overdue=1&archived=1] — liste filtrée, overdue-first. Lecture
/// (viewer OK). #4a-bis : par défaut les cases ARCHIVÉS sont MASQUÉS ; `?archived=1` liste UNIQUEMENT les archives.
pub(crate) async fn cases_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let status = q.get("status").cloned().unwrap_or_default();
    let assignee = q.get("assignee").cloned().unwrap_or_default();
    let priority = q.get("priority").and_then(|s| parse_priority(&json!(s))).unwrap_or(0);
    let overdue_only = q.get("overdue").map(|s| s == "1" || s == "true").unwrap_or(false);
    let archived = q.get("archived").map(|s| s == "1" || s == "true").unwrap_or(false);
    // BATCH 1 : pagination + tri serveur. Absents -> défaut historique (page unique 300, tri overdue-first).
    let sort = q.get("sort").cloned().unwrap_or_default();
    let limit = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(300).clamp(1, 1000);
    // M6 : offset plafonné (anti deep-pagination).
    let offset = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
    // M6 : SORT du mutex d'ÉCRITURE (avant : req_db -> lock writer pendant le scan/tri de la table incident,
    // contention avec l'ingestion). Passe au pool read-only + query_sem + spawn_blocking + watchdog, comme
    // /api/query. Lecture pure (incident/incident_item) -> aucun secret dénié par l'authorizer du read-pool.
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(crate::handlers::portillon::corps_de_refus(json!({ "cases": [], "total": 0 }))),
    };
    let db_path = req_db_path(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "cases": [], "total": 0 }), move |conn| {
            cases_list_json_paged(conn, now_i, &status, &assignee, priority, overdue_only, archived, &sort, limit, offset)
        })
    })
    .await
    .unwrap_or_else(|_| json!({ "cases": [], "total": 0 }));
    Json(res)
}

/// POST /api/cases — crée un case first-class (status='new', priorité, sla_due). Mutating (editor/admin). #4a.
pub(crate) async fn case_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let title = b.get("title").and_then(|v| v.as_str()).unwrap_or("Incident").trim().to_string();
    let sev = b.i64_field("severity", 2);
    let summary = b.str_field("summary");
    let assignee = b.get("assignee").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
    let priority = b.get("priority").and_then(parse_priority).unwrap_or(3);
    crate::req_conn!(st, au, conn);
    let id = case_create_row(&conn, &au.name, &title, sev, summary, assignee, priority);
    let sla_due: Option<i64> = conn.query_row("SELECT sla_due FROM incident WHERE id=?1", params![id], |r| r.get(0)).unwrap_or(None);
    Json(json!({ "id": id, "status": "new", "priority": priority, "priority_label": priority_label(priority), "sla_due": sla_due }))
}

/// GET /api/cases/{id} — métadonnées + timeline (refs résolues) + overdue calculé. Lecture (viewer OK). #4a.
pub(crate) async fn case_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    // FIELD FILTERS (#45) : la timeline d'un cas résout `event:<id>` -> `event.message` (HORS run_query_ex,
    // point-lookup) -> on masque `ref_title` pour le rôle appelant si `message` est masqué. VIDE -> no-op.
    let dbp = req_db_path(&st, &au);
    let masks = effective_masks(&dbp, &au.role, &au.tenant, au.env_filter());
    with_write(&st, &au, move |conn| {
    match case_get_json(&conn, id, now()) {
        Some(mut c) => {
            if !masks.is_empty() {
                if let Some(items) = c.get_mut("items").and_then(|i| i.as_array_mut()) {
                    for it in items.iter_mut() {
                        let is_event = it.get("ref").and_then(|r| r.as_str()).map(|s| s.starts_with("event:")).unwrap_or(false);
                        if is_event {
                            if let Some(t) = it.get("ref_title").cloned() {
                                it["ref_title"] = mask_field_value(&dbp, &masks, "message", &t);
                            }
                        }
                    }
                }
            }
            Json(c).into_response()
        }
        None => (StatusCode::NOT_FOUND, "incident introuvable").into_response(),
    }
    })
}

/// POST /api/cases/{id} — patch (status/priority/assignee/severity/title/summary). Chaque changement -> item
/// typé + audit. Couvre assign / close / reopen / priorisation. Mutating (editor/admin). #4a.
pub(crate) async fn case_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    // DISPOSITION (#4a) — validation FERMÉE au bord : un verdict non-vide hors de l'allowlist -> 400 AVANT toute
    // écriture. NULL/'' (unset) est légitime. Le CRUD du case reste gated editor+ par la RBAC de /api/cases/{id}.
    if let Some(dv) = b.get("disposition") {
        let d = dv.as_str().unwrap_or("").trim();
        if !d.is_empty() && !disposition_valid(d) {
            return StatusCode::BAD_REQUEST;
        }
    }
    with_write(&st, &au, |conn| {
    if case_apply_update(&conn, id, &au.name, &b) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
    })
}

/// POST /api/cases/{id}/items — ajoute un item de timeline : note (add_note), OU rattachement d'une alerte
/// (kind='alert', ref='alert:ID' = link_alert) / d'un event (kind='event', ref='event:ID' = link_event) /
/// action. Mutating (editor/admin). #4a.
pub(crate) async fn case_item_add(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return StatusCode::NOT_FOUND;
    }
    let kind = match b.get("kind").and_then(|v| v.as_str()) {
        Some("alert") => "alert",
        Some("event") => "event",
        Some("action") => "action",
        _ => "note",
    };
    let body = b.str_field("body");
    let rf = b.get("ref").and_then(|v| v.as_str());
    case_add_item(&conn, id, now(), kind, &au.name, body, rf);
    StatusCode::NO_CONTENT
}

/// DELETE /api/cases/{id}/items/{item_id} — détache un item (alerte/event/note) du case + trace le geste.
/// Mutating (editor/admin). 404 si l'item n'appartient pas au case. #4a.
pub(crate) async fn case_item_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, item_id)): Path<(i64, i64)>) -> StatusCode {
    with_write(&st, &au, |conn| {
    if case_detach_item(&conn, id, item_id, &au.name) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
    })
}

/// #4a-bis — ARCHIVE (soft-delete) / DÉSARCHIVE un case. Bascule `archived` (1/0), pose/efface archived_ts +
/// archived_by, et AJOUTE un item de timeline ('archive'/'unarchive'). STRICTEMENT APPEND-ONLY : ne SUPPRIME
/// jamais la ligne `incident` ni aucun `incident_item` (intégrité d'audit préservée) — l'archive ne fait que
/// MASQUER le case de la liste par défaut (cases_list_json filtre archived=0). Idempotent-safe. false si le
/// case n'existe pas. La GARDE admin-only est appliquée EN AMONT (rbac_gate + re-check handler).
pub(crate) fn case_set_archived(conn: &Connection, id: i64, author: &str, archived: bool) -> bool {
    if conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return false;
    }
    let t = now();
    if archived {
        let _ = conn.execute(
            "UPDATE incident SET archived=1, archived_ts=?1, archived_by=?2 WHERE id=?3",
            params![t, author, id],
        );
        case_add_item(conn, id, t, "archive", author, "Case archivé (masqué de la liste ; historique conservé)", None);
        ledger_append(conn, "case.archive", &format!("#{id} by {author}"));
    } else {
        let _ = conn.execute(
            "UPDATE incident SET archived=0, archived_ts=NULL, archived_by=NULL WHERE id=?1",
            params![id],
        );
        case_add_item(conn, id, t, "unarchive", author, "Case désarchivé (ré-affiché dans la liste)", None);
        ledger_append(conn, "case.unarchive", &format!("#{id} by {author}"));
    }
    true
}

/// POST /api/cases/{id}/archive — ARCHIVE (soft-delete) un case : le MASQUE de la liste par défaut tout en
/// conservant la ligne + sa timeline (append-only). Action DELETE-LIKE => ADMIN-ONLY : gatée au choke-point
/// (rbac_gate) ET re-vérifiée ICI (défense en profondeur). 403 hors admin ; 404 si le case n'existe pas. #4a-bis.
pub(crate) async fn case_archive(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    if !au.is_admin() {
        return StatusCode::FORBIDDEN;
    }
    with_write(&st, &au, |conn| {
    if case_set_archived(&conn, id, &au.name, true) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
    })
}

/// POST /api/cases/{id}/unarchive — DÉSARCHIVE un case (le ré-affiche dans la liste). ADMIN-ONLY (idem archive).
/// 403 hors admin ; 404 si le case n'existe pas. #4a-bis.
pub(crate) async fn case_unarchive(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    if !au.is_admin() {
        return StatusCode::FORBIDDEN;
    }
    with_write(&st, &au, |conn| {
    if case_set_archived(&conn, id, &au.name, false) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
    })
}

pub(crate) async fn ack(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.execute(
        "UPDATE alert SET status='ack', acked_at=?1, acked_by=?2 WHERE id=?3",
        params![now(), au.name, id],
    ) {
        Ok(_) => {
            ledger_append(&conn, "alert.ack", &format!("#{id} by {}", au.name));
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// Acquitte d'un coup toutes les alertes encore « new » (vide la file après un afflux).
pub(crate) async fn ack_all(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let n = conn
        .execute("UPDATE alert SET status='ack', acked_at=?1, acked_by=?2 WHERE status='new'", params![now(), au.name])
        .unwrap_or(0);
    ledger_append(&conn, "alert.ack_all", &format!("{n} alertes by {}", au.name));
    Json(json!({ "acked": n }))
}
