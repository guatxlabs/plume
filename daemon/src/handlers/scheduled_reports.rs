//! #60 — SCHEDULED REPORTS : un DATASET (#47, SOQL sauvegardé) exécuté sur un intervalle et livré à un
//! NOTIFIER (#53, canal admin-configuré). RÉUTILISE l'infra existante — AUCUN nouveau mécanisme de livraison
//! (`notify_send`) ni de compilation (le SOQL du dataset passe par le MÊME chemin masqué `soql_to_sql_masked_x`
//! que /api/query). Additif : table `scheduled_report` VIDE -> `run_due_reports` sélectionne 0 ligne -> no-op
//! strict (mode 0 byte-identique, aucun réseau).
//!
//! RUN-AS (garantie anti-exfiltration) : chaque rapport porte un `run_as_role` EXPLICITE ; le résultat est
//! MASQUÉ (#45) PAR CE RÔLE (`effective_masks(run_as_role)`), pas par le rôle du destinataire. Un editor NE
//! PEUT PAS créer un rapport `run_as=admin` (le CRUD PLAFONNE run_as au rôle du créateur) -> un planificateur
//! peu privilégié ne peut pas exfiltrer des données qu'il ne verrait pas lui-même, même livrées à un admin.
//! CHOIX env/tenant : masqué avec `env=None` (baseline du rôle) MAIS sur le `tenant` DU CRÉATEUR (persisté à
//! la création, comme /api/query passe `&au.tenant`) -> les field-filters tenant-scopés (`tenant='clientX'`)
//! s'appliquent bien ; run_as défaut = `viewer` (le plus masqué). Le notifier est admin-configuré (secret hors de
//! portée de l'editor). CRUD ledgerisé (gouvernance).
use crate::*;


/// Rôle d'exécution valide + PLAFONNÉ au rôle du créateur (anti-escalade). Enum FERMÉ (jamais 'agent').
pub(crate) fn resolve_run_as(requested: &str, creator_role: &str) -> Result<String, String> {
    let r = requested.trim();
    let r = if r.is_empty() { "viewer" } else { r };
    if !matches!(r, "viewer" | "editor" | "admin") {
        return Err(format!("run_as_role invalide (viewer|editor|admin) : {r}"));
    }
    if role_rank(r) > role_rank(creator_role) {
        return Err(format!("run_as_role '{r}' > votre rôle '{creator_role}' (escalade refusée)"));
    }
    Ok(r.to_string())
}

/// GET /api/scheduled-reports — liste (editor+ ; secret notifier JAMAIS projeté, seulement l'id).
pub(crate) async fn reports_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let items: Vec<Value> = conn
        .prepare("SELECT id,name,dataset_id,notifier_id,run_as_role,interval_s,enabled,last_run,last_ok,last_error,last_count,created,created_by FROM scheduled_report ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "dataset_id": r.get::<_,i64>(2)?,
                    "notifier_id": r.get::<_,i64>(3)?, "run_as_role": r.get::<_,String>(4)?, "interval_s": r.get::<_,i64>(5)?,
                    "enabled": r.get::<_,i64>(6)? != 0, "last_run": r.get::<_,i64>(7)?, "last_ok": r.get::<_,i64>(8)?,
                    "last_error": r.get::<_,Option<String>>(9)?, "last_count": r.get::<_,i64>(10)?, "created": r.get::<_,i64>(11)?, "created_by": r.get::<_,String>(12)? }))
            }).map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    Json(json!({ "reports": items })).into_response()
}

/// POST /api/scheduled-reports — crée un rapport planifié. editor+ ; run_as PLAFONNÉ au rôle du créateur.
pub(crate) async fn report_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let dataset_id = match b.get("dataset_id").and_then(|v| v.as_i64()) { Some(v) => v, None => return bad_req("dataset_id requis") };
    let notifier_id = match b.get("notifier_id").and_then(|v| v.as_i64()) { Some(v) => v, None => return bad_req("notifier_id requis") };
    let run_as = match resolve_run_as(b.str_field("run_as_role"), &au.role) { Ok(r) => r, Err(e) => return bad_req(e) };
    let interval_s = b.get("interval_s").and_then(|v| v.as_i64()).unwrap_or(86400).clamp(60, 31_536_000);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    // Le dataset ET le notifier référencés doivent EXISTER (fail-closed : pas de rapport orphelin).
    if conn.query_row("SELECT 1 FROM dataset WHERE id=?1", params![dataset_id], |_| Ok(())).is_err() {
        return bad_req("dataset introuvable");
    }
    if conn.query_row("SELECT 1 FROM notifier WHERE id=?1", params![notifier_id], |_| Ok(())).is_err() {
        return bad_req("notifier introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO scheduled_report(name,dataset_id,notifier_id,run_as_role,tenant,interval_s,enabled,created,created_by,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8)",
            params![name, dataset_id, notifier_id, run_as, au.tenant, interval_s, enabled, now(), au.name])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.scheduled_report.create",
            &format!("rapport planifié '{name}' (dataset #{dataset_id} -> notifier #{notifier_id}, run_as {run_as}, #{id}) par {}", au.name), 2,
            &format!("rapport planifié '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"scheduled_report", "id":id, "name":name, "run_as":run_as, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    match outcome {
        Ok(_) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": conn.last_insert_rowid() })).into_response() }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") { return bad_req("un rapport porte déjà ce nom"); }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// DELETE /api/scheduled-reports/:id — supprime (editor+, audité).
pub(crate) async fn report_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM scheduled_report WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("rapport introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM scheduled_report WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.scheduled_report.delete",
            &format!("rapport planifié '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("rapport planifié '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"scheduled_report", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    match outcome {
        Ok(_) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

/// POST /api/scheduled-reports/:id/run — déclenche MANUELLEMENT (editor+). Exécute + livre TOUT DE SUITE avec
/// le run_as du rapport (masqué par CE rôle, pas par l'appelant) -> même garantie que le tick de fond.
pub(crate) async fn report_run_now(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let db_path = req_db_path(&st, &au);
    let __rc = req_db(&st, &au);
    // Vérifie l'existence AVANT de lâcher le lock ; l'exécution se fait via run_query_ex (pool read séparé).
    {
        let conn = __rc.lock();
        if conn.query_row("SELECT 1 FROM scheduled_report WHERE id=?1", params![id], |_| Ok(())).is_err() {
            return not_found("rapport introuvable");
        }
    }
    let outcome = tokio::task::spawn_blocking(move || deliver_report(&__rc, &db_path, id)).await;
    match outcome {
        Ok(Ok((count, delivered))) => Json(json!({ "ok": true, "rows": count, "delivered": delivered })).into_response(),
        Ok(Err(e)) => bad_req(e),
        Err(_) => server_err("exécution du rapport échouée"),
    }
}

/// Rend un résumé TEXTE compact d'un résultat de requête (déjà masqué) pour le corps de notification.
fn format_report_detail(name: &str, v: &Value) -> (i64, String) {
    let cols: Vec<String> = v.get("columns").and_then(|c| c.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let rows = v.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let n = rows.len() as i64;
    let mut out = format!("Rapport '{name}' : {n} ligne(s).\n{}\n", cols.join(" | "));
    for row in rows.iter().take(20) {
        if let Some(arr) = row.as_array() {
            let cells: Vec<String> = arr.iter().map(|c| match c {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }).collect();
            out.push_str(&cells.join(" | "));
            out.push('\n');
        }
    }
    if n > 20 { out.push_str(&format!("… (+{} lignes non affichées)\n", n - 20)); }
    (n, out)
}

/// EXÉCUTE un rapport (dataset SOQL) MASQUÉ par son `run_as_role` et le LIVRE via son notifier. Coeur partagé
/// par le tick de fond et /run. Ne PANIQUE jamais (les erreurs remontent en `Err`). Le lock métadonnées n'est
/// tenu QUE pour lire la définition + écrire le statut ; la requête (`run_query_ex`, pool read séparé) et
/// l'envoi (`notify_send`) tournent HORS lock.
pub(crate) fn deliver_report(db: &Arc<Mutex<Connection>>, db_path: &str, id: i64) -> Result<(i64, bool), String> {
    // 1) charge la définition + le dataset SOQL + le notifier (kind/url/config) sous lock, puis relâche.
    let (name, run_as, tenant, soql, nkind, nurl, nconfig): (String, String, String, String, String, String, String) = {
        let conn = db.lock();
        let (name, dataset_id, notifier_id, run_as, tenant): (String, i64, i64, String, String) = conn.query_row(
            "SELECT name,dataset_id,notifier_id,run_as_role,tenant FROM scheduled_report WHERE id=?1 AND enabled=1",
            params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .map_err(|_| "rapport introuvable ou désactivé".to_string())?;
        let soql: String = conn.query_row("SELECT soql FROM dataset WHERE id=?1 AND enabled=1", params![dataset_id], |r| r.get(0))
            .map_err(|_| "dataset introuvable ou désactivé".to_string())?;
        let (nkind, nurl, nconfig): (String, String, String) = conn.query_row(
            "SELECT kind,url,config FROM notifier WHERE id=?1 AND enabled=1", params![notifier_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|_| "notifier introuvable ou désactivé".to_string())?;
        (name, run_as, tenant, soql, nkind, nurl, nconfig)
    };
    // 2) COMPILE+EXÉCUTE MASQUÉ (via render_report_detail) puis LIVRE. Séparé pour que le CONTENU masqué livré
    //    soit OBSERVABLE en test (deliver_report ne rend que count+bool).
    let now_ts = now();
    match render_report_detail(db_path, &name, &run_as, &tenant, &soql) {
        Ok((count, detail)) => {
            let config: Value = serde_json::from_str(&nconfig).unwrap_or(json!({}));
            let title = format!("Rapport planifié : {name}");
            let delivered = notify_send(&nkind, &nurl, &config, 2, &title, &detail, "", now_ts);
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE scheduled_report SET last_run=?1, last_ok=?1, last_error=NULL, last_count=?2 WHERE id=?3",
                params![now_ts, count, id]);
            Ok((count, delivered))
        }
        Err(e) => {
            let conn = db.lock();
            let _ = conn.execute("UPDATE scheduled_report SET last_run=?1, last_error=?2 WHERE id=?3", params![now_ts, e, id]);
            Err(e)
        }
    }
}

/// COMPILE le SOQL du dataset MASQUÉ par `(run_as, tenant)` — parité EXACTE avec /api/query, qui passe
/// `effective_masks(path, &au.role, &au.tenant, env)`. `run_as` remplace le rôle de l'appelant (garantie
/// anti-exfiltration) ; `tenant` = celui DU CRÉATEUR (persisté à la création) -> les field-filters tenant-scopés
/// (`tenant='clientX'`) matchent. Un `tenant=""` codé en dur les RATAIT -> livraison de données brutes non
/// masquées (HIGH). `env=None` baseline (documenté). Exécute et rend `(count, detail_texte_masqué)`. Extrait de
/// `deliver_report` UNIQUEMENT pour rendre le contenu livré OBSERVABLE (test de non-régression du masque tenant).
pub(crate) fn render_report_detail(db_path: &str, name: &str, run_as: &str, tenant: &str, soql: &str) -> Result<(i64, String), String> {
    let masks = effective_masks(db_path, run_as, tenant, None);
    // Choke-point unique : `soql_to_sql_masked_x` (= /api/query) -> denylist de secrets + enum fermée intacts.
    let compiled = soql_to_sql_masked_x(soql, 0, 0, None, &masks)?;
    if compiled.is_empty() { return Err("rapport : requête vide".into()); }
    let page_sql = format!("SELECT * FROM ({compiled}) LIMIT 5000");
    let v = run_query_ex(db_path, &page_sql, query_budget_interactive_ms(), None)?;
    Ok(format_report_detail(name, &v))
}

/// TICK de fond (thread dédié, PAR TENANT). Sélectionne les rapports DUS (enabled + intervalle écoulé) et les
/// livre. INERTE mode 0 : table vide -> 0 ligne -> retour immédiat (aucun réseau, aucune écriture). FAIL-SAFE :
/// chaque rapport isolé (catch_unwind + erreur consignée dans last_error) -> un rapport cassé n'arrête pas les
/// autres. Séquentiel (budget 2 Go).
pub(crate) fn run_due_reports(db: &Arc<Mutex<Connection>>, db_path: &str) {
    let now_ts = now();
    let due: Vec<i64> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id FROM scheduled_report WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) { Ok(s) => s, Err(_) => return }; // table absente (pré-v97) -> no-op
        let rows = stmt.query_map(params![now_ts], |r| r.get::<_, i64>(0));
        match rows {
            Ok(r) => r.flatten().collect(),
            Err(_) => return,
        }
    };
    if due.is_empty() {
        return; // INVARIANT mode 0 : rien à faire, aucun effet de bord
    }
    for id in due {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver_report(db, db_path, id)));
        match r {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {} // erreur déjà consignée dans last_error par deliver_report
            Err(_) => {
                let conn = db.lock();
                let _ = conn.execute("UPDATE scheduled_report SET last_run=?1, last_error=?2 WHERE id=?3",
                    params![now_ts, "panic interne du rapport (capturé)", id]);
            }
        }
    }
}
