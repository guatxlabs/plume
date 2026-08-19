//! Playbooks (réponse automatisée) : listing `playbooks_list`, CRUD/test des playbooks, rendu de
//! cellule `playbook_cell`, et l'exécuteur périodique `run_playbooks`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

pub(crate) async fn playbooks_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = conn.prepare("SELECT id,name,enabled,query,is_soql,action_kind,interval_s,window_s,last_run,managed FROM playbook ORDER BY id").unwrap();
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? != 0,
            "query": r.get::<_, String>(3)?, "is_soql": r.get::<_, i64>(4)? != 0, "action_kind": r.get::<_, String>(5)?,
            "interval_s": r.get::<_, i64>(6)?, "window_s": r.get::<_, i64>(7)?, "last_run": r.get::<_, Option<i64>>(8)?,
            "managed": r.get::<_, i64>(9)?
        }))
    }).unwrap();
    Json(json!({ "playbooks": rows.flatten().collect::<Vec<_>>() }))
}
pub(crate) async fn playbook_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let is_soql = b.bool_field("is_soql", true);
    let query = b.str_field("query").to_string();
    let action_kind = b.get("action_kind").and_then(|v| v.as_str()).unwrap_or("ban_ip").to_string();
    let window_s = b.i64_field("window_s", 3600);
    // #1c garde-fous #1/#2/#3 : SQL brut=admin + requête compile + action_kind ∈ ENUM FERMÉ — avant écriture.
    if let Err((code, msg)) = validate_detection_content("playbook", is_soql, &query, &action_kind, window_s, &au.role) {
        return err_json(code, msg);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Playbook").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let interval_s = b.i64_field("interval_s", 300);
    crate::req_conn!(st, au, conn);
    // #1c garde-fous #4/#6 : INSERT managed=2 (ad-hoc UI) + audit #1b, transaction fail-closed.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            // DURCISSEMENT : `created_by_role` marque l'AUTEUR -> run_playbooks n'auto-approuve
            // (mode active) QUE les playbooks admin-authored. `validate_detection_content` garantit déjà que seul
            // un admin arrive ici pour un playbook à action destructive ; ce marquage DOUBLE la garde (défense
            // en profondeur : même un playbook editor résiduel resterait pending/dry_run en mode active).
            "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES(?1,?2,?3,?4,?5,?6,?7,2,?8)",
            params![name, enabled, query, is_soql as i64, action_kind, interval_s, window_s, au.role],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.playbook.create",
            &format!("playbook '{name}' (#{id}) créé par {}", au.name), 2,
            &format!("playbook de réponse '{name}' (action {action_kind}) créé par {}", au.name),
            &json!({ "op": "create", "kind": "playbook", "id": id, "name": name, "action_kind": action_kind, "is_soql": is_soql, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "managed": 2 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn playbook_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT is_soql,query,window_s,action_kind,managed FROM playbook WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)),
    );
    let (cur_soql, cur_query, cur_window, cur_kind, cur_managed) = match cur {
        Ok(x) => x,
        Err(_) => return not_found("playbook introuvable"),
    };
    // #1c garde-fous #1/#2/#3 : valeurs EFFECTIVES post-PATCH ; anti-contournement editor->SQL brut ; la
    // requête compile ; action_kind effectif ∈ ENUM FERMÉ.
    let eff_soql = b.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(cur_soql);
    let eff_query = b.get("query").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_query);
    let eff_window = b.get("window_s").and_then(|x| x.as_i64()).unwrap_or(cur_window);
    let eff_kind = b.get("action_kind").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_kind);
    if let Err((code, msg)) = validate_detection_content("playbook", eff_soql, &eff_query, &eff_kind, eff_window, &au.role) {
        return err_json(code, msg);
    }
    // FIX HIGH-1b (bypass adopt-then-toggle) : modifier un playbook BASELINE (seed/builtin managed=0) = ADMIN
    // seul — sinon l'adoption managed=0->2 (plus bas) sert de tremplin à une désactivation editor + ferme le
    // neuter-via-query. Frontière : baseline(0)+overlay(1)=admin ; editor CRUD complet sur SON ad-hoc (managed=2).
    // INVARIANT : `cur_managed != 2` — overlay(1) admin-managé au même titre que le seed(0).
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier un playbook managé (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre playbook");
    }
    // FIX HIGH-1 : toggler `enabled` sur un playbook managé (managed=0 seed, managed=1 overlay) = ADMIN seul ; un
    // non-admin ne bascule `enabled` que sur son playbook ad-hoc managed=2. Fail-closed (refuse tout le PATCH).
    // Évalué sur le managed COURANT (avant l'adoption managed=0->2 plus bas).
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET name=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("query").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET query=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("is_soql").and_then(|x| x.as_bool()) { conn.execute("UPDATE playbook SET is_soql=?1 WHERE id=?2", params![v as i64, id])?; }
        if let Some(v) = b.get("action_kind").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET action_kind=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE playbook SET interval_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("window_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE playbook SET window_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE playbook SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        // #1c garde-fou #4 : éditer un builtin (managed=0) l'ADOPTE en ad-hoc (managed=2) ; overlay (1) reste 1.
        if cur_managed == 0 { conn.execute("UPDATE playbook SET managed=2 WHERE id=?1", params![id])?; }
        // DURCISSEMENT : ré-affirme l'auteur du CONTENU à chaque édition validée (seul un admin
        // passe validate_detection_content pour un playbook à action destructive) -> autorité d'auto-exécution.
        conn.execute("UPDATE playbook SET created_by_role=?1 WHERE id=?2", params![au.role, id])?;
        audit_config_change(
            &conn, "config.playbook.update",
            &format!("playbook #{id} modifié par {}", au.name), 2,
            &format!("playbook #{id} modifié par {}", au.name),
            &json!({ "op": "update", "kind": "playbook", "id": id, "is_soql": eff_soql, "action_kind": eff_kind, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn playbook_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM playbook WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("playbook introuvable"),
    };
    delete_managed_row(&conn, "playbook", "config.playbook", id, managed, &au.name)
}
pub(crate) async fn playbook_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row("SELECT query,is_soql,action_kind,window_s FROM playbook WHERE id=?1", params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))).ok()
    };
    let (query, is_soql, kind, window_s) = match row {
        Some(x) => x,
        None => return Json(json!({ "error": "playbook introuvable" })),
    };
    // #45 — DRY-RUN = SURFACE D'APPELANT : cette route est EDITOR+ et RENVOIE les CIBLES de la requête
    // (1re colonne) à l'appelant. Compilée par la porte SYSTÈME `rule_sql`, un playbook `search | table
    // src_ip` restituait les valeurs EN CLAIR à un rôle dont src_ip est masqué (exfiltration directe, pas
    // seulement un oracle). On passe donc par la porte APPELANT (masque #45 résolu DANS la porte).
    let sql = match rule_sql_for_caller(&st, &au, &query, is_soql, window_s) {
        Ok(s) => s,
        Err(e) => return Json(json!({ "error": e })),
    };
    let db_path = req_db_path(&st, &au);
    let db_path2 = db_path.clone(); // capturé par la closure blocking ; `db_path` reste pour le guard tenant
    match tokio::task::spawn_blocking(move || run_query(&db_path2, &sql)).await {
        Ok(Ok(res)) => {
            let targets: Vec<String> = res.get("rows").and_then(|r| r.as_array())
                .map(|rows| rows.iter().filter_map(|row| row.as_array().and_then(|c| c.first()).map(playbook_cell)).filter(|t| !t.is_empty()).collect())
                .unwrap_or_default();
            let valides = targets.iter().filter(|t| action_valid(&kind, t, &db_path).is_ok()).count();
            Json(json!({ "action_kind": kind, "targets": targets, "valides": valides }))
        }
        Ok(Err(e)) => Json(json!({ "error": e })),
        Err(_) => Json(json!({ "error": "exécution échouée" })),
    }
}

/// Extrait la cible d'une cellule (1re colonne d'une ligne de playbook) : string ou nombre.
pub(crate) fn playbook_cell(c: &Value) -> String {
    if let Some(s) = c.as_str() {
        s.to_string()
    } else if c.is_null() {
        String::new()
    } else {
        c.to_string()
    }
}

/// Exécute les playbooks dus : la requête renvoie des CIBLES (1re colonne) -> 1 action par cible.
/// Mode 'observe' -> pending+dry_run (on voit ce qui SERAIT fait) ; 'active' -> approved+réel (auto).
pub(crate) fn run_playbooks(db: &Arc<Mutex<Connection>>, db_path: &str) {
    let now_ts = now();
    let mode: String = {
        let conn = db.lock();
        conn.query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)).unwrap_or_else(|_| "observe".into())
    };
    // DURCISSEMENT : on lit AUSSI `created_by_role` -> seuls les playbooks ADMIN-authored
    // s'auto-approuvent en mode active. Colonne NOT NULL DEFAULT 'admin' -> les seeds/overlays/playbooks
    // pré-existants restent auto-exécutables (INVARIANT prod inchangé) ; un playbook editor résiduel NON.
    // #64 : `admin_authored` = AUTORITÉ ADMIN EFFECTIVE de l'auteur ET perm `arm_response` NON retirée
    // (calqué sur la garde d'armement `detection.rs`/`validate_detection_content`). Un rôle composable
    // base=admin (ex. "gov-armer") SANS deny arm_response -> auto-approuve (le #64 lui laisse ARMER) ; AVEC
    // deny arm_response ("gov-noarm") -> reste pending/dry (le deny subsiste ici aussi) ; base non-admin ->
    // jamais. Mode 0 / rôle de base -> byte-identique à `== "admin"` (builtin jamais custom-défini, jamais denied).
    let due: Vec<(i64, String, String, bool, String, i64, bool)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare("SELECT id,name,query,is_soql,action_kind,window_s,COALESCE(created_by_role,'admin') FROM playbook WHERE enabled=1 AND (last_run IS NULL OR ?1-last_run>=interval_s)") {
            Ok(s) => s,
            Err(_) => return,
        };
        let v: Vec<(i64, String, String, bool, String, i64, bool)> = stmt
            .query_map(params![now_ts], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, { let cbr = r.get::<_, String>(6)?; effective_base_role(&cbr) == "admin" && !role_perm_denied(&cbr, "arm_response") })))
            .map(|x| x.flatten().collect())
            .unwrap_or_default();
        v
    };
    for (id, name, query, is_soql, kind, window_s, admin_authored) in due {
        let sql = match rule_sql(&query, is_soql, window_s) {
            Ok(s) => s,
            Err(_) => {
                let c = db.lock();
                let _ = c.execute("UPDATE playbook SET last_run=?1 WHERE id=?2", params![now_ts, id]);
                continue;
            }
        };
        // DURCISSEMENT 3b — l'éval du playbook passe par run_query -> connexion LECTURE SEULE (query_only
        // ON + flag READ_ONLY + garde stmt.readonly()) : la requête de sélection des cibles ne peut QUE lire.
        // Les écritures légitimes (table `action`) se font ensuite sur la connexion principale, hors éval.
        let res = run_query(db_path, &sql);
        let conn = db.lock();
        let _ = conn.execute("UPDATE playbook SET last_run=?1 WHERE id=?2", params![now_ts, id]);
        let rows = match &res {
            Ok(v) => v.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        for row in rows {
            let target = row.as_array().and_then(|c| c.first()).map(playbook_cell).unwrap_or_default();
            if target.is_empty() || action_valid(&kind, &target, db_path).is_err() {
                continue;
            }
            // Cible(s) d'exécution : pour un ban d'IP, on agit sur CHAQUE hôte ayant vu cette IP sur
            // la fenêtre (chacun bannit chez lui -> enforcement là où est la menace, pas sur le central).
            // Pour les autres actions (stop_service...) -> central (host NULL).
            let hosts: Vec<Option<String>> = if kind == "ban_ip" || kind == "unban_ip" {
                let mut h: Vec<Option<String>> = conn
                    .prepare("SELECT DISTINCT host FROM event WHERE src_ip=?1 AND ts>=?2 AND host IS NOT NULL AND host<>''")
                    .ok()
                    .and_then(|mut s| {
                        s.query_map(params![target, now_ts - window_s], |r| r.get::<_, Option<String>>(0))
                            .map(|m| m.flatten().collect::<Vec<_>>())
                            .ok()
                    })
                    .unwrap_or_default();
                if h.is_empty() {
                    h.push(None); // IP vue sans hôte -> central
                }
                h
            } else {
                vec![None]
            };
            for host in hosts {
                let dup: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM action WHERE kind=?1 AND target=?2 AND IFNULL(host,'')=IFNULL(?3,'') AND ts>=?4",
                        params![kind, target, host, now_ts - window_s],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if dup > 0 {
                    continue;
                }
                // AUTO-APPROVE (approved + dry_run=0 -> exécution réelle par le responder) UNIQUEMENT si mode
                // active ET playbook admin-authored. Un playbook editor résiduel reste pending/dry même en actif
                // (fix HIGH : `/api/mode active` seul ne suffit JAMAIS à exécuter une action posée par un editor).
                let (status, dry) = if mode == "active" && admin_authored { ("approved", 0) } else { ("pending", 1) };
                let _ = conn.execute(
                    "INSERT INTO action(ts,kind,target,host,status,dry_run,reason) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![now_ts, kind, target, host, status, dry, format!("playbook:{name}")],
                );
                // BAN NATIF PLUME (chantier ② Phase 1) : une réponse ban_ip AUTO-APPROUVÉE (mode actif + playbook
                // admin-authored) ARME AUSSI le blocage HTTP in-process (net_ban) — indépendamment de l'exécuteur
                // (responder local OU agent distant k3s). unban_ip le retire. `action_valid` a déjà écarté les IP
                // protégées / sous engagement en amont (ligne ~219). INERTE hors mode actif (status='pending').
                // OPT-IN : `PLUME_NETBAN_FROM_ACTIONS=1` requis — un auto-approve de
                // playbook ne verrouille PAS l'opérateur au HTTP plume par défaut (anti blast-radius). Canonicalise.
                if netban_from_actions_enabled() && status == "approved" && dry == 0 {
                    let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| target.trim().to_string());
                    if kind == "ban_ip" && !ip_is_protected(&canon) {
                        // REFUS SUR STORE PLEIN : tracé au ledger (tamper-evident). Un chemin automatique qui
                        // avale un refus laisserait croire à un blocage qui n'existe pas.
                        if !netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: playbook ban_ip", "playbook", "prod") {
                            ledger_append(&conn, "netban.plafond", &format!("{canon} refusé : store live plein (playbook:{name})"));
                        }
                    } else if kind == "unban_ip" {
                        netban_remove(&conn, &canon);
                    }
                }
            }
        }
    }
}
