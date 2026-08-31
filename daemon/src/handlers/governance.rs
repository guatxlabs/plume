//! #59 GOUVERNANCE ENTREPRISE — handlers. TROIS surfaces admin-only (route_min_role -> Admin, GET compris) :
//!  - LEGAL-HOLD (per-tenant) : CRUD des rétention-locks. Create/release LEDGERISÉS (audit_config_change ->
//!    ledger tamper-evident + event SOC non-purgeable). L'enforcement de suppression vit dans retention_run
//!    (rollups.rs, fail-closed) ; ici on ne gère que la déclaration/levée du hold + sa preuve.
//!  - EXPORT LEDGER (per-tenant) : téléchargement JSONL chaîne-préservée (read-only) + CRUD des sinks + flush
//!    incrémental (curseur last_id/last_hash). Aucun chemin de mutation vers le ledger (SELECT seul).
//!  - RÔLES COMPOSABLES (control-plane) : CRUD du catalogue global (super-admin en mode 1). Rafraîchit le
//!    cache process (reload_custom_roles) à chaque mutation. base_role validé, deny_perms borné, jamais admin.
use crate::*;

// =====================================================================================
// LEGAL-HOLD (per-tenant, admin-only, ledgerisé)
// =====================================================================================

fn hold_json(id: i64, name: &str, reason: &str, src: &str, s0: i64, s1: i64, active: i64, created: i64, by: &str, rel_ts: i64, rel_by: &str) -> Value {
    json!({
        "id": id, "name": name, "reason": reason,
        "scope_source": src, "scope_start_ts": s0, "scope_end_ts": s1,
        "active": active != 0, "created": created, "created_by": by,
        "released_ts": if rel_ts == 0 { Value::Null } else { json!(rel_ts) },
        "released_by": rel_by,
    })
}

/// GET /api/legal-holds -> liste des holds (actifs + levés), plus récents d'abord.
pub(crate) async fn legal_holds_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    with_write(&st, &au, |conn| {
        let rows: Vec<Value> = match conn.prepare(
            "SELECT id,name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by,released_ts,released_by \
             FROM legal_hold ORDER BY active DESC, id DESC",
        ) {
            Ok(mut s) => s
                .query_map([], |r| {
                    Ok(hold_json(
                        r.get::<_, i64>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, &r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?,
                        &r.get::<_, String>(8)?, r.get::<_, i64>(9)?, &r.get::<_, String>(10)?,
                    ))
                })
                .map(|it| it.flatten().collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Json(json!({ "ok": true, "holds": rows })).into_response()
    })
}

/// POST /api/legal-holds — pose un legal-hold (admin-only, ledgerisé). Body : {name, reason?, scope_source?,
/// scope_start_ts?, scope_end_ts?}. name obligatoire (unique). scope vide/0 = TOUT (source ∈ *, fenêtre ouverte).
pub(crate) async fn legal_hold_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let name = b.str_field("name").trim().to_string();
    if name.is_empty() || name.len() > 200 {
        return err_json(StatusCode::BAD_REQUEST, "nom de hold requis (1..200)");
    }
    let reason = b.str_field("reason").trim().to_string();
    let src = b.str_field("scope_source").trim().to_string();
    let s0 = b.i64_field("scope_start_ts", 0).max(0);
    let s1 = b.i64_field("scope_end_ts", 0).max(0);
    if s0 > 0 && s1 > 0 && s1 < s0 {
        return err_json(StatusCode::BAD_REQUEST, "scope_end_ts < scope_start_ts");
    }
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM legal_hold WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).is_ok() {
        return err_json(StatusCode::CONFLICT, format!("un hold nommé '{name}' existe déjà"));
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
             VALUES(?1,?2,?3,?4,?5,1,?6,?7)",
            params![name, reason, src, s0, s1, now(), au.name.as_str()],
        )?;
        let id = conn.last_insert_rowid();
        // LEDGERISÉ (qui/quand/portée) + event SOC NON-purgeable (origin='daemon') : un hold est un acte de
        // gouvernance -> tracé de façon tamper-evident, comme une baisse de rétention.
        audit_config_change(
            &conn, "config.legal_hold.create",
            &format!("legal-hold '{name}' (#{id}) posé par {} (source='{src}', fenêtre=[{s0},{s1}])", au.name), 3,
            &format!("legal-hold '{name}' posé par {} — suppression BLOQUÉE sur la portée", au.name),
            &json!({ "op": "create", "kind": "legal_hold", "id": id, "name": name, "scope_source": src, "scope_start_ts": s0, "scope_end_ts": s1, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({ "ok": true, "id": id, "name": name, "active": true })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// POST /api/legal-holds/{id}/release — LÈVE un hold (admin-only, ledgerisé). Ne SUPPRIME jamais la ligne
/// (trace conservée) : passe active=0 + released_ts/by. Après levée, la portée redevient purgeable au tick suivant.
pub(crate) async fn legal_hold_release(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row("SELECT name,active FROM legal_hold WHERE id=?1", params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)));
    let (name, active) = match cur {
        Ok(t) => t,
        Err(_) => return not_found("hold introuvable"),
    };
    if active == 0 {
        return err_json(StatusCode::CONFLICT, "hold déjà levé");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("UPDATE legal_hold SET active=0, released_ts=?1, released_by=?2 WHERE id=?3", params![now(), au.name.as_str(), id])?;
        audit_config_change(
            &conn, "config.legal_hold.release",
            &format!("legal-hold '{name}' (#{id}) LEVÉ par {} — la portée redevient purgeable", au.name), 3,
            &format!("legal-hold '{name}' levé par {}", au.name),
            &json!({ "op": "release", "kind": "legal_hold", "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({ "ok": true, "id": id, "active": false })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// =====================================================================================
// LEDGER — export streaming (chaîne préservée) + sinks
// =====================================================================================

/// GET /api/ledger/export?from_id=<n>&limit=<n> -> JSONL (text/plain) de la chaîne du ledger (id,ts,kind,
/// detail,prev_hash,hash) à partir de from_id (exclu), borné. READ-ONLY (aucune mutation). Un vérificateur
/// externe recompute la chaîne (ledger_verify_export). En-têtes : last_id/last_hash pour reprendre.
pub(crate) async fn ledger_export_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let from_id: i64 = q.get("from_id").and_then(|s| s.trim().parse().ok()).unwrap_or(0).max(0);
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse().ok()).unwrap_or(10000).clamp(1, 100000);
    with_write(&st, &au, |conn| {
        // `P10.7-s` — une tranche qu'on ne sait pas lire rend 500, jamais un `200` à corps VIDE. Le corps
        // vide en succès est le pire des deux : il se sauvegarde, se vérifie (`Ok(0)`) et se classe comme
        // une copie légitime. Un `200` reste possible AVEC un corps vide, et c'est voulu : c'est la réponse
        // JUSTE quand la tranche demandée est réellement vide (`from_id` au-delà du dernier maillon).
        let (lines, last_id, last_hash) = match ledger_export_lines(conn, from_id, limit) {
            Ok(t) => t,
            Err(e) => return server_err(format!("export du ledger impossible : {e}")),
        };
        let body = if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) };
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/x-ndjson".to_string()),
                (header::HeaderName::from_static("x-plume-ledger-last-id"), last_id.to_string()),
                (header::HeaderName::from_static("x-plume-ledger-last-hash"), last_hash),
            ],
            body,
        )
            .into_response()
    })
}

fn sink_json(id: i64, name: &str, kind: &str, target: &str, secret_ref: &str, enabled: i64, last_id: i64, last_hash: &str) -> Value {
    json!({
        "id": id, "name": name, "kind": kind, "target": target,
        // JAMAIS le secret en clair : on n'expose que la RÉFÉRENCE (env:/file:/vault:).
        "secret_ref": secret_ref, "enabled": enabled != 0, "last_id": last_id, "last_hash": last_hash,
    })
}

/// GET /api/ledger-sinks -> liste des sinks d'export configurés (secret jamais exposé, seulement secret_ref).
pub(crate) async fn ledger_sinks_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    with_write(&st, &au, |conn| {
        let rows: Vec<Value> = match conn.prepare("SELECT id,name,kind,target,secret_ref,enabled,last_id,last_hash FROM ledger_sink ORDER BY id") {
            Ok(mut s) => s
                .query_map([], |r| {
                    Ok(sink_json(r.get::<_, i64>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, &r.get::<_, String>(7)?))
                })
                .map(|it| it.flatten().collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Json(json!({ "ok": true, "sinks": rows })).into_response()
    })
}

/// POST /api/ledger-sinks — déclare un sink (admin-only, ledgerisé). Body {name, kind(file|stdout), target,
/// secret_ref?}. Le SECRET n'est JAMAIS inline : `secret_ref` doit être une référence (env:/file:/vault:).
pub(crate) async fn ledger_sink_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let name = b.str_field("name").trim().to_string();
    let kind = b.str_field("kind").trim().to_string();
    let target = b.str_field("target").trim().to_string();
    let secret_ref = b.str_field("secret_ref").trim().to_string();
    if name.is_empty() || name.len() > 200 {
        return err_json(StatusCode::BAD_REQUEST, "nom de sink requis (1..200)");
    }
    if !matches!(kind.as_str(), "file" | "stdout") {
        return err_json(StatusCode::BAD_REQUEST, "kind ∈ {file, stdout} (syslog/webhook : suivi séparé)");
    }
    // MEDIUM #59 : un sink kind=file écrit sur l'HÔTE — un admin WEB (rôle SOC) ne doit PAS pouvoir faire
    // appendre le daemon à un chemin arbitraire (FIFO hang / disk-fill / probing). On CONFINE la cible à la
    // racine d'export (PLUME_LEDGER_EXPORT_DIR, défaut <data>/ledger-export) et on refuse le sink dès la
    // création si la cible évade la racine, est un lien symbolique, ou n'est pas un fichier régulier.
    if kind == "file" {
        let root = ledger_export_root(&load_config());
        if let Err(e) = ledger_file_target_validate(&root, &target) {
            return err_json(StatusCode::BAD_REQUEST, format!("target de sink 'file' refusée: {e} (racine autorisée: {})", root.display()));
        }
    }
    // Refuse un secret EN CLAIR : seule une référence est acceptée (env:/file:/vault:), jamais le secret nu.
    if !secret_ref.is_empty() && !(secret_ref.starts_with("env:") || secret_ref.starts_with("file:") || secret_ref.starts_with("vault:")) {
        return err_json(StatusCode::BAD_REQUEST, "secret_ref doit être une référence (env:/file:/vault:), jamais un secret inline");
    }
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM ledger_sink WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).is_ok() {
        return err_json(StatusCode::CONFLICT, format!("un sink nommé '{name}' existe déjà"));
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO ledger_sink(name,kind,target,secret_ref,format,enabled,created,updated,updated_by) \
             VALUES(?1,?2,?3,?4,'jsonl',1,?5,?5,?6)",
            params![name, kind, target, secret_ref, now(), au.name.as_str()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.ledger_sink.create",
            &format!("sink d'export ledger '{name}' (#{id}, {kind}) créé par {}", au.name), 2,
            &format!("sink d'export ledger '{name}' créé par {}", au.name),
            &json!({ "op": "create", "kind": "ledger_sink", "id": id, "name": name, "sink_kind": kind, "target": target, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({ "ok": true, "id": id, "name": name })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// DELETE /api/ledger-sinks/{id} — retire un sink (admin-only, ledgerisé).
pub(crate) async fn ledger_sink_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM ledger_sink WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(n) => n,
        Err(_) => return not_found("sink introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM ledger_sink WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.ledger_sink.delete",
            &format!("sink d'export ledger '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("sink d'export ledger '{name}' supprimé par {}", au.name),
            &json!({ "op": "delete", "kind": "ledger_sink", "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({ "ok": true, "id": id })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction: {e}"))
        }
    }
}

/// POST /api/ledger-sinks/{id}/flush — EXPORTE les nouvelles entrées du ledger (id > last_id) vers le sink,
/// puis avance le curseur (last_id/last_hash) UNIQUEMENT si l'écriture réussit (at-least-once : jamais de
/// trou dans la copie WORM). Read-only sur `ledger` (aucune mutation). Renvoie le nombre d'entrées exportées.
pub(crate) async fn ledger_sink_flush(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    crate::req_conn!(st, au, conn);
    let sink = conn.query_row(
        "SELECT name,kind,target,enabled,last_id FROM ledger_sink WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)),
    );
    let (name, kind, target, enabled, last_id) = match sink {
        Ok(t) => t,
        Err(_) => return not_found("sink introuvable"),
    };
    if enabled == 0 {
        return err_json(StatusCode::CONFLICT, "sink désactivé");
    }
    // `P10.7-s` — LE CURSEUR NE BOUGE PAS SUR UNE TRANCHE QU'ON N'A PAS SU LIRE, et c'est ici que le défaut
    // coûtait le plus cher : la lecture aplatissait, le flush écrivait ce qu'elle avait bien voulu rendre,
    // puis avançait `last_id` — le maillon sauté n'entrait JAMAIS dans la copie inaltérable, et les envois
    // suivants annonçaient « exported: 0 ». Une lacune permanente ET silencieuse dans une preuve WORM.
    // Le refus arrive AVANT le raccourci « rien à exporter » : sans quoi « illisible » se relirait
    // exactement comme « rien de neuf », qui est la confusion que ce lot ferme.
    let (lines, new_last_id, new_last_hash) = match ledger_export_lines(&conn, last_id, 100000) {
        Ok(t) => t,
        Err(e) => return server_err(format!("export vers le sink '{name}' impossible : {e}")),
    };
    if lines.is_empty() {
        return Json(json!({ "ok": true, "exported": 0, "last_id": last_id })).into_response();
    }
    // ÉCRITURE d'abord ; curseur avancé SEULEMENT en cas de succès (pas d'écriture DB avant, donc jamais un
    // curseur avancé sur une écriture ratée). MEDIUM #59 : un sink WEB kind=file est CONFINÉ (confine_root) ->
    // cible dans la racine d'export, O_NOFOLLOW, fichier régulier (défense en profondeur post-CREATE : la
    // cible pourrait avoir été remplacée par un lien entre-temps — TOCTOU).
    let confine = if kind == "file" { Some(ledger_export_root(&load_config())) } else { None };
    if let Err(e) = ledger_sink_write(&kind, &target, &lines, confine.as_deref()) {
        return server_err(format!("écriture sink '{name}': {e}"));
    }
    let n = lines.len();
    let _ = conn.execute("UPDATE ledger_sink SET last_id=?1, last_hash=?2, updated=?3 WHERE id=?4", params![new_last_id, new_last_hash, now(), id]);
    Json(json!({ "ok": true, "exported": n, "last_id": new_last_id, "last_hash": new_last_hash })).into_response()
}

// =====================================================================================
// RÔLES COMPOSABLES (control-plane, super-admin en mode 1)
// =====================================================================================

/// Garde commune des routes /api/roles : le catalogue vit dans le CONTROL-PLANE (mode 1). En mode 0
/// (control=None) -> 404 (inerte, parité). Sinon SUPER-ADMIN uniquement (le catalogue est GLOBAL/plateforme).
fn roles_guard<'a>(st: &'a AppState, au: &AuthUser) -> Result<&'a ControlPlane, Response> {
    let Some(cp) = st.tenants.control.as_ref() else {
        return Err(not_found("rôles composables indisponibles (mode mono-tenant)"));
    };
    if !au.is_superadmin {
        return Err(forbidden("catalogue de rôles réservé au super-admin plateforme"));
    }
    Ok(cp)
}

/// GET /api/roles -> catalogue des rôles composables (name, base_role, deny_perms, description).
pub(crate) async fn roles_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    let cp = match roles_guard(&st, &au) {
        Ok(cp) => cp,
        Err(r) => return r,
    };
    let conn = cp.conn.lock();
    let rows: Vec<Value> = match conn.prepare("SELECT name,base_role,deny_perms,description FROM role_def ORDER BY name") {
        Ok(mut s) => s
            .query_map([], |r| {
                Ok(json!({
                    "name": r.get::<_, String>(0)?,
                    "base_role": r.get::<_, String>(1)?,
                    "deny_perms": r.get::<_, String>(2)?.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect::<Vec<_>>(),
                    "description": r.get::<_, String>(3)?,
                }))
            })
            .map(|it| it.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(json!({ "ok": true, "roles": rows, "known_deny_perms": KNOWN_DENY_PERMS })).into_response()
}

/// POST /api/roles — crée/met à jour un rôle composable (super-admin). Body {name, base_role, deny_perms[],
/// description?}. base_role ∈ {viewer,editor,admin} (JAMAIS is_superadmin -> aucune escalade). deny_perms
/// filtré sur KNOWN_DENY_PERMS. Un nom qui collisionne un rôle intégré est REFUSÉ. Rafraîchit le cache.
pub(crate) async fn role_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let cp = match roles_guard(&st, &au) {
        Ok(cp) => cp,
        Err(r) => return r,
    };
    let name = b.str_field("name").trim().to_string();
    let base = b.str_field("base_role").trim().to_string();
    let desc = b.str_field("description").trim().to_string();
    if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return err_json(StatusCode::BAD_REQUEST, "nom de rôle invalide (alnum . _ - ; 1..64)");
    }
    if is_builtin_role(&name) {
        return err_json(StatusCode::BAD_REQUEST, "nom réservé (rôle intégré) — choisir un autre nom");
    }
    // #64 : `base=admin` est de nouveau ACCEPTÉ (le blocage MEDIUM #59 est LEVÉ). Les checks handler-niveau
    // passent désormais tous par `AuthUser::is_admin()` = `effective_base_role(role)=="admin"` : un rôle custom
    // base=admin (ex. "gov-admin") EST reconnu admin sur les routes, MOINS ses `deny_perms` que `rbac_gate`
    // soustrait EN AMONT (path-guard) via `role_perm_denied` -> "admin-minus-denies", jamais une escalade.
    // base ∈ {viewer, editor, admin} ; JAMAIS super-admin (is_superadmin n'est pas une base -> aucune escalade
    // plateforme ; et la création/édition de rôles reste réservée au SUPER-ADMIN via roles_guard -> un custom-admin
    // ne peut PAS s'auto-éditer pour retirer ses propres denies).
    if !matches!(base.as_str(), "editor" | "viewer" | "admin") {
        return err_json(StatusCode::BAD_REQUEST, "base_role ∈ {viewer, editor, admin} (jamais super-admin)");
    }
    // deny_perms : filtre sur l'enum FERMÉ (un flag inconnu est écarté -> jamais un flag muet qui ouvrirait).
    let deny: Vec<String> = b
        .get("deny_perms")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| KNOWN_DENY_PERMS.contains(&s.as_str())).collect())
        .unwrap_or_default();
    let deny_csv = deny.join(",");
    {
        let conn = cp.conn.lock();
        let _ = conn.execute(
            "INSERT INTO role_def(name,base_role,deny_perms,description,created) VALUES(?1,?2,?3,?4,?5) \
             ON CONFLICT(name) DO UPDATE SET base_role=excluded.base_role, deny_perms=excluded.deny_perms, description=excluded.description",
            params![name, base, deny_csv, desc, now()],
        );
    }
    // AUDIT control-plane (tamper-evident) + rafraîchit le cache process pour un effet immédiat.
    control_ledger_append(&st, "role.upsert", &au.name, "", &format!("role '{name}' base={base} deny=[{deny_csv}]"));
    reload_custom_roles(cp);
    Json(json!({ "ok": true, "name": name, "base_role": base, "deny_perms": deny })).into_response()
}

/// DELETE /api/roles/{name} — retire un rôle composable (super-admin). Rafraîchit le cache. NB : les grants
/// qui référencent ce rôle retombent alors sur effective_base_role="" -> rang 0 -> DEFAULT-DENY (fail-closed).
pub(crate) async fn role_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    let cp = match roles_guard(&st, &au) {
        Ok(cp) => cp,
        Err(r) => return r,
    };
    {
        let conn = cp.conn.lock();
        let affected = conn.execute("DELETE FROM role_def WHERE name=?1", params![name]).unwrap_or(0);
        if affected == 0 {
            return not_found("rôle introuvable");
        }
    }
    control_ledger_append(&st, "role.delete", &au.name, "", &format!("role '{name}' supprimé"));
    reload_custom_roles(cp);
    Json(json!({ "ok": true, "name": name })).into_response()
}
