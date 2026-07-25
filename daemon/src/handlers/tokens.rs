//! Provisioning de JETONS (agent + HEC) réservé admin — pendant UI du CLI `plume-daemon token <name> [host]`.
//! ADDITIF : réutilise EXACTEMENT la table `token` + la sémantique `token_lookup` (SHA-256 stocké, jamais le
//! secret) -> un jeton créé ici s'authentifie à l'IDENTIQUE d'un jeton CLI, sur le seam agent (Bearer /
//! responder host-lié) ET sur le collector HEC (`Splunk <tok>` / `?token=` sur /services/collector). `kind`
//! (agent|hec) est un LIBELLÉ DESCRIPTIF (v82) : il n'aiguille RIEN dans l'auth (les deux chemins partagent la
//! table) ; il ne sert qu'au badge UI + à l'extrait forwarder. Le secret CLAIR n'est renvoyé QU'UNE fois, à la
//! création (show-once) ; il n'est jamais re-dérivable (seul son SHA-256 est en base). Toutes les routes sont
//! admin-only (route_min_role /api/tokens -> Admin, default-deny) AVEC re-check `au.is_admin()` dans le handler.
use crate::*;

/// CSPRNG hex (/dev/urandom). MÊME construction que le CLI `token` : 32 octets -> hex. None si l'entropie
/// noyau est indisponible -> le mint ÉCHOUE (jamais de secret faible/prévisible).
pub(crate) fn token_rand_hex() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(hex_encode(&b))
}

/// Nom de jeton valide : alphanumérique + `. _ -` (comme les comptes user). Non vide.
fn token_name_ok(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Host de liaison valide : hostname raisonnable (alphanumérique + `. _ -`), <= 253 car. (jamais de secret ni
/// d'injection). Vide = non lié (ingest/HEC only ; refusé sur le responder — cf. sémantique CLI/host).
fn token_host_ok(host: &str) -> bool {
    host.len() <= 253 && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// GET /api/tokens — liste les jetons (JAMAIS le secret : ni clair ni hash). Admin-only.
pub(crate) async fn tokens_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    // Le provisioning UI opère sur le magasin de jetons du MODE 0 (table `token` de la base unique), STRICTEMENT
    // comme le CLI et comme `token_lookup` en mode 0. En mode 1, les jetons vivent dans le control-plane
    // (schéma minimal sans name/last_used) -> provisionnés hors UI ; on refuse ici pour ne jamais créer de
    // jeton MORT (invisible de token_lookup control-plane).
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    let conn = st.db.lock();
    let mut stmt = conn
        .prepare("SELECT id,name,kind,host,created,last_used,role FROM token ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            let host: Option<String> = r.get(3)?;
            // kind NULL (jetons CLI historiques) -> 'agent' (défaut du CLI `plume-daemon token`).
            let kind: Option<String> = r.get(2)?;
            let role: Option<String> = r.get(6)?;
            let kind_out = match kind.as_deref() {
                Some("hec") => "hec",
                Some("datasource") => "datasource",
                Some("client") => "client", // #39 jeton client-read
                Some("firehose") => "firehose", // P-HEC : clé de livraison push AWS Firehose (liée à un connecteur)
                _ => "agent",
            };
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "kind": kind_out,
                // rôle read-scoped UNIQUEMENT pour les jetons datasource (#52) ; sinon absent.
                "role": if kind_out == "datasource" { Some(role.unwrap_or_else(|| "viewer".into())) } else { None },
                "host": host.filter(|h| !h.is_empty()),
                "created": r.get::<_, Option<i64>>(4)?,
                "last_used": r.get::<_, Option<i64>>(5)?,
            }))
        })
        .unwrap();
    Json(json!({ "tokens": rows.flatten().collect::<Vec<_>>() })).into_response()
}

/// POST /api/tokens {name, kind:agent|hec, host?} — mint un jeton. Stocke le SHA-256 (jamais le clair) ;
/// renvoie le secret CLAIR UNE SEULE FOIS (show-once). Audité (config.token.create). Admin-only.
pub(crate) async fn token_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    let name = b.trimmed("name");
    let kind = match b.get("kind").and_then(|v| v.as_str()) {
        Some("hec") => "hec",
        Some("datasource") => "datasource", // #52 jeton read-scoped (Grafana/Prometheus pointe SUR plume)
        Some("client") => "client", // #39 jeton client-read (MSSP : le client voit SES cases), read-only strict
        _ => "agent", // défaut = agent (compat CLI)
    };
    // #52 — rôle de LECTURE d'un jeton datasource (viewer|editor, jamais admin/agent). NULL pour agent/hec.
    let role: Option<&str> = if kind == "datasource" {
        Some(match b.get("role").and_then(|v| v.as_str()) {
            Some("editor") => "editor",
            _ => "viewer", // défaut = viewer (moindre privilège)
        })
    } else {
        None
    };
    // #52 DÉFENSE EN PROFONDEUR : un jeton datasource est LECTURE SEULE -> JAMAIS host-lié (un host de liaison
    // n'a de sens que pour le responder agent host-scopé ; le refuser ferme indépendamment tout chemin d'action
    // host-gardé même si le filtre kind de token_lookup régressait un jour). host ignoré pour kind=datasource.
    let host = if kind == "datasource" || kind == "client" { String::new() } else { b.trimmed("host") };
    if !token_name_ok(&name) {
        return bad_req("nom de jeton invalide (alphanumérique, . _ - uniquement)");
    }
    if !host.is_empty() && !token_host_ok(&host) {
        return bad_req("hôte de liaison invalide (alphanumérique, . _ - ; ≤ 253 car.)");
    }
    let host_opt: Option<String> = if host.is_empty() { None } else { Some(host.clone()) };
    let Some(secret) = token_rand_hex() else {
        return server_err("entropie noyau indisponible — jeton NON créé");
    };
    let hash = sha256_hex(secret.as_bytes());
    let conn = st.db.lock();
    // Insert + audit ATOMIQUES fail-closed (aucun jeton sans trace ; si l'audit échoue -> ROLLBACK, le secret
    // renvoyé ne correspondrait à aucune ligne persistée). Le UNIQUE(token_hash) rend une collision improbable
    // -> 409. host NULL = non lié (ingest/HEC only). last_used NULL tant qu'inutilisé.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(
            "INSERT INTO token(name,token_hash,created,host,kind,role) VALUES(?1,?2,?3,?4,?5,?6)",
            params![name, hash, now(), host_opt, kind, role],
        )?;
        audit_config_change(
            &conn, "config.token.create",
            &format!("jeton {kind} '{name}'{} créé par {}", host_opt.as_deref().map(|h| format!(" (hôte {h})")).unwrap_or_default(), au.name), 2,
            &format!("jeton {kind} '{name}' provisionné{} par {}", host_opt.as_deref().map(|h| format!(" lié à l'hôte '{h}'")).unwrap_or_default(), au.name),
            &json!({ "op": "create", "kind": "token", "token_kind": kind, "name": name, "host": host_opt.clone(), "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            // SHOW-ONCE : le secret CLAIR n'est renvoyé QU'ICI (jamais re-dérivable). Le SPA l'affiche une fois.
            Json(json!({
                "name": name, "kind": kind, "host": host_opt, "role": role,
                "token": secret,
                "hec_path": "/services/collector",
                "datasource_path": "/api/ds/query", // #52 : endpoint SOQL-HTTP à pointer depuis Grafana Infinity
            })).into_response()
        }
        Err(_) => {
            let _ = conn.execute_batch("ROLLBACK");
            // Collision UNIQUE(name?) — en réalité name n'est pas unique ; le seul UNIQUE est token_hash.
            (StatusCode::CONFLICT, "échec de création du jeton (collision ou audit) — réessayez").into_response()
        }
    }
}

/// DELETE /api/tokens/:name — révoque (supprime) tous les jetons de ce nom. Audité. Admin-only.
pub(crate) async fn token_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    if !token_name_ok(&name) {
        return bad_req("nom de jeton invalide");
    }
    let conn = st.db.lock();
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM token WHERE name=?1", params![name], |r| r.get(0)).unwrap_or(0);
    if n == 0 {
        return not_found("jeton introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM token WHERE name=?1", params![name])?;
        audit_config_change(
            &conn, "config.token.revoke",
            &format!("jeton '{name}' révoqué par {} ({n})", au.name), 3,
            &format!("jeton '{name}' révoqué ({n} entrée·s) par {} — l'agent/forwarder porteur perd l'accès", au.name),
            &json!({ "op": "revoke", "kind": "token", "name": name, "count": n, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
