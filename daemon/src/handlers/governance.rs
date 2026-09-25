//! #59 GOUVERNANCE ENTREPRISE — handlers. TROIS surfaces admin-only (route_min_role -> Admin, GET compris) :
//!  - LEGAL-HOLD (per-tenant) : CRUD des rétention-locks. Create/release LEDGERISÉS (audit_config_change ->
//!    ledger tamper-evident + event SOC non-purgeable). L'enforcement de suppression vit dans retention_run
//!    (rollups.rs, fail-closed) ; ici on ne gère que la déclaration/levée du hold + sa preuve.
//!  - EXPORT LEDGER (per-tenant) : téléchargement JSONL chaîne-préservée (read-only) + CRUD des sinks + flush
//!    incrémental (curseur last_id/last_hash). Aucun chemin de mutation vers le ledger (SELECT seul).
//!  - RÔLES COMPOSABLES (control-plane) : CRUD du catalogue global (super-admin en mode 1). Rafraîchit le
//!    cache process (reload_custom_roles) à chaque mutation. base_role validé, deny_perms borné, jamais admin.
use crate::*;
use crate::handlers::transaction_validee::{
    ouvrir_la_transaction_du_geste, ouvrir_le_garde_du_geste, refuser_le_geste_non_valide, valider_la_transaction,
};

// =====================================================================================
// LEGAL-HOLD (per-tenant, admin-only, ledgerisé)
// =====================================================================================

// `P10.26-c` — UN GEL JURIDIQUE ET UN PUITS D'EXPORT DU REGISTRE NE SONT ANNONCÉS QU'UNE FOIS LEUR TRANSACTION VALIDÉE.
//
// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`COMMIT` refusé par un autorisateur SQLite, relecture à froid
// sur une connexion neuve) : les quatre gestes ignoraient leur `COMMIT` et laissaient la transaction PENDANTE sur
// l'écrivain partagé — celui que lisent `retention_run` et, avant `P10.26-t`, `ledger_sink_flush`. Ce processus agissait
// donc sur un état que la base n'avait pas pris :
//  * gel posé : 200 `active: true` ; la rétention de ce processus le respectait, aucune ligne à froid — au redémarrage,
//    la portée « gelée » redevenait purgeable ;
//  * gel levé : 200 `active: false`, et la rétention de ce processus PURGEAIT la preuve gelée (dans la transaction
//    pendante), alors que le gel restait actif à froid. L'issue ne dépendait plus du geste mais de qui fermerait la
//    transaction : annulée, la preuve revenait et le gel aussi ; VALIDÉE par le `COMMIT` d'un autre chemin — mesuré
//    avec `rollup_hosts`, qui ignore l'échec de son propre `BEGIN` puis valide ce qui est ouvert sur l'écrivain — la
//    levée ET la purge devenaient durables, sans que la base ait jamais pris le `COMMIT` de la levée. Symétriquement
//    (lu, non joué), un chemin qui ANNULE après un `BEGIN` raté aurait emporté un gel annoncé posé ;
//  * puits créé : 200 ; un envoi sur ce puits exportait vers la copie inaltérable des maillons du registre que la base
//    n'avait JAMAIS validés (dont la trace de sa propre création), et avançait son curseur ; aucun puits à froid. Lu,
//    non joué : `ledger.id` est un `INTEGER PRIMARY KEY` sans `AUTOINCREMENT`, ces identifiants de maillon seraient
//    réattribués après l'annulation, et la copie externe contredirait le registre ;
//  * puits supprimé : 200, toujours déclaré à froid.
// Dans chaque cas la transaction restait ouverte, et un geste suivant qui ouvre la sienne échouait en 500 « verrou base
// indisponible » (mesuré sur une seconde pose de gel).

/// `P10.26-c` — le `COMMIT` de la pose d'un gel juridique refusé.
pub(crate) const CAUSE_GEL_JURIDIQUE_NON_POSE: &str = "GEL JURIDIQUE NON POSÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — aucune portée n'est gelée : la rétention purge toujours ce que ce gel \
     devait protéger, et aucune trace n'est écrite. Réessayez AVANT le prochain passage de la rétention ; si le refus \
     persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_GEL_JURIDIQUE_NON_POSE_TRANSACTION_NON_OUVERTE: &str = "GEL JURIDIQUE NON POSÉ : la base n'a \
     pas pris la transaction de la pose (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : aucune portée n'est gelée : la rétention purge toujours ce que ce gel devait \
     protéger, et aucune trace n'est écrite. Réessayez AVANT le prochain passage de la rétention ; s'il est refusé \
     encore, l'écrivain est occupé ou bloqué.";

/// `P10.26-c` — le `COMMIT` de la levée d'un gel juridique refusé.
pub(crate) const CAUSE_GEL_JURIDIQUE_NON_LEVE: &str = "GEL JURIDIQUE NON LEVÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — le gel est toujours actif, sa portée n'est pas purgée, et aucune \
     trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_GEL_JURIDIQUE_NON_LEVE_TRANSACTION_NON_OUVERTE: &str = "GEL JURIDIQUE NON LEVÉ : la base n'a \
     pas pris la transaction de la levée (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : le gel est toujours actif, sa portée n'est pas purgée, et aucune trace n'est \
     écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.26-c` — le `COMMIT` de la création ou de la suppression d'un puits d'export du registre refusé.
pub(crate) const CAUSE_PUITS_DU_REGISTRE_INCHANGE: &str = "PUITS D'EXPORT DU REGISTRE INCHANGÉ : la base n'a pas \
     validé la transaction (COMMIT refusé) et l'a annulée — le puits n'est ni créé ni supprimé : un puits refusé à la \
     création n'existe pas et ne reçoit rien, un puits dont le retrait est refusé reste déclaré, et aucune trace n'est \
     écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_PUITS_DU_REGISTRE_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "PUITS D'EXPORT DU REGISTRE \
     INCHANGÉ : la base n'a pas pris la transaction de ce geste (BEGIN refusé : verrou tenu, ou transaction d'un \
     autre geste pendante sur l'écrivain) — RIEN n'est écrit : le puits n'est ni créé ni supprimé : un puits refusé \
     à la création n'existe pas et ne reçoit rien, un puits dont le retrait est refusé reste déclaré, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.26-s`, `P10.26-u` — l'envoi vers un puits n'a pas pu ouvrir sa transaction, ou la base a refusé d'y poser le
/// curseur : RIEN n'est écrit dans la copie.
pub(crate) const CAUSE_ENVOI_DU_PUITS_NON_FAIT: &str = "ENVOI VERS LE PUITS NON FAIT : la base n'a pas pris la \
     transaction de l'envoi (BEGIN refusé, ou avance du curseur refusée : verrou tenu, transaction d'un autre geste \
     pendante, base en lecture seule ou pleine) — AUCUN maillon n'est écrit dans la copie et le curseur ne bouge pas. \
     Réessayez ; si le refus persiste, l'écrivain est occupé ou bloqué.";

/// `P10.26-u` — la tranche est DANS la copie, la base a refusé de valider l'avance du curseur.
///
/// CE N'EST PAS UNE CAUSE « RIEN N'A CHANGÉ » : la copie, hors de la base, a reçu la tranche. Elle n'emploie donc pas la
/// forme « (COMMIT refusé) » que la console reconnaît pour « la base a tout annulé, rien n'a changé » (famille de
/// `P10.24-x`, lue par le banc web) — la peindre ainsi serait faux.
pub(crate) const CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE: &str = "MAILLONS EXPORTÉS, CURSEUR NON AVANCÉ : la tranche \
     est écrite dans la copie, mais la base a refusé le COMMIT qui validait l'avance du curseur, et l'a annulée. Le \
     prochain envoi réécrira ces maillons : la copie les portera DEUX fois, et `ledger-verify-export` y lira une rupture \
     de chaîne à la première ligne répétée — ce n'est pas une altération. Vérifiez la copie en écartant les lignes \
     répétées (même id, même hash) ; aucun maillon n'y MANQUE.";

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
        // `P10.7-z` — une lecture qui échoue AVOUE (`ok: false` + `error`) au lieu de servir « aucune rétention légale ».
        let lues: Result<Vec<Value>, rusqlite::Error> = conn.prepare(
            "SELECT id,name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by,released_ts,released_by \
             FROM legal_hold ORDER BY active DESC, id DESC",
        ).and_then(|mut s| {
            s.query_map([], |r| {
                    Ok(hold_json(
                        r.get::<_, i64>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, &r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?,
                        &r.get::<_, String>(8)?, r.get::<_, i64>(9)?, &r.get::<_, String>(10)?,
                    ))
                })
                .and_then(|it| it.collect::<Result<Vec<Value>, _>>())
        });
        match lues {
            Ok(rows) => Json(json!({ "ok": true, "holds": rows })).into_response(),
            Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "ok": false }), "holds")).into_response(),
        }
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "gouvernance", &format!("pose du gel juridique '{name}'"), CAUSE_GEL_JURIDIQUE_NON_POSE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
        // `P10.26-c` — « posé » n'est rendu qu'une fois la transaction VALIDÉE (voir `CAUSE_GEL_JURIDIQUE_NON_POSE`).
        Ok(id) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true, "id": id, "name": name, "active": true })).into_response(),
            Err(e) => refuser_le_geste_non_valide("gouvernance", &format!("pose du gel juridique '{name}'"), &e, CAUSE_GEL_JURIDIQUE_NON_POSE),
        },
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "gouvernance", &format!("levée du gel juridique '{name}' (#{id})"), CAUSE_GEL_JURIDIQUE_NON_LEVE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
        // `P10.26-c` — « levé » n'est rendu qu'une fois la transaction VALIDÉE (voir `CAUSE_GEL_JURIDIQUE_NON_LEVE`).
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true, "id": id, "active": false })).into_response(),
            Err(e) => refuser_le_geste_non_valide("gouvernance", &format!("levée du gel juridique '{name}' (#{id})"), &e, CAUSE_GEL_JURIDIQUE_NON_LEVE),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// =====================================================================================
// LEDGER — export streaming (chaîne préservée) + sinks
// =====================================================================================

/// `P10.26-t` — LA TRANCHE DU REGISTRE QUI SORT VERS UNE COPIE EST LUE LÀ OÙ SEUL LE VALIDÉ EXISTE : une connexion du
/// pool de lecture, jamais l'écrivain partagé.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (transaction d'un autre geste ouverte sur l'écrivain, un maillon
/// ajouté dedans et jamais validé). L'écrivain voit ce que sa transaction pendante a écrit : le téléchargement
/// (`ledger_export_get`) rendait 200 et DEUX lignes pour un seul maillon validé, et l'envoi vers un puits
/// (`ledger_sink_flush`) écrivait ces deux lignes dans la copie inaltérable en répondant `exported: 2`. La transaction
/// annulée, le registre n'avait plus qu'un maillon, le curseur était revenu à zéro (son `UPDATE` était dans la même
/// transaction), et la copie portait un maillon qui n'a jamais existé — dont l'identifiant sera réattribué (`ledger.id`
/// est un `INTEGER PRIMARY KEY` sans `AUTOINCREMENT`). L'énoncé ne nommait que l'envoi ; le téléchargement avait le même
/// défaut.
///
/// Une connexion du pool n'a PAS de transaction pendante à elle : elle lit le dernier état validé du fichier. Aucune
/// connexion de lecture disponible -> `Err`, rien n'est exporté (la cause est celle des autres lectures non faites).
fn tranche_validee_du_registre(db_path: &str, from_id: i64, limit: i64) -> Result<(Vec<String>, i64, String), String> {
    read_with(db_path, Err(crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION.to_string()), |conn| {
        ledger_export_lines(conn, from_id, limit)
    })
}

/// GET /api/ledger/export?from_id=<n>&limit=<n> -> JSONL (text/plain) de la chaîne du ledger (id,ts,kind,
/// detail,prev_hash,hash) à partir de from_id (exclu), borné. READ-ONLY (aucune mutation). Un vérificateur
/// externe recompute la chaîne (ledger_verify_export). En-têtes : last_id/last_hash pour reprendre.
pub(crate) async fn ledger_export_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let from_id: i64 = q.get("from_id").and_then(|s| s.trim().parse().ok()).unwrap_or(0).max(0);
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse().ok()).unwrap_or(10000).clamp(1, 100000);
    // `P10.7-s` — une tranche qu'on ne sait pas lire rend 500, jamais un `200` à corps VIDE. Le corps
    // vide en succès est le pire des deux : il se sauvegarde, se vérifie (`Ok(0)`) et se classe comme
    // une copie légitime. Un `200` reste possible AVEC un corps vide, et c'est voulu : c'est la réponse
    // JUSTE quand la tranche demandée est réellement vide (`from_id` au-delà du dernier maillon).
    // `P10.26-t` — lue sur le pool : seul le validé sort (`tranche_validee_du_registre`).
    let (lines, last_id, last_hash) = match tranche_validee_du_registre(&req_db_path(&st, &au), from_id, limit) {
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
}

/// GET /api/control-ledger/export?from_id=<n>&limit=<n> -> JSONL de la chaîne du journal de CONTRÔLE (accès
/// superadmin cross-tenant, ouvertures d'urgence, gestes d'administration), en-têtes `x-plume-ledger-last-id`
/// / `x-plume-ledger-last-hash` comme l'export voisin. En mode 0 il n'y a PAS de plan de contrôle : la route
/// le DIT (404 nommé) au lieu de rendre une chaîne vide qui se lirait comme « rien ne s'est passé ».
pub(crate) async fn control_ledger_export_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return err_json(StatusCode::NOT_FOUND, "aucun plan de contrôle : le journal de contrôle n'existe qu'en mode multi-tenant (PLUME_MULTI_TENANT)");
    };
    let from_id: i64 = q.get("from_id").and_then(|s| s.trim().parse().ok()).unwrap_or(0).max(0);
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse().ok()).unwrap_or(10000).clamp(1, 100000);
    let conn = cp.conn.lock();
    let (lines, last_id, last_hash) = match crate::governance::control_ledger_export_lines(&conn, from_id, limit) {
        Ok(t) => t,
        Err(e) => return server_err(format!("export du journal de contrôle impossible : {e}")),
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
        // `P10.7-z` — une lecture qui échoue AVOUE au lieu de servir « aucun puits configuré ».
        let lues: Result<Vec<Value>, rusqlite::Error> = conn.prepare("SELECT id,name,kind,target,secret_ref,enabled,last_id,last_hash FROM ledger_sink ORDER BY id").and_then(|mut s| {
            s.query_map([], |r| {
                    Ok(sink_json(r.get::<_, i64>(0)?, &r.get::<_, String>(1)?, &r.get::<_, String>(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, &r.get::<_, String>(7)?))
                })
                .and_then(|it| it.collect::<Result<Vec<Value>, _>>())
        });
        match lues {
            Ok(rows) => Json(json!({ "ok": true, "sinks": rows })).into_response(),
            Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "ok": false }), "sinks")).into_response(),
        }
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "gouvernance", &format!("création du puits du registre '{name}'"), CAUSE_PUITS_DU_REGISTRE_INCHANGE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
        Ok(id) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true, "id": id, "name": name })).into_response(),
            Err(e) => refuser_le_geste_non_valide("gouvernance", &format!("création du puits du registre '{name}'"), &e, CAUSE_PUITS_DU_REGISTRE_INCHANGE),
        },
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "gouvernance", &format!("suppression du puits du registre '{name}' (#{id})"), CAUSE_PUITS_DU_REGISTRE_INCHANGE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true, "id": id })).into_response(),
            Err(e) => refuser_le_geste_non_valide("gouvernance", &format!("suppression du puits du registre '{name}' (#{id})"), &e, CAUSE_PUITS_DU_REGISTRE_INCHANGE),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction: {e}"))
        }
    }
}

/// POST /api/ledger-sinks/{id}/flush — EXPORTE les nouvelles entrées VALIDÉES du ledger (id > last_id) vers le sink et
/// avance le curseur (last_id/last_hash) dans la MÊME transaction, validée seulement après l'écriture de la copie
/// (at-least-once : jamais de trou dans la copie WORM). Read-only sur `ledger` (aucune mutation). Renvoie le nombre
/// d'entrées exportées.
///
/// `P10.26-u` — LE CURSEUR N'AVANCE PLUS PAR UNE ÉCRITURE AVALÉE. MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT
/// (`let _ = conn.execute("UPDATE ledger_sink …")` après l'export, `UPDATE` refusé par un autorisateur SQLite) : 200
/// `exported: 1`, la ligne dans la copie, le curseur à 0 ; l'envoi suivant réécrivait la même ligne (200 `exported: 1`)
/// et la copie ne se vérifiait plus (`ledger_verify_export` : « rupture de chaîne » à la ligne répétée).
///
/// L'ORDRE, DÉCIDÉ. Durablement il reste « exporter PUIS avancer » : le curseur n'est validé qu'une fois la copie
/// écrite, donc un trou — un maillon que la copie ne recevra jamais — reste impossible. Ce qui change est la FENÊTRE du
/// doublon. Le curseur est désormais POSÉ (et compté) dans la transaction de l'envoi AVANT l'écriture de la copie : une
/// transaction non ouverte ou un curseur refusé l'est avant que rien ne soit écrit (503 `CAUSE_ENVOI_DU_PUITS_NON_FAIT`),
/// et seul un `COMMIT` refusé APRÈS l'écriture laisse la tranche dans la copie sans curseur avancé — dit par
/// `CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE`. La copie NE TOLÈRE PAS un doublon : `ledger_verify_export` exige que chaque
/// `prev_hash` soit le `hash` de la ligne précédente, et une tranche réécrite casse la chaîne à sa première ligne (lu,
/// puis mesuré par le témoin). Le doublon reste préférable au trou — il s'écarte à la lecture, un trou ne se comble
/// jamais —, mais il n'est plus produit en silence.
///
/// `P10.26-s` — la transaction de l'envoi est LA SIENNE : un `BEGIN` refusé (transaction d'un autre geste pendante sur
/// l'écrivain) rend le 503 sans rien exporter ; la tranche est lue sur le pool (`P10.26-t`), jamais sur l'écrivain.
pub(crate) async fn ledger_sink_flush(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    let geste = format!("envoi vers le puits du registre #{id}");
    // Le garde `Txn` ANNULE la transaction à sa destruction si elle n'a pas été validée : chaque retour anticipé
    // ci-dessous referme donc la sienne, et elle seule.
    // `P10.28-d` — la forme commune d'une route qui ouvre son garde (même journal, même 503 nommé qu'avant).
    let tx = match ouvrir_le_garde_du_geste(&conn, "gouvernance", &geste, CAUSE_ENVOI_DU_PUITS_NON_FAIT) {
        Ok(tx) => tx,
        Err(refus) => return refus,
    };
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
    let (lines, new_last_id, new_last_hash) = match tranche_validee_du_registre(&db_path, last_id, 100000) {
        Ok(t) => t,
        Err(e) => return server_err(format!("export vers le sink '{name}' impossible : {e}")),
    };
    if lines.is_empty() {
        return Json(json!({ "ok": true, "exported": 0, "last_id": last_id })).into_response();
    }
    // `P10.26-u` — le curseur est POSÉ avant l'écriture de la copie, et COMPTÉ : une ligne, celle du puits lu dans cette
    // même transaction. Refusé, rien n'est écrit dans la copie.
    match conn.execute(
        "UPDATE ledger_sink SET last_id=?1, last_hash=?2, updated=?3 WHERE id=?4 AND last_id=?5",
        params![new_last_id, new_last_hash, now(), id, last_id],
    ) {
        Ok(1) => {}
        Ok(n) => {
            eprintln!("[gouvernance] WARN {geste} NON fait : l'avance du curseur a touché {n} ligne(s) au lieu d'une — rien n'est exporté");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_ENVOI_DU_PUITS_NON_FAIT);
        }
        Err(refus) => return refuser_le_geste_non_valide("gouvernance", &geste, &refus, CAUSE_ENVOI_DU_PUITS_NON_FAIT),
    }
    // ÉCRITURE de la copie. MEDIUM #59 : un sink WEB kind=file est CONFINÉ (confine_root) -> cible dans la racine
    // d'export, O_NOFOLLOW, fichier régulier (défense en profondeur post-CREATE : la cible pourrait avoir été remplacée
    // par un lien entre-temps — TOCTOU). Échec -> le garde annule le curseur posé : il n'a jamais été validé.
    let confine = if kind == "file" { Some(ledger_export_root(&load_config())) } else { None };
    if let Err(e) = ledger_sink_write(&kind, &target, &lines, confine.as_deref()) {
        return server_err(format!("écriture sink '{name}': {e}"));
    }
    let n = lines.len();
    // Le `COMMIT` est JUGÉ : refusé, `Txn::commit` rend `Err` et le garde annule — la tranche est dans la copie, le
    // curseur n'a pas avancé, et la réponse le DIT.
    if let Err(refus) = tx.commit() {
        return refuser_le_geste_non_valide("gouvernance", &geste, &refus, CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE);
    }
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
    // `P10.7-f` (rang 1) — LE CATALOGUE RBAC EST ENTIER OU AVOUÉ. Avant : `.map(|it| it.flatten().collect())
    // .unwrap_or_default()` et `Err(_) => Vec::new()` — un rôle dont la ligne ne se décode pas, ou un
    // catalogue entièrement illisible, se servait `{"ok": true, "roles": []}` : une permission accordée
    // cessait d'être visible, et `ok: true` affirmait que le catalogue avait été lu. Soldé en bloc ; sur
    // échec, `ok: false` + `error` (la forme de `holds_list`/`sinks_list` du même fichier, `P10.7-z`).
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT name,base_role,deny_perms,description FROM role_def ORDER BY name")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({
                    "name": r.get::<_, String>(0)?,
                    "base_role": r.get::<_, String>(1)?,
                    "deny_perms": r.get::<_, String>(2)?.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect::<Vec<_>>(),
                    "description": r.get::<_, String>(3)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(rows) => Json(json!({ "ok": true, "roles": rows, "known_deny_perms": KNOWN_DENY_PERMS })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
            json!({ "ok": false, "known_deny_perms": KNOWN_DENY_PERMS }),
            "roles",
        ))
        .into_response(),
    }
}

/// `P10.21-g` — LE RÔLE QUE LA BASE N'A PAS PRIS EST REFUSÉ : 503, rien au journal de contrôle, le cache
/// des rôles n'est pas rechargé. Le rôle garde la définition qu'il avait (ou n'existe toujours pas).
pub(crate) const CAUSE_ROLE_NON_ECRIT: &str =
    "RÔLE NON ENREGISTRÉ, RIEN N'A CHANGÉ : le plan de contrôle n'a pas pris l'écriture de ce rôle ; sa \
     définition est celle d'avant la demande, et aucune trace ne dit le contraire. Réessayez une fois le \
     plan de contrôle de nouveau écrivable.";

/// `P10.21-g` — LE RETRAIT DE RÔLE QUE LA BASE N'A PAS PRIS EST REFUSÉ : 503 et non plus « introuvable ».
pub(crate) const CAUSE_RETRAIT_DE_ROLE_NON_ECRIT: &str =
    "RETRAIT NON ENREGISTRÉ, LE RÔLE EST TOUJOURS EN PLACE : le plan de contrôle n'a pas pris la \
     suppression de ce rôle ; les droits qui le portent gardent ses permissions, et aucune trace ne dit \
     le contraire. Réessayez une fois le plan de contrôle de nouveau écrivable.";

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
    // `P10.21-g` — LE RÔLE EST COMPTÉ AVANT D'ÊTRE ATTESTÉ. Avalé, un `INSERT` refusé rendait `ok` et
    // posait `role.upsert` au journal de contrôle pour un rôle qui n'existait pas (ou gardait ses anciens
    // refus de permission). Un upsert sans clause `WHERE` écrit toujours une ligne : zéro est un refus.
    let ecriture = {
        let conn = cp.conn.lock();
        EcritureDuPlanDeControle::from(conn.execute(
            "INSERT INTO role_def(name,base_role,deny_perms,description,created) VALUES(?1,?2,?3,?4,?5) \
             ON CONFLICT(name) DO UPDATE SET base_role=excluded.base_role, deny_perms=excluded.deny_perms, description=excluded.description",
            params![name, base, deny_csv, desc, now()],
        ))
    };
    match ecriture {
        EcritureDuPlanDeControle::Ecrite => {}
        EcritureDuPlanDeControle::AucuneLigne => return refuser_le_geste_non_ecrit(CAUSE_ROLE_NON_ECRIT, "aucune ligne écrite"),
        EcritureDuPlanDeControle::Refusee(cause) => return refuser_le_geste_non_ecrit(CAUSE_ROLE_NON_ECRIT, &cause),
    }
    // AUDIT control-plane (tamper-evident) + rafraîchit le cache process pour un effet immédiat.
    // `P10.20-z` — LE RÔLE EST ÉCRIT ; SI SA LIGNE MANQUE AU JOURNAL DE CONTRÔLE, LA RÉPONSE LE DIT à côté
    // du succès. Refuser serait faux : le rôle existe déjà, et le rejeu ne comblerait pas le trou.
    let maillon = control_ledger_append(&st, "role.upsert", &au.name, "", &format!("role '{name}' base={base} deny=[{deny_csv}]"));
    reload_custom_roles(cp);
    let mut corps = json!({ "ok": true, "name": name, "base_role": base, "deny_perms": deny });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    Json(corps).into_response()
}

/// DELETE /api/roles/{name} — retire un rôle composable (super-admin). Rafraîchit le cache. NB : les grants
/// qui référencent ce rôle retombent alors sur effective_base_role="" -> rang 0 -> DEFAULT-DENY (fail-closed).
pub(crate) async fn role_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    let cp = match roles_guard(&st, &au) {
        Ok(cp) => cp,
        Err(r) => return r,
    };
    // `P10.21-g` — « introuvable » et « la base a refusé » sont deux faits. `unwrap_or(0)` les confondait :
    // un retrait refusé rendait un 404 « rôle introuvable » pour un rôle toujours en place.
    let retrait = {
        let conn = cp.conn.lock();
        EcritureDuPlanDeControle::from(conn.execute("DELETE FROM role_def WHERE name=?1", params![name]))
    };
    match retrait {
        EcritureDuPlanDeControle::Ecrite => {}
        EcritureDuPlanDeControle::AucuneLigne => return not_found("rôle introuvable"),
        EcritureDuPlanDeControle::Refusee(cause) => return refuser_le_geste_non_ecrit(CAUSE_RETRAIT_DE_ROLE_NON_ECRIT, &cause),
    }
    // `P10.20-z` — même contrat que `role_upsert` : le rôle est retiré, l'aveu voyage à côté du succès.
    let maillon = control_ledger_append(&st, "role.delete", &au.name, "", &format!("role '{name}' supprimé"));
    reload_custom_roles(cp);
    let mut corps = json!({ "ok": true, "name": name });
    avouer_le_maillon_de_controle_manquant(&mut corps, &maillon);
    Json(corps).into_response()
}
