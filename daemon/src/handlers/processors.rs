//! #40 — CRUD du PROCESSEUR D'INGEST (table `ingest_rule`). Règles ADMIN-ONLY (route_min_role :
//! `/api/processors` -> Admin, GET compris — config sensible d'ingestion). Chaque mutation VALIDE la
//! règle (compilation à blanc `compile_rule`) AVANT écriture (fail-closed : une règle invalide est
//! REFUSÉE en 400, jamais persistée), écrit sous transaction auditée, puis `processors_reload` recompile
//! le registre chaud de CE db_path. La LISTE renvoie les règles + les compteurs live (dropped/masked/
//! routed/sampled_out) : non-silence, la donnée non-indexée est VISIBLE.
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};

/// GET /api/processors — règles ordonnées + compteurs live + erreurs de reload (admin-only).
pub(crate) async fn processors_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LE PIPELINE D'INGESTION EST LU ENTIÈREMENT OU AVOUÉ. Avant : DEUX
    // `unwrap()` (une table `ingest_rule` retirée PANIQUAIT) puis `rows.flatten().collect::<Vec<_>>()`.
    // Une règle avalée disparaît de la seule vue qui dit CE QUI ARRIVE AUX ÉVÉNEMENTS avant indexation —
    // et elle continue de s'appliquer, parce que le registre chaud est compilé ailleurs. « Cette
    // transformation n'existe pas » est alors faux dans le sens le plus coûteux : une règle `drop` ou
    // `mask` invisible explique une donnée absente ou caviardée que plus rien ne rattache à une décision.
    // Les compteurs live servis à côté, eux, viennent d'une AUTRE source (le registre en mémoire de ce
    // `db_path`) : ils restent servis, et le corps dit seulement que les RÈGLES n'ont pas été lues — le
    // désaccord entre un compteur qui bouge et une liste vide devient ainsi lisible au lieu d'être muet.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed FROM ingest_rule ORDER BY ord, id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "ord": r.get::<_, i64>(2)?,
                    "match_field": r.get::<_, String>(3)?, "match_op": r.get::<_, String>(4)?,
                    "match_value": r.get::<_, String>(5)?, "action": r.get::<_, String>(6)?,
                    "action_arg": r.get::<_, String>(7)?, "enabled": r.get::<_, i64>(8)? != 0,
                    "managed": r.get::<_, i64>(9)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    let counters = processors_counters_json(&db_path);
    match lues {
        Ok(rules) => Json(json!({ "rules": rules, "counters": counters })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "counters": counters }), "rules")),
    }
}

/// Valide une règle proposée en la COMPILANT à blanc (mêmes contrôles que le chemin chaud) -> Err(400).
fn validate_rule(mf: &str, mo: &str, mv: &str, act: &str, arg: &str) -> Result<(), Response> {
    match compile_rule(":validate:", 0, mf, mo, mv, act, arg) {
        Ok(_) => Ok(()),
        Err(e) => Err(err_json(StatusCode::BAD_REQUEST, format!("règle invalide: {e}"))),
    }
}

// `P10.25-g` — LES `COMMIT` DES RÈGLES D'INGESTION SONT JUGÉS. MESURÉ sur la forme d'avant (témoins `cjds_`) : 200,
// transaction laissée ouverte, la règle visible pour ce processus et absente à froid. LU : le registre des processeurs de
// l'ingestion était rechargé ensuite depuis cet état pendant ; il ne l'est plus qu'après la validation.
/// `P10.25-g` — règle d'ingestion non créée : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_REGLE_D_INGESTION_NON_CREEE: &str = "RÈGLE D'INGESTION NON CRÉÉE : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — aucune règle n'est écrite ni appliquée aux lots entrants, et \
     aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_REGLE_D_INGESTION_NON_CREEE_TRANSACTION_NON_OUVERTE: &str = "RÈGLE D'INGESTION NON CRÉÉE : la \
     base n'a pas pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : aucune règle n'est écrite ni appliquée aux lots entrants, et \
     aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P10.25-g` — règle d'ingestion inchangée : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_REGLE_D_INGESTION_INCHANGEE: &str = "RÈGLE D'INGESTION INCHANGÉE : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — l'ingestion applique toujours la règle d'avant, et aucune trace \
     n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_REGLE_D_INGESTION_INCHANGEE_TRANSACTION_NON_OUVERTE: &str = "RÈGLE D'INGESTION INCHANGÉE : la \
     base n'a pas pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre \
     geste pendante sur l'écrivain) — RIEN n'est écrit : l'ingestion applique toujours la règle d'avant, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";


/// POST /api/processors — crée une règle (admin-only). Valide AVANT insert (fail-closed).
pub(crate) async fn processor_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Règle d'ingest").to_string();
    let ord = b.get("ord").and_then(|v| v.as_i64()).unwrap_or(0);
    let mf = b.str_field("match_field").to_string();
    let mo = b.get("match_op").and_then(|v| v.as_str()).unwrap_or("eq").to_string();
    let mv = b.str_field("match_value").to_string();
    let act = b.get("action").and_then(|v| v.as_str()).unwrap_or("drop").to_string();
    let arg = b.str_field("action_arg").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    if let Err(resp) = validate_rule(&mf, &mo, &mv, &act, &arg) {
        return resp;
    }
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "processors", "création d'une règle d'ingestion", CAUSE_REGLE_D_INGESTION_NON_CREEE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,2,?9)",
            params![name, ord, mf, mo, mv, act, arg, enabled, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.ingest_rule.create",
            &format!("règle d'ingest '{name}' (#{id}) créée par {}", au.name), 2,
            &format!("règle d'ingest '{name}' créée par {}", au.name),
            &json!({ "op": "create", "kind": "ingest_rule", "id": id, "name": name, "action": act, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "processors", "création d'une règle d'ingestion", CAUSE_REGLE_D_INGESTION_NON_CREEE, || {
            processors_reload(&conn, req_db_path(&st, &au).as_str());
            Json(json!({ "id": id, "managed": 2 })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// POST /api/processors/{id} — met à jour une règle (admin-only). Re-valide la règle RÉSULTANTE avant écriture.
pub(crate) async fn processor_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    // Charge l'existant pour valider la règle FUSIONNÉE (un update partiel ne doit pas produire un état invalide).
    let cur = conn.query_row(
        "SELECT match_field,match_op,match_value,action,action_arg FROM ingest_rule WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?)),
    );
    let (mf0, mo0, mv0, act0, arg0) = match cur {
        Ok(t) => t,
        Err(_) => return not_found("règle introuvable"),
    };
    let mf = b.get("match_field").and_then(|v| v.as_str()).unwrap_or(&mf0).to_string();
    let mo = b.get("match_op").and_then(|v| v.as_str()).unwrap_or(&mo0).to_string();
    let mv = b.get("match_value").and_then(|v| v.as_str()).unwrap_or(&mv0).to_string();
    let act = b.get("action").and_then(|v| v.as_str()).unwrap_or(&act0).to_string();
    let arg = b.get("action_arg").and_then(|v| v.as_str()).unwrap_or(&arg0).to_string();
    if let Err(resp) = validate_rule(&mf, &mo, &mv, &act, &arg) {
        return resp;
    }
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "processors", &format!("modification de la règle d'ingestion #{id}"), CAUSE_REGLE_D_INGESTION_INCHANGEE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE ingest_rule SET name=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("ord").and_then(|x| x.as_i64()) { conn.execute("UPDATE ingest_rule SET ord=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE ingest_rule SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        // Champs de prédicat/action : on écrit la valeur FUSIONNÉE (déjà validée ci-dessus).
        conn.execute(
            "UPDATE ingest_rule SET match_field=?1,match_op=?2,match_value=?3,action=?4,action_arg=?5 WHERE id=?6",
            params![mf, mo, mv, act, arg, id],
        )?;
        audit_config_change(
            &conn, "config.ingest_rule.update",
            &format!("règle d'ingest #{id} modifiée par {}", au.name), 2,
            &format!("règle d'ingest #{id} modifiée par {}", au.name),
            &json!({ "op": "update", "kind": "ingest_rule", "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "processors", &format!("modification de la règle d'ingestion #{id}"), CAUSE_REGLE_D_INGESTION_INCHANGEE, || {
            processors_reload(&conn, req_db_path(&st, &au).as_str());
            Json(json!({ "ok": true })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// DELETE /api/processors/{id} — supprime une règle (admin-only). managed=2 (ad-hoc) -> suppression réelle.
pub(crate) async fn processor_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM ingest_rule WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("règle introuvable"),
    };
    match delete_managed_row_tx(&conn, "ingest_rule", "config.ingest_rule", id, managed, &au.name) {
        Ok(body) => {
            processors_reload(&conn, req_db_path(&st, &au).as_str());
            Json(body).into_response()
        }
        Err((code, msg)) => err_json(code, msg),
    }
}

/// POST /api/processors/test — dry-run : évalue un event-échantillon contre les règles ACTIVES et renvoie
/// le verdict + l'event résultant (masqué/routé). N'écrit RIEN. Aide l'admin à valider avant activation.
pub(crate) async fn processor_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let db_path = req_db_path(&st, &au);
    let ev = b.get("event").cloned().unwrap_or_else(|| json!({}));
    let mut row = EventRow {
        ts: ev.get("ts").and_then(|x| x.as_i64()).unwrap_or_else(now),
        source: ev.get("source").and_then(|x| x.as_str()).unwrap_or("agent").to_string(),
        category: ev.get("category").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        severity: ev.get("severity").and_then(|x| x.as_i64()).unwrap_or(0),
        message: ev.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        host: ev.get("host").and_then(|x| x.as_str()).map(|s| s.to_string()),
        src_ip: ev.get("src_ip").and_then(|x| x.as_str()).map(|s| s.to_string()),
        dst_ip: ev.get("dst_ip").and_then(|x| x.as_str()).map(|s| s.to_string()),
        url: ev.get("url").and_then(|x| x.as_str()).map(|s| s.to_string()),
        dedup: None,
        fields: ev.get("fields").filter(|f| !f.is_null()).map(|f| f.to_string()),
        engagement_id: String::new(),
        origin: String::new(),
        env_id: None,
    };
    // Dry-run : N'INCRÉMENTE PAS les compteurs live (ne pollue pas la vue « dropped-by-policy »).
    let verdict = processors_dryrun(&db_path, &mut row);
    Json(json!({
        "verdict": if verdict == ProcVerdict::Drop { "drop" } else { "keep" },
        "result": {
            "source": row.source, "category": row.category, "severity": row.severity,
            "message": row.message, "host": row.host, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "url": row.url, "fields": row.fields, "env_id": row.env_id,
        }
    })).into_response()
}
