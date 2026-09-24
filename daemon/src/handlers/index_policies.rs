//! #49 — CRUD des INDEXES LOGIQUES NOMMÉS (table `index_policy`) + statistiques par index. ADMIN-ONLY
//! (`route_min_role : /api/index-policies -> Admin`, GET compris — gouvernance de la donnée : ces politiques
//! PILOTENT une purge DESTRUCTIVE). L'IDENTITÉ d'un index = la colonne `event.env_id` (v66) — le MÊME axe
//! que route l'action ROUTE du processeur d'ingest #40 et qu'agrègent les rollups (v67) ; AUCUN concept de
//! routage parallèle. Un index HEC (`fields.index`) se route vers un env via une règle #40
//! `match fields.index eq <x> -> route env=<x>`.
//!
//! FAIL-CLOSED : chaque mutation VALIDE (nom via env_id_ok = MÊME allowlist que #40 ; bornes) AVANT écriture,
//! sous transaction auditée (ledger + event SOC). Une valeur de rétention >0 est planchée [7,3650] à
//! l'écriture (miroir de load_index_policies) : jamais persister une fenêtre sous le plancher anti-effacement.
//! Les STATS par index (compte / plus ancien / estimation de taille) sont lues depuis `event_rollup`
//! (pré-agrégé, cheap) — JAMAIS un scan de `event` (doctrine « jamais scanner event par requête au volume »).
use crate::*;
use crate::handlers::transaction_validee::rendre_apres_validation;

/// Estimation d'octets par event pour la taille par index (message+fields+colonnes+index+overhead SQLite).
/// APPROXIMATIVE et DISPLAY-only (l'UI affiche « ~N ») ; le plafond `max_bytes` réel se mesure ligne-à-ligne
/// dans retention_apply_caps (length() exacte), pas via cette constante.
const EST_BYTES_PER_EVENT: i64 = 512;

/// Borne le nombre d'index NON gérés (env_id vus dans event_rollup sans policy) affichés — anti-explosion
/// (un opérateur qui route des milliers d'env ne noie pas l'UI). Les indexes gérés sont TOUS renvoyés.
const MAX_UNMANAGED_SHOWN: usize = 200;

/// Stats d'un index (env_id) depuis event_rollup : compte, plus ancien bucket, plus récent last_ts.
///
/// `P10.7-f` (rang 3) — REND UN `Result`, ET C'EST LE POINT. Cette lecture était TROIS FOIS avalée : un
/// `if let Ok` sur la préparation, un `if let Ok` sur l'exécution, et un `rows.flatten()` sur les lignes.
/// Les trois retombaient sur la MÊME valeur, une map VIDE, qu'`index_policies_list` sert ensuite comme
/// un fait — et pas un fait quelconque : un index GÉRÉ s'y affiche « 0 event » (l'opérateur en conclut
/// que le flux est mort, ou que sa rétention n'a plus rien à purger), et un index NON GÉRÉ DISPARAÎT
/// entièrement de la liste, puisque la liste des non-gérés est dérivée des CLÉS de cette map. Une seule
/// ligne illisible — un blob dans `event_rollup.env_id`, une colonne qu'une migration vient d'ajouter —
/// suffisait à faire disparaître UN index, silencieusement, d'une vue qui pilote une purge DESTRUCTIVE.
/// L'appelant est désormais obligé de trancher entre « lu » et « non lu » ; il avoue.
fn index_stats(conn: &Connection) -> rusqlite::Result<HashMap<String, (i64, Option<i64>, Option<i64>)>> {
    let lignes: Vec<(String, i64, Option<i64>, Option<i64>)> = conn
        .prepare("SELECT env_id, COALESCE(SUM(n),0), MIN(bucket), NULLIF(MAX(last_ts),0) FROM event_rollup GROUP BY env_id")
        .and_then(|mut st| {
            st.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, Option<i64>>(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })?;
    let mut m = HashMap::new();
    for (env, cnt, oldest, newest) in lignes {
        m.insert(env, (cnt, oldest, newest));
    }
    Ok(m)
}

/// JSON d'un index (policy éventuelle + stats). `id`=NULL et `managed`=false pour un index NON géré (env_id
/// vu en donnée mais sans policy -> il hérite de la rétention globale).
fn index_json(name: &str, policy: Option<&(i64, i64, i64, i64, String, i64, i64)>, stats: Option<&(i64, Option<i64>, Option<i64>)>) -> Value {
    let (count, oldest, newest) = stats.map(|s| (s.0, s.1, s.2)).unwrap_or((0, None, None));
    let mut o = serde_json::Map::new();
    o.insert("name".into(), json!(name));
    o.insert("events".into(), json!(count));
    o.insert("oldest_ts".into(), json!(oldest));
    o.insert("newest_ts".into(), json!(newest));
    o.insert("size_bytes_est".into(), json!(count * EST_BYTES_PER_EVENT));
    o.insert("size_est_approx".into(), json!(true));
    match policy {
        Some((id, rdays, max_rows, max_bytes, desc, enabled, managed)) => {
            o.insert("id".into(), json!(id));
            o.insert("retention_days".into(), json!(rdays));
            o.insert("max_rows".into(), json!(max_rows));
            o.insert("max_bytes".into(), json!(max_bytes));
            o.insert("description".into(), json!(desc));
            o.insert("enabled".into(), json!(*enabled != 0));
            o.insert("managed".into(), json!(managed));
            o.insert("has_policy".into(), json!(true));
        }
        None => {
            o.insert("id".into(), Value::Null);
            o.insert("retention_days".into(), json!(0)); // hérite du global
            o.insert("max_rows".into(), json!(0));
            o.insert("max_bytes".into(), json!(0));
            o.insert("description".into(), json!(""));
            o.insert("enabled".into(), json!(true));
            o.insert("managed".into(), Value::Null);
            o.insert("has_policy".into(), json!(false));
        }
    }
    Value::Object(o)
}

/// GET /api/index-policies — policies + indexes découverts (env_id en donnée sans policy) + rétention globale
/// effective (pour afficher « hérite du global = N j »). Admin-only.
pub(crate) async fn index_policies_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    crate::req_conn!(st, au, conn);
    let global_days = retention_effective(&conn, &conf, "retention_days");
    // `P10.7-f` (rang 3) — LES DEUX LECTURES QUI ALIMENTENT `indexes` SONT ENTIÈRES OU AVOUÉES. La
    // seconde était aplatie comme la première : une politique dont le mappeur échoue (blob dans
    // `index_policy.name`, colonne absente de la connexion qui sert) sortait de `policies`, donc de
    // `managed_names`, et son index se réaffichait sous l'autre branche d'`index_json` — `has_policy:
    // false`, `retention_days: 0`, c'est-à-dire « cet index n'a pas de politique, il HÉRITE DU GLOBAL ».
    // Sur une vue qui pilote une purge DESTRUCTIVE, une politique perdue se lisait donc comme une
    // rétention globale appliquée à un index qui en avait une à lui. Aucune des deux lectures ne peut
    // plus se solder par un « fait » : l'échec sert l'aveu du dépôt.
    let lectures: rusqlite::Result<(HashMap<String, (i64, Option<i64>, Option<i64>)>, Vec<(String, (i64, i64, i64, i64, String, i64, i64))>)> =
        index_stats(&conn).and_then(|stats| {
            let policies = conn
                .prepare("SELECT id,name,retention_days,max_rows,max_bytes,description,enabled,managed FROM index_policy ORDER BY name")
                .and_then(|mut s| {
                    s.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(1)?,
                            (r.get::<_, i64>(0)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?,
                             r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?),
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
                })?;
            Ok((stats, policies))
        });
    let (stats, policies) = match lectures {
        Ok(v) => v,
        // NI STATS NI POLITIQUES : `indexes` est VIDE et le DIT (`error`), et `ok` retombe à `false` —
        // un inventaire d'index NON LU ne se sert pas avec `ok: true`, comme le catalogue des rôles du
        // rang 1. `global_retention_days` et `bounds` viennent d'ailleurs et restent servis.
        Err(_) => {
            return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
                json!({
                    "ok": false,
                    "global_retention_days": global_days,
                    "bounds": { "retention_days": { "min_when_set": 7, "max": 3650, "inherit": 0 } },
                }),
                "indexes",
            ))
            .into_response()
        }
    };
    let managed_names: std::collections::HashSet<&str> = policies.iter().map(|(n, _)| n.as_str()).collect();
    let mut out: Vec<Value> = policies.iter().map(|(n, p)| index_json(n, Some(p), stats.get(n))).collect();
    // indexes NON gérés : env_id vus en donnée mais sans policy (hérite du global). Bornés (anti-explosion).
    let mut unmanaged: Vec<&String> = stats.keys().filter(|n| !managed_names.contains(n.as_str())).collect();
    unmanaged.sort();
    for name in unmanaged.into_iter().take(MAX_UNMANAGED_SHOWN) {
        out.push(index_json(name, None, stats.get(name)));
    }
    Json(json!({
        "ok": true,
        "global_retention_days": global_days,
        "bounds": { "retention_days": { "min_when_set": 7, "max": 3650, "inherit": 0 } },
        "indexes": out,
    })).into_response()
}

/// Valide les champs d'une policy proposée. `retention_days` : 0 (hérite) ou [7,3650] (clampé). `max_*` >= 0.
/// Nom via env_id_ok (MÊME allowlist que #40). Renvoie (retention_days clampé, max_rows, max_bytes).
fn validate_policy(name: &str, rdays: i64, max_rows: i64, max_bytes: i64) -> Result<(i64, i64, i64), Response> {
    if !env_id_ok(name) {
        return Err(err_json(StatusCode::BAD_REQUEST, format!("nom d'index invalide (charset borné, 1..=64): '{name}'")));
    }
    if rdays < 0 || max_rows < 0 || max_bytes < 0 {
        return Err(err_json(StatusCode::BAD_REQUEST, "valeurs négatives interdites"));
    }
    let rd = if rdays > 0 { rdays.clamp(7, 3650) } else { 0 };
    Ok((rd, max_rows, max_bytes))
}

// `P10.25-g` — LES `COMMIT` DES POLITIQUES D'INDEX SONT JUGÉS : un refus rend l'une de ces causes en 503, la transaction fermée.
/// `P10.25-g` — politique d'index non créée : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_POLITIQUE_D_INDEX_NON_CREEE: &str = "POLITIQUE D'INDEX NON CRÉÉE : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — l'index garde la rétention globale, aucune purge ne suit une \
     politique qui n'existe pas, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en \
     lecture seule, pleine ou verrouillée.";
/// `P10.25-g` — politique d'index inchangée : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_POLITIQUE_D_INDEX_INCHANGEE: &str = "POLITIQUE D'INDEX INCHANGÉE : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — la rétention et les plafonds d'avant s'appliquent toujours à la \
     purge, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";


/// POST /api/index-policies — crée une policy d'index (admin-only). Valide + clampe AVANT insert (fail-closed).
pub(crate) async fn index_policy_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let name = b.str_field("name").trim().to_string();
    let rdays = b.get("retention_days").and_then(|v| v.as_i64()).unwrap_or(0);
    let max_rows = b.get("max_rows").and_then(|v| v.as_i64()).unwrap_or(0);
    let max_bytes = b.get("max_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let desc = b.str_field("description").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let (rd, mr, mb) = match validate_policy(&name, rdays, max_rows, max_bytes) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    crate::req_conn!(st, au, conn);
    // 409 explicite sur nom déjà pris (UNIQUE) plutôt qu'un échec de transaction opaque.
    if conn.query_row("SELECT 1 FROM index_policy WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).is_ok() {
        return err_json(StatusCode::CONFLICT, format!("un index nommé '{name}' existe déjà"));
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description,enabled,managed,created,updated,updated_by) \
             VALUES(?1,?2,?3,?4,?5,?6,2,?7,?7,?8)",
            params![name, rd, mr, mb, desc, enabled, now(), au.name.as_str()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.index_policy.create",
            &format!("index logique '{name}' (#{id}) créé par {} (rétention={rd}j, max_rows={mr}, max_bytes={mb})", au.name), 2,
            &format!("index logique '{name}' créé par {}", au.name),
            &json!({ "op": "create", "kind": "index_policy", "id": id, "name": name, "retention_days": rd, "max_rows": mr, "max_bytes": mb, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "index-policies", &format!("création de la politique d'index '{name}'"), CAUSE_POLITIQUE_D_INDEX_NON_CREEE, || {
            Json(json!({ "id": id, "name": name, "retention_days": rd, "managed": 2 })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// POST /api/index-policies/{id} — met à jour une policy (admin-only). Re-valide la valeur RÉSULTANTE.
pub(crate) async fn index_policy_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT name,retention_days,max_rows,max_bytes FROM index_policy WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)),
    );
    let (name0, rd0, mr0, mb0) = match cur {
        Ok(t) => t,
        Err(_) => return not_found("index introuvable"),
    };
    // Le NOM (identité env_id) n'est PAS renommable (renommer changerait l'index cible d'une purge) : on
    // fusionne les autres champs et re-valide sur le nom existant.
    let rd = b.get("retention_days").and_then(|v| v.as_i64()).unwrap_or(rd0);
    let mr = b.get("max_rows").and_then(|v| v.as_i64()).unwrap_or(mr0);
    let mb = b.get("max_bytes").and_then(|v| v.as_i64()).unwrap_or(mb0);
    let (rd, mr, mb) = match validate_policy(&name0, rd, mr, mb) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(
            "UPDATE index_policy SET retention_days=?1,max_rows=?2,max_bytes=?3,updated=?4,updated_by=?5 WHERE id=?6",
            params![rd, mr, mb, now(), au.name.as_str(), id],
        )?;
        if let Some(v) = b.get("description").and_then(|x| x.as_str()) {
            conn.execute("UPDATE index_policy SET description=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE index_policy SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        let destructive = rd0 == 0 && rd > 0 || (rd0 > 0 && rd < rd0) || (mr0 == 0 && mr > 0) || (mb0 == 0 && mb > 0);
        audit_config_change(
            &conn, "config.index_policy.update",
            &format!("index logique '{name0}' (#{id}) modifié par {} (rétention {rd0}->{rd}j, max_rows {mr0}->{mr}, max_bytes {mb0}->{mb})", au.name),
            if destructive { 3 } else { 2 },
            &format!("index logique '{name0}' modifié par {}", au.name),
            &json!({ "op": "update", "kind": "index_policy", "id": id, "name": name0, "retention_days": rd, "max_rows": mr, "max_bytes": mb, "actor": au.name, "destructive": destructive }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "index-policies", &format!("modification de la politique d'index #{id}"), CAUSE_POLITIQUE_D_INDEX_INCHANGEE, || {
            Json(json!({ "ok": true, "retention_days": rd, "max_rows": mr, "max_bytes": mb })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// DELETE /api/index-policies/{id} — supprime une policy (admin-only). L'index (env_id) retombe alors sur la
/// rétention GLOBALE ; AUCUN event n'est touché par la suppression de la policy (seul le régime de purge change).
pub(crate) async fn index_policy_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM index_policy WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("index introuvable"),
    };
    match delete_managed_row_tx(&conn, "index_policy", "config.index_policy", id, managed, &au.name) {
        Ok(body) => Json(body).into_response(),
        Err((code, msg)) => err_json(code, msg),
    }
}
