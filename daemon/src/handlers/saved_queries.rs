//! SAVED QUERIES — requêtes GXQL NOMMÉES, PERSISTANTES, PER-USER (table `saved_query`, v107). Outillage
//! d'analyste PERSONNEL : `/api/saved-queries` GET (liste MES requêtes) / POST (créer {name, soql}) /
//! PUT `/:id` (modifier {name?, soql?}) / DELETE `/:id`. RBAC = viewer+ SELF-SERVICE (route_min_role :
//! `/api/saved-queries` -> Read, MÊME modèle que `/api/prefs` et `/api/mfa/*`) : ce n'est PAS une surface
//! admin (aucun secret, aucune autz), juste de l'outillage personnel ; le CSRF cookie s'applique quand même
//! aux POST/PUT/DELETE (chemin mutant normal).
//!
//! ISOLATION (critique) — OWNER-SCOPED STRICT : `owner = au.name` est TOUJOURS posé par le serveur (jamais
//! par le client). La lecture est `WHERE owner=?` ; toute mutation ciblée est `WHERE id=? AND owner=?` -> un
//! utilisateur ne peut JAMAIS voir/charger/éditer/supprimer la ligne d'un autre (IDOR bloqué : l'id seul ne
//! suffit pas). Tenant-scoped STRUCTURELLEMENT via `req_db` (table par-tenant, comme user_pref). Ces requêtes
//! ne sont JAMAIS ajoutées à une projection client-read multi-tenant (outillage interne).
//!
//! DRAFTS : le `soql` est stocké TEL QUEL (jamais compilé au save -> on peut sauver un brouillon incomplet).
//! Le chargement ne fait que remplir la barre côté client ; l'exécution passe par le chemin VALIDÉ /api/query
//! (compilation GXQL + authorizer + masquage). Le texte stocké est INERTE : aucune injection possible tant
//! qu'il n'est pas exécuté, et l'exécution est gardée comme n'importe quelle requête tapée à la main.
use crate::*;

/// Plafond du nombre de requêtes sauvegardées PAR UTILISATEUR (anti-abus de la table par-tenant). 200 = très
/// large pour de l'outillage personnel, négligeable pour la base.
pub(crate) const SAVED_QUERY_MAX_PER_USER: i64 = 200;
/// Plafond de longueur du NOM (caractères). Un libellé, pas un document.
pub(crate) const SAVED_QUERY_NAME_MAX: usize = 200;
/// Plafond de longueur du TEXTE GXQL (octets). Très large pour une requête (même longue avec `| eval`/`| where`
/// enchaînés), borne l'abus de stockage. Miroir d'esprit des autres plafonds (prefs 64 KiB).
pub(crate) const SAVED_QUERY_SOQL_MAX: usize = 16 * 1024;

/// Erreur de validation -> message stable (mappé en 400/409/413 par le handler). Pure -> testable.
#[derive(Debug, PartialEq)]
pub(crate) enum SqErr {
    NameEmpty,
    NameTooLong,
    SoqlTooLong,
    CapReached,
    NotFound,
    Db,
}

/// Normalise + valide {name, soql} AVANT écriture (fail-closed). `name` trimmé non-vide et borné ; `soql`
/// borné (draft autorisé -> peut être vide ; jamais compilé ici). Pure -> testable.
fn validate(name: &str, soql: &str) -> Result<(String, String), SqErr> {
    let name = name.trim();
    if name.is_empty() {
        return Err(SqErr::NameEmpty);
    }
    if name.chars().count() > SAVED_QUERY_NAME_MAX {
        return Err(SqErr::NameTooLong);
    }
    if soql.len() > SAVED_QUERY_SOQL_MAX {
        return Err(SqErr::SoqlTooLong);
    }
    Ok((name.to_string(), soql.to_string()))
}

/// Nombre de requêtes de CE propriétaire (pour le plafond). Pure -> testable.
fn count_for_owner(conn: &Connection, owner: &str) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM saved_query WHERE owner=?1", params![owner], |r| r.get(0)).unwrap_or(0)
}

/// Liste OWNER-SCOPED : toutes les requêtes de `owner`, jamais d'autrui. Pure -> testable.
fn list_for_owner(conn: &Connection, owner: &str) -> Vec<Value> {
    conn.prepare("SELECT id,name,soql,created,updated FROM saved_query WHERE owner=?1 ORDER BY name COLLATE NOCASE, id")
        .and_then(|mut s| {
            s.query_map(params![owner], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "soql": r.get::<_, String>(2)?,
                    "created": r.get::<_, i64>(3)?,
                    "updated": r.get::<_, i64>(4)?,
                }))
            })
            .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default()
}

/// Création OWNER-SCOPED (plafond appliqué). `owner` posé par le serveur. Pure (hors horloge) -> testable.
fn create(conn: &Connection, owner: &str, name: &str, soql: &str, ts: i64) -> Result<i64, SqErr> {
    let (name, soql) = validate(name, soql)?;
    if count_for_owner(conn, owner) >= SAVED_QUERY_MAX_PER_USER {
        return Err(SqErr::CapReached);
    }
    conn.execute(
        "INSERT INTO saved_query(owner,name,soql,created,updated) VALUES(?1,?2,?3,?4,?4)",
        params![owner, name, soql, ts],
    )
    .map_err(|_| SqErr::Db)?;
    Ok(conn.last_insert_rowid())
}

/// Mise à jour IDOR-SÛRE : `WHERE id=? AND owner=?` -> ne touche JAMAIS la ligne d'un autre propriétaire.
/// 0 ligne affectée (id inexistant OU appartenant à autrui) -> NotFound (aucune fuite d'existence cross-user).
/// Pure (hors horloge) -> testable.
fn update(conn: &Connection, owner: &str, id: i64, name: &str, soql: &str, ts: i64) -> Result<(), SqErr> {
    let (name, soql) = validate(name, soql)?;
    let n = conn
        .execute(
            "UPDATE saved_query SET name=?1, soql=?2, updated=?3 WHERE id=?4 AND owner=?5",
            params![name, soql, ts, id, owner],
        )
        .map_err(|_| SqErr::Db)?;
    if n == 0 {
        return Err(SqErr::NotFound);
    }
    Ok(())
}

/// Suppression IDOR-SÛRE : `WHERE id=? AND owner=?`. 0 ligne -> NotFound. Pure -> testable.
fn delete(conn: &Connection, owner: &str, id: i64) -> Result<(), SqErr> {
    let n = conn
        .execute("DELETE FROM saved_query WHERE id=?1 AND owner=?2", params![id, owner])
        .map_err(|_| SqErr::Db)?;
    if n == 0 {
        return Err(SqErr::NotFound);
    }
    Ok(())
}

/// Mappe une `SqErr` vers une réponse HTTP stable.
fn sq_err_resp(e: SqErr) -> Response {
    match e {
        SqErr::NameEmpty => bad_req("nom requis (non vide)"),
        SqErr::NameTooLong => bad_req("nom trop long (max 200 caractères)"),
        SqErr::SoqlTooLong => err_json(StatusCode::PAYLOAD_TOO_LARGE, "requête trop volumineuse (max 16 KiB)"),
        SqErr::CapReached => err_json(StatusCode::CONFLICT, "limite de requêtes sauvegardées atteinte (max 200)"),
        SqErr::NotFound => not_found("requête sauvegardée introuvable"),
        SqErr::Db => err_json(StatusCode::INTERNAL_SERVER_ERROR, "enregistrement échoué"),
    }
}

/// GET /api/saved-queries — liste MES requêtes (owner = appelant). viewer+, self-scoped.
pub(crate) async fn saved_queries_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    Json(json!({ "queries": list_for_owner(&conn, &au.name) })).into_response()
}

/// POST /api/saved-queries {name, soql} — crée une requête pour L'APPELANT. Audit ledger `saved_query.create`.
pub(crate) async fn saved_query_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let soql = b.get("soql").and_then(|v| v.as_str()).unwrap_or("");
    crate::req_conn!(st, au, conn);
    match create(&conn, &au.name, name, soql, now()) {
        Ok(id) => {
            ledger_append(&conn, "saved_query.create", &format!("#{id} '{}' by {}", name.trim(), au.name));
            Json(json!({ "ok": true, "id": id })).into_response()
        }
        Err(e) => sq_err_resp(e),
    }
}

/// PUT /api/saved-queries/:id {name, soql} — met à jour MA requête (IDOR-sûr). Audit `saved_query.update`.
pub(crate) async fn saved_query_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let soql = b.get("soql").and_then(|v| v.as_str()).unwrap_or("");
    crate::req_conn!(st, au, conn);
    match update(&conn, &au.name, id, name, soql, now()) {
        Ok(()) => {
            ledger_append(&conn, "saved_query.update", &format!("#{id} '{}' by {}", name.trim(), au.name));
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => sq_err_resp(e),
    }
}

/// DELETE /api/saved-queries/:id — supprime MA requête (IDOR-sûr). Audit `saved_query.delete`.
pub(crate) async fn saved_query_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    match delete(&conn, &au.name, id) {
        Ok(()) => {
            ledger_append(&conn, "saved_query.delete", &format!("#{id} by {}", au.name));
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => sq_err_resp(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE saved_query(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, \
             soql TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        conn
    }

    // (a) CRUD roundtrip OWNER-SCOPED : create -> list -> update -> delete, tout sur alice.
    #[test]
    fn crud_roundtrip_owner_scoped() {
        let conn = mem();
        let id = create(&conn, "alice", "  errors last hour  ", "search severity>=4", 100).unwrap();
        let rows = list_for_owner(&conn, "alice");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "errors last hour"); // trimmé
        assert_eq!(rows[0]["soql"], "search severity>=4");
        assert_eq!(rows[0]["created"], 100);
        // update
        update(&conn, "alice", id, "errors", "search severity>=5", 200).unwrap();
        let rows = list_for_owner(&conn, "alice");
        assert_eq!(rows[0]["name"], "errors");
        assert_eq!(rows[0]["soql"], "search severity>=5");
        assert_eq!(rows[0]["updated"], 200);
        assert_eq!(rows[0]["created"], 100); // created NON modifié par l'update
        // delete
        delete(&conn, "alice", id).unwrap();
        assert!(list_for_owner(&conn, "alice").is_empty());
    }

    // (b) IDOR : bob ne peut NI voir, NI update, NI delete la requête d'alice (id seul insuffisant).
    #[test]
    fn idor_blocked_cross_user() {
        let conn = mem();
        let aid = create(&conn, "alice", "a-query", "search source=a", 1).unwrap();
        let _bid = create(&conn, "bob", "b-query", "search source=b", 1).unwrap();
        // LIST : bob ne voit QUE la sienne, jamais celle d'alice.
        let blist = list_for_owner(&conn, "bob");
        assert_eq!(blist.len(), 1);
        assert_eq!(blist[0]["name"], "b-query");
        assert!(list_for_owner(&conn, "bob").iter().all(|q| q["name"] != "a-query"));
        // UPDATE : bob tente de modifier la ligne d'alice par son id -> NotFound, ligne d'alice INTACTE.
        assert_eq!(update(&conn, "bob", aid, "hacked", "search source=evil", 2), Err(SqErr::NotFound));
        let alist = list_for_owner(&conn, "alice");
        assert_eq!(alist[0]["name"], "a-query");
        assert_eq!(alist[0]["soql"], "search source=a"); // NON altéré
        // DELETE : bob tente de supprimer la ligne d'alice -> NotFound, ligne d'alice TOUJOURS là.
        assert_eq!(delete(&conn, "bob", aid), Err(SqErr::NotFound));
        assert_eq!(list_for_owner(&conn, "alice").len(), 1);
    }

    // (c) PLAFOND per-user : au-delà de SAVED_QUERY_MAX_PER_USER -> CapReached (rien de plus persisté).
    #[test]
    fn per_user_cap_enforced() {
        let conn = mem();
        for i in 0..SAVED_QUERY_MAX_PER_USER {
            create(&conn, "alice", &format!("q{i}"), "search *", 1).unwrap();
        }
        assert_eq!(count_for_owner(&conn, "alice"), SAVED_QUERY_MAX_PER_USER);
        assert_eq!(create(&conn, "alice", "one too many", "search *", 1), Err(SqErr::CapReached));
        assert_eq!(count_for_owner(&conn, "alice"), SAVED_QUERY_MAX_PER_USER);
        // le plafond est PAR utilisateur : bob peut toujours créer la sienne.
        assert!(create(&conn, "bob", "bob-q", "search *", 1).is_ok());
    }

    // Validation : nom vide refusé (draft de soql vide autorisé) ; bornes name/soql.
    #[test]
    fn validation_bounds() {
        let conn = mem();
        assert_eq!(create(&conn, "alice", "   ", "search *", 1), Err(SqErr::NameEmpty));
        assert_eq!(create(&conn, "alice", &"x".repeat(SAVED_QUERY_NAME_MAX + 1), "search *", 1), Err(SqErr::NameTooLong));
        assert_eq!(create(&conn, "alice", "big", &"x".repeat(SAVED_QUERY_SOQL_MAX + 1), 1), Err(SqErr::SoqlTooLong));
        // DRAFT : soql VIDE autorisé (on sauve un brouillon, jamais compilé au save).
        assert!(create(&conn, "alice", "draft", "", 1).is_ok());
        assert_eq!(count_for_owner(&conn, "alice"), 1); // seul le draft valide a été persisté
    }

    // MODE 0 : table VIDE tant qu'aucune écriture -> liste vide, aucune ligne SEED par la migration (parité).
    #[test]
    fn empty_by_default_no_seed() {
        let conn = mem();
        assert!(list_for_owner(&conn, "anyone").is_empty());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM saved_query", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }

    // (f) AUDIT : une mutation (create) émet une entrée LEDGER tamper-evident `saved_query.create` — MÊME
    // séquence que le handler (op pure PUIS ledger_append). On monte aussi la table `ledger` (chaîne de hash).
    #[test]
    fn mutation_writes_ledger() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE ledger(id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, detail TEXT, prev_hash TEXT, hash TEXT);",
        )
        .unwrap();
        let id = create(&conn, "alice", "my q", "search *", 1).unwrap();
        ledger_append(&conn, "saved_query.create", &format!("#{id} 'my q' by alice"));
        let (kind, detail): (String, String) = conn
            .query_row("SELECT kind,detail FROM ledger ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(kind, "saved_query.create");
        assert!(detail.contains(&format!("#{id}")) && detail.contains("by alice"));
        // le ledger porte une chaîne de hash non vide (tamper-evident).
        let hash: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        assert!(!hash.is_empty());
    }

    // RBAC : /api/saved-queries = viewer+ self-service (Read même en mutation) ; une route mutante
    // inconnue reste refusée au viewer (fail-closed default-deny=admin).
    #[test]
    fn rbac_saved_queries_is_viewer_self_service() {
        assert!(crate::rbac_gate("viewer", "/api/saved-queries", false).is_ok());
        assert!(crate::rbac_gate("viewer", "/api/saved-queries", true).is_ok());
        assert!(crate::rbac_gate("viewer", "/api/saved-queries/5", true).is_ok());
        assert!(crate::rbac_gate("editor", "/api/saved-queries", true).is_ok());
        // garde-fou : une route mutante inconnue reste refusée au viewer.
        assert!(crate::rbac_gate("viewer", "/api/zzz-unknown", true).is_err());
    }
}
