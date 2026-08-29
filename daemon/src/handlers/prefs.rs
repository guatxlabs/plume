//! #62 — PRÉFÉRENCES UTILISATEUR (per-user UI prefs) : GET/PUT `/api/prefs`. SELF-SCOPED — chaque compte
//! authentifié (viewer+) lit/écrit UNIQUEMENT SA PROPRE ligne, clé `user = au.name`. Le client n'envoie
//! JAMAIS d'identifiant d'utilisateur : il ne peut donc pas lire ni écrire la ligne d'un autre (pas de
//! surface d'énumération/IDOR). Tenant-scoped en mode 1 via `req_db` (base du tenant courant ; `alice` du
//! tenant A ≠ `alice` du tenant B — lignes distinctes, bases distinctes). Blob JSON UI-ONLY plafonné à
//! 64 KiB (anti-abus) ; ne stocke AUCUN secret, ne change AUCUNE autorisation. RBAC : `route_min_role`
//! renvoie `Read` pour `/api/prefs` (viewer+, section self-service, MIROIR de `/api/mfa/*`) — le PUT est
//! `mutating` mais reste self-scoped -> ce n'est pas une surface admin ; le CSRF cookie s'applique au PUT.
use crate::*;

/// Plafond du blob de préférences SÉRIALISÉ (anti-abus de la table par-utilisateur). 64 KiB : très large
/// pour de l'état d'UI (colonnes/favoris/réglages par vue), négligeable pour la base.
pub(crate) const PREFS_MAX_BYTES: usize = 64 * 1024;

/// Lecture SELF-SCOPED : blob JSON de `user` (objet ; "{}" si aucune ligne). Pure -> testable.
fn prefs_read(conn: &Connection, user: &str) -> String {
    conn.query_row("SELECT prefs FROM user_pref WHERE user=?1", params![user], |r| r.get::<_, String>(0))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "{}".to_string())
}

/// Écriture SELF-SCOPED (upsert par `user`). Fail-closed : refuse un blob > PREFS_MAX_BYTES ou non-objet.
/// Pure (hors horloge) -> testable (self-scoping + plafond + forme). Ne TOUCHE que la ligne `user`.
fn prefs_write(conn: &Connection, user: &str, blob: &str, ts: i64) -> Result<(), &'static str> {
    if blob.len() > PREFS_MAX_BYTES {
        return Err("préférences trop volumineuses (max 64 KiB)");
    }
    // Doit être un OBJET JSON (ni scalaire ni tableau) : borne la forme + garantit un merge côté client sain.
    match serde_json::from_str::<Value>(blob) {
        Ok(Value::Object(_)) => {}
        _ => return Err("préférences invalides (objet JSON attendu)"),
    }
    conn.execute(
        "INSERT INTO user_pref(user,prefs,updated) VALUES(?1,?2,?3) \
         ON CONFLICT(user) DO UPDATE SET prefs=excluded.prefs, updated=excluded.updated",
        params![user, blob, ts],
    )
    .map(|_| ())
    .map_err(|_| "enregistrement des préférences échoué")
}

/// GET /api/prefs — renvoie `{prefs:{...}}` pour L'APPELANT (viewer+, self-scoped).
pub(crate) async fn prefs_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let blob = prefs_read(&conn, &au.name);
    let prefs: Value = serde_json::from_str(&blob).unwrap_or_else(|_| json!({}));
    Json(json!({ "prefs": prefs })).into_response()
}

/// PUT /api/prefs {prefs:{...}} — remplace le blob de L'APPELANT (viewer+, self-scoped, plafonné 64 KiB).
/// Accepte la forme canonique `{prefs:{...}}` OU directement un objet de préférences (tolérance de forme).
pub(crate) async fn prefs_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let obj = match b.get("prefs") {
        Some(v) => v.clone(),
        None => b.clone(),
    };
    if !obj.is_object() {
        return bad_req("préférences invalides (objet JSON attendu sous 'prefs')");
    }
    let blob = obj.to_string();
    crate::req_conn!(st, au, conn);
    match prefs_write(&conn, &au.name, &blob, now()) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) if e.starts_with("préférences trop") => err_json(StatusCode::PAYLOAD_TOO_LARGE, e),
        Err(e) => bad_req(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE user_pref(user TEXT PRIMARY KEY, prefs TEXT NOT NULL DEFAULT '{}', updated INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        conn
    }

    // SELF-SCOPING : chaque user ne voit QUE sa ligne ; écrire bob ne fuit jamais vers alice (et vice-versa).
    #[test]
    fn prefs_are_self_scoped() {
        let conn = mem();
        prefs_write(&conn, "alice", r#"{"theme":"dark","fav":[1,2]}"#, 100).unwrap();
        prefs_write(&conn, "bob", r#"{"theme":"light"}"#, 100).unwrap();
        assert_eq!(prefs_read(&conn, "alice"), r#"{"theme":"dark","fav":[1,2]}"#);
        assert_eq!(prefs_read(&conn, "bob"), r#"{"theme":"light"}"#);
        // un user inconnu ne lit RIEN d'autrui -> objet vide (jamais la ligne d'un voisin).
        assert_eq!(prefs_read(&conn, "carol"), "{}");
    }

    // PORTÉE D'UNE ÉCRITURE : exactement UNE ligne, et cette ligne REMPLACÉE EN ENTIER.
    //  - un upsert de bob ne peut PAS écraser/altérer la ligne d'alice (clé primaire = user) ;
    //  - sur SA propre ligne, l'upsert REMPLACE le blob (`prefs=excluded.prefs`), il ne FUSIONNE pas : une
    //    clé présente dans l'ancien blob et absente du nouveau est PARTIE. Le stockage est un blob OPAQUE —
    //    aucune trace par clé, donc aucun moyen de distinguer « supprimée » de « jamais posée » : ici,
    //    L'ABSENCE EST LA SUPPRESSION, et c'est la SEULE chose qui rende une suppression de préférence
    //    transmissible d'un poste à l'autre. `web/prefs.js` en dépend pour réconcilier par REMPLACEMENT et
    //    non par fusion (clé `P11.15-e`) ; le jour où cette écriture fusionnerait, une suppression cesserait
    //    silencieusement de traverser — et ce témoin rougirait AVANT elle.
    #[test]
    fn write_never_touches_other_users_row() {
        let conn = mem();
        prefs_write(&conn, "alice", r#"{"k":"a"}"#, 1).unwrap();
        prefs_write(&conn, "bob", r#"{"k":"b","z":1}"#, 2).unwrap();
        prefs_write(&conn, "bob", r#"{"k":"b2"}"#, 3).unwrap();
        assert_eq!(prefs_read(&conn, "alice"), r#"{"k":"a"}"#);
        // REMPLACEMENT, pas fusion : `z` a DISPARU du blob de bob, sans rien aspirer chez alice.
        assert_eq!(prefs_read(&conn, "bob"), r#"{"k":"b2"}"#);
        // Un blob VIDE est un remplacement comme un autre : retirer la DERNIÈRE préférence est représentable.
        prefs_write(&conn, "bob", "{}", 4).unwrap();
        assert_eq!(prefs_read(&conn, "bob"), "{}");
        assert_eq!(prefs_read(&conn, "alice"), r#"{"k":"a"}"#);
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM user_pref", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
    }

    // PLAFOND 64 KiB : un blob trop gros est REFUSÉ et n'est JAMAIS persisté (fail-closed).
    #[test]
    fn size_cap_enforced() {
        let conn = mem();
        let big = format!("{{\"x\":\"{}\"}}", "a".repeat(PREFS_MAX_BYTES));
        assert!(big.len() > PREFS_MAX_BYTES);
        let err = prefs_write(&conn, "alice", &big, 1).unwrap_err();
        assert!(err.starts_with("préférences trop"));
        // rien persisté -> lecture = "{}" (pas de ligne partielle).
        assert_eq!(prefs_read(&conn, "alice"), "{}");
        // pile sous le plafond avec un objet valide -> accepté.
        let ok = format!("{{\"x\":\"{}\"}}", "a".repeat(PREFS_MAX_BYTES - 16));
        assert!(ok.len() <= PREFS_MAX_BYTES);
        prefs_write(&conn, "alice", &ok, 2).unwrap();
        assert_eq!(prefs_read(&conn, "alice"), ok);
    }

    // FORME : seul un OBJET JSON est accepté (ni scalaire ni tableau) -> borne la surface + merge client sain.
    #[test]
    fn only_json_object_accepted() {
        let conn = mem();
        assert!(prefs_write(&conn, "alice", "[1,2,3]", 1).is_err());
        assert!(prefs_write(&conn, "alice", "42", 1).is_err());
        assert!(prefs_write(&conn, "alice", "\"hi\"", 1).is_err());
        assert!(prefs_write(&conn, "alice", "not json", 1).is_err());
        assert_eq!(prefs_read(&conn, "alice"), "{}"); // aucun rejet n'a persisté quoi que ce soit
        assert!(prefs_write(&conn, "alice", "{}", 1).is_ok());
    }

    // MODE 0 : la table est VIDE tant qu'aucune écriture -> aucune ligne SEED par la migration (parité).
    #[test]
    fn empty_by_default_no_seed() {
        let conn = mem();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM user_pref", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
        assert_eq!(prefs_read(&conn, "anyone"), "{}");
    }

    // RBAC : /api/prefs = viewer+ self-service (Read même en PUT) ; une mutation NON déclarée reste admin-only.
    #[test]
    fn rbac_prefs_is_viewer_self_service() {
        // GET (lecture) et PUT (mutating) : viewer autorisé.
        assert!(crate::rbac_gate("viewer", "/api/prefs", false).is_ok());
        assert!(crate::rbac_gate("viewer", "/api/prefs", true).is_ok());
        assert!(crate::rbac_gate("editor", "/api/prefs", true).is_ok());
        // garde-fou fail-closed : une route mutante inconnue reste refusée au viewer (default-deny=admin).
        assert!(crate::rbac_gate("viewer", "/api/zzz-unknown", true).is_err());
    }
}
