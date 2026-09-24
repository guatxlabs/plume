//! Comptes utilisateurs (réservé admin) et tables de correspondance (lookups) : CRUD utilisateurs
//! (`users_list`/`user_create`/`user_delete`/`user_update`) et lookups (`value_to_lookup_str`/
//! `build_lookup_kv`, `lookups_list`/`lookup_upload`/`lookup_delete`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- comptes utilisateurs (réservé admin via auth_guard) ----------
pub(crate) async fn users_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 1) — « QUI A ACCÈS » EST LU ENTIÈREMENT OU AVOUÉ. Avant : deux `unwrap()` (une
    // panique n'est pas un aveu) puis `rows.flatten()` — un compte dont la ligne ne se décode pas
    // disparaissait de la liste que l'AUDIT lit, sans un mot. Soldé en bloc ; sur échec, la liste n'est
    // pas ÉTABLIE et le corps le dit par `error`, au lieu d'un inventaire d'accès rassurant.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,role,created FROM user ORDER BY id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                    "role": r.get::<_, String>(2)?, "created": r.get::<_, i64>(3)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    // P11.5-c — QUI A ACCÈS. `user` ne porte QUE les comptes que le produit crée : un compte d'annuaire
    // externe (SSO d'en-têtes) accède sans jamais y avoir de ligne. `acces` est l'inventaire de CEUX QUI
    // ACCÈDENT, quelle que soit leur provenance, consigné au choke-point d'authentification. Rendu À CÔTÉ
    // de `users` (jamais fondu dedans) : `users` reste la liste GÉRABLE ici (créer/éditer/supprimer),
    // `acces` est un CONSTAT, y compris pour des comptes que cette console ne peut pas administrer.
    // Aucun secret n'y figure — cf. `acces_observe`, la table n'en porte aucun.
    let acces = crate::acces_observe::inventaire_des_acces(&conn);
    match lues {
        Ok(locaux) => Json(json!({ "users": locaux, "me": au.name, "acces": acces })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
            json!({ "me": au.name, "acces": acces }),
            "users",
        )),
    }
}

pub(crate) async fn user_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let pw = b.str_field("password");
    let role = match b.get("role").and_then(|v| v.as_str()) {
        Some("admin") => "admin",
        Some("viewer") => "viewer",
        _ => "editor",
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return (StatusCode::BAD_REQUEST, "nom invalide (alphanumérique, . _ - uniquement)").into_response();
    }
    // MODE ENGAGEMENT : le préfixe `eng-cred-` est RÉSERVÉ aux credentials mintés par le provisioning
    // d'engagement (compte scopé + hard-expiry). L'interdire à la création interactive garantit qu'aucun
    // compte durable ne peut usurper ce discriminant du chemin d'auth (hard-expiry + no-cache).
    if name.starts_with(ENG_CRED_PREFIX) {
        return (StatusCode::BAD_REQUEST, "préfixe 'eng-cred-' réservé aux credentials d'engagement").into_response();
    }
    // POLITIQUE MDP (item 3) — à la CRÉATION du compte uniquement (les comptes existants intacts).
    if pw.chars().count() < PASSWORD_MIN_CHARS {
        return (StatusCode::BAD_REQUEST, format!("mot de passe trop court (≥ {PASSWORD_MIN_CHARS} caractères)")).into_response();
    }
    let hash = hash_pw(pw);
    crate::req_conn!(st, au, conn);
    // AUDIT D'IDENTITÉ : création de compte = mutation d'IDENTITÉ -> AUDIT fail-closed DANS la transaction (patron
    // audit_config_change des lookups/notifiers). Sans trace, un admin compromis plante une persistance
    // (nouvel admin) invisible. Le hash n'est JAMAIS mis dans l'audit — seuls actor/target/rôle. Créer un
    // ADMIN = sévérité 4 (HIGH, alertable) ; editor/viewer = 3.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let sev = if role == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![name, hash, role])?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.user.create",
            &format!("compte '{name}' (rôle {role}) créé par {}", au.name), sev,
            &format!("compte utilisateur '{name}' créé (rôle {role}) par {}", au.name),
            &json!({ "action": "config.user.create", "kind": "user", "target": name, "role": role, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id })).into_response() }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            // distinguer un conflit de nom (UNIQUE) d'un vrai échec d'audit — même sémantique 409 qu'avant.
            let es = e.to_string();
            if es.contains("UNIQUE") || es.contains("constraint") {
                (StatusCode::CONFLICT, "ce nom de compte existe déjà").into_response()
            } else {
                server_err(format!("échec transaction audit (aucune modification): {e}"))
            }
        }
    }
}

pub(crate) async fn user_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let target: Option<(String, String)> = conn
        .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let Some((tname, trole)) = target else {
        return (StatusCode::NOT_FOUND, "compte introuvable").into_response();
    };
    if tname == au.name {
        return (StatusCode::BAD_REQUEST, "impossible de supprimer son propre compte").into_response();
    }
    if trole == "admin" {
        let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
        if admins <= 1 {
            return (StatusCode::BAD_REQUEST, "dernier administrateur — suppression refusée").into_response();
        }
    }
    // AUDIT D'IDENTITÉ : suppression de compte = mutation d'identité -> AUDIT fail-closed transactionnel. Supprimer un
    // ADMIN = sévérité 4. Rien n'est purgé sans trace (source=plume-config, non-purgeable).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let sev = if trole == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM user WHERE id=?1", params![id])?;
        // `P10.24-c` — CE QUI EST LIÉ AU NOM PART AVEC LE COMPTE, ET SES JETONS AVEC LUI. Mesuré le 2026-09-24 sur la
        // forme d'avant : après cette suppression puis la création d'un homonyme, la session frappée AVANT résolvait
        // l'identité du NOUVEAU compte (son époque, restée à zéro, était celle du jeton), le ticket MFA d'avant
        // ouvrait une session avec un code de l'ANCIENNE graine, et la connexion du nouveau titulaire était arrêtée
        // au second facteur de l'ancien — `user_mfa` et `user_pref` survivaient. L'époque du compte AVANCE (sa clé
        // `meta` survit à la ligne : un homonyme repart au-delà de tout jeton frappé pour l'ancien), la graine et les
        // codes de secours sont retirés, les préférences aussi — DANS cette transaction : pas de compte supprimé dont
        // les jetons vaudraient encore pour son homonyme, ni de purge sans suppression.
        let seconds_facteurs_retires = conn.execute("DELETE FROM user_mfa WHERE user=?1", params![tname])?;
        conn.execute("DELETE FROM user_pref WHERE user=?1", params![tname])?;
        avancer_l_epoque_du_compte(&conn, &tname)?;
        audit_config_change(
            &conn, "config.user.delete",
            &format!("compte '{tname}' (rôle {trole}) supprimé par {}", au.name), sev,
            &format!("compte utilisateur '{tname}' supprimé (rôle {trole}) par {}", au.name),
            &json!({
                "action": "config.user.delete", "kind": "user", "target": tname, "role": trole, "actor": au.name,
                "second_facteur_retire": seconds_facteurs_retires > 0,
            })
            .to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            st.auth_cache.lock().clear(); // invalide les creds en cache du compte supprimé
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// MAJ d'un compte (admin only via auth_guard) : rôle et/ou reset du mot de passe.
//
// `P10.24-a` — SON PROPRE MOT DE PASSE SE CHANGE PAR LE MOT DE PASSE ACTUEL, PAS PAR LA SESSION. Mesuré le 2026-09-24
// sur la forme d'avant : sous la seule session de `adm`, `{password}` sur son propre identifiant rendait 204, et
// `{password, current: <faux>}` aussi (`current` n'était pas lu) — la prise de compte que `P10.23-m` a fermée sur
// `/api/password` restait ouverte ici, et le titulaire, dont les sessions tombent avec le changement, était mis
// dehors. Quand la cible EST l'appelant et que le corps change le mot de passe, `current` est jugé par le jugement
// partagé avec `/api/password` (`juger_le_mot_de_passe_actuel`) : même preuve, même verrou (compte, adresse) que la
// connexion, mêmes refus nommés. Un compte SANS mot de passe local (fédéré) ne s'en pose pas un sur la foi de sa
// session — une session fédérée volée devenait sinon un mot de passe local, hors de portée de l'annuaire qui la
// révoque ; un AUTRE administrateur peut le poser.
//
// LE GESTE D'ADMINISTRATION SUR UN AUTRE COMPTE RESTE, SANS LE MOT DE PASSE DE SON AUTEUR. C'est son objet : le
// titulaire a oublié le sien, ou il faut lui retirer l'accès. Ce qui le borne : il est attesté au registre et au SIEM
// sous le nom de son auteur (sévérité 4, alertable, règle d'auto-détection des mutations d'identité), et le compte
// VISÉ perd ses sessions et ses tickets (`P10.23-l`). Le mot de passe de l'AUTEUR n'y est pas exigé : un
// administrateur servi par un SSO d'en-têtes n'en a pas, et la même persistance s'obtient par d'autres gestes
// d'administration (créer ou promouvoir un administrateur, frapper un jeton) — une preuve récente se décide pour eux
// tous à la fois, pas pour l'un d'eux.
pub(crate) async fn user_update(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Extension(au): Extension<AuthUser>,
    Path(id): Path<i64>,
    Json(b): Json<Value>,
) -> Response {
    let new_pw = b.get("password").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
    let new_role = b.get("role").and_then(|v| v.as_str());
    // LECTURE ET VALIDATION sous le verrou de la base, RELÂCHÉ avant la preuve : en mode 0 la base de la requête est
    // celle que la preuve relit (`prouver_le_premier_facteur` la verrouille à son tour).
    let (tname, trole, role_change) = {
        crate::req_conn!(st, au, conn);
        let target: Option<(String, String)> = conn
            .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok();
        let Some((tname, trole)) = target else { return (StatusCode::NOT_FOUND, "compte introuvable").into_response(); };
        // VALIDATION AVANT toute écriture (rôle valide, anti-lockout, longueur mdp) — inchangé, mais hors transaction.
        let role_change: Option<&str> = if let Some(nr) = new_role {
            let role = match nr { "admin" => "admin", "editor" => "editor", "viewer" => "viewer", _ => return (StatusCode::BAD_REQUEST, "rôle invalide (admin|editor|viewer)").into_response() };
            // anti-lockout : ne pas rétrograder le DERNIER admin
            if trole == "admin" && role != "admin" {
                let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
                if admins <= 1 { return (StatusCode::BAD_REQUEST, "dernier administrateur — rétrogradation refusée").into_response(); }
            }
            Some(role)
        } else { None };
        if let Some(pw) = new_pw {
            if pw.chars().count() < PASSWORD_MIN_CHARS { return (StatusCode::BAD_REQUEST, format!("mot de passe trop court (≥ {PASSWORD_MIN_CHARS} caractères)")).into_response(); } // POLITIQUE MDP (item 3) — reset admin uniquement
        }
        (tname, trole, role_change)
    };
    // `P10.24-a` — jugé APRÈS la validation, comme `/api/password` : un corps irrecevable n'engage aucun essai du mot
    // de passe actuel. Un refus n'écrit RIEN, pas même le rôle demandé dans le même corps.
    let son_propre_compte = tname == au.name;
    if new_pw.is_some() && son_propre_compte {
        if let Err(refus) = juger_le_mot_de_passe_actuel(
            &st,
            &tname,
            &peer.ip().to_string(),
            b.str_field("current"),
            CAUSE_SON_PROPRE_COMPTE_SANS_MOT_DE_PASSE_LOCAL,
            &format!("réinitialisation du mot de passe de son propre compte '{tname}' refusée : mot de passe actuel refusé"),
        ) {
            return refus;
        }
    }
    crate::req_conn!(st, au, conn);
    // AUDIT D'IDENTITÉ : changement de rôle ET/OU reset mdp = mutations d'identité -> AUDIT fail-closed transactionnel
    // (un audit PAR type de changement : role_change / password_reset). Un reset mdp ou une escalade vers admin
    // = sévérité 4 (HIGH, alertable). Le nouveau hash n'est JAMAIS mis dans l'audit.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    // `P10.24-a` — le verrou relâché pour la preuve, les écritures visent le compte LU ET JUGÉ (identifiant ET nom) :
    // un identifiant réattribué entre-temps ne reçoit pas un mot de passe prouvé pour un autre compte.
    let une_ligne = |ecrites: usize| if ecrites == 1 { Ok(()) } else { Err(rusqlite::Error::StatementChangedRows(ecrites)) };
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(role) = role_change {
            une_ligne(conn.execute("UPDATE user SET role=?1 WHERE id=?2 AND name=?3", params![role, id, tname])?)?;
            let sev = if role == "admin" || trole == "admin" { 4 } else { 3 };
            audit_config_change(
                &conn, "config.user.role_change",
                &format!("compte '{tname}' : rôle {trole} -> {role} par {}", au.name), sev,
                &format!("rôle du compte '{tname}' modifié ({trole} -> {role}) par {}", au.name),
                &json!({ "action": "config.user.role_change", "kind": "user", "target": tname, "from": trole, "to": role, "actor": au.name }).to_string(),
            )?;
        }
        if let Some(pw) = new_pw {
            une_ligne(conn.execute("UPDATE user SET hash=?1 WHERE id=?2 AND name=?3", params![hash_pw(pw), id, tname])?)?;
            // `P10.23-l` — LA RÉINITIALISATION RÉVOQUE LES SESSIONS ET LES TICKETS MFA DU SEUL COMPTE RÉINITIALISÉ.
            // Mesuré le 2026-09-24 sur la forme d'avant : après ce 204, la session d'avant du compte résolvait
            // encore son identité, et un ticket MFA émis avant ouvrait encore une session — l'époque de session est
            // GLOBALE et ce chemin ne la touchait pas (l'avancer déconnecterait tous les comptes). L'époque du
            // COMPTE avance DANS cette transaction : pas de mot de passe réinitialisé sans ses jetons d'avant
            // révoqués, ni l'inverse.
            avancer_l_epoque_du_compte(&conn, &tname)?;
            // `P10.24-a` — l'attestation dit si c'est le titulaire (mot de passe actuel prouvé) ou un autre.
            let par_qui = if son_propre_compte { " (son propre compte, mot de passe actuel prouvé)" } else { "" };
            audit_config_change(
                &conn, "config.user.password_reset",
                &format!("mot de passe du compte '{tname}' réinitialisé par {}{par_qui}", au.name), 4,
                &format!("mot de passe du compte '{tname}' (rôle {trole}) réinitialisé par {}{par_qui}", au.name),
                &json!({
                    "action": "config.user.password_reset", "kind": "user", "target": tname, "actor": au.name,
                    "mot_de_passe_actuel_prouve": son_propre_compte,
                })
                .to_string(),
            )?;
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            st.auth_cache.lock().clear(); // invalide le cache d'auth (rôle/mdp changés)
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// ---------- LOOKUP : tables d'enrichissement (admin only via auth_guard) ----------
// NOYAU FONCTIONNEL : table + endpoint admin minimal + op GXQL `lookup`. L'UI de GESTION (formulaire
// d'upload CSV/JSON, édition, aperçu) est un SUIVI ULTÉRIEUR — ici seul l'endpoint REST est exposé.

/// Convertit une valeur JSON scalaire en chaîne exploitable comme clé/valeur de lookup. String -> telle
/// quelle ; nombre/bool -> représentation textuelle ; null/objet/array -> None (clé inexploitable).
pub(crate) fn value_to_lookup_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Transforme les lignes d'upload `[{...}]` en paires (key, val_json) + l'ensemble ordonné des colonnes
/// de sortie. PURE (testable sans DB). Pour chaque ligne : la valeur de `key_field` devient la CLÉ ;
/// les AUTRES paires (clé passant `soql_ident_ok`, donc requêtable via json_extract) sont sérialisées
/// dans `val`. Lignes sans clé exploitable -> ignorées. `val` est TOUJOURS du JSON valide par
/// construction (un `val` malformé ne peut donc pas naître de l'API ; le compilo garde de toute façon
/// `json_valid` en lecture).
pub(crate) fn build_lookup_kv(key_field: &str, rows: &[Value]) -> (Vec<(String, String)>, Vec<String>) {
    let mut out_cols: Vec<String> = Vec::new();
    let mut kv: Vec<(String, String)> = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        let key = match obj.get(key_field).and_then(value_to_lookup_str) {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };
        let mut val = serde_json::Map::new();
        for (k, v) in obj {
            if k == key_field || !soql_ident_ok(k) {
                continue;
            }
            if !out_cols.iter().any(|c| c == k) {
                out_cols.push(k.clone());
            }
            val.insert(k.clone(), v.clone());
        }
        kv.push((key, Value::Object(val).to_string()));
    }
    (kv, out_cols)
}

/// GET /api/lookups -> liste des lookups déclarés (depuis lookup_meta) + nombre de lignes par lookup.
pub(crate) async fn lookups_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — L'INVENTAIRE DES LOOKUPS EST ENTIER OU AVOUÉ. Avant : DEUX `unwrap()`
    // (une table `lookup_meta` retirée PANIQUAIT — une panique n'est pas un aveu) puis
    // `rows.flatten().collect::<Vec<_>>()`, qui jetait la ligne dont le mappeur échoue (`name` corrompu,
    // colonne de migration que la connexion qui sert ne voit pas encore) et servait le reste comme une
    // liste complète. Un lookup absent d'ici se lit « ce lookup n'existe pas », et c'est la conclusion la
    // plus trompeuse du rang : la commande `lookup <nom> …` de GXQL CONTINUE de fonctionner sur lui (elle
    // lit `lookup_kv`, pas cette vue), donc un enrichissement qu'on croit absent est en réalité
    // INVISIBLE — on le recharge par un upload qui REMPLACE intégralement son contenu, et l'ancien est
    // perdu pour de bon. Même forme d'aveu que `users_list` dans ce fichier
    // (`liste_bornee::corps_de_liste_illisible` : `lookups` présente et VIDE, `error` nomme la cause).
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT m.name, m.key_field, m.cols, m.updated, \
             (SELECT COUNT(*) FROM lookup_kv k WHERE k.name=m.name) \
             FROM lookup_meta m ORDER BY m.name",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "name": r.get::<_, String>(0)?,
                    "key_field": r.get::<_, Option<String>>(1)?,
                    "cols": r.get::<_, Option<String>>(2)?,
                    "updated": r.get::<_, Option<i64>>(3)?,
                    "rows": r.get::<_, i64>(4)?,
                    // D12 — origine du contenu (badge managed, cohérent avec rule/parser/playbook). Les lookups
                    // n'ont ni seed builtin ni overlay config.d : tout lookup est créé via l'UI/API => 2 (perso).
                    "managed": 2,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(rows) => Json(json!({ "lookups": rows })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "lookups")),
    }
}

/// POST /api/lookups {name, key_field, rows:[{...}]} -> REMPLACE intégralement le contenu du lookup
/// `name` (UPSERT, val = JSON des colonnes hors `key_field`). Valide name/key_field via soql_ident_ok.
pub(crate) async fn lookup_upload(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let key_field = b.trimmed("key_field");
    // #1c garde-fou #1 (lookup) : nom + champ-clé au format identifiant GXQL (soql_ident_ok), rows = tableau.
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide (alphanumérique + _)");
    }
    if !soql_ident_ok(&key_field) {
        return bad_req("champ-clé invalide (alphanumérique + _)");
    }
    let Some(rows) = b.get("rows").and_then(|v| v.as_array()) else {
        return bad_req("champ 'rows' (tableau d'objets) requis");
    };
    let (kv, out_cols) = build_lookup_kv(&key_field, rows);
    crate::req_conn!(st, au, conn);
    // #1c garde-fou #6 : remplacement ATOMIQUE fail-closed + audit #1b (ledger + event plume-config). Si un
    // write ou l'audit échoue -> ROLLBACK (aucun remplacement partiel, aucune mutation sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        {
            let mut ins = conn.prepare("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES(?1,?2,?3)")?;
            for (k, v) in &kv {
                ins.execute(params![name, k, v])?;
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO lookup_meta(name,key_field,cols,updated) VALUES(?1,?2,?3,?4)",
            params![name, key_field, out_cols.join(","), now()],
        )?;
        audit_config_change(
            &conn, "config.lookup.upload",
            &format!("lookup '{name}' ({} lignes) chargé par {}", kv.len(), au.name), 2,
            &format!("table d'enrichissement '{name}' remplacée ({} lignes) par {}", kv.len(), au.name),
            &json!({ "op": "upload", "kind": "lookup", "name": name, "rows": kv.len(), "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "name": name, "rows": kv.len(), "cols": out_cols })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

/// DELETE /api/lookups/{name} -> supprime le lookup (lignes kv + métadonnées). #1c : audit fail-closed.
pub(crate) async fn lookup_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide");
    }
    crate::req_conn!(st, au, conn);
    // existe ? (pour renvoyer 404 sans ouvrir de transaction inutile)
    if conn.query_row("SELECT 1 FROM lookup_meta WHERE name=?1", params![name], |_| Ok(())).is_err() {
        return not_found("lookup introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        conn.execute("DELETE FROM lookup_meta WHERE name=?1", params![name])?;
        audit_config_change(
            &conn, "config.lookup.delete",
            &format!("lookup '{name}' supprimé par {}", au.name), 3,
            &format!("table d'enrichissement '{name}' supprimée par {}", au.name),
            &json!({ "op": "delete", "kind": "lookup", "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true, "deleted": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
