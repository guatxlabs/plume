//! #46 — CRUD des KNOWLEDGE OBJECTS (tables `knowledge_alias`/`knowledge_calc`/`knowledge_eventtype`/
//! `knowledge_tag`). CRUD = editor+ (route_min_role : `/api/knowledge` -> Write ; ils façonnent la recherche
//! de TOUT LE MONDE, comme les règles de détection). GET (liste) = viewer+ (transparence de la politique).
//! Chaque mutation VALIDE l'objet (idents allowlistés ; expr de calc compilée via `eval` ; filtre d'eventtype
//! compilé via GXQL) AVANT écriture (fail-closed : objet invalide REFUSÉ en 400, jamais persisté), écrit sous
//! transaction auditée, puis `knowledge_reload` recompile le `KnowledgeSet` de CE db_path -> auto-appliqué à
//! la compilation GXQL suivante (Explore, panels, règles, export en héritent).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};


/// GET /api/knowledge — les 4 familles d'objets de savoir (viewer+). Rend la politique LISIBLE.
///
/// `P10.7-f` (rang 4) — LES SIX FAMILLES SONT ENTIÈRES OU AVOUÉES, ET L'AVEU NOMME LAQUELLE. Avant : SIX
/// `.map(|rows| rows.flatten().collect()).unwrap_or_default()` dans la MÊME fonction, tous coulant dans
/// un seul corps. Un objet de savoir avalé — parce que le cache de schéma du pool rend « no such table »
/// au PREMIER pas (`flatten-avale-no-such-table-au-premier-pas`), parce qu'une migration a ajouté une
/// colonne que la connexion qui sert ne voit pas encore, parce qu'une expression est corrompue — sortait
/// de la liste sans un mot. C'est la page où l'on VÉRIFIE la politique : un alias absent s'y lit « ce
/// champ n'est pas renommé » alors qu'il l'est pour TOUTE recherche du produit, un eventtype absent
/// « cette catégorie n'existe pas », une macro absente « ce raccourci est libre » — et on en réécrit un
/// second, qui entrera en conflit à l'insertion. Chaque lecture est soldée en bloc ; celles qui échouent
/// sont NOMMÉES (`non_lus`) et leur clé reste présente et VIDE, les autres restent servies. Un `error`
/// global qui ne dirait pas LAQUELLE ne couvrirait rien : cinq familles honnêtes seraient suspectées
/// avec la sixième.
pub(crate) async fn knowledge_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let mut non_lus: Vec<&'static str> = Vec::new();
    // Une lecture ratée ne se traduit PAS en liste vide : elle entre dans `non_lus` et la clé de la
    // famille reste vide — c'est `corps_de_listes_illisibles` qui pose l'aveu, une seule fois.
    let mut servie = |nom: &'static str, lue: rusqlite::Result<Vec<Value>>| -> Vec<Value> {
        match lue {
            Ok(v) => v,
            Err(_) => {
                non_lus.push(nom);
                Vec::new()
            }
        }
    };
    let aliases = servie("aliases", conn
        .prepare("SELECT id,canonical,source,enabled,managed,created,updated FROM knowledge_alias ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "canonical": r.get::<_,String>(1)?, "source": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "managed": r.get::<_,i64>(4)?, "created": r.get::<_,i64>(5)?, "updated": r.get::<_,i64>(6)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    let calcs = servie("calcs", conn
        .prepare("SELECT id,name,expr,enabled,ord,managed,created,updated FROM knowledge_calc ORDER BY ord, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "expr": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "ord": r.get::<_,i64>(4)?, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    let eventtypes = servie("eventtypes", conn
        .prepare("SELECT id,name,filter,enabled,managed,created,updated FROM knowledge_eventtype ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "filter": r.get::<_,String>(2)?,
                    "enabled": r.get::<_,i64>(3)? != 0, "managed": r.get::<_,i64>(4)?, "created": r.get::<_,i64>(5)?, "updated": r.get::<_,i64>(6)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    let tags = servie("tags", conn
        .prepare("SELECT id,label,field,value,enabled,managed,created,updated FROM knowledge_tag ORDER BY label, id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "label": r.get::<_,String>(1)?, "field": r.get::<_,String>(2)?, "value": r.get::<_,String>(3)?,
                    "enabled": r.get::<_,i64>(4)? != 0, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    // #60 — MACROS + AUTO-LOOKUPS. LE REPLI « base pré-v97 » EST CONSERVÉ MAIS IL N'EST PLUS MUET : une
    // table absente reste une lecture qui n'a pas eu lieu, et le corps le dit au lieu de servir `[]`.
    let macros = servie("macros", conn
        .prepare("SELECT id,name,params,body,enabled,managed,created,updated FROM macro_def ORDER BY name")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "params": r.get::<_,String>(2)?, "body": r.get::<_,String>(3)?,
                    "enabled": r.get::<_,i64>(4)? != 0, "managed": r.get::<_,i64>(5)?, "created": r.get::<_,i64>(6)?, "updated": r.get::<_,i64>(7)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    let auto_lookups = servie("auto_lookups", conn
        .prepare("SELECT id,name,key_field,out_cols,kind,enabled,managed,created,updated FROM auto_lookup ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "key_field": r.get::<_,String>(2)?, "out_cols": r.get::<_,String>(3)?,
                    "kind": r.get::<_,String>(4)?, "enabled": r.get::<_,i64>(5)? != 0, "managed": r.get::<_,i64>(6)?, "created": r.get::<_,i64>(7)?, "updated": r.get::<_,i64>(8)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        }));
    let corps = json!({ "aliases": aliases, "calcs": calcs, "eventtypes": eventtypes, "tags": tags,
        "macros": macros, "auto_lookups": auto_lookups });
    Json(crate::handlers::liste_bornee::corps_de_listes_illisibles(corps, &non_lus)).into_response()
}

// `P10.25-g` — LE `COMMIT` DES OBJETS DE SAVOIR EST JUGÉ, une fois, dans le squelette commun. MESURÉ sur la forme d'avant
// (témoins `cjds_`) : 200, transaction laissée ouverte, l'objet visible pour ce processus et absent à froid. LU : la
// compilation des requêtes était rechargée ensuite depuis cet état pendant ; elle ne l'est plus qu'après la validation.
/// `P10.25-g` — objet de savoir non écrit : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_OBJET_DE_SAVOIR_NON_ECRIT: &str = "OBJET DE SAVOIR NON ÉCRIT : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — rien n'est créé ni supprimé, les recherches appliquent toujours \
     les alias, calculs, types d'événement, étiquettes, macros et recherches automatiques d'avant, et aucune trace \
     n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE: &str = "OBJET DE SAVOIR NON ÉCRIT : la \
     base n'a pas pris la transaction de ce geste (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : rien n'est créé ni supprimé, les recherches appliquent toujours \
     les alias, calculs, types d'événement, étiquettes, macros et recherches automatiques d'avant, et aucune trace \
     n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// Émet la réponse d'un create/delete audité + `knowledge_reload`. Factorise le squelette transactionnel.
///
/// `P10.27-x` — LE CORPS DU SUCCÈS SE CONSTRUIT SUR L'IDENTIFIANT QUE LA FERMETURE A RENDU, lu au pied de l'`INSERT`
/// de l'objet, jamais sur un second `conn.last_insert_rowid()` : la forme d'avant le relisait APRÈS l'audit et servait
/// le numéro de l'ÉVÉNEMENT de configuration. MESURÉ le 2026-09-25 (témoins `isdl_`, un événement déjà ingéré) : les
/// six créations servaient ce numéro ; l'alias d'Alice était servi avec l'identifiant de l'alias de Bob, et la
/// suppression de « son » alias par cet identifiant retirait celui de Bob (200) ; lu, non mesuré : le registre
/// recompilé ensuite n'appliquait plus l'alias de Bob à aucune recherche du produit.
fn ko_commit(st: &AppState, au: &AuthUser, conn: &Connection, outcome: rusqlite::Result<i64>, corps_du_succes: impl FnOnce(i64) -> Value) -> Response {
    match outcome {
        Ok(id) => rendre_apres_validation(conn, "knowledge", "écriture d'un objet de savoir", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT, || {
            let dbp = req_db_path(st, au);
            knowledge_reload(conn, dbp.as_str());
            knowledge_activate(dbp.as_str()); // CRUD sur le tenant courant -> réactive la compilation
            Json(corps_du_succes(id)).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") {
                return bad_req("un objet de savoir porte déjà ce nom");
            }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 1) ALIAS de champ : canonical -> source
// ---------------------------------------------------------------------------------------------
pub(crate) async fn alias_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let canonical = match validate_ko_ident(b.str_field("canonical")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let source = match validate_ko_ident(b.str_field("source")) { Ok(f) => f, Err(e) => return bad_req(e) };
    if canonical == source { return bad_req("alias : canonical et source doivent différer"); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'un alias de champ", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_alias(canonical,source,enabled,created,updated) VALUES(?1,?2,?3,?4,?4)",
            params![canonical, source, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.alias.create",
            &format!("alias '{canonical}' -> '{source}' (#{id}) par {}", au.name), 2,
            &format!("alias '{canonical}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_alias", "id":id, "canonical":canonical, "source":source, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn alias_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let canonical = match conn.query_row("SELECT canonical FROM knowledge_alias WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("alias introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression de l'alias #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_alias WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.alias.delete",
            &format!("alias '{canonical}' (#{id}) supprimé par {}", au.name), 2,
            &format!("alias '{canonical}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_alias", "id":id, "canonical":canonical, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 2) CHAMPS CALCULÉS : name = <expr eval>
// ---------------------------------------------------------------------------------------------
pub(crate) async fn calc_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let expr = b.str_field("expr").trim().to_string();
    if expr.is_empty() { return bad_req("calc : expression requise"); }
    // Compile-check via le chemin `eval` (injection-safe) AVANT persistance (fail-closed).
    if let Err(e) = validate_calc_expr(&name, &expr) { return bad_req(format!("expression de calc invalide : {e}")); }
    let ord = b.get("ord").and_then(|v| v.as_i64()).unwrap_or(0);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'un champ calculé", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_calc(name,expr,enabled,ord,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![name, expr, enabled, ord, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.calc.create",
            &format!("champ calculé '{name}' (#{id}) par {}", au.name), 2,
            &format!("champ calculé '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_calc", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn calc_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM knowledge_calc WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("champ calculé introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression du champ calculé #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_calc WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.calc.delete",
            &format!("champ calculé '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("champ calculé '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_calc", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 3) EVENT TYPES : name + filtre GXQL
// ---------------------------------------------------------------------------------------------
pub(crate) async fn eventtype_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let filter = b.str_field("filter").trim().to_string();
    if filter.is_empty() { return bad_req("eventtype : filtre requis"); }
    // Compile-check du filtre via `eventtype=<name>` -> chemin GXQL normal (allowlist/échappement) AVANT persistance.
    if let Err(e) = validate_eventtype_filter(&name, &filter) { return bad_req(format!("filtre d'eventtype invalide : {e}")); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'un type d'événement", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_eventtype(name,filter,enabled,created,updated) VALUES(?1,?2,?3,?4,?4)",
            params![name, filter, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.eventtype.create",
            &format!("eventtype '{name}' (#{id}) par {}", au.name), 2,
            &format!("eventtype '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_eventtype", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn eventtype_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM knowledge_eventtype WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("eventtype introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression du type d'événement #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_eventtype WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.eventtype.delete",
            &format!("eventtype '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("eventtype '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_eventtype", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 4) TAGS : label sur field=value
// ---------------------------------------------------------------------------------------------
pub(crate) async fn tag_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let label = match validate_ko_ident(b.str_field("label")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let field = match validate_ko_ident(b.str_field("field")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let value = b.str_field("value").to_string(); // valeur libre -> échappée à la compilation (soql_esc)
    if value.is_empty() { return bad_req("tag : valeur requise"); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'une étiquette", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO knowledge_tag(label,field,value,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![label, field, value, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.tag.create",
            &format!("tag '{label}' sur {field}={value} (#{id}) par {}", au.name), 2,
            &format!("tag '{label}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"knowledge_tag", "id":id, "label":label, "field":field, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn tag_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let label = match conn.query_row("SELECT label FROM knowledge_tag WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("tag introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression de l'étiquette #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM knowledge_tag WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.tag.delete",
            &format!("tag '{label}' (#{id}) supprimé par {}", au.name), 2,
            &format!("tag '{label}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"knowledge_tag", "id":id, "label":label, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 5) MACROS (#60) : fragment GXQL nommé + paramétré, détendu À LA COMPILATION par le compilateur FERMÉ.
//    Corps + params compile-vérifiés (validate_macro : dry-expansion + compile-check) AVANT persistance.
// ---------------------------------------------------------------------------------------------
pub(crate) async fn macro_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    // params : liste (JSON array) OU chaîne "a,b" ; chaque param = ident GXQL sûr (validate_ko_ident).
    let params: Vec<String> = match b.get("params") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => Vec::new(),
    };
    for p in &params {
        if let Err(e) = validate_ko_ident(p) { return bad_req(format!("paramètre de macro invalide : {e}")); }
    }
    let body = b.str_field("body").trim().to_string();
    // COMPILE-CHECK (fail-closed) : dry-expansion + compilation par le compilateur fermé.
    if let Err(e) = validate_macro(&name, &params, &body) { return bad_req(e); }
    let params_str = params.join(",");
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'une macro", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO macro_def(name,params,body,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?5)",
            params![name, params_str, body, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.macro.create",
            &format!("macro '{name}'({params_str}) (#{id}) par {}", au.name), 2,
            &format!("macro '{name}' créée par {}", au.name),
            &json!({ "op":"create", "kind":"macro", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn macro_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM macro_def WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("macro introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression de la macro #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM macro_def WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.macro.delete",
            &format!("macro '{name}' (#{id}) supprimée par {}", au.name), 2,
            &format!("macro '{name}' supprimée par {}", au.name),
            &json!({ "op":"delete", "kind":"macro", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}

// ---------------------------------------------------------------------------------------------
// 6) AUTO-LOOKUPS (#60) : enrichissement auto-appliqué au-dessus de la base (mask-aware, réutilise
//    compile_lookup). GeoIP = un auto-lookup dont la table lookup_kv est peuplée depuis une base BYO.
// ---------------------------------------------------------------------------------------------
pub(crate) async fn auto_lookup_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_ko_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let key_field = match validate_ko_ident(b.str_field("key_field")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let out_cols: Vec<String> = match b.get("out_cols") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        _ => Vec::new(),
    };
    for c in &out_cols {
        if let Err(e) = validate_ko_ident(c) { return bad_req(format!("colonne de sortie invalide : {e}")); }
    }
    // kind : label 'lookup' (défaut) ou 'geoip' (mécanique identique ; GeoIP = table BYO peuplée hors-ligne).
    let kind = match b.str_field("kind").trim() { "" | "lookup" => "lookup", "geoip" => "geoip", k => return bad_req(format!("kind invalide (lookup|geoip) : {k}")) }.to_string();
    if let Err(e) = validate_auto_lookup(&name, &key_field, &out_cols) { return bad_req(e); }
    let out_str = out_cols.join(",");
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", "création d'une recherche automatique", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO auto_lookup(name,key_field,out_cols,kind,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![name, key_field, out_str, kind, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.knowledge.autolookup.create",
            &format!("auto-lookup '{name}' sur {key_field} ({kind}, #{id}) par {}", au.name), 2,
            &format!("auto-lookup '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"auto_lookup", "id":id, "name":name, "key_field":key_field, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |id| json!({ "id": id }))
}

pub(crate) async fn auto_lookup_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM auto_lookup WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("auto-lookup introuvable"),
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "knowledge", &format!("suppression de la recherche automatique #{id}"), CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM auto_lookup WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.knowledge.autolookup.delete",
            &format!("auto-lookup '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("auto-lookup '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"auto_lookup", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    ko_commit(&st, &au, &conn, outcome, |_| json!({ "ok": true }))
}
