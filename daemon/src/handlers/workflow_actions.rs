//! #60 — WORKFLOW ACTIONS : actions de menu contextuel attachées à un champ/événement (façon Splunk
//! workflow_actions). PUREMENT DÉCLARATIVES (table `workflow_action` VIDE -> mode 0, aucun effet). Trois
//! genres, tous SÛRS PAR CONSTRUCTION :
//!   - `search`  : NAVIGATION — un gabarit GXQL avec `$field$` ouvre une nouvelle recherche. Le gabarit est
//!                 compile-vérifié (compilateur FERMÉ) à la création ; à la résolution, la VALEUR substituée
//!                 est validée (charset scalaire) puis le GXQL RECOMPILÉ -> jamais de SQL brut, enum fermée.
//!   - `url`     : NAVIGATION — un gabarit d'URL avec `$field$`. `safe_url` (http/https) au gabarit ; à la
//!                 résolution la valeur est POURCENT-ENCODÉE (anti-injection/XSS dans la console).
//!   - `response`: DÉCLENCHE une RÉPONSE — le `target` référence UNIQUEMENT l'ENUM D'ACTION FERMÉ
//!                 (`ban_ip|unban_ip|kill_pid|stop_service`, `action_kind_valid`). AUCUN script custom, aucune
//!                 commande. L'EXÉCUTION reste le chemin /api/actions EXISTANT (approbation + ledger) : ce
//!                 workflow-action ne fait que RÉFÉRENCER l'action ; il ne l'exécute pas. Création = ADMIN.
use crate::*;
use crate::handlers::transaction_validee::rendre_apres_validation;


/// Pourcent-encode une valeur pour insertion SÛRE dans une URL (unreserved RFC 3986 conservés ; tout le reste
/// encodé %XX). Empêche l'évasion du contexte URL (injection de paramètre, `javascript:`, XSS via `<`/`"`).
fn percent_encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Une VALEUR de champ substituée dans un gabarit `search`/`response` doit être un scalaire SÛR (même charset
/// que les arguments de macro : anti-rupture de fragment/commande/quote/injection shell). Rejet sinon.
pub(crate) fn value_scalar_ok(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '*' | '@'))
}

/// GET /api/workflow-actions — liste (viewer+ via section 6 ; ici défense en profondeur editor pour mutations).
pub(crate) async fn workflow_actions_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LA LISTE DES ACTIONS DE WORKFLOW EST ENTIÈRE OU AVOUÉE. Avant :
    // `.map(|rows| rows.flatten().collect())` puis `.unwrap_or_default()` — une action dont la ligne ne se
    // décode pas (`target`, le gabarit `$field$`, corrompu ; colonne de migration que la connexion qui sert
    // ne voit pas encore) disparaissait du menu contextuel que cette liste PEUPLE. L'analyste conclut que
    // le pivot qu'il cherche n'a jamais été défini et le refabrique, alors que le nom est déjà pris
    // (`name TEXT NOT NULL UNIQUE`) : la création sera refusée sans qu'il puisse voir pourquoi. L'aveu est
    // celui du dépôt (`liste_bornee::corps_de_liste_illisible` : `workflow_actions` présente et VIDE,
    // `error` nomme la cause) ; la RÉSOLUTION d'une action (`/resolve`) lit la ligne par son id et n'est
    // pas concernée — ce lot tient l'INVENTAIRE servi, pas l'exécution.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,label,scope_field,kind,target,enabled,managed,created,updated FROM workflow_action ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "label": r.get::<_,String>(2)?,
                    "scope_field": r.get::<_,String>(3)?, "kind": r.get::<_,String>(4)?, "target": r.get::<_,String>(5)?,
                    "enabled": r.get::<_,i64>(6)? != 0, "managed": r.get::<_,i64>(7)?, "created": r.get::<_,i64>(8)?, "updated": r.get::<_,i64>(9)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(items) => Json(json!({ "workflow_actions": items })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "workflow_actions")).into_response(),
    }
}

/// COMPILE-VÉRIFIE un gabarit selon son genre (fail-closed AVANT persistance). Renvoie l'erreur explicite.
fn validate_workflow_action(kind: &str, scope_field: &str, target: &str) -> Result<(), String> {
    match kind {
        "search" => {
            // dry-substitution `$field$` -> valeur factice sûre, puis compile-check (fermé, standalone OU search-).
            let dummy = target.replace("$field$", "x1");
            if guatx_core::soql::to_sql(&dummy, 0, 0, &guatx_core::soql::Schema::events()).is_ok() {
                return Ok(());
            }
            guatx_core::soql::to_sql(&format!("search {dummy}"), 0, 0, &guatx_core::soql::Schema::events())
                .map(|_| ()).map_err(|e| format!("gabarit search non compilable : {e}"))
        }
        "url" => {
            let dummy = target.replace("$field$", "x1");
            if crate::handlers::notifiers::safe_url(&dummy) { Ok(()) } else { Err("gabarit url : schéma non autorisé (http/https attendu)".into()) }
        }
        "response" => {
            // target = action de l'ENUM FERMÉ uniquement (scope_field porte la VALEUR-cible à la résolution).
            let _ = scope_field;
            action_kind_valid(target)
        }
        _ => Err(format!("kind invalide (search|url|response) : {kind}")),
    }
}

/// POST /api/workflow-actions — crée. editor+ ; kind='response' EXIGE admin (référence le moteur de réponse).
pub(crate) async fn workflow_action_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let label = b.str_field("label").trim().to_string();
    // scope_field : '*' (tout champ) ou un ident GXQL sûr.
    let scope_field = b.str_field("scope_field").trim().to_string();
    let scope_field = if scope_field.is_empty() { "*".to_string() } else { scope_field };
    if scope_field != "*" {
        if let Err(e) = validate_ko_ident(&scope_field) { return bad_req(format!("scope_field : {e}")); }
    }
    let kind = b.str_field("kind").trim().to_string();
    let target = b.str_field("target").trim().to_string();
    if target.is_empty() { return bad_req("target requis"); }
    // kind='response' = référence le moteur de réponse (enum fermé) -> ADMIN uniquement (défense en profondeur).
    if kind == "response" {
        if let Err(r) = require_admin(&au) { return r; }
    }
    if let Err(e) = validate_workflow_action(&kind, &scope_field, &target) { return bad_req(e); }
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO workflow_action(name,label,scope_field,kind,target,enabled,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",
            params![name, label, scope_field, kind, target, enabled, now()])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.workflow_action.create",
            &format!("workflow-action '{name}' ({kind} sur {scope_field}, #{id}) par {}", au.name), 2,
            &format!("workflow-action '{name}' créée par {}", au.name),
            &json!({ "op":"create", "kind":"workflow_action", "id":id, "name":name, "action_kind":kind, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    // `P10.27-w` — LE `COMMIT` EST JUGÉ, ET L'IDENTIFIANT SERVI EST CELUI QUE LA FERMETURE A LU AU PIED DE L'`INSERT`
    // (voir `report_create`, même forme d'avant, même mesure : 200 et transaction OUVERTE sous un `COMMIT` refusé, le
    // numéro de l'ÉVÉNEMENT d'audit servi comme identifiant sinon).
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "workflow-actions", &format!("création de la workflow-action '{name}'"), CAUSE_WORKFLOW_ACTION_NON_CREEE, || {
            Json(json!({ "id": id })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") { return bad_req("une workflow-action porte déjà ce nom"); }
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

/// `P10.27-w` — workflow-action non créée : le `COMMIT` de ce geste refusé. Tête sans trait d'union (voir plus bas).
pub(crate) const CAUSE_WORKFLOW_ACTION_NON_CREEE: &str = "ACTION DE WORKFLOW NON CRÉÉE : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — aucune action n'est écrite ni proposée sur les champs qu'elle viserait, \
     et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

// `P10.25-g` — LE `COMMIT` DE LA SUPPRESSION D'UNE WORKFLOW-ACTION EST JUGÉ. `P10.27-w` — celui de la création aussi.
/// `P10.25-g` — workflow-action non supprimée : le `COMMIT` de ce geste refusé.
/// La tête s'écrit sans trait d'union : la console reconnaît la famille « rien n'a changé » à une tête en capitales,
/// apostrophes, virgules et espaces (`OUVERTURE_DE_L_ECRITURE_NON_VALIDEE`, `web/core.js`).
pub(crate) const CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE: &str = "ACTION DE WORKFLOW NON SUPPRIMÉE : la base n'a pas validé \
     la transaction (COMMIT refusé) et l'a annulée — elle est toujours là et toujours proposée sur les champs qu'elle \
     vise, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";

/// DELETE /api/workflow-actions/{id} — supprime (editor+, audité).
pub(crate) async fn workflow_action_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let name = match conn.query_row("SELECT name FROM workflow_action WHERE id=?1", params![id], |r| r.get::<_,String>(0)) {
        Ok(n) => n, Err(_) => return not_found("workflow-action introuvable"),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou base indisponible"); }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM workflow_action WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.workflow_action.delete",
            &format!("workflow-action '{name}' (#{id}) supprimée par {}", au.name), 2,
            &format!("workflow-action '{name}' supprimée par {}", au.name),
            &json!({ "op":"delete", "kind":"workflow_action", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    match outcome {
        Ok(_) => rendre_apres_validation(&conn, "workflow-actions", &format!("suppression de la workflow-action #{id}"), CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE, || {
            Json(json!({ "ok": true })).into_response()
        }),
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

/// POST /api/workflow-actions/{id}/resolve {value} — RÉSOUT l'action pour une valeur de champ concrète (viewer+
/// via readonly_post). Retourne une CIBLE DE NAVIGATION prête (GXQL recompilé / URL encodée) OU, pour
/// 'response', l'action de l'enum + la valeur (la console la joue via /api/actions -> approbation + ledger).
/// La valeur est SANITISÉE ; jamais d'exécution ici.
pub(crate) async fn workflow_action_resolve(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let value = b.str_field("value").to_string();
    let __rc = req_db(&st, &au);
    let (kind, target): (String, String) = {
        let conn = __rc.lock();
        match conn.query_row("SELECT kind,target FROM workflow_action WHERE id=?1 AND enabled=1", params![id], |r| Ok((r.get(0)?, r.get(1)?))) {
            Ok(t) => t, Err(_) => return not_found("workflow-action introuvable ou désactivée"),
        }
    };
    match kind.as_str() {
        "search" => {
            if !value_scalar_ok(&value) { return bad_req("valeur non substituable (caractère interdit)"); }
            let soql = target.replace("$field$", &value);
            // RECOMPILE par le compilateur FERMÉ (le résultat n'est jamais du SQL brut ; masque/enum s'appliquent
            // à l'exécution ultérieure via /api/query). On renvoie le GXQL de navigation, pas de SQL.
            let probe = if guatx_core::soql::to_sql(&soql, 0, 0, &guatx_core::soql::Schema::events()).is_ok() {
                soql.clone()
            } else {
                let wrapped = format!("search {soql}");
                if guatx_core::soql::to_sql(&wrapped, 0, 0, &guatx_core::soql::Schema::events()).is_err() {
                    return bad_req("GXQL de navigation invalide après substitution");
                }
                wrapped
            };
            Json(json!({ "kind": "search", "soql": probe })).into_response()
        }
        "url" => {
            let url = target.replace("$field$", &percent_encode(&value));
            if !crate::handlers::notifiers::safe_url(&url) { return bad_req("url résolue non autorisée"); }
            Json(json!({ "kind": "url", "url": url })).into_response()
        }
        "response" => {
            // target = action de l'enum fermé ; value = la CIBLE (ip/pid/service). Sanitisée ; la console
            // POST /api/actions (admin + approbation + ledger). On ne déclenche RIEN ici.
            if action_kind_valid(&target).is_err() { return bad_req("action de réponse hors enum fermé"); }
            if !value_scalar_ok(&value) { return bad_req("cible d'action non valide (caractère interdit)"); }
            Json(json!({ "kind": "response", "action_kind": target, "target": value,
                "note": "à jouer via POST /api/actions (approbation + ledger)" })).into_response()
        }
        other => bad_req(format!("kind inconnu : {other}")),
    }
}
