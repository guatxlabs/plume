//! PURGE EXPLICITE D'ÉVÉNEMENTS — surface HTTP (deux temps), ADMIN-ONLY et FERMÉE PAR DÉFAUT.
//!
//! POURQUOI FERMÉE PAR DÉFAUT. La sous-commande `plume-daemon purge` n'ajoute aucune capacité : celui qui
//! l'exécute possède déjà la clé SQLCipher et l'hôte. Une ROUTE, elle, ajoute une capacité de destruction de
//! preuves À DISTANCE, atteignable avec une simple session admin. Ce n'est pas la même menace, donc ce n'est
//! pas le même défaut : `PLUME_PURGE_API` doit être posé explicitement au DÉPLOIEMENT pour que la route
//! opère. Cela sépare deux principals — celui qui détient le mot de passe admin, et celui qui contrôle le
//! déploiement — là où un simple `au.is_admin()` n'en aurait exigé qu'un. Mode 0 : flag absent -> la route
//! existe (donc elle est balayée par les gardes de câblage du routeur) mais refuse.
//!
//! CE QUI GARDE CETTE SURFACE, et où c'est prouvé :
//!  - `route_min_role("/api/purge…") == Admin` (préfixe déclaré dans la section admin-only, GET compris) ;
//!  - le balayage `router_viewer_cannot_reach_any_mutating_route` LIT la table de routage dans `server.rs` :
//!    ces deux routes y entrent AUTOMATIQUEMENT, sans qu'on ait à les inscrire quelque part ;
//!  - `route_denied_perm("/api/purge") == Some("purge_events")` : un rôle composable base=admin peut se voir
//!    RETIRER la purge tout en gardant le reste de l'autorité admin (soustractif, jamais additif) ;
//!  - le re-check `au.is_admin()` dans chaque handler (défense en profondeur, miroir de #59) ;
//!  - et, en mode 1, une purge cross-tenant par un super-admin passe déjà par le break-glass de
//!    `resolve_tenant_access` (mutation -> raison obligatoire + marqueur opérateur non désactivable).
use crate::*;

/// La surface HTTP de purge est-elle ARMÉE ? Défaut : NON.
pub(crate) fn purge_api_enabled() -> bool {
    matches!(
        cfg(&load_config(), "PLUME_PURGE_API", "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Réponse commune aux deux routes quand la surface n'est pas armée. 403 (et pas 404) : l'opérateur doit
/// comprendre que la capacité existe et comment l'armer, pas croire à une route disparue.
fn purge_api_closed() -> Response {
    forbidden(
        "purge par API DÉSACTIVÉE (défaut). Utiliser la sous-commande `plume-daemon purge` (l'appelant y \
         détient déjà la clé de la base), ou armer explicitement la surface HTTP au déploiement avec \
         PLUME_PURGE_API=1 — c'est une capacité de destruction de preuves à distance.",
    )
}

/// Périmètre depuis le corps JSON. MÊME analyseur que la CLI (`purge_scope_from_args`) -> il n'existe qu'un
/// seul jeu de règles de validation, donc pas de surface plus permissive d'un côté que de l'autre.
fn scope_from_body(b: &Value) -> Result<PurgeScope, String> {
    let mut sel: Vec<(String, String)> = Vec::new();
    for kind in ["source", "env", "origin", "engagement"] {
        let v = b.str_field(kind).trim().to_string();
        if !v.is_empty() {
            sel.push((kind.to_string(), v));
        }
    }
    // Les bornes sont acceptées en NOMBRE (epoch) ou en TEXTE (« -7d »). Absentes -> chaîne vide ->
    // `purge_parse_ts` refuse : il n'y a pas de défaut, parce qu'il n'y a pas de fenêtre par défaut.
    let as_bound = |k: &str| -> String {
        match b.get(k) {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.trim().to_string(),
            _ => String::new(),
        }
    };
    purge_scope_from_args(&sel, &as_bound("since"), &as_bound("until"), now())
}

fn purge_refusal_response(e: PurgeRefusal) -> Response {
    // Un REFUS n'est pas une erreur serveur : c'est une décision. 409 CONFLICT porte « l'état du système
    // s'y oppose » (hold actif, tier froid, case citant, jeton caduc) ; 400 les entrées manquantes.
    let code = match &e {
        PurgeRefusal::ReasonRequired => StatusCode::BAD_REQUEST,
        PurgeRefusal::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    };
    (
        code,
        Json(json!({ "ok": false, "refusal": purge_refusal_code(&e), "message": e.to_string() })),
    )
        .into_response()
}

/// POST /api/purge/plan — TEMPS 1 : SIMULE. Aucune écriture (que des SELECT). Rend le compte EXACT, la
/// ventilation par source, un échantillon des deux extrémités, ce qui N'EST PAS couvert, et le JETON.
pub(crate) async fn purge_plan_route(
    State(st): State<AppState>,
    Extension(au): Extension<AuthUser>,
    Json(b): Json<Value>,
) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    if !purge_api_enabled() {
        return purge_api_closed();
    }
    let scope = match scope_from_body(&b) {
        Ok(s) => s,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    crate::req_conn!(st, au, conn);
    match purge_plan(&conn, scope) {
        Ok(p) => Json(purge_plan_json(&p)).into_response(),
        Err(e) => purge_refusal_response(e),
    }
}

/// POST /api/purge/apply — TEMPS 2 : RE-SIMULE, compare le jeton à l'empreinte du périmètre TEL QU'IL EST
/// MAINTENANT, puis exécute. Rejouer ce POST après coup échoue : le contenu a changé (les lignes ne sont plus
/// là), donc l'empreinte aussi. `reason` est obligatoire et entre au registre.
pub(crate) async fn purge_apply_route(
    State(st): State<AppState>,
    Extension(au): Extension<AuthUser>,
    Json(b): Json<Value>,
) -> Response {
    if !au.is_admin() {
        return forbidden("réservé à l'administrateur");
    }
    if !purge_api_enabled() {
        return purge_api_closed();
    }
    let scope = match scope_from_body(&b) {
        Ok(s) => s,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let token = b.str_field("token").trim().to_string();
    if token.is_empty() {
        return err_json(
            StatusCode::BAD_REQUEST,
            "jeton de confirmation requis : simuler d'abord (POST /api/purge/plan) et rendre le `token` obtenu",
        );
    }
    let reason = b.str_field("reason").to_string();
    // ACTEUR : l'identité RÉSOLUE par le choke-point d'authentification, jamais un champ du corps.
    let actor = format!("api:{}", au.name);
    crate::req_conn!(st, au, conn);
    match purge_confirm_and_apply(&conn, scope, &token, &actor, &reason) {
        Ok(r) => Json(purge_receipt_json(&r)).into_response(),
        Err(e) => purge_refusal_response(e),
    }
}
