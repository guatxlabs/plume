//! #59 SCIM 2.0 — provisioning/deprovisioning depuis un IdP (Okta/Azure AD). Endpoint AUTHENTIFIÉ par un
//! bearer DÉDIÉ (`scim_token`, control-plane, distinct des sessions et des tokens agent), scopé à UN tenant.
//! Le provisioning mappe vers `platform_user` + `grant` EXISTANTS :
//!   - un User SCIM = un `platform_user` (is_superadmin TOUJOURS 0 — un IdP externe ne peut JAMAIS accorder
//!     le super-admin plateforme, ni contourner le gate rôle->permission) ;
//!   - un Group SCIM = un RÔLE dans le tenant du token (`grant`) ; l'appartenance passe par `valid_grant_role`
//!     (enum FERMÉ admin/editor/viewer + rôles composables DÉFINIS) -> aucune escalade.
//! Deprovisioning : DELETE ou active=false -> retrait des grants du user dans le tenant. Mode 0 (control=None)
//! -> l'endpoint répond 404 (inerte) : parité byte-identique (aucune route SCIM fonctionnelle sans mode 1).
//! Le SECRET du bearer se provisionne hors-git (CLI `scim-token`, stocké HASHÉ sha256) — jamais inline.
use crate::*;

/// Contexte SCIM injecté par auth_guard après validation du bearer : le tenant que ce token provisionne.
#[derive(Clone)]
pub(crate) struct ScimCtx {
    pub(crate) tenant: String,
}

/// Valide un bearer SCIM (`Authorization: Bearer <tok>`) contre `scim_token` (hash sha256) et rend le
/// tenant provisionné. None = bearer absent/invalide. Met à jour last_used (best-effort). Le hash est la
/// clé primaire -> lookup direct (comme token_lookup agent) ; le secret n'est jamais stocké en clair.
pub(crate) fn scim_authenticate(cp: &ControlPlane, authz: &str) -> Option<String> {
    let tok = authz.strip_prefix("Bearer ")?.trim();
    if tok.is_empty() {
        return None;
    }
    let h = sha256_hex(tok.as_bytes());
    let conn = cp.conn.lock();
    let tenant: Option<String> = conn.query_row("SELECT tenant_id FROM scim_token WHERE hash=?1", params![h], |r| r.get(0)).ok();
    if tenant.is_some() {
        let _ = conn.execute("UPDATE scim_token SET last_used=?1 WHERE hash=?2", params![now(), h]);
    }
    tenant
}

fn scim_err(code: StatusCode, detail: &str) -> Response {
    (
        code,
        [(header::CONTENT_TYPE, "application/scim+json")],
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": detail, "status": code.as_u16().to_string() }).to_string(),
    )
        .into_response()
}

// `P10.21-l` — UN DROIT SCIM SE COMPTE AVANT QUE LE JOURNAL DE CONTRÔLE OU L'IdP NE L'APPRENNENT.
// Les écritures de droits de ce fichier passaient sous `let _ =` (ou `unwrap_or(0)`) : un retrait que la
// base refusait laissait l'accès EN PLACE pendant que la ligne `scim.user.deprovision` l'attestait et que
// l'IdP recevait un succès — il ne rejoue jamais un succès. Chaque écriture de `"grant"` est désormais
// classée (`EcritureDuPlanDeControle`) avant toute trace ; un refus de la base rend le corps d'erreur
// SCIM 2.0 (RFC 7644 §3.12) avec le statut `503`, sans rien attester. La RFC fixe le CORPS, pas la
// politique de rejeu : `503` est l'indisponibilité PASSAGÈRE de HTTP (RFC 9110 §15.6.4), le seul statut
// qui dise « rien n'a eu lieu, recommencez ». Que le fournisseur en service rejoue réellement un `503`
// est une question d'exploitation, ouverte sous la clé : aucun code de ce dépôt ne peut y répondre.
//
// CE QUE L'IdP REÇOIT, ET CE QU'IL NE REÇOIT PAS : la cause du GESTE, dite pour l'exploitant de l'IdP ;
// la cause du MOTEUR (noms de tables internes) part sur la sortie d'erreur du démon, avec le seul genre
// du geste — ni utilisateur, ni tenant, ni jeton.

pub(crate) const CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT: &str =
    "RETRAIT DES DROITS NON ÉCRIT : la base du plan de contrôle n'a pas pris le retrait — l'accès de cet \
     utilisateur à ce tenant est TOUJOURS EN PLACE. Rien n'est attesté ; la même demande peut être rejouée \
     telle quelle.";
pub(crate) const CAUSE_SCIM_DROITS_DEMANDES_NON_ECRITS: &str =
    "DROITS NON ÉCRITS : la base du plan de contrôle n'a pas pris l'écriture d'un droit — l'utilisateur \
     existe, les droits demandés ne sont PAS en place. Rien n'est attesté ; la même demande peut être \
     rejouée telle quelle.";
pub(crate) const CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE: &str =
    "OPÉRATION DE GROUPE NON ÉCRITE : la base du plan de contrôle n'a pas pris l'ajout ou le retrait d'un \
     membre — un retrait demandé n'a PAS eu lieu, l'accès de ce membre est TOUJOURS EN PLACE. Les \
     opérations précédentes de la même demande ont pu être appliquées ; chacune est idempotente, la \
     demande entière peut être rejouée telle quelle. Rien n'est attesté.";
pub(crate) const CAUSE_SCIM_UTILISATEUR_ILLISIBLE: &str =
    "UTILISATEUR ILLISIBLE : la base du plan de contrôle n'a pas pu lire l'utilisateur visé — ni sa \
     présence ni son absence n'est affirmée, et rien n'est modifié. La même demande peut être rejouée \
     telle quelle.";

/// Le refus d'un geste SCIM que la base n'a pas pris (ou pas pu lire) : `503` au format d'erreur SCIM 2.0,
/// rien d'attesté — l'IdP rejoue.
fn scim_refuser_a_rejouer(genre: &str, cause_du_geste: &str, cause_du_moteur: &str) -> Response {
    eprintln!("[scim] WARN geste '{genre}' refusé en 503, rien n'est attesté : {cause_du_moteur}");
    scim_err(StatusCode::SERVICE_UNAVAILABLE, cause_du_geste)
}

/// Le nom de l'utilisateur `id` s'il porte un droit dans `tenant`. TROIS issues : `Ok(Some)` présent,
/// `Ok(None)` absent (le `404` de la RFC 7644 §3.6), `Err` illisible — jamais servi comme une absence, car
/// un `404` sur une suppression est lu par l'IdP comme « déjà déprovisionné ».
///
/// `P7.19-i` — `LIMIT 1` sans ordre, et sans arbitraire : `"grant"` a pour clé primaire
/// `(user_id, tenant_id)` et `platform_user.id` est clé primaire, donc ce prédicat lié sur les DEUX
/// colonnes de la clé ne peut joindre qu'AU PLUS UNE ligne. Le singleton vient du SCHÉMA.
fn scim_nom_dans_le_tenant(cp: &ControlPlane, tenant: &str, id: &str) -> rusqlite::Result<Option<String>> {
    use rusqlite::OptionalExtension as _;
    cp.conn
        .lock()
        .query_row(
            "SELECT p.name FROM platform_user p JOIN \"grant\" g ON g.user_id=p.id \
             WHERE p.id=?1 AND g.tenant_id=?2 LIMIT 1",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()
}

/// Représentation SCIM d'un platform_user (+ ses grants dans `tenant` -> `groups`).
fn scim_user_resource(cp: &ControlPlane, tenant: &str, id: &str, name: &str) -> Value {
    let conn = cp.conn.lock();
    let groups: Vec<Value> = match conn.prepare("SELECT role FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2") {
        Ok(mut s) => s
            .query_map(params![id, tenant], |r| Ok(json!({ "value": r.get::<_, String>(0)?, "type": "direct" })))
            .map(|it| it.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let active: bool = !groups.is_empty();
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "userName": name,
        "active": active,
        "groups": groups,
        "meta": { "resourceType": "User" }
    })
}

/// GET /scim/v2/Users — liste (filtre `userName eq "x"` supporté a minima). ListResponse SCIM.
pub(crate) async fn scim_users_list(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    // Filtre minimal : `userName eq "value"`.
    let filter_name: Option<String> = q.get("filter").and_then(|f| {
        let f = f.trim();
        f.strip_prefix("userName eq ").map(|v| v.trim().trim_matches('"').to_string())
    });
    // HIGH #59 — TENANT-SCOPING : `platform_user` est GLOBAL (multi-tenant). Ne JAMAIS lister les identités
    // d'un AUTRE tenant. On joint par `grant` filtré sur le tenant du token -> seuls les users PROVISIONNÉS
    // dans CE tenant sont visibles (fuite cross-tenant fermée). DISTINCT : un user peut avoir plusieurs grants.
    let mut ids: Vec<(String, String)> = Vec::new();
    let conn = cp.conn.lock();
    if let Ok(mut s) = conn.prepare(
        "SELECT DISTINCT p.id, p.name FROM platform_user p \
         JOIN \"grant\" g ON g.user_id=p.id WHERE g.tenant_id=?1 ORDER BY p.name",
    ) {
        if let Ok(rows) = s.query_map(params![ctx.tenant], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for row in rows.flatten() {
                ids.push(row);
            }
        }
    }
    drop(conn);
    let resources: Vec<Value> = ids
        .into_iter()
        .filter(|(_, name)| filter_name.as_ref().map(|f| f == name).unwrap_or(true))
        .map(|(id, name)| scim_user_resource(cp, &ctx.tenant, &id, &name))
        .collect();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/scim+json")],
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": resources.len(),
            "Resources": resources,
        })
        .to_string(),
    )
        .into_response()
}

/// GET /scim/v2/Users/{id} — un user.
pub(crate) async fn scim_user_get(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Path(id): Path<String>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    // HIGH #59 — TENANT-SCOPING : un GET pour un id qui n'a AUCUN grant dans le tenant du token -> 404
    // (identité d'un autre tenant JAMAIS révélée), même si le platform_user existe globalement.
    match scim_nom_dans_le_tenant(cp, &ctx.tenant, &id) {
        Ok(Some(n)) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], scim_user_resource(cp, &ctx.tenant, &id, &n).to_string()).into_response(),
        Ok(None) => scim_err(StatusCode::NOT_FOUND, "User introuvable"),
        Err(e) => scim_refuser_a_rejouer("scim.user.get", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
    }
}

/// ANTI-LOCKOUT SCIM (HIGH #59, #64) — le retrait des grants de `uid` dans `tenant` VIDERAIT-il le DERNIER admin ?
/// True SEULEMENT si le user a un grant à AUTORITÉ ADMIN EFFECTIVE dans ce tenant (littéral `admin` OU rôle
/// composable base=admin) ET que c'est le seul (tenant_admin_grant_count <= 1, lui-même effective-base-aware
/// depuis #64). Miroir de la garde de `tenants.rs` (grant_delete). `tenant_admin_grant_count` verrouille cp.conn
/// en interne -> à appeler HORS de tout lock déjà tenu.
pub(crate) fn scim_would_orphan_last_admin(cp: &ControlPlane, tenant: &str, uid: &str) -> bool {
    let is_admin_here = {
        let conn = cp.conn.lock();
        conn.query_row(
            "SELECT role FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2",
            params![uid, tenant],
            |r| r.get::<_, String>(0),
        )
        .map(|role| effective_base_role(&role) == "admin")
        .unwrap_or(false)
    };
    is_admin_here && tenant_admin_grant_count(cp, tenant) <= 1
}

/// POST /scim/v2/Users — PROVISIONNE un user (idempotent par userName). Crée le platform_user
/// (is_superadmin=0 IMPOSÉ) et, si le body porte des `roles`/`groups` mappables, applique les grants dans le
/// tenant du token (via valid_grant_role). N'accorde JAMAIS le super-admin.
pub(crate) async fn scim_user_create(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Json(b): Json<Value>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    let username = b.get("userName").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !platform_user_name_ok(&username) {
        return scim_err(StatusCode::BAD_REQUEST, "userName invalide");
    }
    // ensure_platform_user : crée (is_superadmin=0) OU récupère l'existant — jamais ne modifie is_superadmin.
    let Some(id) = ensure_platform_user(cp, &username) else {
        return scim_err(StatusCode::INTERNAL_SERVER_ERROR, "création platform_user échouée");
    };
    // Grants optionnels : le body peut porter des groups (value=role). On applique via valid_grant_role
    // (enum fermé + rôles composables définis) dans le tenant du token. Un rôle inconnu est IGNORÉ (default-deny).
    // `P10.21-l` — un droit n'entre dans `applied` (donc au journal de contrôle) que s'il est ÉCRIT ; un
    // refus de la base rend le `503` avant toute trace. L'utilisateur, lui, reste créé : le rejeu du même
    // POST le retrouve par son nom (`ensure_platform_user`) et repose les droits (upsert).
    let mut applied: Vec<String> = Vec::new();
    if let Some(groups) = b.get("groups").and_then(|g| g.as_array()) {
        let conn = cp.conn.lock();
        for g in groups {
            if let Some(role) = g.get("value").and_then(|v| v.as_str()) {
                if valid_grant_role(role) {
                    match EcritureDuPlanDeControle::from(conn.execute(
                        "INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3) \
                         ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                        params![id, ctx.tenant, role],
                    )) {
                        EcritureDuPlanDeControle::Ecrite => applied.push(role.to_string()),
                        EcritureDuPlanDeControle::AucuneLigne => {}
                        EcritureDuPlanDeControle::Refusee(cause) => {
                            return scim_refuser_a_rejouer("scim.user.provision", CAUSE_SCIM_DROITS_DEMANDES_NON_ECRITS, &cause)
                        }
                    }
                }
            }
        }
    }
    // `P10.20-z` — LE CONTRAT DE CETTE RÉPONSE EST ÉTRANGER (SCIM 2.0, lu par un fournisseur d'identité, pas
    // par un exploitant) : il n'a aucun champ où porter un aveu. Un maillon manquant reste à l'aveu de la
    // primitive, sur la sortie d'erreur. Même classement pour les trois autres gestes SCIM de ce fichier.
    control_ledger_append(&st, "scim.user.provision", "scim", &ctx.tenant, &format!("user '{username}' (id={id}) grants=[{}]", applied.join(",")))
        .laisser_a_l_aveu_de_la_primitive();
    (StatusCode::CREATED, [(header::CONTENT_TYPE, "application/scim+json")], scim_user_resource(cp, &ctx.tenant, &id, &username).to_string()).into_response()
}

/// PUT /scim/v2/Users/{id} — remplace (ici : gère `active`). active=false -> DEPROVISION (retrait des grants
/// du user dans le tenant du token). Ne touche jamais is_superadmin.
pub(crate) async fn scim_user_replace(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    // #59 — TENANT-SCOPING de l'existence (mirroir du GET) : un id sans AUCUN grant dans le tenant
    // du token -> 404, même si le platform_user existe globalement (pas d'oracle d'existence cross-tenant).
    let name = match scim_nom_dans_le_tenant(cp, &ctx.tenant, &id) {
        Ok(Some(n)) => n,
        Ok(None) => return scim_err(StatusCode::NOT_FOUND, "User introuvable"),
        Err(e) => return scim_refuser_a_rejouer("scim.user.replace", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
    };
    let active = b.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    if !active {
        // ANTI-LOCKOUT (HIGH #59) : désactiver retire TOUS les grants du user dans ce tenant. Refuser si cela
        // viderait le dernier admin (l'IdP ne doit jamais orpheliner un tenant sans admin).
        if scim_would_orphan_last_admin(cp, &ctx.tenant, &id) {
            return scim_err(StatusCode::CONFLICT, "dernier administrateur du tenant — désactivation refusée (anti-lockout)");
        }
        // `P10.21-l` — LE RETRAIT EST COMPTÉ AVANT D'ÊTRE ATTESTÉ. L'énoncé reste écrit ICI, au site qui
        // atteste, sur un verrou LIÉ à un nom : la rechute vers la forme d'avant (`let _ = conn.execute(…)`
        // dans ce bloc) est vue par la garde des écritures avalées. Elle ne verrait PAS `let _ =
        // cp.conn.lock().execute(…)` — un receveur qui n'est pas un chemin sort de sa liaison sourde, par
        // construction ; seuls les témoins `dsa_` tiennent cette forme-là.
        let retrait = {
            let conn = cp.conn.lock();
            EcritureDuPlanDeControle::from(conn.execute("DELETE FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2", params![id, ctx.tenant]))
        };
        match retrait {
            EcritureDuPlanDeControle::Ecrite => {}
            // Présent à la lecture, absent à l'écriture : déprovisionné entre-temps. Rien n'est retiré par
            // CE geste, rien n'est attesté ; la RFC 7644 §3.6 veut un 404 sur une ressource déjà supprimée.
            EcritureDuPlanDeControle::AucuneLigne => return scim_err(StatusCode::NOT_FOUND, "User introuvable"),
            EcritureDuPlanDeControle::Refusee(cause) => {
                return scim_refuser_a_rejouer("scim.user.deprovision", CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT, &cause)
            }
        }
        control_ledger_append(&st, "scim.user.deprovision", "scim", &ctx.tenant, &format!("user '{name}' (id={id}) désactivé -> grants retirés"))
            .laisser_a_l_aveu_de_la_primitive();
    }
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], scim_user_resource(cp, &ctx.tenant, &id, &name).to_string()).into_response()
}

/// DELETE /scim/v2/Users/{id} — DEPROVISION : retire les grants du user dans le tenant du token. Le
/// platform_user (identité plateforme, possiblement multi-tenant) n'est pas détruit ici (retrait de grant =
/// perte d'accès au tenant ; la destruction d'identité reste une action admin séparée).
pub(crate) async fn scim_user_delete(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Path(id): Path<String>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    // #59 — existence TENANT-SCOPÉE (mirroir du GET/PUT) : id sans grant dans ce tenant -> 404. `P10.21-l` —
    // une lecture RATÉE n'est plus ce 404 : l'IdP lit un 404 sur un DELETE comme « déjà déprovisionné ».
    match scim_nom_dans_le_tenant(cp, &ctx.tenant, &id) {
        Ok(Some(_)) => {}
        Ok(None) => return scim_err(StatusCode::NOT_FOUND, "User introuvable"),
        Err(e) => return scim_refuser_a_rejouer("scim.user.delete", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
    }
    // ANTI-LOCKOUT (HIGH #59) : le DELETE retire les grants du user dans ce tenant — refuser s'il viderait le
    // dernier admin (mirroir de tenants.rs/grant_delete). Vérifié HORS lock (tenant_admin_grant_count verrouille).
    if scim_would_orphan_last_admin(cp, &ctx.tenant, &id) {
        return scim_err(StatusCode::CONFLICT, "dernier administrateur du tenant — deprovisioning refusé (anti-lockout)");
    }
    // `P10.21-l` — même comptage que le PUT `active=false`, écrit au site pour la même raison.
    let retrait = {
        let conn = cp.conn.lock();
        EcritureDuPlanDeControle::from(conn.execute("DELETE FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2", params![id, ctx.tenant]))
    };
    match retrait {
        EcritureDuPlanDeControle::Ecrite => {}
        EcritureDuPlanDeControle::AucuneLigne => return scim_err(StatusCode::NOT_FOUND, "User introuvable"),
        EcritureDuPlanDeControle::Refusee(cause) => {
            return scim_refuser_a_rejouer("scim.user.deprovision", CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT, &cause)
        }
    }
    control_ledger_append(&st, "scim.user.deprovision", "scim", &ctx.tenant, &format!("user id={id} deprovisionné (DELETE)"))
        .laisser_a_l_aveu_de_la_primitive();
    StatusCode::NO_CONTENT.into_response()
}

/// GET /scim/v2/Groups — les groupes = les RÔLES assignables dans le tenant du token (base + composables
/// définis). displayName = nom du rôle. Jamais `is_superadmin` (non assignable via SCIM).
pub(crate) async fn scim_groups_list(State(st): State<AppState>, Extension(_ctx): Extension<ScimCtx>) -> Response {
    if st.tenants.control.is_none() {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    }
    let mut roles: Vec<String> = vec!["admin".into(), "editor".into(), "viewer".into()];
    for name in custom_roles_cell().lock().keys() {
        roles.push(name.clone());
    }
    let resources: Vec<Value> = roles
        .iter()
        .map(|r| json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": r, "displayName": r, "meta": { "resourceType": "Group" } }))
        .collect();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/scim+json")],
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": resources.len(), "Resources": resources }).to_string(),
    )
        .into_response()
}

/// PATCH /scim/v2/Groups/{role} — ajoute/retire des membres (grant du rôle dans le tenant du token). Le rôle
/// (displayName) DOIT être valide (valid_grant_role) -> jamais super-admin, jamais un rôle indéfini.
pub(crate) async fn scim_group_patch(State(st): State<AppState>, Extension(ctx): Extension<ScimCtx>, Path(role): Path<String>, Json(b): Json<Value>) -> Response {
    let Some(cp) = st.tenants.control.as_ref() else {
        return scim_err(StatusCode::NOT_FOUND, "SCIM indisponible");
    };
    if !valid_grant_role(&role) {
        return scim_err(StatusCode::BAD_REQUEST, "rôle (displayName) invalide ou indéfini");
    }
    let ops = b.get("Operations").and_then(|o| o.as_array()).cloned().unwrap_or_default();
    let (mut added, mut removed) = (0i64, 0i64);
    let conn = cp.conn.lock();
    for op in &ops {
        let action = op.get("op").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        // members : soit op.value = [{value:id}], soit path=members.
        let members: Vec<String> = op
            .get("value")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|m| m.get("value").and_then(|x| x.as_str()).map(String::from)).collect())
            .unwrap_or_default();
        for uid in members {
            // le user doit exister (identité plateforme) — jamais de grant fantôme. `P10.21-l` — une lecture
            // RATÉE n'est pas une absence : sautée, elle laissait en place le membre qu'un `remove` retirait.
            match conn.query_row("SELECT 1 FROM platform_user WHERE id=?1", params![uid], |r| r.get::<_, i64>(0)) {
                Ok(_) => {}
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(e) => return scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
            }
            // `P10.21-l` — chaque écriture est COMPTÉE : un membre n'entre dans `added`/`removed` (donc au
            // journal de contrôle) que si sa ligne est écrite ; un refus rend le 503 avant toute trace.
            match action.as_str() {
                "add" | "replace" => {
                    match EcritureDuPlanDeControle::from(conn.execute(
                        "INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3) ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                        params![uid, ctx.tenant, role],
                    )) {
                        EcritureDuPlanDeControle::Ecrite => added += 1,
                        EcritureDuPlanDeControle::AucuneLigne => {}
                        EcritureDuPlanDeControle::Refusee(cause) => {
                            return scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE, &cause)
                        }
                    }
                }
                "remove" => {
                    // ANTI-LOCKOUT (HIGH #59, #64) : ne JAMAIS retirer le DERNIER grant à AUTORITÉ ADMIN EFFECTIVE
                    // d'un tenant via SCIM. Le grant retiré porte `role` (path) ; s'il a une base effective admin
                    // (littéral `admin` OU rôle composable base=admin -> sinon retirer le dernier `gov-admin`
                    // orphelinerait le tenant = lockout DoS), on compte les grants effective-admin du tenant (résolu
                    // en Rust — SQL ne connaît pas effective_base_role) et on bloque si le retrait le ferait tomber
                    // à 0. Compté sur le MÊME `conn` déjà tenu (helper `..._conn` -> pas de re-lock/deadlock).
                    if effective_base_role(&role) == "admin" {
                        let has_grant = conn
                            .query_row("SELECT 1 FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2 AND role=?3", params![uid, ctx.tenant, role], |_| Ok(()))
                            .is_ok();
                        let admins = effective_admin_grant_count_conn(&conn, &ctx.tenant);
                        if has_grant && admins <= 1 {
                            return scim_err(StatusCode::CONFLICT, "dernier administrateur du tenant — retrait de membre refusé (anti-lockout)");
                        }
                    }
                    // Un membre qui ne portait pas ce rôle n'est pas un échec (aucune ligne) : l'état demandé
                    // est atteint, rien n'est compté. Un refus de la base, lui, laisse l'accès en place.
                    match EcritureDuPlanDeControle::from(
                        conn.execute("DELETE FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2 AND role=?3", params![uid, ctx.tenant, role]),
                    ) {
                        EcritureDuPlanDeControle::Ecrite => removed += 1,
                        EcritureDuPlanDeControle::AucuneLigne => {}
                        EcritureDuPlanDeControle::Refusee(cause) => {
                            return scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE, &cause)
                        }
                    }
                }
                _ => {}
            }
        }
    }
    drop(conn);
    control_ledger_append(&st, "scim.group.patch", "scim", &ctx.tenant, &format!("role '{role}' +{added}/-{removed} membres"))
        .laisser_a_l_aveu_de_la_primitive();
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role }).to_string()).into_response()
}
