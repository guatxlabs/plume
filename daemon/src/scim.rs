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
// `P10.21-o` — LA DEMANDE EST ATOMIQUE (RFC 7644 §3.5.2 : « a PATCH request, regardless of the number of
// operations, SHALL be treated as atomic »). La phrase d'avant disait « les opérations précédentes de la
// même demande ont pu être appliquées » : c'était VRAI, et c'était le défaut.
pub(crate) const CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE: &str =
    "OPÉRATION DE GROUPE NON ÉCRITE : la base du plan de contrôle n'a pas pris l'ajout ou le retrait d'un \
     membre — un retrait demandé n'a PAS eu lieu, l'accès de ce membre est TOUJOURS EN PLACE. La demande \
     est atomique : AUCUNE de ses opérations n'est appliquée, et la demande entière peut être rejouée \
     telle quelle. Rien n'est attesté.";
pub(crate) const CAUSE_SCIM_UTILISATEUR_ILLISIBLE: &str =
    "UTILISATEUR ILLISIBLE : la base du plan de contrôle n'a pas pu lire l'utilisateur visé — ni sa \
     présence ni son absence n'est affirmée, et rien n'est modifié. La même demande peut être rejouée \
     telle quelle.";
// `P10.21-o` — L'ANTI-VERROUILLAGE QUI N'A PAS PU LIRE. Sœur SCIM de `CAUSE_DERNIER_ADMINISTRATEUR_NON_ETABLI`
// (rbac.rs), écrite pour l'exploitant de l'IdP : sans nom de table, la cause du moteur part sur la sortie
// d'erreur du démon (`scim_refuser_a_rejouer`).
pub(crate) const CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI: &str =
    "DERNIER ADMINISTRATEUR NON ÉTABLI : la base du plan de contrôle n'a pas pu lire les droits \
     d'administration de ce tenant — ce retrait pourrait lui retirer son dernier administrateur, il est \
     REFUSÉ plutôt que deviné. Rien n'est modifié ni attesté ; la même demande peut être rejouée telle \
     quelle.";
// `P10.21-o` — LA LISTE NON LUE. Le contrat `ListResponse` (RFC 7644 §3.4.2) n'a aucun champ où porter
// un aveu : `totalResults` y est lu comme le compte COMPLET. Une liste amputée servie en `200` est lue par
// l'IdP comme la vérité du tenant — il n'en voit pas les absents. Aucune liste n'est donc servie.
pub(crate) const CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE: &str =
    "LISTE DES UTILISATEURS ILLISIBLE : la base du plan de contrôle n'a pas pu lire les utilisateurs de ce \
     tenant ou leurs droits — aucune liste n'est servie plutôt qu'une liste amputée, qu'un fournisseur \
     d'identité lirait comme complète. Rien n'est modifié ; la même demande peut être rejouée telle quelle.";
// `P10.21-o` — LE GESTE A EU LIEU, SA REPRÉSENTATION N'A PAS PU ÊTRE RELUE. Ce n'est PAS le `503` des
// refus voisins : celui-là dit « rien n'a eu lieu, recommencez », et ce serait faux ici — l'écriture est
// faite et la ligne de contrôle est posée. Le statut est donc `500` (RFC 7644 §3.12, erreur interne), et
// la phrase dit ce qui est établi et ce qui ne l'est pas.
pub(crate) const CAUSE_SCIM_REPRESENTATION_NON_RELUE: &str =
    "REPRÉSENTATION NON RELUE : le geste demandé A EU LIEU et il est attesté au journal de contrôle ; seule \
     la relecture de l'utilisateur pour cette réponse a échoué — ni ses droits ni son état ne sont affirmés \
     ici. Un GET sur l'utilisateur les relit.";

/// Le refus d'un geste SCIM que la base n'a pas pris (ou pas pu lire) : `503` au format d'erreur SCIM 2.0,
/// rien d'attesté — l'IdP rejoue.
fn scim_refuser_a_rejouer(genre: &str, cause_du_geste: &str, cause_du_moteur: &str) -> Response {
    eprintln!("[scim] WARN geste '{genre}' refusé en 503, rien n'est attesté : {cause_du_moteur}");
    scim_err(StatusCode::SERVICE_UNAVAILABLE, cause_du_geste)
}

/// `P10.21-o` — un geste FAIT et ATTESTÉ dont la représentation n'a pas pu être relue : `500`, jamais le
/// `503` « rien n'a eu lieu » (voir `CAUSE_SCIM_REPRESENTATION_NON_RELUE`).
fn scim_avouer_la_representation_non_relue(genre: &str, cause_du_moteur: &str) -> Response {
    eprintln!("[scim] WARN geste '{genre}' FAIT et attesté, représentation NON relue (500) : {cause_du_moteur}");
    scim_err(StatusCode::INTERNAL_SERVER_ERROR, CAUSE_SCIM_REPRESENTATION_NON_RELUE)
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

/// La forme SCIM d'un utilisateur, à partir de droits DÉJÀ ÉTABLIS (lus, ou posés par le geste qui répond).
/// `active` se dérive des droits : un utilisateur sans droit dans ce tenant n'y a pas d'accès.
fn scim_user_representation(id: &str, name: &str, groups: Vec<Value>) -> Value {
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

/// Représentation SCIM d'un platform_user (+ ses grants dans `tenant` -> `groups`).
///
/// `P10.21-o` — UNE LECTURE RATÉE N'EST PLUS UN UTILISATEUR SANS DROIT. Préparation ratée, parcours raté
/// ou ligne illisible rendaient `groups: []` et donc `active: false` : un utilisateur EN PLACE était servi
/// à l'IdP comme désactivé, et un IdP qui réconcilie peut agir sur ce faux état. `Err` = rien d'établi ;
/// chaque appelant le dit selon ce que SON geste a déjà fait (`503` s'il n'a rien fait, `500` sinon).
fn scim_user_resource(cp: &ControlPlane, tenant: &str, id: &str, name: &str) -> rusqlite::Result<Value> {
    let roles: Vec<String> = {
        let conn = cp.conn.lock();
        let mut s = conn.prepare("SELECT role FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2")?;
        let lus = s.query_map(params![id, tenant], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        lus
    };
    let groups = roles.into_iter().map(|role| json!({ "value": role, "type": "direct" })).collect();
    Ok(scim_user_representation(id, name, groups))
}

/// HIGH #59 — TENANT-SCOPING : `platform_user` est GLOBAL (multi-tenant). Ne JAMAIS lister les identités
/// d'un AUTRE tenant. On joint par `grant` filtré sur le tenant du token -> seuls les users PROVISIONNÉS
/// dans CE tenant sont visibles (fuite cross-tenant fermée). DISTINCT : un user peut avoir plusieurs grants.
/// `P10.21-o` — la liste est lue EN BLOC : une ligne illisible fait échouer la lecture, jamais disparaître
/// un utilisateur (`.flatten()` l'aurait retiré en silence).
fn scim_utilisateurs_du_tenant(cp: &ControlPlane, tenant: &str) -> rusqlite::Result<Vec<(String, String)>> {
    let conn = cp.conn.lock();
    let mut s = conn.prepare(
        "SELECT DISTINCT p.id, p.name FROM platform_user p \
         JOIN \"grant\" g ON g.user_id=p.id WHERE g.tenant_id=?1 ORDER BY p.name",
    )?;
    let lus = s.query_map(params![tenant], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(lus)
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
    // `P10.21-o` — LA LISTE EST ENTIÈRE OU ELLE N'EST PAS SERVIE : la liste des utilisateurs ET les droits de
    // chacun. Le refus est le `503` SCIM des refus voisins, parce que le contrat `ListResponse` n'a aucun
    // champ où porter un aveu (voir `CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE`).
    let ids = match scim_utilisateurs_du_tenant(cp, &ctx.tenant) {
        Ok(ids) => ids,
        Err(e) => return scim_refuser_a_rejouer("scim.users.list", CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE, &e.to_string()),
    };
    let mut resources: Vec<Value> = Vec::new();
    for (id, name) in ids.into_iter().filter(|(_, name)| filter_name.as_ref().map(|f| f == name).unwrap_or(true)) {
        match scim_user_resource(cp, &ctx.tenant, &id, &name) {
            Ok(r) => resources.push(r),
            Err(e) => return scim_refuser_a_rejouer("scim.users.list", CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE, &e.to_string()),
        }
    }
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
        Ok(Some(n)) => match scim_user_resource(cp, &ctx.tenant, &id, &n) {
            Ok(r) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], r.to_string()).into_response(),
            // `P10.21-o` — présent, mais ses droits n'ont pas pu être lus : ni actif, ni désactivé.
            Err(e) => scim_refuser_a_rejouer("scim.user.get", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
        },
        Ok(None) => scim_err(StatusCode::NOT_FOUND, "User introuvable"),
        Err(e) => scim_refuser_a_rejouer("scim.user.get", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
    }
}

/// ANTI-LOCKOUT SCIM (HIGH #59, #64) — le retrait des grants de `uid` dans `tenant` VIDERAIT-il le DERNIER admin ?
/// True SEULEMENT si le user a un grant à AUTORITÉ ADMIN EFFECTIVE dans ce tenant (littéral `admin` OU rôle
/// composable base=admin) ET que c'est le seul (effective-base-aware depuis #64). Miroir de la garde de `tenants.rs`
/// (grant_delete).
///
/// `P10.21-o` — TROIS ISSUES : `Ok(true)` le retrait viderait le tenant, `Ok(false)` il ne le viderait pas,
/// `Err` NON ÉTABLI. La lecture du rôle passait par `unwrap_or(false)` : une lecture ratée suivie d'une
/// écriture qui passe retirait le DERNIER administrateur (mesuré, témoin `pafv_`). L'appelant refuse en 503.
///
/// `P10.21-r` — SUR LA CONNEXION DU GESTE, DÉJÀ EN TRANSACTION (`jouer_le_geste_garde`). Elle prenait `cp` et
/// verrouillait deux fois (le rôle, puis le compte), et l'écriture du retrait reprenait un troisième verrou : deux
/// déprovisionnements concurrents des deux derniers administrateurs passaient (mesuré, témoins `mpra_`). La lecture
/// est désormais `rbac::le_geste_retirerait_le_dernier_administrateur`, partagée avec les droits de tenant.
pub(crate) fn scim_would_orphan_last_admin(conn: &Connection, tenant: &str, uid: &str) -> rusqlite::Result<bool> {
    le_geste_retirerait_le_dernier_administrateur(conn, tenant, uid, None)
}

/// `P10.21-r` — POURQUOI UN DÉPROVISIONNEMENT SCIM (`PUT active=false`, `DELETE`) N'A PAS EU LIEU. Rien n'est écrit
/// ni attesté dans aucun des cas : la transaction du geste est annulée.
enum RefusDuDeprovisionnement {
    /// Il retirerait au tenant son dernier administrateur (409).
    DernierAdministrateur,
    /// L'anti-verrouillage n'a pas pu lire (503).
    NonEtabli(String),
    /// Présent à la lecture d'existence, plus de droit à retirer : déprovisionné entre-temps (404).
    Introuvable,
    /// La base n'a pas pris le retrait (503).
    NonEcrit(String),
}

/// `P10.21-r` — LE DÉPROVISIONNEMENT, GARDE ET RETRAIT DANS UNE TRANSACTION : l'anti-verrouillage est lu sur la
/// connexion du geste, puis le `DELETE` des droits est écrit et compté (`P10.21-l`), sans que le verrou soit relâché
/// entre les deux. `Ok(())` : validé ; sinon la réponse SCIM du refus (rien d'écrit, rien d'attesté).
fn scim_deprovisionner(cp: &ControlPlane, tenant: &str, id: &str, genre: &str, refus_409: &str) -> Result<(), Response> {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, point_de_course, IssueDuGesteGarde as Issue};
    let issue = {
        let conn = cp.conn.lock();
        jouer_le_geste_garde(&conn, "scim", "déprovisionnement SCIM", |conn| {
            match scim_would_orphan_last_admin(conn, tenant, id) {
                Ok(false) => {}
                Ok(true) => return Err(RefusDuDeprovisionnement::DernierAdministrateur),
                Err(e) => return Err(RefusDuDeprovisionnement::NonEtabli(e.to_string())),
            }
            point_de_course(&cp.db_path);
            match EcritureDuPlanDeControle::from(conn.execute("DELETE FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2", params![id, tenant])) {
                EcritureDuPlanDeControle::Ecrite => Ok(()),
                EcritureDuPlanDeControle::AucuneLigne => Err(RefusDuDeprovisionnement::Introuvable),
                EcritureDuPlanDeControle::Refusee(cause) => Err(RefusDuDeprovisionnement::NonEcrit(cause)),
            }
        })
    };
    match issue {
        Issue::Valide(()) => Ok(()),
        Issue::Refuse(RefusDuDeprovisionnement::DernierAdministrateur) => Err(scim_err(StatusCode::CONFLICT, refus_409)),
        Issue::Refuse(RefusDuDeprovisionnement::NonEtabli(cause)) => {
            Err(scim_refuser_a_rejouer(genre, CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI, &cause))
        }
        // Présent à la lecture, absent à l'écriture : déprovisionné entre-temps. Rien n'est retiré par CE geste, rien
        // n'est attesté ; la RFC 7644 §3.6 veut un 404 sur une ressource déjà supprimée.
        Issue::Refuse(RefusDuDeprovisionnement::Introuvable) => Err(scim_err(StatusCode::NOT_FOUND, "User introuvable")),
        Issue::Refuse(RefusDuDeprovisionnement::NonEcrit(cause)) => Err(scim_refuser_a_rejouer(genre, CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT, &cause)),
        Issue::NonOuvert(e) | Issue::NonValide(e) => Err(scim_refuser_a_rejouer(genre, CAUSE_SCIM_RETRAIT_DES_DROITS_NON_ECRIT, &e.to_string())),
    }
}

/// `P10.21-o` — LA MÊME QUESTION POUR LE RETRAIT D'UN SEUL RÔLE PAR `PATCH /Groups`, sur la connexion DÉJÀ
/// tenue (celle de la transaction du PATCH : les retraits précédents de la même demande sont vus). Le membre
/// porte-t-il ce rôle, et en resterait-il un administrateur effectif ? Mêmes trois issues ; la lecture
/// d'appartenance passait par `.is_ok()`, qui lisait l'échec comme « ne le porte pas ».
fn scim_retrait_du_role_viderait_le_dernier_admin(conn: &Connection, tenant: &str, uid: &str, role: &str) -> rusqlite::Result<bool> {
    use rusqlite::OptionalExtension as _;
    let porte_le_role = conn
        .query_row("SELECT 1 FROM \"grant\" WHERE user_id=?1 AND tenant_id=?2 AND role=?3", params![uid, tenant, role], |_| Ok(()))
        .optional()?
        .is_some();
    if !porte_le_role {
        return Ok(false);
    }
    Ok(effective_admin_grant_count_conn(conn, tenant)? <= 1)
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
    //
    // `P10.21-r` — LES DROITS DE LA DEMANDE S'ÉCRIVENT DANS UNE TRANSACTION (forme commune `jouer_le_geste_garde`), et un
    // droit qui écraserait le rôle du DERNIER administrateur effectif du tenant est refusé (409, aucun droit de la
    // demande appliqué). MESURÉ le 2026-09-25 sur la forme d'avant (témoins `mpra_`) : `POST /Users` du seul
    // administrateur avec le groupe `viewer` rendait 201 — l'`UPSERT` écrasait son rôle et le tenant n'avait plus
    // d'administrateur ; chaque droit s'écrivait en autocommit (un refus au second laissait le premier en place).
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    let demandes: Vec<String> = b
        .get("groups")
        .and_then(|g| g.as_array())
        .map(|groups| groups.iter().filter_map(|g| g.get("value").and_then(|v| v.as_str())).filter(|r| valid_grant_role(r)).map(String::from).collect())
        .unwrap_or_default();
    let mut applied: Vec<String> = Vec::new();
    if !demandes.is_empty() {
        let issue = {
            let conn = cp.conn.lock();
            jouer_le_geste_garde(&conn, "scim", "droits d'un utilisateur SCIM provisionné", |conn| -> Result<Vec<String>, Response> {
                let mut ecrits = Vec::new();
                for role in &demandes {
                    match le_geste_retirerait_le_dernier_administrateur(conn, &ctx.tenant, &id, Some(role)) {
                        Ok(false) => {}
                        Ok(true) => {
                            return Err(scim_err(
                                StatusCode::CONFLICT,
                                "dernier administrateur du tenant — droit qui le rétrograderait refusé (anti-lockout) ; aucun \
                                 droit de la demande n'est appliqué, l'utilisateur existe",
                            ))
                        }
                        Err(e) => return Err(scim_refuser_a_rejouer("scim.user.provision", CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI, &e.to_string())),
                    }
                    match EcritureDuPlanDeControle::from(conn.execute(
                        "INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3) \
                         ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                        params![id, ctx.tenant, role],
                    )) {
                        EcritureDuPlanDeControle::Ecrite => ecrits.push(role.clone()),
                        EcritureDuPlanDeControle::AucuneLigne => {}
                        EcritureDuPlanDeControle::Refusee(cause) => {
                            return Err(scim_refuser_a_rejouer("scim.user.provision", CAUSE_SCIM_DROITS_DEMANDES_NON_ECRITS, &cause))
                        }
                    }
                }
                Ok(ecrits)
            })
        };
        applied = match issue {
            Issue::Valide(ecrits) => ecrits,
            Issue::Refuse(refus) => return refus,
            Issue::NonOuvert(e) | Issue::NonValide(e) => {
                return scim_refuser_a_rejouer("scim.user.provision", CAUSE_SCIM_DROITS_DEMANDES_NON_ECRITS, &e.to_string())
            }
        };
    }
    // `P10.20-z` — LE CONTRAT DE CETTE RÉPONSE EST ÉTRANGER (SCIM 2.0, lu par un fournisseur d'identité, pas
    // par un exploitant) : il n'a aucun champ où porter un aveu. Un maillon manquant reste à l'aveu de la
    // primitive, sur la sortie d'erreur. Même classement pour les trois autres gestes SCIM de ce fichier.
    control_ledger_append(&st, "scim.user.provision", "scim", &ctx.tenant, &format!("user '{username}' (id={id}) grants=[{}]", applied.join(",")))
        .laisser_a_l_aveu_de_la_primitive();
    // `P10.21-o` — la représentation est RELUE (un utilisateur existant peut déjà porter un droit que cette
    // demande ne nomme pas) ; relue en échec, elle n'est pas fabriquée : le geste, lui, est fait et attesté.
    match scim_user_resource(cp, &ctx.tenant, &id, &username) {
        Ok(r) => (StatusCode::CREATED, [(header::CONTENT_TYPE, "application/scim+json")], r.to_string()).into_response(),
        Err(e) => scim_avouer_la_representation_non_relue("scim.user.provision", &e.to_string()),
    }
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
        // viderait le dernier admin (l'IdP ne doit jamais orpheliner un tenant sans admin). `P10.21-o` — une
        // lecture ratée REFUSE (503), elle ne permet plus. `P10.21-l` — LE RETRAIT EST COMPTÉ AVANT D'ÊTRE ATTESTÉ.
        // `P10.21-r` — garde et retrait dans UNE transaction, sous un seul verrou (`scim_deprovisionner`).
        if let Err(refus) = scim_deprovisionner(
            cp,
            &ctx.tenant,
            &id,
            "scim.user.deprovision",
            "dernier administrateur du tenant — désactivation refusée (anti-lockout)",
        ) {
            return refus;
        }
        control_ledger_append(&st, "scim.user.deprovision", "scim", &ctx.tenant, &format!("user '{name}' (id={id}) désactivé -> grants retirés"))
            .laisser_a_l_aveu_de_la_primitive();
        // `P10.21-o` — L'ÉTAT RENDU EST CELUI QUE LE GESTE VIENT D'ÉTABLIR : le `DELETE` a retiré TOUS les
        // droits de ce membre dans ce tenant (clé primaire `(user_id, tenant_id)`) et il est compté `Ecrite`.
        // Aucune relecture ne peut donc manquer ici — c'est un fait posé, pas un fait supposé.
        return (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], scim_user_representation(&id, &name, Vec::new()).to_string())
            .into_response();
    }
    // `P10.21-o` — rien n'a été modifié : une relecture ratée est le `503` d'un utilisateur illisible.
    match scim_user_resource(cp, &ctx.tenant, &id, &name) {
        Ok(r) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], r.to_string()).into_response(),
        Err(e) => scim_refuser_a_rejouer("scim.user.replace", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string()),
    }
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
    // dernier admin (mirroir de tenants.rs/grant_delete). `P10.21-o` — une lecture ratée REFUSE (503), elle ne permet
    // plus. `P10.21-l` — même comptage que le PUT `active=false`. `P10.21-r` — garde et retrait dans UNE transaction.
    if let Err(refus) =
        scim_deprovisionner(cp, &ctx.tenant, &id, "scim.user.deprovision", "dernier administrateur du tenant — deprovisioning refusé (anti-lockout)")
    {
        return refus;
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
    // `P10.21-o` — LA DEMANDE EST ATOMIQUE (RFC 7644 §3.5.2). Chaque opération était écrite en autocommit :
    // un refus à la N-ième opération — anti-lockout `409`, écriture ou lecture refusée `503` — laissait
    // appliquées les N-1 précédentes, pendant que la réponse disait « refusé » et que rien n'était attesté
    // (mesuré, témoins `pafv_` : un retrait d'administrateur restait fait sous un `409`). Toutes les
    // opérations vivent désormais dans UNE transaction : tout refus avant la validation la défait, et la ligne de
    // contrôle n'est posée qu'APRÈS la validation. `P10.21-r` — la transaction est celle de la forme commune
    // (`jouer_le_geste_garde`, qui dit au journal un `BEGIN` refusé), et un AJOUT qui écraserait le rôle du dernier
    // administrateur effectif est refusé comme son retrait.
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    let issue = {
        let conn = cp.conn.lock();
        jouer_le_geste_garde(&conn, "scim", "opérations de groupe SCIM", |conn| -> Result<(i64, i64), Response> {
            let (mut added, mut removed) = (0i64, 0i64);
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
                        Err(e) => return Err(scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_UTILISATEUR_ILLISIBLE, &e.to_string())),
                    }
                    // `P10.21-l` — chaque écriture est COMPTÉE : un membre n'entre dans `added`/`removed` (donc au
                    // journal de contrôle) que si sa ligne est écrite ; un refus rend le 503 avant toute trace.
                    match action.as_str() {
                        "add" | "replace" => {
                            // `P10.21-r` — L'AJOUT ÉCRASE LE RÔLE (un seul droit par membre et par tenant). MESURÉ le
                            // 2026-09-25 sur la forme d'avant (témoins `mpra_`) : `add` du SEUL administrateur au
                            // groupe `viewer` rendait 200 et laissait le tenant sans administrateur — aucune garde.
                            match le_geste_retirerait_le_dernier_administrateur(conn, &ctx.tenant, &uid, Some(&role)) {
                                Ok(false) => {}
                                Ok(true) => {
                                    return Err(scim_err(
                                        StatusCode::CONFLICT,
                                        "dernier administrateur du tenant — ajout qui le rétrograderait refusé (anti-lockout) ; la \
                                         demande est atomique, aucune de ses opérations n'est appliquée",
                                    ))
                                }
                                Err(e) => {
                                    return Err(scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI, &e.to_string()))
                                }
                            }
                            match EcritureDuPlanDeControle::from(conn.execute(
                                "INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3) ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                                params![uid, ctx.tenant, role],
                            )) {
                                EcritureDuPlanDeControle::Ecrite => added += 1,
                                EcritureDuPlanDeControle::AucuneLigne => {}
                                EcritureDuPlanDeControle::Refusee(cause) => {
                                    return Err(scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE, &cause))
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
                            // `P10.21-o` — une lecture ratée REFUSE (503) au lieu d'ouvrir la garde, et l'un comme
                            // l'autre refus défont les opérations précédentes de la demande.
                            if effective_base_role(&role) == "admin" {
                                match scim_retrait_du_role_viderait_le_dernier_admin(conn, &ctx.tenant, &uid, &role) {
                                    Ok(false) => {}
                                    Ok(true) => {
                                        return Err(scim_err(
                                            StatusCode::CONFLICT,
                                            "dernier administrateur du tenant — retrait de membre refusé (anti-lockout) ; la demande est \
                                             atomique, aucune de ses opérations n'est appliquée",
                                        ))
                                    }
                                    Err(e) => {
                                        return Err(scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI, &e.to_string()))
                                    }
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
                                    return Err(scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE, &cause))
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok((added, removed))
        })
    };
    // `P10.21-o` — la validation est le dernier geste avant la trace : refusée, rien n'est appliqué et rien n'est attesté.
    let (added, removed) = match issue {
        Issue::Valide(compte) => compte,
        Issue::Refuse(refus) => return refus,
        Issue::NonOuvert(e) | Issue::NonValide(e) => {
            return scim_refuser_a_rejouer("scim.group.patch", CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE, &e.to_string())
        }
    };
    control_ledger_append(&st, "scim.group.patch", "scim", &ctx.tenant, &format!("role '{role}' +{added}/-{removed} membres"))
        .laisser_a_l_aveu_de_la_primitive();
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/scim+json")], json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "id": role, "displayName": role }).to_string()).into_response()
}
