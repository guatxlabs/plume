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
//!  - le balayage `router_viewer_cannot_reach_any_mutating_route` LIT la table de routage dans `server/groupes_de_routes.rs` :
//!    ces deux routes y entrent AUTOMATIQUEMENT, sans qu'on ait à les inscrire quelque part ;
//!  - `route_denied_perm("/api/purge") == Some("purge_events")` : un rôle composable base=admin peut se voir
//!    RETIRER la purge tout en gardant le reste de l'autorité admin (soustractif, jamais additif) ;
//!  - le re-check `au.is_admin()` dans chaque handler (défense en profondeur, miroir de #59) ;
//!  - et, en mode 1, une purge cross-tenant par un super-admin passe déjà par le break-glass de
//!    `resolve_tenant_access` (mutation -> raison obligatoire + marqueur opérateur non désactivable).
use crate::*;

/// La surface HTTP de purge est-elle ARMÉE ? Défaut : NON.
pub(crate) fn purge_api_enabled() -> bool {
    #[cfg(test)]
    if let Some(armee) = porte_de_purge_de_temoin::lue() {
        return armee;
    }
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

/// STATUT HTTP d'un refus de purge. Un REFUS n'est pas une erreur serveur : c'est une décision. 409 CONFLICT
/// porte « l'état LU du système s'y oppose » (hold actif, tier froid, case citant, index désynchronisé, jeton
/// caduc, inscription et suppression qui divergent) ; 400 les entrées manquantes.
///
/// CHOIX ÉCRIT (`P10.31-x`) — UNE LECTURE NON FAITE A UNE SEULE NATURE, 500, quelle que soit la forme de la
/// lecture qu'elle frappe. Une même cause (l'interruption par le quota, un verrou, un catalogue illisible)
/// sortait en 500 `db` sur un `query_row` (COUNT, bornes, présence d'une table) et en 409 `plan_row_unread`
/// sur une ligne d'itérateur (ventilation, échantillon, ids cités), et en 409 `legal_hold_undetermined` /
/// `legal_hold_unread` sur la table ou une ligne de rétention légale : l'appelant lisait une DÉCISION là où
/// rien n'avait été décidé, seulement pas lu. Ces trois codes rejoignent donc `db` sous 500 ; leurs codes
/// machine restent distincts parce qu'ils nomment le SITE (et, pour la rétention légale, qu'une preuve est
/// peut-être retenue), pas la nature. Le refus reste fail-closed et rien n'est supprimé, comme avant. 500 et
/// non 503 : c'est le contrat déjà servi pour `db`, que la CLI et les intégrations lisent.
///
/// `P10.29-h` — LA TRANSACTION NON OUVERTE EST UN 503, comme toute route dont le `BEGIN` est refusé
/// (`ouvrir_la_transaction_du_geste`) : rien n'a été lu de travers ni décidé, l'écrivain n'était pas disponible.
pub(crate) fn statut_du_refus_de_purge(e: &PurgeRefusal) -> StatusCode {
    match e {
        PurgeRefusal::ReasonRequired => StatusCode::BAD_REQUEST,
        PurgeRefusal::TransactionNotOpened => StatusCode::SERVICE_UNAVAILABLE,
        PurgeRefusal::Db(_)
        | PurgeRefusal::TransactionLeftOpen { .. }
        | PurgeRefusal::PlanRowUnread { .. }
        | PurgeRefusal::LegalHoldUndetermined
        | PurgeRefusal::LegalHoldUnread(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    }
}

/// Phrase SERVIE pour une lecture de la base non faite qui porte un texte du moteur (`plan_row_unread`,
/// `legal_hold_unread` : deux SITES de lecture). Fixe : le texte du moteur part au journal `[purge]`, jamais au client.
pub(crate) const PHRASE_PURGE_LECTURE_DE_LA_BASE_NON_FAITE: &str = "REFUS — lecture de la base NON FAITE : la purge \
     n'a rien décidé, aucune ligne supprimée. La cause est écrite au journal du démon.";

/// Phrase SERVIE pour `db`. NEUTRE : `db` porte des lectures (plan, relecture dans la transaction) ET des écritures
/// refusées de l'exécution (inscription au registre, `DELETE`, reconstruction des rollups, `COMMIT`) ; la phrase ne dit
/// ni lecture ni écriture, la nature exacte est au journal. « aucune ligne supprimée » est VRAI pour chaque site : une
/// lecture du plan n'écrit rien ; une écriture refusée et un `COMMIT` refusé sortent de `purge_apply` après le
/// `ROLLBACK` de toute la transaction (registre compris), et un `COMMIT` refusé ne rend rien durable (commit atomique
/// du moteur). Si ce `ROLLBACK` est lui-même refusé et que la connexion reste en transaction, ce n'est plus `db` qui
/// sort mais `transaction_left_open` (`PHRASE_PURGE_TRANSACTION_RESTEE_OUVERTE`, `P10.29-l`) : la phrase de `db` ne
/// couvre que les refus annulés.
pub(crate) const PHRASE_PURGE_REFUS_DE_LA_BASE: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, \
     aucune ligne supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

/// Phrase SERVIE pour `transaction_left_open` (`P10.29-l`) : l'exécution refusée n'a pas pu être annulée, la connexion est
/// restée en transaction. Fixe : l'étape et les deux textes du moteur sont sur la ligne `[<id>] [purge] ERREUR` écrite par
/// `purge::annuler_la_purge`, sous l'identifiant servi. Elle ne dit PAS « aucune ligne supprimée » : rien n'est validé,
/// mais l'état de l'écrivain n'est pas celui d'un refus propre. Elle ne dit PAS non plus « les écritures suivantes sont
/// refusées » : vrai pour un geste qui ouvre par `BEGIN`, faux pour une écriture en autocommit sur l'écrivain (ex.
/// `handlers/alerting.rs`, état d'une règle avancée, sous `db.lock()` sans `BEGIN`), acceptée dans la transaction pendante puis
/// perdue à la fermeture.
pub(crate) const PHRASE_PURGE_TRANSACTION_RESTEE_OUVERTE: &str = "REFUS — la base a refusé l'opération, puis l'annulation \
     de la transaction : la purge n'est pas validée, mais la transaction reste ouverte jusqu'à sa fermeture ou au \
     redémarrage du démon : un geste qui ouvre sa propre transaction est refusé, une écriture faite sans transaction propre \
     y est prise puis perdue à la fermeture. La cause est écrite au journal du démon, sous l'identifiant servi.";

/// La RÉPONSE servie par les deux routes pour un refus : le statut est celui de `statut_du_refus_de_purge`
/// (seul juge de la nature), le corps nomme le code machine. `pub(crate)` pour qu'un témoin juge ce que la
/// route SERT, pas seulement la table des statuts (`P10.31-x`).
///
/// `P10.29-l` — TEXTE DU MOTEUR HORS DU CORPS. `db`, `plan_row_unread` et `legal_hold_unread` portent le texte
/// rendu par SQLite (et, pour certains `db`, une phrase du produit qui l'enveloppe) : le corps servi prend une phrase
/// fixe (`PHRASE_PURGE_REFUS_DE_LA_BASE` pour `db`, neutre entre lecture et écriture ; `PHRASE_PURGE_LECTURE_DE_LA_BASE_NON_FAITE`
/// pour les deux sites de lecture) et un champ `id`, l'identifiant de corrélation tiré de la séquence de `err_json`.
/// Le texte part à UNE ligne `[<id>] [purge] WARN` (même identifiant, code machine, site de la lecture pour
/// `plan_row_unread`, texte échappé sur une ligne), sans la phrase du refus. Le tenant n'y est pas nommé : la fabrique
/// ne le reçoit pas, l'identifiant relie la ligne au ticket. Statuts inchangés. Les autres refus (décisions lues, entrée
/// manquante, transaction non ouverte, `legal_hold_undetermined`) gardent leur corps à l'octet, sans `id` : leur texte
/// ne cite pas le moteur. Le `Display` de `PurgeRefusal` reste celui de la CLI (l'opérateur y détient déjà la clé de la
/// base). La console ne lit pas `/api/purge`.
pub(crate) fn purge_refusal_response(e: PurgeRefusal) -> Response {
    let code = statut_du_refus_de_purge(&e);
    let refusal = purge_refusal_code(&e);
    let texte_du_moteur = match &e {
        PurgeRefusal::Db(texte) => Some((format!("refus de la base ({refusal})"), PHRASE_PURGE_REFUS_DE_LA_BASE, texte)),
        PurgeRefusal::LegalHoldUnread(texte) => {
            Some((format!("lecture de la base non faite ({refusal})"), PHRASE_PURGE_LECTURE_DE_LA_BASE_NON_FAITE, texte))
        }
        PurgeRefusal::PlanRowUnread { site, cause } => {
            Some((format!("lecture de la base non faite ({refusal}, {site})"), PHRASE_PURGE_LECTURE_DE_LA_BASE_NON_FAITE, cause))
        }
        _ => None,
    };
    // `P10.29-l` — la ligne de journal est déjà écrite au site de l'annulation, sous l'identifiant porté par la variante :
    // la réponse le reprend tel quel, sans seconde ligne ni second identifiant.
    if let PurgeRefusal::TransactionLeftOpen { id, .. } = &e {
        return (code, Json(json!({ "ok": false, "refusal": refusal, "message": PHRASE_PURGE_TRANSACTION_RESTEE_OUVERTE, "id": id })))
            .into_response();
    }
    match texte_du_moteur {
        Some((nature, phrase, texte)) => {
            let id = crate::identifiant_de_correlation();
            eprintln!("[{id}] [purge] WARN refus servi, {nature} : {texte:?}");
            (code, Json(json!({ "ok": false, "refusal": refusal, "message": phrase, "id": id }))).into_response()
        }
        None => (code, Json(json!({ "ok": false, "refusal": refusal, "message": e.to_string() }))).into_response(),
    }
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

/// Point d'injection de TÉMOIN (`P10.32-b`) : force l'état de la porte sur le FIL COURANT, sans poser
/// `PLUME_PURGE_API` dans l'environnement du processus (qui ferait courir `purge_http_surface_is_closed_by_default`
/// et tout fil voisin). Hors `cfg(test)`, ce module n'existe pas : la porte de production ne lit que la
/// configuration, fermée par défaut. Un `#[tokio::test]` (exécuteur mono-fil) joue la route sur ce même fil.
#[cfg(test)]
pub(crate) mod porte_de_purge_de_temoin {
    use std::cell::Cell;
    thread_local! {
        static FORCEE: Cell<Option<bool>> = const { Cell::new(None) };
    }
    /// Garde : la porte reprend la lecture de la configuration quand elle tombe, panique comprise.
    pub(crate) struct Ouverte(());
    impl Drop for Ouverte {
        fn drop(&mut self) {
            FORCEE.with(|f| f.set(None));
        }
    }
    pub(crate) fn ouvrir() -> Ouverte {
        FORCEE.with(|f| f.set(Some(true)));
        Ouverte(())
    }
    pub(crate) fn lue() -> Option<bool> {
        FORCEE.with(|f| f.get())
    }
}
