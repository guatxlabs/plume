//! Ergonomie des dashboards (#54) — SUR-ENSEMBLE Grafana/Splunk, ADDITIF & INERTE en mode 0 :
//!   - `library_panel` : panneaux RÉUTILISABLES (édités une fois, référencés par N dashboards ; la
//!     résolution de la définition EXÉCUTÉE vit dans le coffre `panneau_resolu.rs`, et c'est elle que
//!     la porte « SQL brut = admin » emprunte — P7.13-a) ;
//!   - `playlist` : listes ORDONNÉES de dashboards qui défilent (NOC wall-board) ;
//!   - `dashboard_snapshot` : capture POINT-IN-TIME des données rendues, partageable en LECTURE SEULE via
//!     un token CSPRNG. Deux garanties DISTINCTES, et ce bandeau n'en annonçait qu'une seule en les
//!     mélangeant (« hérite #45 + RBAC ») alors que la seconde était ABSENTE :
//!       1. CHAMPS — la capture passe par le CHEMIN GXQL MASQUÉ (effective_masks du rôle du créateur)
//!          -> un snapshot ne fige jamais un CHAMP hors de la portée du créateur (#45) ;
//!       2. PANNEAUX — la capture reçoit désormais la PORTÉE DE LECTURE du créateur (`PorteeLecture`,
//!          paramètre OBLIGATOIRE) -> un panneau PRIVÉ d'un autre propriétaire n'y entre pas. Mesuré
//!          le 2026-08-03 sur `3256e4d` AVANT ce correctif : `dash_get` -> `panels: []` et `panel_data`
//!          -> 403 pour ce tiers, mais `snapshot_create` -> 200 avec la ligne privée figée dedans.
//! CRUD = editor+ (route_min_role section 7) ; lecture d'un snapshot par token = viewer+ (Read, section 6).
use crate::*;
use rusqlite::OptionalExtension;
use crate::handlers::transaction_validee::{ouvrir_le_garde_du_geste, rendre_apres_validation_du_garde};

// ---------- helpers communs ----------
/// Le compte peut-il modifier CET objet (library_panel / playlist) ? admin: toujours ; sinon: propriétaire,
/// partagé, ou ownership vide (legacy). Miroir de `dash_editable`/`view_*`. `table` allowlistée (jamais du body).
/// P7.13-a : le PRÉDICAT lui-même n'est plus réécrit ici — c'est `panneau_resolu::lisible_par`, le MÊME que
/// celui qui filtre l'inventaire (`library_panels_list`) et que celui qui autorise un RATTACHEMENT. Trois
/// surfaces, une seule expression : elles ne peuvent plus diverger.
///
/// `P10.33-l` — TROIS ISSUES : `Ok(true)` le droit est établi, `Ok(false)` le refus de droit est établi
/// (403), `Err` la lecture du propriétaire et de la visibilité a été refusée — ni droit ni refus ne sont établis. La
/// forme d'avant (`Err(_) => false`) rendait 403 sur une lecture refusée : un refus de droit inventé, pour un objet que
/// le compte a peut-être le droit de modifier.
fn ergo_editable(conn: &Connection, au: &AuthUser, table: &str, id: i64) -> rusqlite::Result<bool> {
    if au.is_admin() {
        return Ok(true);
    }
    let sql = match table {
        "library_panel" => "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM library_panel WHERE id=?1",
        "playlist" => "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM playlist WHERE id=?1",
        _ => return Ok(false),
    };
    let (owner, vis) = conn.query_row(sql, params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    Ok(panneau_resolu::lisible_par(&owner, &vis, au))
}

/// `P10.33-l` — LA PORTE D'ÉDITION D'UN GESTE, rendue en réponse : `None` le geste peut continuer ; `Some(403)` refus
/// de droit établi ; `Some(404)` l'objet n'a plus de ligne (l'appelant vient d'en lire l'existence sous le même verrou
/// d'écrivain : seul un autorisateur à état l'atteint, dans le témoin) ; `Some(503 nommé)` la lecture du droit a été
/// refusée — la cause du moteur part au journal avec le reste de la phrase, par `err_json`.
fn refus_de_la_porte_d_edition(conn: &Connection, au: &AuthUser, table: &str, id: i64) -> Option<Response> {
    match ergo_editable(conn, au, table, id) {
        Ok(true) => None,
        Ok(false) => Some(StatusCode::FORBIDDEN.into_response()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Some(StatusCode::NOT_FOUND.into_response()),
        Err(e) => Some(err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_DROIT_D_EDITION_NON_LU} ({table} #{id} : {e})"))),
    }
}

/// `P10.20-w` (gestes de `dash_ergonomics`) — UNE écriture sur une ligne dont l'existence vient d'être lue :
/// `Ok(1)` seul est un fait. `Err` (refus du moteur) et `Ok(n != 1)` (un déclencheur qui ignore l'écriture)
/// rendent la cause, que le geste porte dans son refus.
fn une_ligne_ecrite(issue: rusqlite::Result<usize>, quoi: &str) -> Result<(), String> {
    match issue {
        Ok(1) => Ok(()),
        Ok(n) => Err(format!("{quoi} : {}", crate::handlers::dashboards::lignes_ecrites_au_lieu_d_une(n))),
        Err(e) => Err(format!("{quoi} : {e}")),
    }
}

/// `P10.20-w` — la modification d'une définition de bibliothèque refusée : rien n'en est écrit.
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE: &str = "PANNEAU DE BIBLIOTHÈQUE INCHANGÉ : la base n'a pas \
     pris l'écriture de la modification ou n'en a écrit aucune ligne, et la transaction est annulée — la définition, sa \
     visibilité et le cache des panneaux qui la référencent sont ceux d'avant. Réessayez ; si le refus persiste, la base \
     est en lecture seule, pleine ou verrouillée.";
/// `P10.20-w` — le `BEGIN` de cette modification refusé.
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "PANNEAU DE BIBLIOTHÈQUE \
     INCHANGÉ : la base n'a pas pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un \
     autre geste pendante sur l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé \
     ou bloqué.";
/// `P10.20-w` — la suppression d'une définition de bibliothèque refusée : la définition reste, ses référents aussi.
/// `P10.33-l` (vague AG) — la phrase couvre aussi le détachement des référents : refusé, compté sans succès, ou qui en
/// détache un autre nombre que celui compté dans la même transaction.
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME: &str = "PANNEAU DE BIBLIOTHÈQUE NON SUPPRIMÉ : la base n'a \
     pas pris l'effacement de la définition ou le détachement de chacun de ses référents, et la transaction est annulée \
     — elle a refusé une écriture, n'a effacé aucune définition, ou n'a pas compté ou pas détaché tous les panneaux qui la \
     référencent : la définition existe toujours et ces panneaux y restent rattachés. Réessayez ; si le refus persiste, \
     la base est en lecture seule, pleine ou verrouillée.";
/// `P10.20-w` — le `BEGIN` de cette suppression refusé.
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "PANNEAU DE BIBLIOTHÈQUE \
     NON SUPPRIMÉ : la base n'a pas pris la transaction de la suppression (BEGIN refusé : verrou tenu, ou transaction \
     d'un autre geste pendante sur l'écrivain) — RIEN n'est écrit : la définition et ses rattachements sont intacts. \
     Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P10.33-l` — la modification d'une liste de lecture refusée : rien n'en est écrit. Servie en corps du 503 de
/// `playlist_update` (et au journal par `err_json`), à l'ouverture que la console sait lire
/// (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_LISTE_DE_LECTURE_INCHANGEE: &str = "LISTE DE LECTURE INCHANGÉE : la base n'a pas pris l'écriture \
     de la modification ou n'en a écrit aucune ligne, et la transaction est annulée — le nom, l'intervalle, les tableaux \
     et la visibilité de la liste sont ceux d'avant (une liste partagée le reste). Réessayez ; si le refus persiste, la \
     base est en lecture seule, pleine ou verrouillée.";
/// `P10.33-l` — le `BEGIN` de cette modification refusé. Servie en corps du 503 ; ouverture de la forme
/// `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`.
pub(crate) const CAUSE_LISTE_DE_LECTURE_INCHANGEE_TRANSACTION_NON_OUVERTE: &str = "LISTE DE LECTURE INCHANGÉE : la base \
     n'a pas pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P10.33-l` — la suppression d'une liste de lecture refusée : la liste reste, avec sa visibilité.
pub(crate) const CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE: &str = "LISTE DE LECTURE NON SUPPRIMÉE : la base n'a pas pris \
     l'effacement de la liste ou n'en a effacé aucune ligne, et la transaction est annulée — la liste existe toujours, \
     avec sa visibilité (partagée si elle l'était). Réessayez ; si le refus persiste, la base est en lecture seule, \
     pleine ou verrouillée.";
/// `P10.33-l` — le `BEGIN` de cette suppression refusé.
pub(crate) const CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE: &str = "LISTE DE LECTURE NON SUPPRIMÉE : \
     la base n'a pas pris la transaction de la suppression (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : la liste est intacte. Réessayez ; s'il est refusé encore, l'écrivain \
     est occupé ou bloqué.";
/// `P10.33-l` — l'existence de la liste n'a pas pu être lue : ni absence (404) ni présence ne sont établies, rien
/// n'est écrit.
pub(crate) const CAUSE_LISTE_DE_LECTURE_NON_LUE: &str = "LISTE DE LECTURE NON LUE : la base a refusé la lecture qui \
     établit son existence — ce n'est pas une absence, et RIEN n'est écrit. Réessayez ; si le refus persiste, la base \
     est illisible ou verrouillée.";
/// `P10.33-l` — le droit de modifier un panneau de bibliothèque ou une liste de lecture n'a pas pu être lu (propriétaire
/// et visibilité) : ce n'est pas un refus de droit (403), et rien n'est écrit.
pub(crate) const CAUSE_DROIT_D_EDITION_NON_LU: &str = "DROIT D'ÉDITION NON LU : la base a refusé la lecture du \
     propriétaire et de la visibilité de l'objet — ce n'est pas un refus de droit, et RIEN n'est écrit. Réessayez ; si le \
     refus persiste, la base est illisible ou verrouillée.";
// `P10.20-l` et `P10.33-l` (vague AE) — UNE LECTURE RATÉE N'EST PAS UNE ABSENCE. Trois gestes lisaient leur ligne par
// `match … { Ok(x) => …, Err(_) => 404 }` : une définition, un tableau de bord ou un instantané ILLISIBLE se disait
// introuvable. Décision par défaut de la vague AE : trois issues par `.optional()` — lue, le geste suit ; absente, le
// 404 d'avant à l'identique (corps compris) ; lecture ratée, 503 nommé, RIEN n'est écrit, aucun droit n'est jugé, la
// cause du moteur au journal seul (jamais dans le corps). Ces phrases ne nomment ni `BEGIN` ni `COMMIT` ni une
// transaction annulée : aucune transaction n'a été refusée, c'est la lecture qui manque — la console les lit en
// refus nommé, phrase entière (web/core.js, `refus_nomme`).

/// `P10.33-l` — le mode de requête (GXQL ou SQL brut) d'un panneau de bibliothèque n'a pas été lu : rien n'est écrit,
/// et le garde-fou editor -> SQL brut reste fermé (aucun mode n'est supposé).
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU: &str = "PANNEAU DE BIBLIOTHÈQUE INCHANGÉ : la base n'a \
     pas rendu ce panneau de bibliothèque (son mode de requête, GXQL ou SQL brut) — ce n'est PAS une absence, c'est une \
     lecture qui n'a pas eu lieu. RIEN n'est écrit : la définition, son mode et sa visibilité sont ceux d'avant. \
     Réessayez ; si le refus persiste, la table des panneaux de bibliothèque est illisible.";
/// `P10.20-l` — le tableau de bord à capturer n'a pas été lu : rien n'est capturé, aucun jeton n'est émis.
pub(crate) const CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU: &str = "INSTANTANÉ NON CRÉÉ : la base n'a pas rendu \
     ce tableau de bord (nom, propriétaire, visibilité) — ce n'est PAS « dashboard introuvable », c'est une lecture qui \
     n'a pas eu lieu. RIEN n'est capturé ni partagé : aucun jeton n'est émis. Réessayez ; si le refus persiste, la table \
     des tableaux de bord est illisible.";
/// `P10.20-l` — l'auteur de l'instantané à révoquer n'a pas été lu : rien n'est supprimé, le droit n'est pas jugé.
pub(crate) const CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU: &str = "INSTANTANÉ NON SUPPRIMÉ : la base n'a pas rendu cet \
     instantané (son auteur) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de le \
     révoquer n'est pas jugé. RIEN n'est supprimé : s'il existe, l'instantané RESTE LISIBLE par son jeton de partage. \
     Réessayez ; si le refus persiste, la table des instantanés est illisible.";
/// `P10.33-l` (vague AF) — l'existence de la définition à supprimer n'a pas été lue : rien n'est détaché ni supprimé.
pub(crate) const CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU: &str = "PANNEAU DE BIBLIOTHÈQUE NON SUPPRIMÉ : la \
     base n'a pas rendu ce panneau de bibliothèque — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et \
     le droit de le supprimer n'est pas jugé. RIEN n'est détaché ni supprimé : la définition et les panneaux qui la \
     référencent sont intacts. Réessayez ; si le refus persiste, la table des panneaux de bibliothèque est illisible.";
/// `P10.20-l` (vague AF) — l'instantané demandé par son jeton n'a pas été lu : ce n'est pas une absence (ni une
/// révocation), rien n'est servi.
pub(crate) const CAUSE_INSTANTANE_NON_LU: &str = "INSTANTANÉ NON LU : la base n'a pas rendu l'instantané de ce jeton \
     — ce n'est PAS une absence ni une révocation, c'est une lecture qui n'a pas eu lieu. RIEN n'est servi. Réessayez ; si \
     le refus persiste, la table des instantanés est illisible.";
/// `P10.20-w` — la révocation d'un instantané refusée : il reste lisible par son jeton.
pub(crate) const CAUSE_INSTANTANE_NON_SUPPRIME: &str = "INSTANTANÉ NON SUPPRIMÉ : la base a refusé la suppression (ou \
     n'a supprimé aucune ligne) — l'instantané existe toujours et RESTE LISIBLE par son jeton de partage. Réessayez ; si \
     le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

fn vis_of(b: &Value) -> &'static str {
    if b.get("visibility").and_then(|v| v.as_str()) == Some("private") { "private" } else { "shared" }
}

// =====================================================================================
// LIBRARY PANELS
// =====================================================================================
pub(crate) async fn library_panels_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) — portée par `ident`, dont
    // `is_admin()` est la première branche.
    // `P11.20-n` — `ident` porte l'identité jusqu'au coffre : le drapeau `editable` et le filtre
    // `lisible_par` rendent la MÊME décision, écrite une seule fois.
    let ident = au.clone();
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "error": "lecture NON FAITE : aucune connexion de lecture disponible", "library_panels": [], "me": &me, "role": &role })), |conn| {
        let mut stmt = match conn.prepare(
            "SELECT id,name,title,query,is_soql,viz,COALESCE(drill,''),COALESCE(owner,''),COALESCE(visibility,'shared'),\
                    (SELECT COUNT(*) FROM panel p WHERE p.library_panel_id=library_panel.id) \
             FROM library_panel ORDER BY name,id",
        ) {
            Ok(s) => s,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "library_panels")),
        };
        // P7.13-a — LE MÊME PRÉDICAT que celui qui autorise un RATTACHEMENT (`panneau_resolu::lisible_par`).
        // Il était auparavant écrit une 2e fois en SQL ici ; c'est cette duplication qui rendait crédible
        // « l'editor ne voit pas cette définition » alors que le rattachement, lui, ne regardait rien.
        // Le filtre passe en Rust (la table des définitions réutilisables est petite : dizaines de lignes).
        let out: Result<Vec<Value>, rusqlite::Error> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)? != 0, r.get::<_, String>(5)?, r.get::<_, String>(6)?, r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?, r.get::<_, i64>(9)?,
                ))
            })
            .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
            .map(|lues| {
                lues.into_iter()
                    .filter(|(_, _, _, _, _, _, _, owner, vis, _)| panneau_resolu::lisible_par(owner, vis, &au))
                    .map(|(id, name, title, query, is_soql, viz, drill, owner, vis, used_by)| {
                        // `P11.20-n` — le drapeau dit ce que la porte fera : `ergo_editable`, dont
                        // le corps EST `lisible_par`. Une seule phrase pour la porte et pour la vue.
                        let owns = panneau_resolu::lisible_par(&owner, &vis, &ident);
                        json!({
                            "id": id, "name": name, "title": title, "query": query, "is_soql": is_soql, "viz": viz,
                            "drill": drill, "owner": owner, "visibility": vis, "used_by": used_by, "editable": owns
                        })
                    })
                    .collect()
            })
            ;
        // `P10.7-z` — une exécution qui échoue AVOUE, au lieu de servir une bibliothèque vide.
        let out = match out {
            Ok(v) => v,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "library_panels")),
        };
        Json(json!({ "library_panels": out, "me": &me, "role": &role }))
    })
}

pub(crate) async fn library_panel_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Panneau réutilisable").to_string();
    let title = b.get("title").and_then(|v| v.as_str()).unwrap_or("Panneau").to_string();
    let query = b.str_field("query").to_string();
    let is_soql = if b.bool_field("is_soql", true) { 1 } else { 0 };
    let viz = b.get("viz").and_then(|v| v.as_str()).unwrap_or("table").to_string();
    let drill = b.str_field("drill").to_string();
    let visibility = vis_of(&b);
    // SQL BRUT (is_soql=0) = lecture arbitraire de toute la base à chaque refresh -> RÉSERVÉ ADMIN (miroir panel_create).
    if !raw_sql_allowed(is_soql == 1, &au.role) {
        return forbidden("SQL brut réservé à l'administrateur (utilisez GXQL)");
    }
    crate::req_conn!(st, au, conn);
    match conn.execute(
        "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
        params![name, title, query, is_soql, viz, drill, au.name, visibility, now()],
    ) {
        // `P10.20-w` (rang quatre) — l'identifiant n'est servi que sur UNE ligne écrite.
        Ok(1) => Json(json!({ "id": conn.last_insert_rowid() })).into_response(),
        Ok(n) => crate::handlers::dashboards::refus_d_un_objet_non_cree("panneau de bibliothèque", crate::handlers::dashboards::lignes_ecrites_au_lieu_d_une(n)),
        Err(e) => crate::handlers::dashboards::refus_d_un_objet_non_cree("panneau de bibliothèque", e),
    }
}

pub(crate) async fn library_panel_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    // is_soql EFFECTIF (corps si fourni, sinon base) -> un editor ne peut NI basculer en SQL brut NI éditer un
    // panneau déjà en SQL brut (miroir panel_update, anti-contournement fail-closed).
    // `P10.33-l` — TROIS ISSUES : lu, la porte suit ; absent, le 404 d'avant ; lecture ratée, 503
    // `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU` — rien n'est écrit et le garde-fou reste FERMÉ (ni GXQL ni SQL brut
    // n'est supposé). La forme d'avant (`Err(_) => 404`) disait absente une définition illisible.
    let cur_soql: bool = match conn
        .query_row("SELECT COALESCE(is_soql,1) FROM library_panel WHERE id=?1", params![id], |r| r.get::<_, i64>(0).map(|n| n != 0))
        .optional()
    {
        Ok(Some(x)) => x,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_NON_LU);
            eprintln!("[dashboards] WARN panneau de bibliothèque #{id} NON lu pour la modification, rien n'est écrit ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    };
    if let Some(refus) = refus_de_la_porte_d_edition(&conn, &au, "library_panel", id) {
        return refus;
    }
    let eff_soql = b.get("is_soql").and_then(|v| v.as_bool()).unwrap_or(cur_soql);
    if !raw_sql_allowed(eff_soql, &au.role) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // `P10.20-w` (gestes de `dash_ergonomics`) — les écritures de la modification vivent sous UN garde de geste :
    // une seule refusée ou sans effet (`Ok(0)` sur une ligne dont l'existence vient d'être lue) annule TOUTES les
    // autres, et la route refuse en 503 au lieu de rendre 204. La forme d'avant enchaînait cinq `let _ =` : une
    // bascule en « private » refusée laissait la définition PARTAGÉE pendant que la console lisait un succès.
    // `P10.33-l` — la route rend une `Response` : les trois refus (transaction non ouverte, écriture refusée ou sans
    // effet, validation refusée) servent leur cause nommée en corps, avec l'identifiant de corrélation du journal. La
    // forme d'avant rendait `StatusCode` : la cause partait au journal seul et la console lisait un 503 nu — sans
    // apprendre que la définition gardait sa visibilité d'avant (partagée si elle l'était).
    let geste = format!("modification du panneau de bibliothèque #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    let ecrit: Result<(), String> = (|| {
        for (k, col) in [("name", "name"), ("title", "title"), ("query", "query"), ("viz", "viz"), ("drill", "drill")] {
            if let Some(v) = b.get(k).and_then(|v| v.as_str()) {
                une_ligne_ecrite(conn.execute(&format!("UPDATE library_panel SET {col}=?1 WHERE id=?2"), params![v, id]), col)?;
            }
        }
        if let Some(v) = b.get("is_soql").and_then(|v| v.as_bool()) {
            une_ligne_ecrite(conn.execute("UPDATE library_panel SET is_soql=?1 WHERE id=?2", params![v as i64, id]), "is_soql")?;
        }
        if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
            let vv = if v == "private" { "private" } else { "shared" };
            une_ligne_ecrite(conn.execute("UPDATE library_panel SET visibility=?1 WHERE id=?2", params![vv, id]), "visibility")?;
        }
        une_ligne_ecrite(conn.execute("UPDATE library_panel SET updated=?1 WHERE id=?2", params![now(), id]), "updated")
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : l'état d'avant, cache compris (rien n'est invalidé).
        return err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE} ({geste} : {cause})"));
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE, || {
        // Édition d'une bibliothèque -> purge le cache des panneaux qui la référencent (leur requête a pu changer).
        panneau_avoue::cache_invalider_bibliotheque(&conn, id);
        StatusCode::NO_CONTENT.into_response()
    })
}

pub(crate) async fn library_panel_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.33-l` et `P10.20-l` (vague AF) — trois issues : lue, le geste suit ; absente, le 404 d'avant (sans corps) ;
    // lecture ratée, 503 `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU` — ni droit jugé, ni détachement, ni
    // suppression. La forme d'avant (`.is_err()` -> 404) disait « introuvable » une définition illisible.
    let lecture = conn.query_row("SELECT 1 FROM library_panel WHERE id=?1", params![id], |_| Ok(())).optional();
    match lecture {
        Ok(Some(())) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU);
            eprintln!("[dashboards] WARN panneau de bibliothèque #{id} NON lu pour la suppression, rien n'est détaché ni supprimé ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    if let Some(refus) = refus_de_la_porte_d_edition(&conn, &au, "library_panel", id) {
        return refus;
    }
    // On DÉTACHE les panneaux référents (ils redeviennent autonomes avec leur query locale) — pas de perte.
    // `P10.20-w` (gestes de `dash_ergonomics`) — détachement et suppression sous UN garde : une suppression refusée
    // ou sans effet annule le détachement (les référents restent rattachés à la définition qui subsiste) et la
    // route refuse en 503 nommé. La forme d'avant avalait les deux et rendait 204.
    let geste = format!("suppression du panneau de bibliothèque #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // `P10.33-l` (vague AG) — LE DÉTACHEMENT EST COMPTÉ. Le nombre de panneaux référents se lit DANS la transaction (une
    // lecture refusée annule tout : 503) ; le détachement doit en écrire exactement autant, sinon la transaction est
    // annulée (Drop -> ROLLBACK) et la route refuse en 503 nommé. La forme d'avant acceptait un détachement sans effet
    // (un déclencheur qui ignore l'écriture) : la définition partait et ses référents gardaient un `library_panel_id`
    // orphelin. Zéro référent et zéro ligne détachée est un succès. `P10.29-l` (vague AG) — le corps porte la phrase fixe
    // et l'identifiant de corrélation ; la cause du moteur va au journal seul (`refuser_le_retrait_non_pris`).
    let ecrit: Result<(), String> = (|| {
        let referents: i64 = conn
            .query_row("SELECT COUNT(*) FROM panel WHERE library_panel_id=?1", params![id], |r| r.get(0))
            .map_err(|e| format!("comptage des panneaux référents : {e}"))?;
        let detaches = conn
            .execute("UPDATE panel SET library_panel_id=NULL WHERE library_panel_id=?1", params![id])
            .map_err(|e| format!("détachement des panneaux référents : {e}"))?;
        if i64::try_from(detaches).ok() != Some(referents) {
            return Err(format!("détachement des panneaux référents : {detaches} ligne(s) écrite(s) pour {referents} référent(s) compté(s)"));
        }
        une_ligne_ecrite(conn.execute("DELETE FROM library_panel WHERE id=?1", params![id]), "suppression de la définition")
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : le détachement est annulé avec la suppression.
        return crate::handlers::dashboards::refuser_le_retrait_non_pris(&geste, &cause, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME, || StatusCode::NO_CONTENT.into_response())
}

// =====================================================================================
// PLAYLISTS (rotation de dashboards)
// =====================================================================================
/// Normalise `items` (JSON) en liste ORDONNÉE d'ids de dashboards (ignore le non-entier). Sérialisé en TEXT.
pub(crate) fn playlist_items_json(b: &Value) -> Option<String> {
    let arr = b.get("items")?.as_array()?;
    let ids: Vec<i64> = arr.iter().filter_map(|v| v.as_i64()).collect();
    Some(serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()))
}

pub(crate) async fn playlists_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) -> bind `?1` visibilité.
    // `P11.20-n` — l'ownership de la closure passe par `ident` et le coffre ; `?2<>''` refuse
    // l'appariement d'une identité SANS NOM à une colonne `owner` vide.
    let adm = if au.is_admin() { "admin" } else { "" };
    let ident = au.clone();
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "error": "lecture NON FAITE : aucune connexion de lecture disponible", "playlists": [], "me": &me, "role": &role })), |conn| {
        let mut stmt = match conn.prepare(
            "SELECT id,name,interval_s,items,COALESCE(owner,''),COALESCE(visibility,'shared') FROM playlist \
             WHERE ?1='admin' OR COALESCE(visibility,'shared')='shared' OR (?2<>'' AND owner=?2) \
             ORDER BY name,id",
        ) {
            Ok(s) => s,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "playlists")),
        };
        let out: Result<Vec<Value>, rusqlite::Error> = stmt
            .query_map(params![adm, me], |r| {
                let owner: String = r.get(4)?;
                let vis: String = r.get(5)?;
                let items_raw: String = r.get(3)?;
                let items: Value = serde_json::from_str(&items_raw).unwrap_or_else(|_| json!([]));
                // `P11.20-n` — le drapeau dit ce que la porte fera : `ergo_editable` = `lisible_par`.
                let owns = panneau_resolu::lisible_par(&owner, &vis, &ident);
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "interval_s": r.get::<_, i64>(2)?,
                    "items": items, "owner": owner, "visibility": vis, "editable": owns
                }))
            })
            .and_then(|rows| rows.collect::<Result<Vec<Value>, _>>());
        let out = match out {
            Ok(v) => v,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "playlists")),
        };
        Json(json!({ "playlists": out, "me": &me, "role": &role }))
    })
}

pub(crate) async fn playlist_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Playlist").to_string();
    let interval_s = b.i64_field("interval_s", 30).clamp(3, 3600);
    let items = playlist_items_json(&b).unwrap_or_else(|| "[]".into());
    let visibility = vis_of(&b);
    crate::req_conn!(st, au, conn);
    match conn.execute(
        "INSERT INTO playlist(name,interval_s,items,owner,visibility,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
        params![name, interval_s, items, au.name, visibility, now()],
    ) {
        // `P10.20-w` (rang quatre) — l'identifiant n'est servi que sur UNE ligne écrite.
        Ok(1) => Json(json!({ "id": conn.last_insert_rowid() })).into_response(),
        Ok(n) => crate::handlers::dashboards::refus_d_un_objet_non_cree("liste de lecture", crate::handlers::dashboards::lignes_ecrites_au_lieu_d_une(n)),
        Err(e) => crate::handlers::dashboards::refus_d_un_objet_non_cree("liste de lecture", e),
    }
}

/// `P10.33-l` — L'EXISTENCE D'UNE LISTE DE LECTURE, LUE AVANT UN GESTE : `Ok(())` elle existe, `Err(404)` son absence
/// est ÉTABLIE (aucune ligne), `Err(503 nommé)` la lecture a été refusée — ni absence ni présence ne sont établies.
/// La forme d'avant (`query_row(..).is_err()`) rendait 404 sur une lecture refusée : « cette liste n'existe pas »,
/// pour une liste qui existe toujours.
fn liste_de_lecture_existe(conn: &Connection, id: i64) -> Result<(), Response> {
    match conn.query_row("SELECT 1 FROM playlist WHERE id=?1", params![id], |_| Ok(())) {
        Ok(()) => Ok(()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(StatusCode::NOT_FOUND.into_response()),
        Err(e) => Err(err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_LISTE_DE_LECTURE_NON_LUE} (liste de lecture #{id} : {e})"))),
    }
}

pub(crate) async fn playlist_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    if let Err(refus) = liste_de_lecture_existe(&conn, id) {
        return refus;
    }
    if let Some(refus) = refus_de_la_porte_d_edition(&conn, &au, "playlist", id) {
        return refus;
    }
    // `P10.33-l` — même forme que `library_panel_update` : les écritures de la modification vivent sous UN garde de
    // geste ; une seule refusée ou sans effet (`Ok(0)` sur une ligne dont l'existence vient d'être lue) annule TOUTES
    // les autres, et la route refuse en 503 au lieu de rendre 204. La forme d'avant enchaînait cinq `let _ =` : une
    // bascule en « private » refusée laissait la liste PARTAGÉE pendant que la console lisait un succès. Les trois refus
    // servent leur cause nommée en corps (la route rend une `Response`, plus un `StatusCode` qui la laissait au journal).
    let geste = format!("modification de la liste de lecture #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_LISTE_DE_LECTURE_INCHANGEE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    let ecrit: Result<(), String> = (|| {
        if let Some(v) = b.get("name").and_then(|v| v.as_str()) {
            une_ligne_ecrite(conn.execute("UPDATE playlist SET name=?1 WHERE id=?2", params![v, id]), "name")?;
        }
        if let Some(v) = b.get("interval_s").and_then(|v| v.as_i64()) {
            une_ligne_ecrite(conn.execute("UPDATE playlist SET interval_s=?1 WHERE id=?2", params![v.clamp(3, 3600), id]), "interval_s")?;
        }
        if let Some(items) = playlist_items_json(&b) {
            une_ligne_ecrite(conn.execute("UPDATE playlist SET items=?1 WHERE id=?2", params![items, id]), "items")?;
        }
        if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
            let vv = if v == "private" { "private" } else { "shared" };
            une_ligne_ecrite(conn.execute("UPDATE playlist SET visibility=?1 WHERE id=?2", params![vv, id]), "visibility")?;
        }
        une_ligne_ecrite(conn.execute("UPDATE playlist SET updated=?1 WHERE id=?2", params![now(), id]), "updated")
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : la liste d'avant, visibilité comprise.
        return err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_LISTE_DE_LECTURE_INCHANGEE} ({geste} : {cause})"));
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_LISTE_DE_LECTURE_INCHANGEE, || StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn playlist_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    if let Err(refus) = liste_de_lecture_existe(&conn, id) {
        return refus;
    }
    if let Some(refus) = refus_de_la_porte_d_edition(&conn, &au, "playlist", id) {
        return refus;
    }
    // `P10.33-l` — l'effacement exige UNE ligne, sous le garde du geste (il n'écrit jamais dans la transaction d'un
    // autre geste) ; un refus rend le 503 nommé. La forme d'avant avalait le `DELETE` et rendait 204 : la liste
    // restait en place, partagée si elle l'était.
    let geste = format!("suppression de la liste de lecture #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    if let Err(cause) = une_ligne_ecrite(conn.execute("DELETE FROM playlist WHERE id=?1", params![id]), "suppression de la liste") {
        drop(tx); // Drop -> ROLLBACK.
        return err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE} ({geste} : {cause})"));
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE, || StatusCode::NO_CONTENT.into_response())
}

// =====================================================================================
// DASHBOARD SNAPSHOTS (capture point-in-time partageable, LECTURE SEULE)
// =====================================================================================
/// Jeton de partage CSPRNG (32 octets d'entropie noyau -> 64 hex). Non devinable ; sert de capability du partage
/// read-only. FAIL-CLOSED : `None` si l'entropie noyau est indisponible -> le
/// partage ÉCHOUE, plus jamais un fallback `Sha256(now|pid|time)` DEVINABLE (parité avec `token_rand_hex`).
pub(crate) fn gen_snapshot_token() -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut buf).ok()?;
    Some(hex_encode(&buf))
}

/// CAPTURE (pure, testable sans AppState) : résout TOUS les panneaux d'un dashboard en données rendues, via
/// le CHEMIN GXQL MASQUÉ (mêmes garanties que panel_data_masked_live). `masks` = jeu EFFECTIF du rôle du
/// créateur (effective_masks) : VIDE -> compilation NON masquée (identique au rendu live d'un rôle non masqué).
/// Non vide -> GXQL masqué dans le SQL (soql_to_sql_masked_x) + masquage POST-requête du SQL brut opaque
/// (mask_query_result). Le snapshot ne peut donc JAMAIS contenir un champ hors de la portée du créateur.
/// Résout aussi les LIBRARY PANELS — par le coffre `panneau_resolu` (P7.13-a), donc par la MÊME
/// expression que `panel_access` et `dash_get`. Renvoie {dashboard_id, name, captured_at, panels:[…]}.
///
/// `conf` EST UN PARAMÈTRE, ET C'EST UNE CORRECTION DE PLACEMENT MESURÉE (`P10.5-i`). Cette fonction est
/// appelée À L'INTÉRIEUR du `req_conn!` de `snapshot_create`, c'est-à-dire sous le MUTEX WRITER du
/// tenant. Le `load_config()` qu'elle faisait elle-même y ajoutait un `std::fs::read_to_string` NON
/// mémoïsé (`main.rs`) — un accès DISQUE tenu sous le verrou qui bloque l'ingestion, contre la
/// discipline que `dashboards.rs` énonce en toutes lettres (« HORS LOCK : lecture config … AVANT de
/// prendre le lock writer ») et que ce même lot invoque pour justifier son geste là-bas. L'appelant le
/// fait donc AVANT de prendre le verrou, une seule fois, et le passe.
///
/// `P10.7-f` (rang 4) — UNE CAPTURE AMPUTÉE NE SE FIGE PLUS. Cette fonction rend un `rusqlite::Result`,
/// et c'est le SEUL site du rang qui refuse au lieu d'avouer dans son corps : l'instantané n'est pas une
/// page qu'on relit en ligne, c'est un ARTEFACT QUI VOYAGE — sérialisé dans `dashboard_snapshot.data`,
/// partageable par jeton, relu des semaines plus tard par un TIERS hors de tout contexte. Un aveu posé
/// dans le corps y serait figé avec lui et lu par quelqu'un qui n'a aucun moyen de refaire la lecture.
/// Avant : une préparation ratée rendait `panels: []` — une capture VIDE présentée comme complète — et
/// `.map(|it| it.flatten().collect()).unwrap_or_default()` faisait disparaître un panneau dont le
/// mappeur échoue, sans un mot, dans un artefact que personne ne pourra plus recouper. `snapshot_create`
/// REFUSE désormais la capture avec sa cause, et n'écrit RIEN : aucun instantané partiel n'est partagé.
pub(crate) fn capture_dashboard_data(
    db_path: &str, conn: &Connection, conf: &HashMap<String, String>, dashboard_id: i64, dash_name: &str, from: i64, to: i64,
    env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet, portee: &PorteeLecture,
) -> rusqlite::Result<Value> {
    let mut panels_out: Vec<Value> = Vec::new();
    let rows: Vec<(String, String, bool, String, String, String)> = conn
        .prepare(&format!(
            "SELECT {t},{q},{s},{v},{d},COALESCE(p.visibility,'shared') FROM {j} WHERE p.dashboard_id=?1 ORDER BY p.position,p.id",
            t = panneau_resolu::COL_TITRE, q = panneau_resolu::COL_QUERY, s = panneau_resolu::COL_IS_SOQL,
            v = panneau_resolu::COL_VIZ, d = panneau_resolu::COL_DRILL, j = panneau_resolu::JOINTURE,
        ))
        .and_then(|mut stmt| {
            stmt.query_map(params![dashboard_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })?;
    // P7.13-a — LA MÊME PORTÉE DE LECTURE QUE `dash_get`/`panel_access` : un panneau PRIVÉ d'un autre
    // propriétaire n'entre PAS dans la capture. MESURÉ AVANT (2026-08-03, `3256e4d`) : sur un dashboard
    // PARTAGÉ d'alice portant un panneau privé, un editor tiers avait `dash_get` -> `panels: []` et
    // `panel_data` -> 403, mais `snapshot_create` -> 200 avec la ligne privée FIGÉE dans le snapshot,
    // ensuite partageable par jeton. L'en-tête de ce module affirmait « hérite #45 + RBAC ».
    let rows: Vec<_> = rows.into_iter().filter(|(_, _, _, _, _, pvis)| portee.voit(pvis)).collect();
    for (title, query, is_soql, viz, _drill, _pvis) in rows {
        // `P10.5-i` — TROIS SITES DE COMPILATION deviennent DEUX BRANCHES, et c'est un déplacement pur :
        // le coffre non masqué traite déjà `is_soql=0` par la MÊME substitution appliquée au MÊME
        // `apply_excl_placeholders`, et le coffre masqué reproduit le corps de `panel_data_masked_live`.
        // Le troisième site (masques NON vides + `is_soql=1`) produisait un `String` nu : sans cette
        // réduction, la MOITIÉ des instantanés — ceux d'un appelant à masques actifs — sortirait sans aveu.
        let compiled = if masks.is_empty() {
            panneau_avoue::compile_panneau_avoue(&query, is_soql, from, to, env)
        } else {
            panneau_avoue::compile_panneau_avoue_masque(&query, is_soql, from, to, env, masks)
        };
        let pc = match compiled {
            Ok(pc) => pc,
            Err(e) => { panels_out.push(json!({ "title": title, "viz": viz, "error": e })); continue; }
        };
        // SQL brut opaque : masquage POST-requête par nom de colonne (le masque ne s'injecte pas).
        let post_mask = !is_soql && !masks.is_empty();
        match panneau_avoue::executer(db_path, conf, pc, from) {
            Ok(mut v) => {
                if post_mask {
                    mask_query_result(db_path, masks, &mut v);
                }
                panels_out.push(json!({
                    "title": title, "viz": viz,
                    "columns": v.get("columns").cloned().unwrap_or_else(|| json!([])),
                    "rows": v.get("rows").cloned().unwrap_or_else(|| json!([])),
                    // L'INSTANTANÉ EST L'ARTEFACT QUI VOYAGE : partageable par jeton, relu des semaines
                    // plus tard, hors de tout contexte de fenêtre. Sans cette ligne, l'aveu s'arrêterait
                    // ici — et c'est la garde dérivée du routeur (règle sur `data.panels[*]`) qui la tient.
                    "stats": v.get("stats").cloned().unwrap_or_else(|| json!({})),
                }));
            }
            Err(e) => panels_out.push(json!({ "title": title, "viz": viz, "error": e })),
        }
    }
    Ok(json!({ "dashboard_id": dashboard_id, "name": dash_name, "captured_at": now(), "panels": panels_out }))
}

pub(crate) async fn snapshot_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let dashboard_id = b.i64_field("dashboard_id", 0);
    let from = b.i64_field("from", 0);
    let to = b.i64_field("to", 0);
    let env = au.env_filter();
    // La capture lit la BASE COURANTE du tenant ET le registre de masques -> même db_path partout.
    let db_path = req_db_path(&st, &au);
    // 1) Le créateur peut-il VOIR ce dashboard ? (mêmes règles que dash_get : admin / partagé / propriétaire.)
    let (name, owner, vis): (String, String, String) = {
        crate::req_conn!(st, au, conn);
        // `P10.20-l` — trois issues : lu, la capture suit ; absent, le 404 d'avant (corps compris) ; lecture ratée, 503
        // `CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU`, rien n'est capturé ni partagé.
        match conn
            .query_row(
                "SELECT name,COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
                params![dashboard_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
        {
            Ok(Some(x)) => x,
            Ok(None) => return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response(),
            Err(e) => {
                let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_INSTANTANE_NON_CREE_TABLEAU_DE_BORD_NON_LU);
                eprintln!("[dashboards] WARN tableau de bord #{dashboard_id} NON lu pour l'instantané, rien n'est capturé ({}) : {e}", cid.unwrap_or_default());
                return refus;
            }
        }
    };
    // `P11.20-n` — MÊME phrase que `dash_get` : un dashboard SANS propriétaire n'est plus « à nous ».
    if !panneau_resolu::lisible_par(&owner, &vis, &au) {
        return forbidden("dashboard privé");
    }
    let snap_name = b.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| name.clone());
    // 2) CAPTURE via le chemin MASQUÉ (jeu effectif du rôle du CRÉATEUR) — jamais de données hors de sa portée.
    let masks = effective_masks(&db_path, &au.role, &au.tenant, env);
    // P7.13-a — la capture reçoit la PORTÉE DE LECTURE du créateur (même décision que `dash_get`) : un
    // panneau privé d'un autre propriétaire n'y entre pas. Le paramètre est OBLIGATOIRE (E0061) : un
    // futur appelant ne peut pas l'oublier, ce qui était exactement la faute mesurée ici.
    let portee = PorteeLecture::du_dashboard(&au, &owner);
    // HORS LOCK, ET UNE SEULE FOIS (`P10.5-i`) : `load_config()` fait un accès DISQUE non mémoïsé.
    // Le prendre SOUS le mutex writer bloquerait l'ingestion du tenant le temps d'une lecture de fichier.
    let conf = load_config();
    let capture = {
        crate::req_conn!(st, au, conn);
        capture_dashboard_data(&db_path, &conn, &conf, dashboard_id, &name, from, to, env, &masks, &portee)
    };
    // `P10.7-f` (rang 4) — UNE CAPTURE DONT UNE LECTURE A ÉCHOUÉ N'EST JAMAIS FIGÉE. La porte est ICI et
    // pas dans le corps : ce que cette route écrit part vivre sa vie derrière un jeton de partage, et un
    // `error` embarqué serait relu par un tiers qui ne peut plus rien recouper. Refuser en nommant la
    // cause laisse la main à l'appelant — il peut réessayer —, et AUCUNE ligne n'entre dans
    // `dashboard_snapshot` : pas de jeton, pas d'artefact partiel partageable.
    let data = match capture {
        Ok(v) => v,
        Err(e) => {
            return err_json(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("instantané REFUSÉ : les panneaux de ce tableau de bord n'ont pas pu être lus ({e}) — \
                         rien n'a été capturé ni partagé, car une capture amputée serait figée et partagée comme complète. RÉESSAYER"),
            );
        }
    };
    let payload = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
    let token = match gen_snapshot_token() {
        Some(t) => t,
        None => return server_err("entropie noyau indisponible — création du partage refusée (jamais de jeton faible)"),
    };
    {
        crate::req_conn!(st, au, conn);
        // `P10.20-w` (rang quatre) — NI identifiant NI jeton sur une ligne non écrite : le jeton servi
        // était un lien de partage qui ne menait à RIEN, présenté comme valide.
        match conn.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) \
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![dashboard_id, snap_name, token, payload, now(), au.name, au.role],
        ) {
            Ok(1) => Json(json!({ "id": conn.last_insert_rowid(), "token": token })).into_response(),
            Ok(n) => crate::handlers::dashboards::refus_d_un_objet_non_cree("instantané", crate::handlers::dashboards::lignes_ecrites_au_lieu_d_une(n)),
            Err(e) => crate::handlers::dashboards::refus_d_un_objet_non_cree("instantané", e),
        }
    }
}

pub(crate) async fn snapshots_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) -> bind `?1` visibilité + ownership.
    let adm = if au.is_admin() { "admin" } else { "" };
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "error": "lecture NON FAITE : aucune connexion de lecture disponible", "snapshots": [], "me": &me, "role": &role })), |conn| {
        // MÉTADONNÉES seulement (jamais le blob `data` en liste). L'admin voit tout ; sinon ses propres captures.
        let mut stmt = match conn.prepare(
            "SELECT id,dashboard_id,name,token,created,COALESCE(created_by,''),COALESCE(role_at_capture,'') FROM dashboard_snapshot \
             WHERE ?1='admin' OR COALESCE(created_by,'')=?2 ORDER BY created DESC,id DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "snapshots")),
        };
        let out: Result<Vec<Value>, rusqlite::Error> = stmt
            .query_map(params![adm, me], |r| {
                let created_by: String = r.get(5)?;
                let owns = adm == "admin" || created_by == me;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "dashboard_id": r.get::<_, i64>(1)?, "name": r.get::<_, String>(2)?,
                    "token": r.get::<_, String>(3)?, "created": r.get::<_, i64>(4)?, "created_by": created_by,
                    "role_at_capture": r.get::<_, String>(6)?, "editable": owns
                }))
            })
            .and_then(|rows| rows.collect::<Result<Vec<Value>, _>>());
        let out = match out {
            Ok(v) => v,
            Err(_) => return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "snapshots")),
        };
        Json(json!({ "snapshots": out, "me": &me, "role": &role }))
    })
}

/// Lecture d'un snapshot PAR TOKEN (read-only, token-scoped). Renvoie les données DÉJÀ figées & masquées à la
/// capture -> aucune re-exécution GXQL, aucune fuite : ce que le créateur a vu, rien de plus. viewer+ (Read).
pub(crate) async fn snapshot_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(token): Path<String>) -> Response {
    // token allowlisté (hex 64) : anti-injection & anti-probe (aucun match si format inattendu).
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::NOT_FOUND, "snapshot introuvable").into_response();
    }
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AF) — trois issues : lu, l'instantané est servi ; absent, le 404 d'avant (corps « snapshot
    // introuvable » à l'identique) ; lecture ratée, 503 `CAUSE_INSTANTANE_NON_LU`. La forme d'avant (`Err(_)` -> 404)
    // disait « introuvable » un instantané illisible : le destinataire d'un lien de partage le croyait révoqué.
    let lecture = conn
        .query_row(
            "SELECT name,dashboard_id,data,created,COALESCE(created_by,''),COALESCE(role_at_capture,'') FROM dashboard_snapshot WHERE token=?1",
            params![token],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?)),
        )
        .optional();
    match lecture {
        Ok(Some((name, did, data, created, by, role))) => {
            let parsed: Value = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
            Json(json!({
                "name": name, "dashboard_id": did, "created": created, "created_by": by,
                "role_at_capture": role, "readonly": true, "data": parsed
            }))
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "snapshot introuvable").into_response(),
        Err(e) => {
            // Ni le jeton (un secret de partage) ni rien de la requête au journal : la cause du moteur seule.
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_INSTANTANE_NON_LU);
            eprintln!("[dashboards] WARN instantané NON lu par son jeton, rien n'est servi ({}) : {e}", cid.unwrap_or_default());
            refus
        }
    }
}

pub(crate) async fn snapshot_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-l` — trois issues : lu, le droit est jugé ; absent, le 404 d'avant ; lecture ratée, 503
    // `CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU` — ni 403 ni révocation : le droit n'est pas jugé sur un auteur non lu.
    match conn.query_row("SELECT COALESCE(created_by,'') FROM dashboard_snapshot WHERE id=?1", params![id], |r| r.get::<_, String>(0)).optional() {
        Ok(Some(by)) => {
            if !au.is_admin() && by != au.name {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_INSTANTANE_NON_SUPPRIME_NON_LU);
            eprintln!("[dashboards] WARN instantané #{id} NON lu pour la révocation, rien n'est supprimé ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    // `P10.20-w` (gestes de `dash_ergonomics`) — la révocation n'est affirmée que sur UNE ligne supprimée : la forme
    // d'avant avalait le DELETE et rendait 204, et l'instantané « révoqué » restait servi par son jeton.
    match une_ligne_ecrite(conn.execute("DELETE FROM dashboard_snapshot WHERE id=?1", params![id]), "suppression de l'instantané") {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(cause) => err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_INSTANTANE_NON_SUPPRIME} (instantané #{id} : {cause})")),
    }
}
