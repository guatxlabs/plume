//! #60 — SCHEDULED REPORTS : un DATASET (#47, GXQL sauvegardé) exécuté sur un intervalle et livré à un
//! NOTIFIER (#53, canal admin-configuré). RÉUTILISE l'infra existante — AUCUN nouveau mécanisme de livraison
//! (`notify_send`) ni de compilation (le GXQL du dataset passe par le MÊME chemin masqué `soql_to_sql_masked_x`
//! que /api/query). Additif : table `scheduled_report` VIDE -> `run_due_reports` sélectionne 0 ligne -> no-op
//! strict (mode 0 byte-identique, aucun réseau).
//!
//! RUN-AS (garantie anti-exfiltration) : chaque rapport porte un `run_as_role` EXPLICITE ; le résultat est
//! MASQUÉ (#45) PAR CE RÔLE (`effective_masks(run_as_role)`), pas par le rôle du destinataire. Un editor NE
//! PEUT PAS créer un rapport `run_as=admin` (le CRUD PLAFONNE run_as au rôle du créateur) -> un planificateur
//! peu privilégié ne peut pas exfiltrer des données qu'il ne verrait pas lui-même, même livrées à un admin.
//! CHOIX env/tenant : masqué avec `env=None` (baseline du rôle) MAIS sur le `tenant` DU CRÉATEUR (persisté à
//! la création, comme /api/query passe `&au.tenant`) -> les field-filters tenant-scopés (`tenant='clientX'`)
//! s'appliquent bien ; run_as défaut = `viewer` (le plus masqué). Le notifier est admin-configuré (secret hors de
//! portée de l'editor). CRUD ledgerisé (gouvernance).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};
use rusqlite::OptionalExtension;


/// Rôle d'exécution valide + PLAFONNÉ au rôle du créateur (anti-escalade). Enum FERMÉ (jamais 'agent').
pub(crate) fn resolve_run_as(requested: &str, creator_role: &str) -> Result<String, String> {
    let r = requested.trim();
    let r = if r.is_empty() { "viewer" } else { r };
    if !matches!(r, "viewer" | "editor" | "admin") {
        return Err(format!("run_as_role invalide (viewer|editor|admin) : {r}"));
    }
    if role_rank(r) > role_rank(creator_role) {
        return Err(format!("run_as_role '{r}' > votre rôle '{creator_role}' (escalade refusée)"));
    }
    Ok(r.to_string())
}

/// GET /api/scheduled-reports — liste (editor+ ; secret notifier JAMAIS projeté, seulement l'id).
pub(crate) async fn reports_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LA LISTE DES RAPPORTS PLANIFIÉS EST ENTIÈRE OU AVOUÉE. Avant :
    // `.map(|rows| rows.flatten().collect())` puis `.unwrap_or_default()` — un rapport dont la ligne ne se
    // décode pas (`last_error` non textuel après un échec d'envoi, `name` corrompu, colonne de migration
    // que la connexion qui sert ne voit pas encore) disparaissait de la seule vue qui les recense. Un
    // rapport absent se lit « rien n'est planifié » : on en crée un second, qui portera le même nom et sera
    // refusé par la contrainte d'unicité — ou qui passera sous un autre nom et DOUBLERA l'envoi périodique
    // vers le canal. Pire : le planificateur, lui, continue de l'exécuter sous son `run_as_role`, donc le
    // rapport invisible garde son identité d'exécution. L'aveu est celui du dépôt
    // (`liste_bornee::corps_de_liste_illisible` : `reports` présente et VIDE, `error` nomme la cause).
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,dataset_id,notifier_id,run_as_role,interval_s,enabled,last_run,last_ok,last_error,last_count,created,created_by FROM scheduled_report ORDER BY id")
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "name": r.get::<_,String>(1)?, "dataset_id": r.get::<_,i64>(2)?,
                    "notifier_id": r.get::<_,i64>(3)?, "run_as_role": r.get::<_,String>(4)?, "interval_s": r.get::<_,i64>(5)?,
                    "enabled": r.get::<_,i64>(6)? != 0, "last_run": r.get::<_,i64>(7)?, "last_ok": r.get::<_,i64>(8)?,
                    "last_error": r.get::<_,Option<String>>(9)?, "last_count": r.get::<_,i64>(10)?, "created": r.get::<_,i64>(11)?, "created_by": r.get::<_,String>(12)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(items) => Json(json!({ "reports": items })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "reports")).into_response(),
    }
}

// `P10.20-l` (vague AG) — UNE LECTURE RATÉE N'EST PAS UNE ABSENCE. `report_delete` et `report_run_now` lisaient le
// rapport par `Err(_) => not_found(…)` / `.is_err()`, `report_create` le jeu de données et le canal par `.is_err()` :
// une table hors d'atteinte, une ligne qui ne se lit pas, se servaient « introuvable » — l'administrateur lisait absent
// un rapport qui PART TOUJOURS vers son canal à chaque échéance. Trois issues : lue, le geste suit ; absente, le refus
// d'avant au corps près ; lecture ratée, 503 nommé (refus nommé côté console : ni `BEGIN` ni `COMMIT` ni transaction
// annulée — c'est la lecture qui manque), rien n'est écrit, supprimé ni envoyé, la cause du moteur au journal seul.
/// `P10.20-l` (vague AG) — le jeu de données ou le canal qu'un rapport à créer référence n'a pas été lu.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE: &str = "RAPPORT PLANIFIÉ NON CRÉÉ : la base n'a pas \
     rendu le jeu de données ou le canal que ce rapport référence — ce n'est PAS « introuvable », c'est une lecture qui \
     n'a pas eu lieu. RIEN n'est écrit : aucun rapport n'est créé, rien ne partira vers le canal, et aucune trace n'est \
     écrite. Réessayez ; si le refus persiste, la table des jeux de données ou des canaux est illisible.";
/// `P10.20-l` (vague AG) — le rapport à supprimer n'a pas été lu : il n'est pas supprimé, et il part toujours.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU: &str = "RAPPORT PLANIFIÉ NON SUPPRIMÉ : la base n'a pas \
     rendu ce rapport — ce n'est PAS « introuvable », c'est une lecture qui n'a pas eu lieu. RIEN n'est supprimé : s'il \
     existe, il est toujours là et PART TOUJOURS à son échéance, et aucune trace n'est écrite. Réessayez ; si le refus \
     persiste, la table des rapports planifiés est illisible.";
/// `P10.20-l` (vague AG) — le rapport à déclencher n'a pas été lu : rien n'est exécuté ni envoyé.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU: &str = "RAPPORT PLANIFIÉ NON DÉCLENCHÉ : la base n'a pas \
     rendu ce rapport — ce n'est PAS « introuvable », c'est une lecture qui n'a pas eu lieu. Rien n'est exécuté ni \
     envoyé vers le canal, et sa marque d'échéance est inchangée. Réessayez ; si le refus persiste, la table des \
     rapports planifiés est illisible.";

/// `P10.20-l` (vague AG) — juge, en trois issues, la lecture de la ligne que `geste` vise : lue, sa valeur ; absente,
/// le refus d'avant (`absente`) ; lecture ratée, 503 `cause` avec l'identifiant de corrélation, la cause du moteur au
/// journal seul avec le geste (identifiants internes seulement : jamais le nom du rapport, son canal ni sa requête).
fn ligne_du_rapport<T>(lue: rusqlite::Result<Option<T>>, absente: impl FnOnce() -> Response, geste: &str, cause: &'static str) -> Result<T, Response> {
    match lue {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(absente()),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, cause);
            eprintln!("[rapports] WARN {geste} refusé : la ligne visée n'a pas pu être lue, rien n'est écrit ni envoyé ({}) : {e}", cid.unwrap_or_default());
            Err(refus)
        }
    }
}

/// POST /api/scheduled-reports — crée un rapport planifié. editor+ ; run_as PLAFONNÉ au rôle du créateur.
pub(crate) async fn report_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let name = match validate_dm_ident(b.str_field("name")) { Ok(f) => f, Err(e) => return bad_req(e) };
    let dataset_id = match b.get("dataset_id").and_then(|v| v.as_i64()) { Some(v) => v, None => return bad_req("dataset_id requis") };
    let notifier_id = match b.get("notifier_id").and_then(|v| v.as_i64()) { Some(v) => v, None => return bad_req("notifier_id requis") };
    let run_as = match resolve_run_as(b.str_field("run_as_role"), &au.role) { Ok(r) => r, Err(e) => return bad_req(e) };
    let interval_s = b.get("interval_s").and_then(|v| v.as_i64()).unwrap_or(86400).clamp(60, 31_536_000);
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    // Le dataset ET le notifier référencés doivent EXISTER (fail-closed : pas de rapport orphelin).
    // `P10.20-l` (vague AG) — absents, les 400 d'avant ; lecture ratée, 503 nommé, rien d'écrit (pas de rapport orphelin).
    let geste_des_references = format!("création d'un rapport planifié (jeu de données #{dataset_id}, canal #{notifier_id})");
    let lu = conn.query_row("SELECT 1 FROM dataset WHERE id=?1", params![dataset_id], |_| Ok(())).optional();
    if let Err(refus) = ligne_du_rapport(lu, || bad_req("dataset introuvable"), &geste_des_references, CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE) {
        return refus;
    }
    let lu = conn.query_row("SELECT 1 FROM notifier WHERE id=?1", params![notifier_id], |_| Ok(())).optional();
    if let Err(refus) = ligne_du_rapport(lu, || bad_req("notifier introuvable"), &geste_des_references, CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE) {
        return refus;
    }
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "rapports", &format!("création du rapport planifié '{name}'"), CAUSE_RAPPORT_PLANIFIE_NON_CREE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO scheduled_report(name,dataset_id,notifier_id,run_as_role,tenant,interval_s,enabled,created,created_by,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8)",
            params![name, dataset_id, notifier_id, run_as, au.tenant, interval_s, enabled, now(), au.name])?;
        let id = conn.last_insert_rowid();
        audit_config_change(&conn, "config.scheduled_report.create",
            &format!("rapport planifié '{name}' (dataset #{dataset_id} -> notifier #{notifier_id}, run_as {run_as}, #{id}) par {}", au.name), 2,
            &format!("rapport planifié '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"scheduled_report", "id":id, "name":name, "run_as":run_as, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    // `P10.27-w` — LE `COMMIT` EST JUGÉ, ET L'IDENTIFIANT SERVI EST CELUI QUE LA FERMETURE A LU AU PIED DE L'`INSERT`.
    // La forme d'avant (`let _ = conn.execute_batch("COMMIT")` puis `conn.last_insert_rowid()`) faisait les deux fautes
    // à la fois. MESURÉ le 2026-09-25 (témoins `isdl_`) : sous un `COMMIT` refusé, 200 et un identifiant, la transaction
    // laissée OUVERTE sur l'écrivain, le rapport visible pour ce processus et absent à froid ; `COMMIT` accepté, le
    // numéro servi était celui de l'ÉVÉNEMENT d'audit — le rapport d'Alice servi avec l'identifiant de celui de Bob, et
    // la suppression de « son » rapport par cet identifiant retirait celui de Bob (200).
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "rapports", &format!("création du rapport planifié '{name}'"), CAUSE_RAPPORT_PLANIFIE_NON_CREE, || {
            Json(json!({ "id": id })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            if e.to_string().contains("UNIQUE") { return bad_req("un rapport porte déjà ce nom"); }
            // `P10.29-l` (vague AG) — phrase fixe, cause du moteur au journal seul (jamais le nom du rapport).
            crate::handlers::users_lookups::servir_l_echec_de_la_transaction_d_audit("[rapports]", &geste_des_references, &e)
        }
    }
}

/// `P10.27-w` — rapport planifié non créé : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_CREE: &str = "RAPPORT PLANIFIÉ NON CRÉÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — aucun rapport n'est écrit, rien ne partira vers le canal, et aucune \
     trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "RAPPORT PLANIFIÉ NON CRÉÉ : la \
     base n'a pas pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : aucun rapport n'est écrit, rien ne partira vers le canal, et \
     aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

// `P10.25-g` — LE `COMMIT` DE LA SUPPRESSION D'UN RAPPORT PLANIFIÉ EST JUGÉ. `P10.27-w` — celui de la création aussi.
/// `P10.25-g` — rapport planifié non supprimé : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME: &str = "RAPPORT PLANIFIÉ NON SUPPRIMÉ : la base n'a pas validé \
     la transaction (COMMIT refusé) et l'a annulée — il est toujours là et PART TOUJOURS à son échéance, et aucune \
     trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "RAPPORT PLANIFIÉ NON SUPPRIMÉ \
     : la base n'a pas pris la transaction du retrait (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : il est toujours là et PART TOUJOURS à son échéance, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// DELETE /api/scheduled-reports/{id} — supprime (editor+, audité).
pub(crate) async fn report_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let lue = conn.query_row("SELECT name FROM scheduled_report WHERE id=?1", params![id], |r| r.get::<_,String>(0)).optional();
    let name = match ligne_du_rapport(lue, || not_found("rapport introuvable"), &format!("suppression du rapport planifié #{id}"), CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU) {
        Ok(n) => n,
        Err(refus) => return refus,
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "rapports", &format!("suppression du rapport planifié #{id}"), CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("DELETE FROM scheduled_report WHERE id=?1", params![id])?;
        audit_config_change(&conn, "config.scheduled_report.delete",
            &format!("rapport planifié '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("rapport planifié '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"scheduled_report", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(id)
    })();
    match outcome {
        Ok(_) => rendre_apres_validation(&conn, "rapports", &format!("suppression du rapport planifié #{id}"), CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME, || {
            Json(json!({ "ok": true })).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            // `P10.29-l` (vague AG) — phrase fixe, cause du moteur au journal seul.
            crate::handlers::users_lookups::servir_l_echec_de_la_transaction_d_audit("[rapports]", &format!("suppression du rapport planifié #{id}"), &e)
        }
    }
}

/// POST /api/scheduled-reports/{id}/run — déclenche MANUELLEMENT (editor+). Exécute + livre TOUT DE SUITE avec
/// le run_as du rapport (masqué par CE rôle, pas par l'appelant) -> même garantie que le tick de fond.
pub(crate) async fn report_run_now(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_editor(&au) { return r; }
    let db_path = req_db_path(&st, &au);
    let __rc = req_db(&st, &au);
    // Vérifie l'existence AVANT de lâcher le lock ; l'exécution se fait via run_query_ex (pool read séparé).
    {
        let conn = __rc.lock();
        // `P10.20-l` (vague AG) — absent, le 404 d'avant ; lecture ratée, 503 nommé, rien n'est exécuté ni envoyé.
        let lu = conn.query_row("SELECT 1 FROM scheduled_report WHERE id=?1", params![id], |_| Ok(())).optional();
        if let Err(refus) = ligne_du_rapport(lu, || not_found("rapport introuvable"), &format!("déclenchement du rapport planifié #{id}"), CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU) {
            return refus;
        }
    }
    let outcome = tokio::task::spawn_blocking(move || deliver_report(&__rc, &db_path, id)).await;
    // `P10.20-w` — la réponse DIT si la marque d'échéance est écrite : un envoi dont la marque manque repartirait
    // au prochain tick, et l'appelant doit le lire au lieu d'un « ok » nu.
    match outcome {
        Ok(Ok(IssueDuRapport::Envoye { count, delivered, statut_ecrit })) => Json(json!({
            "ok": true, "rows": count, "delivered": delivered, "marque_ecrite": true, "statut_ecrit": statut_ecrit,
        })).into_response(),
        Ok(Ok(IssueDuRapport::MarqueRefusee)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "marque d'échéance du rapport non écrite : aucun envoi", "delivered": false, "marque_ecrite": false,
        }))).into_response(),
        Ok(Ok(IssueDuRapport::Echec { erreur, consigne })) => (StatusCode::BAD_REQUEST, Json(json!({
            "error": erreur, "marque_ecrite": consigne,
        }))).into_response(),
        // `P10.20-l` — absente ou désactivée : la phrase d'avant, à l'octet ; lecture ratée : 503 nommé, rien n'est
        // exécuté, envoyé ni écrit, la cause du moteur au journal seul avec l'identifiant de corrélation servi.
        Ok(Err(DefinitionNonPrise::Absente { lecture, .. })) => bad_req(lecture.phrase_d_absence()),
        Ok(Err(DefinitionNonPrise::NonLue { lecture, moteur })) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, lecture.cause_non_lue());
            eprintln!(
                "[rapports] WARN déclenchement du rapport planifié #{id} (tenant '{}') refusé : {}, rien n'est exécuté, envoyé ni écrit ({}) : {moteur}",
                au.tenant, lecture.constat(), cid.unwrap_or_default()
            );
            refus
        }
        Err(_) => server_err("exécution du rapport échouée"),
    }
}

/// Rend un résumé TEXTE compact d'un résultat de requête (déjà masqué) pour le corps de notification.
fn format_report_detail(name: &str, v: &Value) -> (i64, String) {
    let cols: Vec<String> = v.get("columns").and_then(|c| c.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let rows = v.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let n = rows.len() as i64;
    let mut out = format!("Rapport '{name}' : {n} ligne(s).\n{}\n", cols.join(" | "));
    for row in rows.iter().take(20) {
        if let Some(arr) = row.as_array() {
            let cells: Vec<String> = arr.iter().map(|c| match c {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }).collect();
            out.push_str(&cells.join(" | "));
            out.push('\n');
        }
    }
    if n > 20 { out.push_str(&format!("… (+{} lignes non affichées)\n", n - 20)); }
    // `P11.22-g` — la coupe mesurée par la ligne excédentaire est DITE dans le texte livré, avec sa borne.
    if v.get("truncated").and_then(|t| t.as_bool()).unwrap_or(false) {
        let borne = v.get("window").and_then(|w| w.as_i64()).unwrap_or(n);
        out.push_str(&format!("LISTE COUPÉE à {borne} lignes : le rapport en portait davantage, et ce texte n'en est pas le total.\n"));
    }
    (n, out)
}

/// Issue d'un rapport dont la définition a été lue (`P10.20-w`). Chaque écriture de statut est COMPTÉE : une
/// écriture refusée (ou sans effet) n'est plus avalée, elle se lit ici et se compte au bilan du tick.
#[derive(Debug, PartialEq)]
pub(crate) enum IssueDuRapport {
    /// Marque d'échéance (`last_run`) écrite AVANT l'envoi, puis rapport envoyé. `statut_ecrit` : le statut d'après
    /// envoi écrit (une ligne) — `last_ok` / `last_count` si `delivered`, `last_error` sinon (`P10.33-h`) ; `false` =
    /// envoi tenté, statut perdu (journalisé, compté, aucun second envoi).
    Envoye { count: i64, delivered: bool, statut_ecrit: bool },
    /// Marque d'échéance refusée ou sans effet : AUCUN envoi. Le rapport reste dû au tick suivant, sans effet
    /// externe à re-tenter.
    MarqueRefusee,
    /// Exécution en échec (aucun envoi). `consigne` : `last_run` + `last_error` écrits (une ligne).
    Echec { erreur: String, consigne: bool },
}

/// Écriture de statut d'un rapport : `true` sur UNE ligne écrite ; sinon la ligne de journal (identifiant du
/// rapport + cause du moteur — jamais le nom, l'endpoint du notificateur ni le contenu) et `false`.
fn statut_du_rapport_ecrit(id: i64, ecrit: rusqlite::Result<usize>, geste: &str) -> bool {
    match ecrit {
        Ok(1) => true,
        autre => {
            let cause = match autre { Err(e) => e.to_string(), Ok(n) => format!("{n} ligne(s) écrite(s) au lieu d'une") };
            eprintln!("[plume] rapport planifié {id} : {geste} : {cause}");
            false
        }
    }
}

/// Transmet le rapport au notificateur. Point unique d'envoi du tick ET de /run ; en test, un témoin du fil
/// courant peut l'intercepter (compter les envois, refuser, paniquer) — aucun réseau.
fn envoyer_le_rapport(kind: &str, url: &str, config: &Value, title: &str, detail: &str, ts: i64) -> bool {
    #[cfg(test)]
    {
        if let Some(verdict) = temoin_d_envoi::intercepter(kind, title, detail) {
            return verdict;
        }
    }
    notify_send(kind, url, config, 2, title, detail, "", ts)
}

/// `last_error` d'un rapport dont l'envoi a été refusé par le notificateur (`P10.33-h`) : constante nommée, sans
/// l'URL du notificateur (elle peut porter une crédence) ni le contenu du rapport.
pub(crate) const ENVOI_REFUSE_PAR_LE_NOTIFICATEUR: &str = "envoi refusé par le notificateur";

// `P10.20-l` / `P10.33-h` — LES TROIS LECTURES DE DÉFINITION DE `deliver_report` EN TROIS ISSUES. Avant :
// `.map_err(|_| "… introuvable ou désactivé")` sur chacune — une table hors d'atteinte, une ligne qui ne se décode pas,
// se servaient comme une absence (400 de `/run`), et le tick les avalait (`Ok(Err(_)) => {}`) sans compte ni trace.
// Lue, le rapport suit ; absente ou désactivée, la phrase d'avant à l'octet ; lecture ratée, 503 nommé à la route et
// abandon compté au tick, rien n'est exécuté, envoyé ni écrit, la cause du moteur au journal seul.
/// `P10.20-l` — le jeu de données d'un rapport à déclencher n'a pas été lu : rien n'est exécuté ni envoyé.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_JEU_DE_DONNEES_NON_LU: &str = "RAPPORT PLANIFIÉ NON DÉCLENCHÉ : \
     la base n'a pas rendu le jeu de données de ce rapport — ce n'est PAS « introuvable ou désactivé », c'est une \
     lecture qui n'a pas eu lieu. Rien n'est exécuté ni envoyé vers le canal, et sa marque d'échéance est inchangée. \
     Réessayez ; si le refus persiste, la table des jeux de données est illisible.";
/// `P10.20-l` — le canal d'un rapport à déclencher n'a pas été lu : rien n'est exécuté ni envoyé.
pub(crate) const CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_CANAL_NON_LU: &str = "RAPPORT PLANIFIÉ NON DÉCLENCHÉ : la base \
     n'a pas rendu le canal de ce rapport — ce n'est PAS « introuvable ou désactivé », c'est une lecture qui n'a pas \
     eu lieu. Rien n'est exécuté ni envoyé vers le canal, et sa marque d'échéance est inchangée. Réessayez ; si le \
     refus persiste, la table des canaux est illisible.";
/// `P10.33-h` — `last_error` d'un rapport DÛ dont le jeu de données est introuvable ou désactivé (écrit par le tick :
/// sans lui, le rapport dû ne laissait aucune trace).
pub(crate) const RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT: &str =
    "rapport dû non exécuté : dataset introuvable ou désactivé";
/// `P10.33-h` — `last_error` d'un rapport DÛ dont le canal est introuvable ou désactivé.
pub(crate) const RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT: &str = "rapport dû non exécuté : notifier introuvable ou désactivé";
/// `P10.29-l` — `last_error` et 400 de `/run` d'un rapport dont la base a refusé l'exécution : le texte du moteur (qui
/// peut citer l'énoncé compilé entier) ne part plus au client ni dans la liste des rapports ; il va au journal seul.
pub(crate) const EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE: &str = "exécution du rapport refusée par la base : rien \
     n'est envoyé, la cause est au journal du démon";

/// La lecture de définition que `deliver_report` fait, nommée : chacune a sa phrase d'absence (celle d'avant, à
/// l'octet), sa cause de lecture ratée et, pour le jeu de données et le canal, sa trace écrite par le tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum LectureDeLaDefinition {
    Rapport,
    JeuDeDonnees,
    Canal,
}

impl LectureDeLaDefinition {
    /// La phrase d'avant (400 de `/run`), à l'octet.
    pub(crate) fn phrase_d_absence(self) -> &'static str {
        match self {
            Self::Rapport => "rapport introuvable ou désactivé",
            Self::JeuDeDonnees => "dataset introuvable ou désactivé",
            Self::Canal => "notifier introuvable ou désactivé",
        }
    }
    /// La cause du 503 de `/run` quand cette lecture n'a pas eu lieu.
    pub(crate) fn cause_non_lue(self) -> &'static str {
        match self {
            Self::Rapport => CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU,
            Self::JeuDeDonnees => CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_JEU_DE_DONNEES_NON_LU,
            Self::Canal => CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_CANAL_NON_LU,
        }
    }
    /// Le `last_error` que le tick écrit sur un rapport dû dont la référence est absente ou désactivée. Aucun pour le
    /// rapport lui-même : absent ou désactivé entre la sélection et la lecture, il n'est plus dû.
    pub(crate) fn trace_d_absence(self) -> Option<&'static str> {
        match self {
            Self::Rapport => None,
            Self::JeuDeDonnees => Some(RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT),
            Self::Canal => Some(RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT),
        }
    }
    /// Ce qui n'a pas été lu, pour le journal (jamais un nom, un endpoint ni une requête).
    fn constat(self) -> &'static str {
        match self {
            Self::Rapport => "sa définition n'a pas pu être lue",
            Self::JeuDeDonnees => "son jeu de données n'a pas pu être lu",
            Self::Canal => "son canal n'a pas pu être lu",
        }
    }
}

/// Une définition que `deliver_report` n'a pas prise : rien n'est exécuté, envoyé ni écrit par lui.
#[derive(Debug, PartialEq)]
pub(crate) enum DefinitionNonPrise {
    /// Absente ou désactivée. `trace_posee` : le `last_error` du rapport porte déjà la trace d'absence de cette
    /// lecture (relu dans la lecture du rapport) — le tick ne la récrit pas à chaque passage.
    Absente { lecture: LectureDeLaDefinition, trace_posee: bool },
    /// Lecture ratée : `moteur` est la cause du moteur, pour le journal SEUL.
    NonLue { lecture: LectureDeLaDefinition, moteur: String },
}

/// Juge une lecture de définition en trois issues.
fn lecture_de_la_definition<T>(lue: rusqlite::Result<Option<T>>, lecture: LectureDeLaDefinition, trace_posee: bool) -> Result<T, DefinitionNonPrise> {
    match lue {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(DefinitionNonPrise::Absente { lecture, trace_posee }),
        Err(e) => Err(DefinitionNonPrise::NonLue { lecture, moteur: e.to_string() }),
    }
}

/// Échec du rendu d'un rapport, typé par son auteur : une phrase écrite par plume (compilation GXQL, requête vide,
/// budget, mémoire, quota), servie telle quelle ; ou le texte du moteur, qui ne va qu'au journal.
#[derive(Debug, PartialEq)]
pub(crate) enum EchecDuRendu {
    Plume(String),
    Moteur(String),
}

/// `P10.29-l` — les phrases écrites par plume que `run_query_ex` peut rendre pour une requête sans `qid` (liste
/// blanche, par ouverture) : interruption par le budget, budget mémoire (plafond appliqué ou non), quota de
/// déversement. Tout autre texte est celui du moteur.
const OUVERTURES_DES_PHRASES_DE_PLUME_DE_L_EXECUTION: [&str; 4] = [
    "requête interrompue (budget ",
    "budget mémoire dépassé : ",
    "mémoire épuisée pendant l'exécution (aucun plafond dur",
    "quota de déversement dépassé : ",
];

/// Classe l'échec rendu par `run_query_ex` : phrase de plume ou texte du moteur.
pub(crate) fn classer_l_echec_d_execution(e: String) -> EchecDuRendu {
    if OUVERTURES_DES_PHRASES_DE_PLUME_DE_L_EXECUTION.iter().any(|o| e.starts_with(o)) {
        EchecDuRendu::Plume(e)
    } else {
        EchecDuRendu::Moteur(e)
    }
}

/// EXÉCUTE un rapport (dataset GXQL) MASQUÉ par son `run_as_role` et le LIVRE via son notifier. Coeur partagé
/// par le tick de fond et /run. Ne PANIQUE jamais (les erreurs remontent en `Err`). Le lock métadonnées n'est
/// tenu QUE pour lire la définition + écrire le statut ; la requête (`run_query_ex`, pool read séparé) et
/// l'envoi (`notify_send`) tournent HORS lock.
///
/// `P10.20-w` — MARQUE D'ABORD : `last_run` est posé et COMPTÉ (une ligne) AVANT l'envoi. Avant, l'UPDATE venait
/// après `notify_send` en `let _ =` : refusé, `last_run` n'avançait pas et le rapport repartait vers le
/// notificateur tiers à chaque tick, sans `last_error` ni bilan. `Err` = définition non prise (absente, désactivée ou
/// non lue : [`DefinitionNonPrise`]) — rien n'est écrit ni envoyé.
///
/// Ce que « marque d'abord » change, et seulement cela : un processus tué ENTRE la marque et l'envoi perd le
/// rapport de cet intervalle (`interval_s`) au lieu de le renvoyer au redémarrage. Un envoi rendu `false` ou un
/// panic écrivaient déjà `last_run` avant ce changement : un envoi raté attendait déjà l'échéance suivante.
/// `P10.33-h` — un envoi que le notificateur rend `false` n'écrit NI `last_ok` NI `last_count`, et n'efface pas
/// l'erreur : il pose `last_error` = [`ENVOI_REFUSE_PAR_LE_NOTIFICATEUR`] (jamais l'URL ni le contenu). Avant, le
/// même UPDATE que le succès écrivait un « dernier succès » et effaçait l'erreur précédente. `delivered` reste rendu
/// tel quel à /run ; `statut_ecrit` se rapporte à l'écriture faite, quelle que soit l'issue de l'envoi.
pub(crate) fn deliver_report(db: &Arc<Mutex<Connection>>, db_path: &str, id: i64) -> Result<IssueDuRapport, DefinitionNonPrise> {
    // 1) charge la définition + le dataset GXQL + le notifier (kind/url/config) sous lock, puis relâche. Chaque lecture
    //    en trois issues (`P10.20-l`) ; le `last_error` courant est relu DANS la lecture du rapport, en valeur brute
    //    (aucun type exigé : une ligne qui se lisait avant se lit encore), pour dire si la trace d'absence est posée.
    let (name, run_as, tenant, soql, nkind, nurl, nconfig): (String, String, String, String, String, String, String) = {
        let conn = db.lock();
        type LigneDuRapport = (String, i64, i64, String, String, rusqlite::types::Value);
        let lue: rusqlite::Result<Option<LigneDuRapport>> = conn.query_row(
            "SELECT name,dataset_id,notifier_id,run_as_role,tenant,last_error FROM scheduled_report WHERE id=?1 AND enabled=1",
            params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).optional();
        let (name, dataset_id, notifier_id, run_as, tenant, last_error) = lecture_de_la_definition(lue, LectureDeLaDefinition::Rapport, false)?;
        let trace_posee = |lecture: LectureDeLaDefinition| {
            matches!((&last_error, lecture.trace_d_absence()), (rusqlite::types::Value::Text(t), Some(trace)) if t == trace)
        };
        let lu = conn.query_row("SELECT soql FROM dataset WHERE id=?1 AND enabled=1", params![dataset_id], |r| r.get::<_, String>(0)).optional();
        let soql = lecture_de_la_definition(lu, LectureDeLaDefinition::JeuDeDonnees, trace_posee(LectureDeLaDefinition::JeuDeDonnees))?;
        let lu = conn.query_row(
            "SELECT kind,url,config FROM notifier WHERE id=?1 AND enabled=1", params![notifier_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))).optional();
        let (nkind, nurl, nconfig) = lecture_de_la_definition(lu, LectureDeLaDefinition::Canal, trace_posee(LectureDeLaDefinition::Canal))?;
        (name, run_as, tenant, soql, nkind, nurl, nconfig)
    };
    // 2) COMPILE+EXÉCUTE MASQUÉ (via render_report_detail) puis LIVRE. Séparé pour que le CONTENU masqué livré
    //    soit OBSERVABLE en test.
    let now_ts = now();
    match render_report_detail(db_path, &name, &run_as, &tenant, &soql) {
        Ok((count, detail)) => {
            let config: Value = serde_json::from_str(&nconfig).unwrap_or(json!({}));
            let title = format!("Rapport planifié : {name}");
            // 2a) la marque d'échéance, comptée, AVANT tout effet externe.
            let marque = { let conn = db.lock(); conn.execute("UPDATE scheduled_report SET last_run=?1 WHERE id=?2", params![now_ts, id]) };
            if !statut_du_rapport_ecrit(id, marque, "marque d'échéance NON ÉCRITE, aucun envoi, le rapport reste dû au prochain tick") {
                return Ok(IssueDuRapport::MarqueRefusee);
            }
            // 2b) l'envoi, une fois la marque posée.
            let delivered = envoyer_le_rapport(&nkind, &nurl, &config, &title, &detail, now_ts);
            // 2c) le statut d'après envoi, compté — un refus est dit et compté, jamais un second envoi.
            //     `P10.33-h` — un envoi refusé n'est pas un succès : `last_error` seul, `last_ok`/`last_count` intacts.
            let statut = {
                let conn = db.lock();
                if delivered {
                    conn.execute("UPDATE scheduled_report SET last_ok=?1, last_error=NULL, last_count=?2 WHERE id=?3", params![now_ts, count, id])
                } else {
                    conn.execute("UPDATE scheduled_report SET last_error=?1 WHERE id=?2", params![ENVOI_REFUSE_PAR_LE_NOTIFICATEUR, id])
                }
            };
            let geste = if delivered {
                "envoi tenté, mais statut d'envoi (last_ok, last_count) NON ÉCRIT"
            } else {
                "envoi refusé par le notificateur, et last_error NON ÉCRIT"
            };
            let statut_ecrit = statut_du_rapport_ecrit(id, statut, geste);
            Ok(IssueDuRapport::Envoye { count, delivered, statut_ecrit })
        }
        Err(echec) => {
            // `P10.29-l` — la phrase servie (`last_error`, 400 de `/run`) est celle de plume, ou une constante quand
            // c'est le moteur qui a refusé ; le texte du moteur va au journal avec l'identifiant du rapport et son
            // tenant, jamais son nom, son canal ni sa requête.
            let e = match echec {
                EchecDuRendu::Plume(phrase) => phrase,
                EchecDuRendu::Moteur(moteur) => {
                    eprintln!("[rapports] WARN rapport planifié #{id} (tenant '{tenant}') : exécution refusée par la base, last_error porte une phrase fixe : {moteur}");
                    EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE.to_string()
                }
            };
            let ecrit = { let conn = db.lock(); conn.execute("UPDATE scheduled_report SET last_run=?1, last_error=?2 WHERE id=?3", params![now_ts, e, id]) };
            let consigne = statut_du_rapport_ecrit(id, ecrit, "échec d'exécution NON CONSIGNÉ (last_run, last_error)");
            Ok(IssueDuRapport::Echec { erreur: e, consigne })
        }
    }
}

/// COMPILE le GXQL du dataset MASQUÉ par `(run_as, tenant)` — parité EXACTE avec /api/query, qui passe
/// `effective_masks(path, &au.role, &au.tenant, env)`. `run_as` remplace le rôle de l'appelant (garantie
/// anti-exfiltration) ; `tenant` = celui DU CRÉATEUR (persisté à la création) -> les field-filters tenant-scopés
/// (`tenant='clientX'`) matchent. Un `tenant=""` codé en dur les RATAIT -> livraison de données brutes non
/// masquées (HIGH). `env=None` baseline (documenté). Exécute et rend `(count, detail_texte_masqué)`. Extrait de
/// `deliver_report` UNIQUEMENT pour rendre le contenu livré OBSERVABLE (test de non-régression du masque tenant).
/// Borne du détail d'un rapport planifié (`P11.22-g`) : nommée, dite dans le texte livré quand elle mord.
pub(crate) const REPORT_DETAIL_WINDOW: i64 = 5000;
/// `P10.29-l` — l'échec est typé ([`EchecDuRendu`]) : la compilation et la requête vide sont des phrases de plume, l'échec
/// d'exécution est classé par [`classer_l_echec_d_execution`].
pub(crate) fn render_report_detail(db_path: &str, name: &str, run_as: &str, tenant: &str, soql: &str) -> Result<(i64, String), EchecDuRendu> {
    let masks = effective_masks(db_path, run_as, tenant, None);
    // Choke-point unique : `soql_to_sql_masked_x` (= /api/query) -> denylist de secrets + enum fermée intacts.
    let compiled = soql_to_sql_masked_x(soql, 0, 0, None, &masks).map_err(EchecDuRendu::Plume)?;
    if compiled.is_empty() { return Err(EchecDuRendu::Plume("rapport : requête vide".into())); }
    // `P11.22-g` — lue avec sa ligne excédentaire, coupée par la troisième porte du fabricant : le détail livré
    // dit qu'il est coupé, au lieu de se présenter comme le rapport entier.
    let page_sql = format!("SELECT * FROM ({compiled}) LIMIT {}", crate::handlers::liste_bornee::borne_avec_ligne_excedentaire(REPORT_DETAIL_WINDOW));
    let mut v = run_query_ex(db_path, &page_sql, query_budget_interactive_ms(), None).map_err(classer_l_echec_d_execution)?;
    crate::handlers::liste_bornee::couper_le_corps_a_la_borne(&mut v, "rows", REPORT_DETAIL_WINDOW.max(0) as usize);
    Ok(format_report_detail(name, &v))
}

/// TICK de fond (thread dédié, PAR TENANT). Sélectionne les rapports DUS (enabled + intervalle écoulé) et les
/// livre. INERTE mode 0 : table vide -> 0 ligne -> retour immédiat (aucun réseau, aucune écriture). FAIL-SAFE :
/// chaque rapport isolé (catch_unwind + erreur consignée dans last_error) -> un rapport cassé n'arrête pas les
/// autres. Séquentiel (budget 2 Go).
///
/// REND SON BILAN (`P4.1-r`) : `Illisible` si la liste des rapports dus n'a pas pu être lue, `Lue(n)` =
/// rapports dus abandonnés (ligne indécodable, ou panic capturé — consigné aussi dans `last_error`). Une
/// livraison en erreur n'est PAS un abandon : `deliver_report` l'a consignée dans `last_error`.
/// `P10.20-w` — s'y ajoutent les écritures de statut perdues : marque d'échéance refusée (aucun envoi), statut
/// d'après envoi non écrit, échec non consigné, et la consignation d'un panic elle-même refusée.
pub(crate) fn run_due_reports(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnes = 0u32;
    let due: Vec<i64> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id FROM scheduled_report WHERE enabled=1 AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("rapports", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| r.get::<_, i64>(0)) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("rapports", &e),
        };
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(id) => due.push(id),
                Err(_) => abandonnes += 1,
            }
        }
        due
    };
    for id in due {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver_report(db, db_path, id)));
        match r {
            Ok(Ok(IssueDuRapport::Envoye { statut_ecrit: true, .. })) => {}
            Ok(Ok(IssueDuRapport::Envoye { statut_ecrit: false, .. })) => abandonnes += 1,
            Ok(Ok(IssueDuRapport::MarqueRefusee)) => abandonnes += 1,
            Ok(Ok(IssueDuRapport::Echec { consigne: true, .. })) => {} // erreur consignée dans last_error
            Ok(Ok(IssueDuRapport::Echec { consigne: false, .. })) => abandonnes += 1,
            // `P10.20-l` — une définition non lue est un rapport dû abandonné : compté, dit au journal, rien d'écrit.
            Ok(Err(DefinitionNonPrise::NonLue { lecture, moteur })) => {
                abandonnes += 1;
                eprintln!("[rapports] WARN rapport planifié #{id} dû non exécuté : {}, rien n'est envoyé ni écrit, compté abandonné : {moteur}", lecture.constat());
            }
            // `P10.33-h` — jeu de données ou canal absent ou désactivé : le rapport dû le dit dans `last_error` (une phrase
            // fixe, écrite une fois : relue dans la lecture du rapport). Une trace refusée ou sans effet est comptée.
            Ok(Err(DefinitionNonPrise::Absente { lecture, trace_posee })) => match (lecture.trace_d_absence(), trace_posee) {
                (Some(trace), false) => {
                    let ecrit = { let conn = db.lock(); conn.execute("UPDATE scheduled_report SET last_error=?1 WHERE id=?2", params![trace, id]) };
                    if !statut_du_rapport_ecrit(id, ecrit, "référence introuvable ou désactivée NON CONSIGNÉE (last_error)") {
                        abandonnes += 1;
                    }
                }
                // Trace déjà posée : rien à récrire.
                (Some(_), true) => {}
                // Le rapport lui-même absent ou désactivé depuis la sélection : il n'est plus dû, rien à dire.
                (None, _) => {}
            },
            Err(_) => {
                abandonnes += 1;
                let ecrit = {
                    let conn = db.lock();
                    conn.execute("UPDATE scheduled_report SET last_run=?1, last_error=?2 WHERE id=?3",
                        params![now_ts, "panic interne du rapport (capturé)", id])
                };
                if !statut_du_rapport_ecrit(id, ecrit, "panic capturé NON CONSIGNÉ (last_run, last_error)") {
                    abandonnes += 1;
                }
            }
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnes)
}

/// Témoin d'envoi (tests seulement) : intercepte `envoyer_le_rapport` sur le fil courant — le tick appelle
/// `deliver_report` sur SON fil (`catch_unwind`), donc un témoin posé par le test voit chaque envoi du tick.
#[cfg(test)]
pub(crate) mod temoin_d_envoi {
    use std::cell::RefCell;
    type Intercepteur = Box<dyn FnMut(&str, &str, &str) -> bool>;
    thread_local! { static INTERCEPTEUR: RefCell<Option<Intercepteur>> = RefCell::new(None); }
    /// Pose l'intercepteur `(kind, titre, détail) -> livré` du fil courant.
    pub(crate) fn poser(f: impl FnMut(&str, &str, &str) -> bool + 'static) {
        INTERCEPTEUR.with(|c| *c.borrow_mut() = Some(Box::new(f)));
    }
    pub(crate) fn retirer() {
        INTERCEPTEUR.with(|c| *c.borrow_mut() = None);
    }
    pub(super) fn intercepter(kind: &str, title: &str, detail: &str) -> Option<bool> {
        INTERCEPTEUR.with(|c| c.borrow_mut().as_mut().map(|f| f(kind, title, detail)))
    }
}
