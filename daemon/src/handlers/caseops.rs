//! #39 TEAM CASE-OPS (readiness P1) — extension NON DESTRUCTIVE du système de cases first-class (#4a/#4a-bis).
//! Cinq leviers, tous ADDITIFS et INERTES en mode 0 (aucune politique SLA, aucune fusion, aucun lien) :
//!   1. PER-ASSIGNEE QUEUES  : résumé de charge par propriétaire (`case_queues_json`) — compte open/overdue/
//!      ack-pending/breach par assignee, + « my queue ». La LISTE reste `cases_list_json_paged` (#4a, déjà
//!      filtrée assignee + paginée serveur) : on n'ajoute qu'un agrégat de tête.
//!   2. MERGE (soft)         : `case_merge` marque la SOURCE `merged_into=<dst>` + la clôt, SANS supprimer sa
//!      timeline (append-only) ; `case_get_json` combine les items des sources fusionnées dans la cible. Ledger.
//!   3. LINK (non destructif): `case_link_add` associe deux cases (related/duplicate/blocks) sans rien fusionner.
//!   4. MULTI-LEVEL SLA      : table `sla_policy` (ack + resolve par priorité). VIDE -> SLA legacy (#4a) INCHANGÉ.
//!      Chrono ancré sur des timestamps IMMUABLES (`ts`) + un cumul de PAUSE (`sla_pause_accum`) ; pause/reprise
//!      sur le statut 'waiting'. Le tick `sla_multilevel_tick` pose les breach (early-return si 0 politique).
//!   5. MTTA/MTTR DASHBOARD  : `case_metrics_json` agrège mean/p50 MTTA (first_response_ts-ts) & MTTR
//!      (closed_ts-ts-pause) sur une fenêtre, par assignee/severity. Lecture pure sur `incident` (human-scale).
//!   6. CLIENT-READ API      : surface EXTERNE read-only, tenant-scopée, MASQUÉE — un client MSSP voit SES cases
//!      (statut/sévérité/cycle de vie), JAMAIS les identités analystes, les notes internes, ni les refs
//!      alert/event. Auth = jeton `kind='client'` (seam dédié) OU rôle résolu `client`. Cf. INVARIANT plus bas.
//!
//! INVARIANT SÉCU CLIENT-READ :
//!   - TENANT-SCOPE : les handlers lisent la base via `req_db_path`/`req_db` du tenant de l'appelant -> en mode 0
//!     l'unique base ; en mode 1 la base du tenant résolu par auth_guard. AUCUN cross-tenant possible (isolation
//!     par-base, comme /api/query & scheduled-reports #60). On passe le VRAI tenant à effective_masks, jamais "".
//!   - MASQUÉ : `effective_masks(role,tenant,env)` du RÔLE de l'appelant est appliqué aux champs textuels
//!     exposés. Rôle `client` -> role_rank 0 (fail-closed) -> masqué par TOUTE règle field-filter.
//!   - PROJECTION FERMÉE : la sortie est une allowlist de colonnes `incident` (aucune colonne de la denylist de
//!     secrets n'existe sur `incident`) ; owner/assignee/summary interne + refs alert/event NE SONT PAS exposés.
//!   - READ-ONLY : les handlers n'exécutent que des SELECT paramétrés (jamais de SQL brut, jamais /api/query,
//!     jamais une route mutante) ; le jeton client ne s'authentifie QUE sur `client_bearer_path`.
//!
//! ⚠⚠ ISOLATION CLIENT — #3 PHASE 3 Part B (ÉLARGIT LA PROJECTION CLIENT) ⚠⚠
//!   La projection client (`client_case_row`) gagne TROIS champs ADDITIFS, closed-allowlist, tous dérivés de
//!   colonnes NON secrètes déjà tenant-scopées, approuvés par l'opérateur (« minimal safe view ») :
//!     • `is_incident` (bool) = `incident_tier IS NOT NULL` — le BOOLÉEN seul (le SELECT calcule IS NOT NULL en
//!       SQL : le tier BRUT 1..4 ne rentre jamais dans Rust ; `incident_type`/`commander` jamais lus).
//!     • `phase` (enum coarse FERMÉ) — dérivé du SEUL `status` (client_phase), JAMAIS d'une étape/runbook.
//!     • `acknowledged` (bool) = `first_response_ts IS NOT NULL` — timing MTTA-style coarse (pas de timestamp/durée).
//!   DENYLIST DURE INCHANGÉE (jamais exposé, ni valeur ni chaîne dérivable) : `incident_tier` brut,
//!   `incident_type`, `commander`, tout runbook (nom/id/key), tout `case_step` (titre/guidance/status/count/
//!   target/host), tout GXQL/search, tout `action_kind`, notes/commentaires internes, identité analyste/assignee,
//!   cross-tenant. La timeline client garde son allowlist de kinds INCHANGÉE (jamais 'incident'/'runbook'/'step').
use crate::*;
use rusqlite::OptionalExtension;

// ================================================================================================
// MULTI-LEVEL SLA — politiques configurables (ack + resolve par priorité). VIDE = SLA legacy #4a.
// ================================================================================================

/// Politique SLA ACTIVE pour une priorité (1..4) : (policy_id, ack_target_s, resolve_target_s). `Ok(None)` si la
/// table est vide ou aucune politique activée pour ce tier -> l'appelant retombe sur le SLA legacy (sla_due).
/// `P10.20-b` (rang trois) — UNE LECTURE RATÉE N'EST PAS « AUCUNE POLITIQUE » : le `.ok()` d'avant rendait `None` sur
/// une table illisible, et chaque appelant retombait EN SILENCE sur le régime legacy (échéances non posées, ou celles
/// de l'ancienne priorité gardées). L'absence ÉTABLIE (`QueryReturnedNoRows`) reste `Ok(None)` ; l'échec remonte.
pub(crate) fn sla_policy_for(conn: &Connection, priority: i64) -> rusqlite::Result<Option<(i64, i64, i64)>> {
    conn.query_row(
        "SELECT id, ack_target_s, resolve_target_s FROM sla_policy WHERE priority=?1 AND enabled=1",
        params![priority],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
    )
    .optional()
}

/// (Ré)applique la politique SLA multi-niveau à un case : pose `sla_policy_id`, `ack_due` (si PAS encore
/// acquitté : first_response_ts NULL), `resolve_due`, à partir du `ts` IMMUABLE + cibles + cumul de pause.
/// INERTE si aucune politique pour la priorité courante ET aucune politique portée (mode 0 : dues restent NULL ->
/// SLA legacy). Ne touche JAMAIS un case terminal (resolved/closed). Idempotent. Appelée à la création, sur
/// changement de priorité et au recalcul de l'upsert.
/// `P10.20-w` (reste) — L'ÉCRITURE EST COMPTÉE ET RENDUE (`IssueDuChronoSla`) : les deux `UPDATE` étaient avalés et
/// la fonction rendait `()`, donc la création, la mise à jour et le recalcul de l'upsert ne savaient pas si l'échéance
/// avait été posée — le recalcul comptait « recalculé » un dossier dont la base avait refusé l'échéance.
/// `P10.20-b` (rang trois) — LES DEUX LECTURES SONT JUGÉES : la ligne du dossier et la politique de sa priorité
/// étaient lues par `.ok()`, et une lecture ratée rendait `RienAFaire` — « rien à poser » sur un chrono qu'on n'avait
/// pas lu. L'absence établie (dossier disparu, aucune politique) garde la sortie d'avant ; l'échec rend `NonLu`, et
/// RIEN n'est écrit.
/// `P10.20-w` (reste) — UNE PRIORITÉ SANS POLITIQUE N'HÉRITE PLUS DE CELLE D'AVANT : la sortie `RienAFaire` laissait
/// `sla_policy_id`, `ack_due` et `resolve_due` de l'ANCIENNE priorité, servis par la fiche comme ceux de la priorité
/// courante et toujours jugés par le tour multi-niveau (dès qu'une autre politique est active). Le dossier retombe
/// désormais sur le régime legacy, comme s'il avait été créé à cette priorité : les trois colonnes reviennent à NULL
/// (`sla_due` legacy, recalculé par `case_apply_update`, gouverne seul). L'`UPDATE` est conditionné à une politique
/// PORTÉE : zéro ligne y est un fait (dossier déjà legacy -> `RienAFaire`, mode 0 octet pour octet). Même règle au
/// recalcul de l'upsert d'une politique DÉSACTIVÉE : il passe APRÈS l'effacement transactionnel des dossiers de cette
/// politique (`sla_policy_upsert`, `P10.31-v`), donc il ne rend au régime legacy — et ne compte recalculés — que les
/// dossiers ACTIFS de la priorité qui portaient un `sla_policy_id` pendant ou étranger.
/// LIMITES ÉCRITES : les marqueurs `ack_breached`/`resolve_breached` ne sont pas remis à zéro (un dépassement passé
/// sous l'ancienne priorité reste un fait, le registre le porte) ; une pause en cours (`sla_paused_since`) est
/// conservée, et `sla_on_status_change` la reprend à la sortie de `waiting` même sans politique portée (sinon le
/// chrono resterait en pause pour toujours si une politique revenait) ; la SUPPRESSION d'une politique
/// (`sla_policy_delete`) applique la même règle à ses dossiers par son propre `UPDATE` (`P10.31-v`).
pub(crate) fn sla_apply_policy(conn: &Connection, id: i64) -> IssueDuChronoSla {
    let lu: rusqlite::Result<Option<(i64, i64, String, i64, Option<i64>)>> = conn
        .query_row(
            "SELECT ts, priority, status, COALESCE(sla_pause_accum,0), first_response_ts FROM incident WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional();
    let row = match lu {
        Ok(v) => v,
        Err(e) => return IssueDuChronoSla::NonLu(format!("ligne du dossier: {e}")),
    };
    let Some((ts, priority, status, pause_accum, first_resp)) = row else { return IssueDuChronoSla::RienAFaire };
    if matches!(status.as_str(), "resolved" | "closed" | "contained") {
        return IssueDuChronoSla::RienAFaire; // terminal : le chrono est arrêté, on ne recompute pas.
    }
    let politique = match sla_policy_for(conn, priority) {
        Ok(v) => v,
        Err(e) => return IssueDuChronoSla::NonLu(format!("politique de la priorité {priority}: {e}")),
    };
    let Some((pid, ack_s, res_s)) = politique else {
        // pas de politique -> legacy : efface celle d'une ancienne priorité, s'il en porte une.
        return match conn.execute(
            "UPDATE incident SET sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL WHERE id=?1 AND sla_policy_id IS NOT NULL",
            params![id],
        ) {
            Ok(0) => IssueDuChronoSla::RienAFaire,
            res => ecriture_du_chrono("sla_policy_id/ack_due/resolve_due (effacement)", res),
        };
    };
    let resolve_due = ts + res_s + pause_accum;
    // ack_due n'est (re)posé que tant que le case n'est PAS acquitté (first_response_ts NULL) : après ack, le
    // chrono d'acquittement est arrêté et son échéance figée.
    if first_resp.is_none() {
        let ack_due = ts + ack_s + pause_accum;
        ecriture_du_chrono(
            "sla_policy_id/ack_due/resolve_due",
            conn.execute(
                "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?3 WHERE id=?4",
                params![pid, ack_due, resolve_due, id],
            ),
        )
    } else {
        ecriture_du_chrono(
            "sla_policy_id/resolve_due",
            conn.execute(
                "UPDATE incident SET sla_policy_id=?1, resolve_due=?2 WHERE id=?3",
                params![pid, resolve_due, id],
            ),
        )
    }
}

/// `P10.20-w` (reste) — CE QU'A FAIT UNE ÉCRITURE DU CHRONO SLA MULTI-NIVEAU (`sla_apply_policy`,
/// `sla_on_status_change`). Le `()` d'avant ne distinguait pas « écrit » de « refusé par la base » : un appelant
/// qui disait « échéance posée » ou comptait « recalculé » le disait sur une écriture peut-être non faite.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum IssueDuChronoSla {
    /// L'`UPDATE` a posé exactement une ligne.
    Ecrit,
    /// Rien à écrire : absence ÉTABLIE (dossier disparu, pas de politique et aucune portée), dossier terminal ou non
    /// gouverné, état déjà visé.
    RienAFaire,
    /// La base n'a PAS pris l'écriture (erreur, ou autre chose qu'une ligne) : `colonnes: cause`.
    Refuse(String),
    /// `P10.20-b` (rang trois) — une LECTURE qui gouverne le chrono (ligne du dossier, politique de sa priorité) a
    /// échoué : rien n'est écrit, et ce n'est PAS « rien à faire » — `quoi: cause`.
    NonLu(String),
}

/// Compte une écriture du chrono : une ligne, ou le refus nommé par ses colonnes.
fn ecriture_du_chrono(colonnes: &str, res: rusqlite::Result<usize>) -> IssueDuChronoSla {
    match res {
        Ok(1) => IssueDuChronoSla::Ecrit,
        Ok(n) => IssueDuChronoSla::Refuse(format!("{colonnes}: {n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => IssueDuChronoSla::Refuse(format!("{colonnes}: {e}")),
    }
}

/// PAUSE/REPRISE du chrono SLA multi-niveau sur transition de statut. INERTE si le case n'est pas gouverné par
/// une politique (`sla_policy_id` NULL) -> mode 0 byte-identique. Modèle ancré sur des TIMESTAMPS IMMUABLES :
///   - entrée en 'waiting' (on-hold) : mémorise `sla_paused_since=t` (le chrono s'arrête) ;
///   - sortie de 'waiting' vers un statut ACTIF : cumule (t - paused_since) dans `sla_pause_accum` et DÉCALE
///     ack_due/resolve_due d'autant (le temps « en attente » ne consomme pas le SLA), efface paused_since.
/// Le breach reste calculé depuis (ts immuable + cumul) — un analyste ne peut PAS reculer `ts` pour tricher.
/// `P10.20-w` (reste) — les deux écritures (pause, reprise) sont COMPTÉES et rendues (`IssueDuChronoSla`).
/// `P10.20-b` (rang trois) — LA LECTURE EST JUGÉE : `.ok()` rendait `RienAFaire` sur une ligne non lue, et la pause ou la
/// reprise était sautée en silence (chrono qui court pendant l'attente, ou resté en pause sur un dossier actif).
/// Dossier absent = `RienAFaire` d'avant ; lecture ratée = `NonLu`, rien n'est écrit.
/// `P10.20-w` (reste) — une pause EN COURS se reprend même sans politique portée : `sla_apply_policy` efface désormais
/// la politique d'une ancienne priorité sans toucher la pause, et un dossier sorti de `waiting` sans reprise garderait
/// `sla_paused_since` — le tour multi-niveau le sauterait pour toujours si une politique revenait. Mode 0 inchangé :
/// sans politique, `sla_paused_since` n'est jamais posé.
pub(crate) fn sla_on_status_change(conn: &Connection, id: i64, new_status: &str, t: i64) -> IssueDuChronoSla {
    let lu: rusqlite::Result<Option<(Option<i64>, Option<i64>)>> = conn
        .query_row(
            "SELECT sla_policy_id, sla_paused_since FROM incident WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional();
    let row = match lu {
        Ok(v) => v,
        Err(e) => return IssueDuChronoSla::NonLu(format!("chrono du dossier: {e}")),
    };
    let Some((policy_id, paused_since)) = row else { return IssueDuChronoSla::RienAFaire };
    if policy_id.is_none() && paused_since.is_none() {
        return IssueDuChronoSla::RienAFaire; // pas de politique multi-niveau -> aucune comptabilité de pause (legacy inchangé)
    }
    match (paused_since, new_status == "waiting") {
        (None, true) => {
            // le chrono passe EN PAUSE.
            ecriture_du_chrono(
                "sla_paused_since",
                conn.execute("UPDATE incident SET sla_paused_since=?1 WHERE id=?2", params![t, id]),
            )
        }
        (Some(since), false) => {
            // REPRISE : cumule la durée de pause + décale les échéances d'autant.
            let delta = (t - since).max(0);
            ecriture_du_chrono(
                "sla_pause_accum/ack_due/resolve_due",
                conn.execute(
                    "UPDATE incident SET sla_pause_accum = COALESCE(sla_pause_accum,0)+?1, sla_paused_since=NULL, \
                     ack_due = CASE WHEN ack_due IS NULL THEN NULL ELSE ack_due+?1 END, \
                     resolve_due = CASE WHEN resolve_due IS NULL THEN NULL ELSE resolve_due+?1 END WHERE id=?2",
                    params![delta, id],
                ),
            )
        }
        _ => IssueDuChronoSla::RienAFaire, // déjà dans l'état visé -> no-op
    }
}

/// #39 — TICK SLA MULTI-NIVEAU : marque les breach d'ACQUITTEMENT (now>ack_due, pas encore acquitté) et de
/// RÉSOLUTION (now>resolve_due, non terminal), une seule fois (ack_breached/resolve_breached anti re-notif),
/// trace un item 'sla' + ledger, et notifie via les notifiers du tenant (min_severity respecté). SKIP les
/// cases EN PAUSE (sla_paused_since NOT NULL). EARLY-RETURN si `sla_policy` VIDE -> ZÉRO travail mode 0
/// (miroir de escalate_overdue_cases). Séquentiel + LIMIT (budget 2 Go). Appelé dans la boucle de fond.
/// Marqueur, chronologie ou transaction refusés : notifie QUAND MÊME, sans trace (voir `sla_multilevel_tick_par`).
pub(crate) fn sla_multilevel_tick(db: &Arc<Mutex<Connection>>) {
    sla_multilevel_tick_par(db, &mut notify_send);
}

/// `P10.20-w` — fin du `detail` d'une notification de dépassement SLA que la base n'a PAS enregistré : marqueur
/// `ack_breached`/`resolve_breached` refusé, ou (`P10.33-k`) chronologie, `BEGIN` ou `COMMIT` refusés, qui annulent
/// le marqueur avec eux. Le destinataire apprend que le dépassement n'est pas enregistré et que l'alerte reviendra au
/// tour suivant.
pub(crate) const DEPASSEMENT_SLA_NON_ENREGISTRE: &str =
    "DÉPASSEMENT NON ENREGISTRÉ : la base a refusé le marqueur, sa chronologie ou leur transaction — ni marqueur, ni chronologie, ni registre ; cette notification sera renvoyée au prochain tour.";

/// `P10.20-w` (rang trois) — LE MARQUEUR DE DÉPASSEMENT EST ÉCRIT ET COMPTÉ AVANT TOUTE TRACE, comme
/// `escalate_overdue_cases_par`. Avant, la notification partait, puis `UPDATE incident SET {col}=1` était AVALÉ,
/// puis la chronologie et le registre attestaient le dépassement : sur une écriture refusée, le marqueur restait à 0,
/// le dossier restait sélectionné, et CHAQUE tick renvoyait la notification ET ajoutait un `case.sla_*_breach` au
/// registre non purgeable pour un marquage jamais posé.
/// L'ORDRE, DEPUIS `P10.33-k` : marqueur (`AND {col}=0`, un seul marqueur gagnant), chronologie comptée et maillon dans
/// UNE transaction, validée ; PUIS l'envoi. Aucune ligne marquée -> déjà marqué (ou disparu), rien. Transaction validée
/// -> envoi nominal (un maillon manquant n'annule rien : `P10.31-u`, la primitive l'a dit au journal). Marqueur,
/// chronologie, `BEGIN` ou `COMMIT` refusés -> rien n'est écrit, l'envoi part QUAND MÊME (un SLA réellement dépassé ne
/// se tait pas : renvoyé à chaque tour tant que le refus dure), son `detail` finit par `DEPASSEMENT_SLA_NON_ENREGISTRE`,
/// et le refus est compté UNE fois par tour (pas par dossier) au balayage `sla_multilevel_marqueur` (`/metrics`).
/// L'envoyeur est injecté pour que les témoins COMPTENT les envois sans réseau ; la production passe `notify_send`.
#[allow(clippy::type_complexity)]
pub(crate) fn sla_multilevel_tick_par(
    db: &Arc<Mutex<Connection>>,
    envoyer: &mut dyn FnMut(&str, &str, &Value, i64, &str, &str, &str, i64) -> bool,
) {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    let now_i = now();
    let (ack_b, res_b, notifiers): (Vec<(i64, String, i64)>, Vec<(i64, String, i64)>, Vec<(String, String, i64, String)>) = {
        let conn = db.lock();
        // GATE : aucune politique -> on ne fait RIEN (pas même un scan de la table incident).
        // `P10.20-w` — une porte NON LUE n'est pas « aucune politique » : le tour est sauté, mais COMPTÉ (balayage
        // `sla_multilevel_politique`, `/metrics`), sinon des SLA réellement échus se taisent sans trace.
        let has_policy: i64 = match conn.query_row("SELECT EXISTS(SELECT 1 FROM sla_policy WHERE enabled=1)", [], |r| r.get(0)) {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("sla_multilevel_politique", &e.to_string()); return; }
        };
        if has_policy == 0 {
            return;
        }
        let ack_b: Vec<(i64, String, i64)> = match conn
            .prepare(
                "SELECT id,COALESCE(title,''),priority FROM incident \
                 WHERE ack_due IS NOT NULL AND ack_breached=0 AND first_response_ts IS NULL \
                   AND sla_paused_since IS NULL AND merged_into IS NULL \
                   AND status NOT IN ('resolved','closed','contained') AND ?1 > ack_due \
                 ORDER BY ack_due LIMIT 20",
            )
            .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            // `P10.7-f` (lot 106) — lue EN BLOC : une ligne en erreur ne raccourcit plus la liste en silence.
            Err(e) => { crate::metrics::compter_un_tick_aveugle("sla_multilevel", &e.to_string()); return; }
        };
        let res_b: Vec<(i64, String, i64)> = match conn
            .prepare(
                "SELECT id,COALESCE(title,''),priority FROM incident \
                 WHERE resolve_due IS NOT NULL AND resolve_breached=0 \
                   AND sla_paused_since IS NULL AND merged_into IS NULL \
                   AND status NOT IN ('resolved','closed','contained') AND ?1 > resolve_due \
                 ORDER BY resolve_due LIMIT 20",
            )
            .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            // `P10.7-f` (lot 106) — lue EN BLOC : une ligne en erreur ne raccourcit plus la liste en silence.
            Err(e) => { crate::metrics::compter_un_tick_aveugle("sla_multilevel", &e.to_string()); return; }
        };
        if ack_b.is_empty() && res_b.is_empty() {
            return;
        }
        let notifiers: Vec<(String, String, i64, String)> = match conn
            .prepare("SELECT kind,url,min_severity,config FROM notifier WHERE enabled=1")
            .and_then(|mut s| s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(e) => { crate::metrics::compter_un_tick_aveugle("sla_multilevel", &e.to_string()); return; }
        };
        (ack_b, res_b, notifiers)
    };
    // `P10.20-w` — marqueurs refusés CE tour-ci : (nombre de dossiers, dernière cause), comptés une fois après les boucles.
    let mut marqueurs_refuses: (usize, String) = (0, String::new());
    let mut fire = |id: i64, title: &str, priority: i64, col: &str, kind: &str, what: &str| {
        let sev = match priority { 1 => 4, 2 => 3, 3 => 2, _ => 1 };
        let detail = format!("Case #{id} « {title} » : SLA {what} P{priority} dépassé.");
        // `P10.20-w` — LE MARQUEUR D'ABORD, COMPTÉ : sans lui, l'envoi part avec l'aveu, mais aucune trace (voir l'en-tête).
        // `P10.33-k` — la chronologie passait APRÈS l'envoi par `case_add_item`, qui avale : refusée, le
        // dépassement était marqué et notifié sans aveu, absent de la chronologie, jamais renvoyé. Marqueur, chronologie
        // comptée (`ajouter_l_element_au_dossier`) et maillon forment UNE transaction (`jouer_le_geste_garde`), validée
        // AVANT l'envoi (le verrou de la base n'est pas tenu pendant l'envoi) : une chronologie refusée, un `BEGIN` ou un
        // `COMMIT` refusé annulent le marqueur et suivent le chemin du marqueur refusé — envoi QUAND MÊME avec l'aveu,
        // rien en chronologie ni au registre, compté au balayage `sla_multilevel_marqueur`, renvoyé au tour suivant.
        let issue = {
            let conn = db.lock();
            jouer_le_geste_garde(&conn, "caseops", &format!("dépassement SLA du dossier #{id}"), |conn| {
                match conn.execute(&format!("UPDATE incident SET {col}=1 WHERE id=?1 AND {col}=0"), params![id]) {
                    Ok(0) => return Err(None), // déjà marqué (ou disparu) depuis la sélection : rien à notifier ni à tracer
                    Ok(_) => {}
                    Err(e) => return Err(Some(e.to_string())),
                }
                ajouter_l_element_au_dossier(conn, id, now_i, "sla", "system", &detail, None).map_err(|cause| Some(format!("chronologie du dépassement : {cause}")))?;
                Ok(ledger_append(conn, kind, &format!("#{id} P{priority} {what}")))
            })
        };
        let refus = match issue {
            // `P10.31-u` — pas de surface où avouer un maillon manquant ici : la primitive l'a dit au journal.
            Issue::Valide(maillon) => {
                maillon.laisser_a_l_aveu_de_la_primitive();
                None
            }
            Issue::Refuse(None) => return,
            Issue::Refuse(Some(cause)) => Some(cause),
            Issue::NonOuvert(e) => Some(format!("transaction non ouverte : {e}")),
            Issue::NonValide(e) => Some(format!("validation refusée : {e}")),
        };
        let detail_envoye = match refus {
            None => detail.clone(),
            Some(cause) => {
                marqueurs_refuses.0 += 1;
                marqueurs_refuses.1 = cause;
                format!("{detail} {DEPASSEMENT_SLA_NON_ENREGISTRE}")
            }
        };
        for (nk, url, minsev, cfg) in &notifiers {
            if sev >= *minsev {
                let config: Value = serde_json::from_str(cfg).unwrap_or_else(|_| json!({}));
                let _ = envoyer(nk, url, &config, sev, &format!("SLA {what} : {title}"), &detail_envoye, "", now_i);
            }
        }
    };
    for (id, title, pr) in &ack_b {
        fire(*id, title, *pr, "ack_breached", "case.sla_ack_breach", "acquittement (MTTA)");
    }
    for (id, title, pr) in &res_b {
        fire(*id, title, *pr, "resolve_breached", "case.sla_resolve_breach", "résolution (MTTR)");
    }
    if marqueurs_refuses.0 > 0 {
        crate::metrics::compter_une_escalade_notifiee_non_enregistree("sla_multilevel_marqueur", marqueurs_refuses.0, &marqueurs_refuses.1);
    }
}

// ================================================================================================
// MERGE (soft, non destructif) + LINK (association)
// ================================================================================================

/// FUSION SOFT #39 : marque la SOURCE `merged_into=dst` + la clôt ('closed'), SANS supprimer sa ligne ni sa
/// timeline (append-only, audit préservé, réversible via case_unmerge). Trace un item 'merge' sur la source ET
/// la cible + ledger `case.merge`. Refuse : case inexistant, src==dst, source déjà fusionnée, ou fusion CIBLE
/// -> SOURCE (anti-cycle direct). `case_get_json(dst)` combinera les items des sources fusionnées.
/// `P10.29-b` — POURQUOI UNE FUSION N'A PAS LIEU. `case_merge` rendait `false` pour chacun de ces faits, et la route un
/// 404 nu : la console ne pouvait pas dire lequel. Chaque variante a sa réponse nommée (`RefusDeFusion::reponse`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefusDeFusion {
    /// La source et la cible sont le même dossier (demande mal formée).
    MemeDossier,
    /// Aucun dossier ne porte l'identifiant de la source (absence établie).
    SourceAbsente,
    /// Aucun dossier ne porte l'identifiant de la cible (absence établie).
    CibleAbsente,
    /// La source est déjà fusionnée dans ce dossier-là.
    SourceDejaFusionnee(i64),
    /// La source est en amont de la cible dans la chaîne des fusions : fusionner fermerait un cycle.
    Cycle,
    /// Une lecture n'a pas eu lieu : rien n'est établi.
    NonLu(String),
}

/// `P10.29-b` — la fusion d'un dossier dans lui-même.
pub(crate) const CAUSE_FUSION_DANS_LE_MEME_DOSSIER: &str = "FUSION REFUSÉE, MÊME DOSSIER : un dossier ne se fusionne \
     pas dans lui-même — `into` doit désigner un autre dossier. Rien n'a été fait.";
/// `P10.29-b` — la cible de la fusion n'existe pas.
pub(crate) const CAUSE_FUSION_CIBLE_INTROUVABLE: &str = "FUSION REFUSÉE, DOSSIER CIBLE INTROUVABLE : aucun dossier ne \
     porte l'identifiant `into` (la lecture a abouti et n'a trouvé aucune ligne). Rien n'a été fait.";
/// `P10.29-b` — la source est déjà fusionnée ailleurs.
pub(crate) const CAUSE_FUSION_SOURCE_DEJA_FUSIONNEE: &str = "FUSION REFUSÉE, CE DOSSIER EST DÉJÀ FUSIONNÉ : il l'est \
     dans un autre dossier (défusionnez-le d'abord ; il n'est jamais re-fusionné en silence). Rien n'a été fait.";
/// `P10.29-b` — la fusion fermerait un cycle.
pub(crate) const CAUSE_FUSION_FERMERAIT_UN_CYCLE: &str = "FUSION REFUSÉE, ELLE FERMERAIT UN CYCLE : le dossier cible \
     est déjà fusionné, directement ou par une chaîne, dans ce dossier — la fusion ne laisserait aucun dossier \
     survivant dans la liste. Rien n'a été fait.";
/// `P10.29-b` — le corps ne désigne pas de cible.
pub(crate) const CAUSE_FUSION_SANS_CIBLE: &str = "FUSION REFUSÉE : le corps doit porter `into`, l'identifiant (entier \
     positif) du dossier cible. Rien n'a été fait.";
/// `P10.29-b` — la défusion d'un dossier qui n'est pas fusionné.
pub(crate) const CAUSE_DEFUSION_DOSSIER_NON_FUSIONNE: &str = "DÉFUSION REFUSÉE, CE DOSSIER N'EST PAS FUSIONNÉ : il n'a \
     rien à défaire. Rien n'a été fait.";

impl RefusDeFusion {
    /// La réponse nommée de chaque fait : 400 (demande), 404 (absence établie), 409 (état qui s'y oppose), 503 (non lu).
    pub(crate) fn reponse(&self) -> Response {
        match self {
            Self::MemeDossier => bad_req(CAUSE_FUSION_DANS_LE_MEME_DOSSIER),
            Self::SourceAbsente => not_found(crate::handlers::cases::CAUSE_DOSSIER_INTROUVABLE),
            Self::CibleAbsente => not_found(CAUSE_FUSION_CIBLE_INTROUVABLE),
            Self::SourceDejaFusionnee(_) => err_json(StatusCode::CONFLICT, CAUSE_FUSION_SOURCE_DEJA_FUSIONNEE),
            Self::Cycle => err_json(StatusCode::CONFLICT, CAUSE_FUSION_FERMERAIT_UN_CYCLE),
            Self::NonLu(cause) => crate::handlers::cases::refus_du_dossier_non_lu(cause),
        }
    }
}

/// `P10.29-b` — LE JUGEMENT D'UNE FUSION, AVANT TOUTE ÉCRITURE : les mêmes refus que `case_merge` portait, chacun nommé,
/// et une lecture refusée distinguée d'une absence. `case_merge` l'appelle ; la route aussi, pour nommer le refus.
pub(crate) fn juger_la_fusion(conn: &Connection, src_id: i64, dst_id: i64) -> Result<(), RefusDeFusion> {
    if src_id == dst_id {
        return Err(RefusDeFusion::MemeDossier);
    }
    let lire = |id: i64| conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![id], |r| r.get::<_, Option<i64>>(0));
    // les deux doivent exister ; la source ne doit pas être DÉJÀ fusionnée ailleurs.
    let src_merged = match lire(src_id) {
        Ok(m) => m,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(RefusDeFusion::SourceAbsente),
        Err(e) => return Err(RefusDeFusion::NonLu(e.to_string())),
    };
    match lire(dst_id) {
        Ok(_) => {}
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(RefusDeFusion::CibleAbsente),
        Err(e) => return Err(RefusDeFusion::NonLu(e.to_string())),
    }
    if let Some(ailleurs) = src_merged {
        return Err(RefusDeFusion::SourceDejaFusionnee(ailleurs)); // pas de re-fusion silencieuse
    }
    // #39 CORRECTIVE — ANTI-CYCLE de TOUTE longueur (pas seulement le 2-cycle direct). On REMONTE la chaîne
    // `merged_into` depuis dst ; si src y apparaît, la fusion fermerait un cycle (ex. merge(A,B);merge(B,C);
    // merge(C,A)) qui poserait merged_into sur TOUS les cases -> aucun survivant listable (WHERE merged_into IS
    // NULL) = disparition totale + audit cassé. Boucle BORNÉE (≤50 sauts, jamais de récursion non bornée).
    let mut cursor = dst_id;
    for _ in 0..50 {
        if cursor == src_id {
            return Err(RefusDeFusion::Cycle); // src est en AMONT de dst -> fusionner fermerait le cycle : refus
        }
        match lire(cursor) {
            Ok(Some(next)) => cursor = next, // maillon suivant de la chaîne
            Ok(None) | Err(rusqlite::Error::QueryReturnedNoRows) => break, // racine non fusionnée, ou maillon absent
            Err(e) => return Err(RefusDeFusion::NonLu(e.to_string())),
        }
    }
    Ok(())
}

/// `P10.20-w` (rang trois) — CE QUE LA FUSION OU LA DÉFUSION REND. Le `bool` d'avant rendait `true` après un
/// `UPDATE` AVALÉ : une écriture refusée par la base laissait la source NON fusionnée (ou toujours fusionnée) pendant
/// que deux chronologies et le registre non purgeable attestaient le geste, et que la route servait 204. L'écriture est
/// désormais COMPTÉE avant toute trace, et les trois issues sont séparées.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum IssueDeLaFusion {
    /// L'écriture a posé sa ligne : chronologie(s) et registre la portent.
    Ecrite,
    /// Le geste n'avait pas lieu d'être (refus jugé, ou aucune ligne ne correspondait) : la sortie d'AVANT, inchangée
    /// (`false` hier), rien n'est écrit ni tracé.
    Refusee,
    /// La base n'a PAS pris l'écriture : la cause est portée, et rien — ni chronologie, ni registre, ni 204 — ne dit
    /// que le geste a eu lieu. `P10.33-k` — une chronologie refusée, un `BEGIN` ou un `COMMIT` refusé y
    /// mènent aussi : le geste entier est annulé (transaction de `jouer_le_geste_garde`).
    NonEcrite(String),
    /// `P10.20-l` (vague AI) — la lecture qui ouvre le geste, dans sa transaction (second jugement de la fusion,
    /// relecture du dossier fusionné pour la défusion), n'a PAS eu lieu : aucune écriture n'a été tentée, la
    /// transaction est annulée, la cause du moteur est portée pour le journal seul. `NonEcrite` ne convenait pas : la
    /// route la sert « la base n'a pas pris l'écriture », et aucune écriture n'a été tentée.
    DossierNonLu(String),
    /// `P10.31-u` — l'écriture et ses chronologies sont VALIDÉES, mais le maillon du registre n'est pas entré (cause
    /// portée) : le geste a eu lieu, il n'est pas annulé, et la route l'avoue (`registre_sans_maillon`) au lieu d'un 204.
    EcriteSansTrace(String),
}

/// `P10.33-k` / `P10.31-u` — CE QUE REND LE GESTE JOUÉ D'UNE FUSION OU D'UNE DÉFUSION. `with_write` ne
/// prend que le verrou de l'écrivain (`query_exec.rs`, aucune transaction) : le geste ouvre la sienne par le patron du
/// fichier (`jouer_le_geste_garde`, comme `sla_policy_upsert`). Le corps rend le maillon ; un refus (jugement, écriture,
/// chronologie) est déjà une `IssueDeLaFusion` et annule tout ; `BEGIN` ou `COMMIT` refusé -> `NonEcrite`, rien n'est
/// écrit. Maillon manquant -> `EcriteSansTrace`, le geste validé n'est PAS annulé.
fn issue_du_geste_de_fusion(issue: crate::handlers::transaction_validee::IssueDuGesteGarde<MaillonDeRegistre, IssueDeLaFusion>) -> IssueDeLaFusion {
    use crate::handlers::transaction_validee::IssueDuGesteGarde as Issue;
    match issue {
        Issue::Valide(maillon) => match maillon.cause_de_non_inscription() {
            None => IssueDeLaFusion::Ecrite,
            Some(cause) => IssueDeLaFusion::EcriteSansTrace(cause.to_string()),
        },
        Issue::Refuse(refus) => refus,
        Issue::NonOuvert(e) => IssueDeLaFusion::NonEcrite(format!("transaction non ouverte : {e}")),
        Issue::NonValide(e) => IssueDeLaFusion::NonEcrite(format!("validation refusée : {e}")),
    }
}

/// `P10.20-w` — l'`UPDATE` de la fusion n'a pas été écrit : 503 nommé, rien n'atteste la fusion.
pub(crate) const CAUSE_FUSION_NON_ECRITE: &str = "FUSION NON ÉCRITE : la base n'a pas pris l'écriture, donc le dossier \
     n'est PAS fusionné — ni les chronologies ni le registre n'en portent rien. Ce n'est pas un refus de la fusion : \
     rien n'a été fait. Réessayez.";
/// `P10.20-w` — l'`UPDATE` de la défusion n'a pas été écrit : 503 nommé, le dossier reste fusionné.
pub(crate) const CAUSE_DEFUSION_NON_ECRITE: &str = "DÉFUSION NON ÉCRITE : la base n'a pas pris l'écriture, donc le \
     dossier est TOUJOURS fusionné — ni la chronologie ni le registre n'en portent rien. Rien n'a été fait. Réessayez.";

/// `P10.33-k` — LES DEUX CHRONOLOGIES FONT PARTIE DE LA FUSION. Elles passaient par `case_add_item`, qui
/// avale : une chronologie refusée laissait `Ecrite` et 204, fusion sans trace dans les dossiers (MTTA non figé).
/// Décision par défaut (vague AB) : jugement, `UPDATE`, chronologies (`ajouter_l_element_au_dossier`, comptées) et maillon
/// dans UNE transaction ; une chronologie refusée annule la fusion (`NonEcrite`, 503 existant). `P10.31-u` — le maillon
/// est consommé : manquant, il est avoué (`EcriteSansTrace`) sans annuler.
pub(crate) fn case_merge(conn: &Connection, src_id: i64, dst_id: i64, author: &str) -> IssueDeLaFusion {
    use crate::handlers::transaction_validee::jouer_le_geste_garde;
    let issue = jouer_le_geste_garde(conn, "caseops", &format!("fusion du dossier #{src_id} dans #{dst_id}"), |conn| {
        // `P10.29-b` — les refus sont jugés par `juger_la_fusion` (mêmes faits, désormais nommés par la route).
        // `P10.20-l` (vague AI) — une lecture du second jugement qui n'a pas eu lieu n'est plus un refus : `DossierNonLu`.
        match juger_la_fusion(conn, src_id, dst_id) {
            Ok(()) => {}
            Err(RefusDeFusion::NonLu(cause)) => return Err(IssueDeLaFusion::DossierNonLu(cause)),
            Err(_) => return Err(IssueDeLaFusion::Refusee),
        }
        let t = now();
        // `P10.20-w` — L'ÉCRITURE EST COMPTÉE AVANT TOUTE TRACE : une ligne écrite, ou rien n'est attesté.
        match conn.execute(
            "UPDATE incident SET merged_into=?1, status='closed', closed_ts=?2, updated=?2 WHERE id=?3",
            params![dst_id, t, src_id],
        ) {
            Ok(0) => return Err(IssueDeLaFusion::Refusee), // la source a disparu entre le jugement et l'écriture : absence
            Ok(_) => {}
            Err(e) => return Err(IssueDeLaFusion::NonEcrite(e.to_string())),
        }
        ajouter_l_element_au_dossier(conn, src_id, t, "merge", author, &format!("fusionné dans #{dst_id}"), Some(&format!("case:{dst_id}")))
            .map_err(|cause| IssueDeLaFusion::NonEcrite(format!("chronologie de la source : {cause}")))?;
        ajouter_l_element_au_dossier(conn, dst_id, t, "merge", author, &format!("#{src_id} fusionné ici (timeline combinée)"), Some(&format!("case:{src_id}")))
            .map_err(|cause| IssueDeLaFusion::NonEcrite(format!("chronologie de la cible : {cause}")))?;
        Ok(ledger_append(conn, "case.merge", &format!("#{src_id} -> #{dst_id} by {author}")))
    });
    issue_du_geste_de_fusion(issue)
}

/// RÉVERSIBILITÉ de la fusion : dé-fusionne la source (merged_into=NULL) + la rouvre ('triage'). Trace + ledger.
/// false si le case n'existe pas ou n'est pas fusionné. Preuve que la fusion NE DÉTRUIT rien (#39, exigence revue).
/// `P10.29-b` — LE JUGEMENT D'UNE DÉFUSION : `Ok(cible)` si le dossier est fusionné ; sinon la réponse nommée — 404 sur
/// une absence établie, 409 s'il n'est pas fusionné, 503 sur une lecture refusée (les trois rendaient 404 nu).
pub(crate) fn juger_la_defusion(conn: &Connection, src_id: i64) -> Result<i64, Response> {
    match conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![src_id], |r| r.get::<_, Option<i64>>(0)) {
        Ok(Some(dst)) => Ok(dst),
        Ok(None) => Err(err_json(StatusCode::CONFLICT, CAUSE_DEFUSION_DOSSIER_NON_FUSIONNE)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(not_found(crate::handlers::cases::CAUSE_DOSSIER_INTROUVABLE)),
        Err(e) => Err(crate::handlers::cases::refus_du_dossier_non_lu(&e)),
    }
}

/// `P10.33-k` / `P10.31-u` — même geste que `case_merge` : lecture, `UPDATE`, chronologie comptée et maillon
/// dans UNE transaction ; chronologie refusée -> défusion annulée (`NonEcrite`) ; maillon manquant -> `EcriteSansTrace`.
pub(crate) fn case_unmerge(conn: &Connection, src_id: i64, author: &str) -> IssueDeLaFusion {
    use crate::handlers::transaction_validee::jouer_le_geste_garde;
    use rusqlite::OptionalExtension;
    let issue = jouer_le_geste_garde(conn, "caseops", &format!("défusion du dossier #{src_id}"), |conn| {
        // `P10.20-l` (vague AI) — trois issues (`.ok()` rendait `Refusee` sur une lecture ratée) : fusionné, la défusion
        // suit ; absent ou non fusionné, `Refusee` d'avant ; lecture ratée, `DossierNonLu`, la transaction est annulée,
        // rien n'est écrit ; la route journalise la cause du moteur avec l'identifiant qu'elle sert.
        let dst = match conn.query_row("SELECT merged_into FROM incident WHERE id=?1", params![src_id], |r| r.get::<_, Option<i64>>(0)).optional() {
            Ok(Some(Some(dst))) => dst,
            Ok(Some(None)) | Ok(None) => return Err(IssueDeLaFusion::Refusee),
            Err(e) => return Err(IssueDeLaFusion::DossierNonLu(e.to_string())),
        };
        let t = now();
        // `P10.20-w` — L'ÉCRITURE EST COMPTÉE AVANT LA CHRONOLOGIE ET LE REGISTRE.
        match conn.execute("UPDATE incident SET merged_into=NULL, status='triage', closed_ts=NULL, updated=?1 WHERE id=?2", params![t, src_id]) {
            Ok(0) => return Err(IssueDeLaFusion::Refusee), // le dossier a disparu entre la lecture et l'écriture : absence
            Ok(_) => {}
            Err(e) => return Err(IssueDeLaFusion::NonEcrite(e.to_string())),
        }
        ajouter_l_element_au_dossier(conn, src_id, t, "merge", author, &format!("dé-fusionné de #{dst} (ré-ouvert)"), None)
            .map_err(|cause| IssueDeLaFusion::NonEcrite(format!("chronologie du dossier : {cause}")))?;
        Ok(ledger_append(conn, "case.unmerge", &format!("#{src_id} <- #{dst} by {author}")))
    });
    issue_du_geste_de_fusion(issue)
}

/// `P10.20-w` — CE QUE LA POSE D'UN LIEN REND. Le `bool` d'avant portait DEUX zéros sous le même
/// `false` — non, il en portait un de plus : `.unwrap_or(0)` rendait `0` aussi bien quand la base
/// refusait l'écriture que quand le lien existait déjà, et ce `0`-là était lu « déjà lié
/// (idempotent) », donc rendu 204 « fait » à la console sur un lien qui n'existe pas. Les issues sont
/// séparées, et aucune ne se tire du type sans avoir été nommée.
pub(crate) enum LienDeDossier {
    /// Le lien est posé : les deux timelines et le registre le portent.
    Pose,
    /// Les deux dossiers étaient DÉJÀ liés sous ce genre — aucune ligne écrite, aucune trace doublée,
    /// et la demande est honorée (l'énoncé porte `OR IGNORE`).
    DejaLie,
    /// Un des deux dossiers n'existe pas — absence ÉTABLIE. (`P10.29-b` : « les deux identifiants sont le même » et
    /// « la lecture n'a pas eu lieu » ont désormais leur variante ; ils rendaient le même 404 nu.)
    DossierAbsent,
    /// `P10.29-b` — les deux identifiants désignent le même dossier (demande mal formée).
    MemeDossier,
    /// `P10.29-b` — la lecture qui établit l'existence d'un des deux dossiers n'a pas eu lieu.
    DossierNonLu(String),
    /// L'écriture n'a pas eu lieu : la cause est portée, et rien — ni timeline, ni registre, ni
    /// réponse — ne doit dire que les deux dossiers sont liés. `P10.33-k` — une chronologie refusée, un
    /// `BEGIN` ou un `COMMIT` refusé y mènent aussi : la ligne du lien est annulée avec elles.
    NonPose(String),
    /// `P10.31-u` — le lien et ses deux chronologies sont VALIDÉS, le maillon du registre n'est pas entré (cause portée) :
    /// le geste n'est pas annulé, la route l'avoue (`registre_sans_maillon`).
    PoseSansTrace(String),
}

/// LIEN NON DESTRUCTIF #39 : associe deux cases (kind ∈ related|duplicate|blocks) sans les fusionner. Dédup par
/// UNIQUE(src,dst,kind). Trace item 'link' des deux côtés + ledger.
///
/// `P10.33-k` / `P10.31-u` — existence, ligne du lien, deux chronologies comptées
/// (`ajouter_l_element_au_dossier`) et maillon dans UNE transaction (`jouer_le_geste_garde`, `with_write` n'en ouvre
/// aucune) : une chronologie refusée annule le lien (`NonPose`, 503 existant) ; `BEGIN`/`COMMIT` refusé -> `NonPose` ;
/// maillon manquant -> `PoseSansTrace`, le lien validé reste.
pub(crate) fn case_link_add(conn: &Connection, src_id: i64, dst_id: i64, kind: &str, note: &str, author: &str) -> LienDeDossier {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    if src_id == dst_id {
        return LienDeDossier::MemeDossier;
    }
    let kind = match kind {
        "duplicate" | "blocks" | "related" => kind,
        _ => "related",
    };
    let issue = jouer_le_geste_garde(conn, "caseops", &format!("lien des dossiers #{src_id} et #{dst_id}"), |conn| {
        for cid in [src_id, dst_id] {
            match conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![cid], |_| Ok(())) {
                Ok(()) => {}
                Err(rusqlite::Error::QueryReturnedNoRows) => return Err(LienDeDossier::DossierAbsent),
                Err(e) => return Err(LienDeDossier::DossierNonLu(e.to_string())),
            }
        }
        let t = now();
        // L'ÉCRITURE EST COMPTÉE AVANT TOUTE TRACE : `OR IGNORE` rend légitimement zéro ligne quand le
        // lien existe déjà, et c'est le SEUL zéro que cette clause produise — un échec de la base n'en
        // est pas un.
        match conn.execute(
            "INSERT OR IGNORE INTO case_link(src_id,dst_id,kind,note,created,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
            params![src_id, dst_id, kind, note, t, author],
        ) {
            Ok(0) => return Err(LienDeDossier::DejaLie), // déjà lié (idempotent) — pas de double trace, rien à annuler
            Ok(_) => {}
            Err(e) => return Err(LienDeDossier::NonPose(e.to_string())),
        }
        ajouter_l_element_au_dossier(conn, src_id, t, "link", author, &format!("lié à #{dst_id} ({kind})"), Some(&format!("case:{dst_id}")))
            .map_err(|cause| LienDeDossier::NonPose(format!("chronologie du premier dossier : {cause}")))?;
        ajouter_l_element_au_dossier(conn, dst_id, t, "link", author, &format!("lié à #{src_id} ({kind})"), Some(&format!("case:{src_id}")))
            .map_err(|cause| LienDeDossier::NonPose(format!("chronologie du second dossier : {cause}")))?;
        Ok(ledger_append(conn, "case.link", &format!("#{src_id} <-{kind}-> #{dst_id} by {author}")))
    });
    match issue {
        Issue::Valide(maillon) => match maillon.cause_de_non_inscription() {
            None => LienDeDossier::Pose,
            Some(cause) => LienDeDossier::PoseSansTrace(cause.to_string()),
        },
        Issue::Refuse(refus) => refus,
        Issue::NonOuvert(e) => LienDeDossier::NonPose(format!("transaction non ouverte : {e}")),
        Issue::NonValide(e) => LienDeDossier::NonPose(format!("validation refusée : {e}")),
    }
}

/// `P10.20-w` — CE QUE LE RETRAIT D'UN LIEN REND. `.unwrap_or(0)` faisait dire « aucun lien ne
/// reliait ces deux dossiers » (404) à une suppression que la base n'avait pas prise : le lien est
/// TOUJOURS là, et l'exploitant lit qu'il n'a jamais existé.
pub(crate) enum LienRetire {
    /// Le lien est retiré : au moins une ligne a été effacée, et le registre en porte le COMPTE
    /// exact (l'énoncé vise les deux sens, il peut en effacer plus d'une).
    Retire,
    /// `P10.31-u` — le lien EST retiré, mais le registre n'a pas pris la ligne qui l'atteste (cause portée).
    /// Le geste n'est pas annulé (le rejouer ne comblerait pas le trou) : la réponse l'avoue.
    RetireSansTrace(String),
    /// Aucun lien ne reliait ces deux dossiers : absence ÉTABLIE, rien à défaire.
    AucunLien,
    /// La suppression n'a pas eu lieu : la cause est portée, et le lien EST toujours là.
    NonRetire(String),
}

/// Supprime un lien (les deux sens) entre deux cases. Trace + ledger. Le lien est une pure ASSOCIATION -> sa
/// suppression ne détruit AUCUNE donnée de case.
pub(crate) fn case_link_remove(conn: &Connection, a: i64, b: i64, author: &str) -> LienRetire {
    let n = match conn.execute(
        "DELETE FROM case_link WHERE (src_id=?1 AND dst_id=?2) OR (src_id=?2 AND dst_id=?1)",
        params![a, b],
    ) {
        Ok(0) => return LienRetire::AucunLien,
        Ok(n) => n,
        Err(e) => return LienRetire::NonRetire(e.to_string()),
    };
    // Le COMPTE est dit, jamais avalé : l'énoncé vise les deux sens, et savoir combien de lignes il a
    // réellement effacées est ce qui sépare un lien retiré d'un doublon nettoyé au passage.
    // `P10.31-u` — LE MAILLON EST CONSOMMÉ (il était jeté par un appel nu) : un retrait sans trace est dit.
    match ledger_append(conn, "case.unlink", &format!("#{a} x #{b} retirés={n} by {author}")) {
        MaillonDeRegistre::Inscrit => LienRetire::Retire,
        MaillonDeRegistre::NonInscrit(cause) => LienRetire::RetireSansTrace(cause),
    }
}

/// Borne des liens d'un dossier (`P11.22-g`) : nommée, rendue avec la liste, lue avec sa ligne excédentaire.
pub(crate) const CASE_LINKS_WINDOW: i64 = 200;

/// Liens d'un case (dans les deux sens) résolus en (id, titre, statut, kind). Point-lookups bornés (budget 2 Go).
/// Rend le corps du fabricant partagé — `{links, served, window, total, total_capped}` — au lieu d'un tableau nu :
/// un dossier qui porte plus de liens que la borne le DIT (`P11.22-g`), et une lecture qui échoue est avouée.
pub(crate) fn case_links_json(conn: &Connection, id: i64) -> Value {
    use crate::handlers::liste_bornee as aveu;
    let lues: Result<Vec<Value>, rusqlite::Error> = conn
        .prepare(
            "SELECT CASE WHEN l.src_id=?1 THEN l.dst_id ELSE l.src_id END AS other, l.kind, l.note, \
                    COALESCE(i.title,''), COALESCE(i.status,'') \
             FROM case_link l JOIN incident i ON i.id = (CASE WHEN l.src_id=?1 THEN l.dst_id ELSE l.src_id END) \
             WHERE l.src_id=?1 OR l.dst_id=?1 ORDER BY l.created DESC LIMIT ?2",
        )
        // `P10.7-f` (rang 4, vague b) — LE PARCOURS EST SOLDÉ EN BLOC. Avant, `.map(|x| x.flatten()
        // .collect())` jetait la ligne dont le mappeur échoue (cache de schéma du pool périmé rendant
        // « no such table » au PREMIER pas, `kind`/`note`/`title` corrompus) et rendait la SUITE : la
        // branche `Ok` servait alors un corps rigoureusement identique à celui d'un dossier qui n'a pas
        // ce lien, `served`/`total` compris — le dossier lié DISPARAISSAIT de la seule vue qui le montre.
        // La branche d'échec, elle, existait DÉJÀ (`Lignes::Illisible` + `TotalBorne::sans_lecture()`) :
        // solder en bloc y fait simplement tomber aussi l'erreur de LIGNE, sans changer une seule clé.
        .and_then(|mut stmt| {
            stmt.query_map(params![id, aveu::borne_avec_ligne_excedentaire(CASE_LINKS_WINDOW)], |r| {
                Ok(json!({ "id": r.get::<_,i64>(0)?, "kind": r.get::<_,String>(1)?, "note": r.get::<_,String>(2)?,
                           "title": r.get::<_,String>(3)?, "status": r.get::<_,String>(4)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(v) => {
            let vues = v.len() as i64;
            let (servies, _) = aveu::couper_a_la_borne(v, CASE_LINKS_WINDOW as usize);
            aveu::corps("links", aveu::Lignes::Lues(servies), CASE_LINKS_WINDOW, aveu::TotalBorne::depuis_un_recensement_borne(vues, CASE_LINKS_WINDOW))
        }
        Err(_) => aveu::corps("links", aveu::Lignes::Illisible, CASE_LINKS_WINDOW, aveu::TotalBorne::sans_lecture()),
    }
}

// ================================================================================================
// PER-ASSIGNEE QUEUES — agrégat de charge par propriétaire (la liste reste cases_list_json_paged #4a).
// ================================================================================================

/// Résumé de file par ASSIGNEE : open (actifs non fusionnés), overdue (SLA legacy dépassé), ack_pending (SLA
/// multi-niveau : ack_due dépassé, pas acquitté), breach (ack/resolve breach), waiting (en pause). Un bucket
/// `(none)` agrège les non-assignés. Lecture pure agrégée (GROUP BY) sur `incident` (human-scale). #39.
/// Borne des files par assigné (`P11.22-g`) : nommée, rendue, lue avec sa ligne excédentaire.
pub(crate) const CASE_QUEUES_WINDOW: i64 = 500;
pub(crate) fn case_queues_json(conn: &Connection, now_i: i64) -> Value {
    let sql = "SELECT COALESCE(NULLIF(assignee,''),'(none)') AS who, \
               COUNT(*) AS open, \
               SUM(CASE WHEN sla_due IS NOT NULL AND ?1>sla_due THEN 1 ELSE 0 END) AS overdue, \
               SUM(CASE WHEN ack_due IS NOT NULL AND ?1>ack_due AND first_response_ts IS NULL AND sla_paused_since IS NULL THEN 1 ELSE 0 END) AS ack_pending, \
               SUM(CASE WHEN ack_breached=1 OR resolve_breached=1 THEN 1 ELSE 0 END) AS breach, \
               SUM(CASE WHEN status='waiting' THEN 1 ELSE 0 END) AS waiting \
               FROM incident \
               WHERE archived=0 AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained') \
               GROUP BY who ORDER BY open DESC, who LIMIT ?2";
    // `P11.22-g` — la borne est lue avec sa ligne excédentaire et le corps est celui du fabricant partagé :
    // un assigné hors coupe ne disparaît plus en silence de la file qui existe pour le montrer.
    use crate::handlers::liste_bornee as aveu;
    let lues: Result<Vec<Value>, rusqlite::Error> = conn
        .prepare(sql)
        // `P10.7-f` (rang 4, vague b) — MÊME SOLDE EN BLOC QUE LES LIENS, et le même raisonnement : la
        // branche d'échec servait déjà l'aveu, seule la ligne illisible passait dessous. Ici la
        // conséquence est propre à l'agrégat : chaque ligne EST un assigné, donc une ligne avalée retire
        // une personne — avec toute sa charge, ses retards et ses violations — du bandeau qui existe pour
        // répartir le travail, et le total qui l'accompagne le confirme comme un fait.
        .and_then(|mut s| {
            s.query_map(params![now_i, aveu::borne_avec_ligne_excedentaire(CASE_QUEUES_WINDOW)], |r| {
                Ok(json!({ "assignee": r.get::<_,String>(0)?, "open": r.get::<_,i64>(1)?, "overdue": r.get::<_,i64>(2)?,
                           "ack_pending": r.get::<_,i64>(3)?, "breach": r.get::<_,i64>(4)?, "waiting": r.get::<_,i64>(5)? }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(v) => {
            let vues = v.len() as i64;
            let (servies, _) = aveu::couper_a_la_borne(v, CASE_QUEUES_WINDOW as usize);
            aveu::corps("queues", aveu::Lignes::Lues(servies), CASE_QUEUES_WINDOW, aveu::TotalBorne::depuis_un_recensement_borne(vues, CASE_QUEUES_WINDOW))
        }
        Err(_) => aveu::corps("queues", aveu::Lignes::Illisible, CASE_QUEUES_WINDOW, aveu::TotalBorne::sans_lecture()),
    }
}

// ================================================================================================
// MTTA / MTTR DASHBOARD — agrégation sur `incident` (mean/p50, par assignee/severity).
// ================================================================================================

/// p50 (médiane) d'un vecteur trié-able, en Rust (les cases sont human-scale : quelques milliers, pas des
/// millions -> pas de scan chiffré massif). Vecteur vide -> None.
fn p50(mut v: Vec<i64>) -> Option<i64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// TABLEAU DE BORD MTTA/MTTR #39 : agrège sur une FENÊTRE [from,to] (bornée sur closed_ts pour MTTR/MTTA des
/// cases résolus dans la fenêtre) :
///   - MTTA = first_response_ts - ts (temps d'acquittement) ; MTTR = closed_ts - ts - pause (temps de résolution).
///   - overall {resolved, mtta_mean, mtta_p50, mttr_mean, mttr_p50, ack_breaches, resolve_breaches} + open_now,
///     overdue_now (instantanés) ; by_assignee & by_severity (mean MTTA/MTTR + résolus + breach).
/// Lecture pure. `to<=0` -> now. Fenêtre par défaut = 30 j si from<=0.
/// Bornes du tableau MTTA/MTTR (`P11.22-g`) : l'échantillon d'où sortent moyenne et médiane, et les deux
/// ventilations. Nommées, rendues dans le corps, lues avec leur ligne excédentaire.
pub(crate) const CASE_METRICS_SAMPLE_WINDOW: i64 = 50_000;
pub(crate) const CASE_METRICS_BY_ASSIGNEE_WINDOW: i64 = 200;
pub(crate) const CASE_METRICS_BY_SEVERITY_WINDOW: i64 = 20;
pub(crate) fn case_metrics_json(conn: &Connection, from_in: i64, to_in: i64) -> Value {
    let to = if to_in > 0 { to_in } else { now() };
    let from = if from_in > 0 { from_in } else { to - 30 * 86400 };
    // `P10.7-g` (lot 95) — HUIT LECTURES TYPÉES, AUCUN ZÉRO DE REPLI SERVI COMME UNE MESURE. L'échantillon,
    // les cinq comptes et les deux ventilations rendaient 0 / vide sur toute lecture ratée, et le tableau de bord
    // présentait « aucun dossier résolu, aucun retard, aucune violation » — le corps le plus rassurant qui soit.
    // Chaque lecture qui échoue est NOMMÉE dans `non_etablis`, son compte est `null`, le corps porte `error`, et
    // la console lit déjà la cause sous `error` (`web/cases.js`, `causeDuRefusServi`).
    let mut non_etablis: Vec<&'static str> = Vec::new();
    // Valeurs individuelles (résolus dans la fenêtre) pour mean + p50 (Rust). Borné LIMIT (garde-fou mémoire).
    let mut mtta: Vec<i64> = Vec::new();
    let mut mttr: Vec<i64> = Vec::new();
    // `P11.22-g` — l'échantillon est lu avec sa ligne excédentaire : si elle existe, moyenne et médiane sont
    // calculées sur un échantillon COUPÉ et le corps le dit (`sample_truncated`), au lieu de les présenter
    // comme la mesure de la fenêtre entière.
    use crate::handlers::liste_bornee as aveu;
    let mut echantillon_vu: i64 = 0;
    let echantillon: Result<Vec<(Option<i64>, i64, i64, i64)>, rusqlite::Error> = conn
        .prepare(
            "SELECT first_response_ts, closed_ts, ts, COALESCE(sla_pause_accum,0) FROM incident \
             WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL LIMIT ?3",
        )
        .and_then(|mut stmt| {
            stmt.query_map(params![from, to, aveu::borne_avec_ligne_excedentaire(CASE_METRICS_SAMPLE_WINDOW)], |r| {
                Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
            })
            .and_then(|it| it.collect())
        });
    match echantillon {
        Ok(lignes) => {
            for (fr, closed, ts, pause) in lignes {
                echantillon_vu += 1;
                if echantillon_vu > CASE_METRICS_SAMPLE_WINDOW { break; }
                if let Some(fr) = fr {
                    if fr >= ts {
                        mtta.push(fr - ts);
                    }
                }
                let r = closed - ts - pause;
                if r >= 0 {
                    mttr.push(r);
                }
            }
        }
        Err(_) => non_etablis.push("sample"),
    }
    let mean = |v: &[i64]| -> Option<i64> {
        if v.is_empty() { None } else { Some(v.iter().sum::<i64>() / v.len() as i64) }
    };
    let now_i = now();
    // Un compte qui n'a pas abouti est `null`, jamais 0, et il est nommé.
    let mut compte = |nom: &'static str, lu: Result<i64, rusqlite::Error>| -> Value {
        match lu {
            Ok(n) => json!(n),
            Err(_) => {
                non_etablis.push(nom);
                Value::Null
            }
        }
    };
    let resolved = compte("resolved", conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL",
        params![from, to], |r| r.get(0)));
    let open_now = compte("open_now", conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE archived=0 AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained')",
        [], |r| r.get(0)));
    let overdue_now = compte("overdue_now", conn.query_row(
        "SELECT COUNT(*) FROM incident WHERE sla_due IS NOT NULL AND ?1>sla_due AND merged_into IS NULL AND status NOT IN ('resolved','closed','contained')",
        params![now_i], |r| r.get(0)));
    let ack_breaches = compte("ack_breaches", conn.query_row("SELECT COUNT(*) FROM incident WHERE ack_breached=1 AND ts>=?1 AND ts<=?2", params![from, to], |r| r.get(0)));
    let resolve_breaches = compte("resolve_breaches", conn.query_row("SELECT COUNT(*) FROM incident WHERE resolve_breached=1 AND ts>=?1 AND ts<=?2", params![from, to], |r| r.get(0)));
    // by_assignee : mean MTTA/MTTR + résolus + breach (SQL agrégé ; mean SQL suffit par groupe).
    let by_assignee: Result<Vec<Value>, rusqlite::Error> = conn.prepare(
        "SELECT COALESCE(NULLIF(assignee,''),'(none)') AS who, COUNT(*), \
                AVG(CASE WHEN first_response_ts IS NOT NULL AND first_response_ts>=ts THEN first_response_ts-ts END), \
                AVG(CASE WHEN closed_ts-ts-COALESCE(sla_pause_accum,0)>=0 THEN closed_ts-ts-COALESCE(sla_pause_accum,0) END), \
                SUM(CASE WHEN ack_breached=1 OR resolve_breached=1 THEN 1 ELSE 0 END) \
         FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL \
         GROUP BY who ORDER BY COUNT(*) DESC LIMIT ?3")
        .and_then(|mut s| s.query_map(params![from, to, aveu::borne_avec_ligne_excedentaire(CASE_METRICS_BY_ASSIGNEE_WINDOW)], |r| {
            Ok(json!({ "assignee": r.get::<_,String>(0)?, "resolved": r.get::<_,i64>(1)?,
                       "mtta_mean": r.get::<_,Option<f64>>(2)?.map(|x| x as i64),
                       "mttr_mean": r.get::<_,Option<f64>>(3)?.map(|x| x as i64),
                       "breach": r.get::<_,i64>(4)? }))
        }).and_then(|x| x.collect()));
    let by_severity: Result<Vec<Value>, rusqlite::Error> = conn.prepare(
        "SELECT severity, COUNT(*), \
                AVG(CASE WHEN first_response_ts IS NOT NULL AND first_response_ts>=ts THEN first_response_ts-ts END), \
                AVG(CASE WHEN closed_ts-ts-COALESCE(sla_pause_accum,0)>=0 THEN closed_ts-ts-COALESCE(sla_pause_accum,0) END) \
         FROM incident WHERE closed_ts IS NOT NULL AND closed_ts>=?1 AND closed_ts<=?2 AND merged_into IS NULL \
         GROUP BY severity ORDER BY severity DESC LIMIT ?3")
        .and_then(|mut s| s.query_map(params![from, to, aveu::borne_avec_ligne_excedentaire(CASE_METRICS_BY_SEVERITY_WINDOW)], |r| {
            Ok(json!({ "severity": r.get::<_,i64>(0)?, "resolved": r.get::<_,i64>(1)?,
                       "mtta_mean": r.get::<_,Option<f64>>(2)?.map(|x| x as i64),
                       "mttr_mean": r.get::<_,Option<f64>>(3)?.map(|x| x as i64) }))
        }).and_then(|x| x.collect()));
    let by_assignee: Vec<Value> = match by_assignee {
        Ok(v) => v,
        Err(_) => {
            non_etablis.push("by_assignee");
            Vec::new()
        }
    };
    let by_severity: Vec<Value> = match by_severity {
        Ok(v) => v,
        Err(_) => {
            non_etablis.push("by_severity");
            Vec::new()
        }
    };
    let mut corps = json!({
        "window": { "from": from, "to": to },
        "overall": {
            "resolved": resolved, "open_now": open_now, "overdue_now": overdue_now,
            "mtta_mean": mean(&mtta), "mtta_p50": p50(mtta.clone()),
            "mttr_mean": mean(&mttr), "mttr_p50": p50(mttr.clone()),
            "ack_breaches": ack_breaches, "resolve_breaches": resolve_breaches,
        },
        "by_assignee": [],
        "by_severity": [],
    });
    // `P11.22-g` — les deux ventilations sont posées par la seconde porte du fabricant (`<cle>_served`,
    // `<cle>_window`, `<cle>_truncated`), et l'échantillon dit sa fenêtre et sa coupe.
    if let Some(obj) = corps.as_object_mut() {
        aveu::poser_la_sous_liste(obj, "by_assignee", by_assignee, CASE_METRICS_BY_ASSIGNEE_WINDOW as usize);
        aveu::poser_la_sous_liste(obj, "by_severity", by_severity, CASE_METRICS_BY_SEVERITY_WINDOW as usize);
        obj.insert("sample_window".into(), json!(CASE_METRICS_SAMPLE_WINDOW));
        obj.insert("sample_size".into(), json!(echantillon_vu.min(CASE_METRICS_SAMPLE_WINDOW)));
        obj.insert("sample_truncated".into(), json!(echantillon_vu > CASE_METRICS_SAMPLE_WINDOW));
        if !non_etablis.is_empty() {
            obj.insert("error".into(), json!(format!("métriques NON ÉTABLIES : {} — les comptes manquants sont `null` et les listes vides des replis, pas des mesures", non_etablis.join(", "))));
            obj.insert("non_etablis".into(), json!(non_etablis));
        }
    }
    corps
}

// ================================================================================================
// CLIENT-READ API (external, read-only, tenant-scoped, masked). Cf. INVARIANT en tête de module.
// ================================================================================================

/// Statut CLIENT-FACING (mappe le vocabulaire interne vers un cycle de vie neutre pour l'externe) : on n'expose
/// PAS 'triage'/'in_progress' bruts si l'on veut ; ici on garde un mapping lisible sans fuite d'info interne.
fn client_status(internal: &str) -> &'static str {
    match internal {
        "new" => "open",
        "triage" => "open",
        "in_progress" => "in_progress",
        "waiting" => "waiting",
        "resolved" | "contained" => "resolved",
        "closed" => "closed",
        _ => "open",
    }
}

/// #3 PHASE 3 — Part B : PHASE CLIENT COARSE. Étiquette humaine, neutre, dérivée UNIQUEMENT de la colonne
/// `status` (cycle de vie du case) — JAMAIS de `case_step` (aucun titre/nombre/guidance/target d'étape n'entre
/// ici), JAMAIS du runbook, JAMAIS du `incident_tier`/`incident_type`/`commander`. C'est un enum FERMÉ contrôlé
/// serveur (littéraux fixes) : rien de dérivé du client/case en texte libre -> pas de masquage requis (INVARIANT
/// #2 : les enum dérivés de colonnes NON secrètes ne sont pas masqués). 'contained' est un état de cycle de vie
/// du case (pas une étape) -> bucket coarse « contenu ». Le client apprend OÙ EN EST son case, jamais COMMENT.
fn client_phase(internal: &str) -> &'static str {
    match internal {
        "new" | "triage" => "ouvert",
        "in_progress" => "en cours de traitement",
        "waiting" => "en attente",
        "contained" => "contenu",
        "resolved" => "résolu",
        "closed" => "clôturé",
        _ => "ouvert",
    }
}

/// PROJECTION CLIENT d'une ligne de case — ALLOWLIST FERMÉE de colonnes `incident` (aucun secret, aucun
/// owner/assignee, aucune note interne). Titre passé au masque du rôle appelant (défense en profondeur #45).
/// `overdue` calculé au read. C'est le SEUL point où des données de case sortent vers un client.
///
/// #3 PHASE 3 — Part B (⚠ ÉLARGIT LA PROJECTION CLIENT — cf. INVARIANT en tête de module ; surface
/// d'isolation sensible) : trois champs ADDITIFS, tous dérivés de colonnes NON secrètes déjà tenant-scopées, sans
/// aucune colonne interne d'incident/runbook/step :
///   - `is_incident` (bool) = `incident_tier IS NOT NULL`. Le BOOLÉEN seul ; le tier BRUT (1..4), `incident_type`
///     et `commander` NE sont JAMAIS lus ici (le SELECT calcule `IS NOT NULL` en SQL -> l'entier ne rentre même
///     pas dans Rust).
///   - `phase` (string) = enum coarse FERMÉ dérivé du seul `status` (cf. client_phase) — jamais une étape.
///   - `acknowledged` (bool) = `first_response_ts IS NOT NULL` (timing MTTA-style : « quelqu'un a pris le case »).
///     Le timestamp brut / la durée MTTA ne sont PAS exposés (coarse only).
/// Ces trois champs sont des bool/enum contrôlés serveur -> non masqués (INVARIANT #2). Aucun `case_step`,
/// `search_soql`, `action_kind`, note, ref alert/event, identité analyste n'est ajouté : allowlist TOUJOURS fermée.
#[allow(clippy::too_many_arguments)]
fn client_case_row(db_path: &str, masks: &guatx_core::soql::FieldMaskSet, id: i64, ts: i64, updated: i64, title: &str, status: &str, severity: i64, priority: i64, closed_ts: Option<i64>, overdue: bool, is_incident: bool, acknowledged: bool) -> Value {
    let title_v = if masks.is_empty() { json!(title) } else { mask_field_value(db_path, masks, "title", &json!(title)) };
    json!({
        "id": id, "opened": ts, "updated": updated, "title": title_v,
        "status": client_status(status), "severity": severity,
        "priority": priority, "priority_label": priority_label(priority),
        "closed": closed_ts, "overdue": overdue,
        "is_incident": is_incident, "phase": client_phase(status), "acknowledged": acknowledged,
    })
}

/// LISTE CLIENT paginée des cases du tenant appelant : projection fermée, filtre par statut ouvert/résolu
/// optionnel, tri updated DESC. `total` = COUNT après filtre (pager serveur). MASQUE appliqué au titre.
/// EXCLUT les cases archivés ET fusionnés (vue client propre). Lecture pure sur `incident`.
pub(crate) fn client_cases_list_json(conn: &Connection, db_path: &str, masks: &guatx_core::soql::FieldMaskSet, now_i: i64, state: &str, limit: i64, offset: i64) -> Value {
    // filtre de PÉRIMÈTRE client : "open" = actifs, "resolved" = terminaux, "" = tous. Toujours non-archivé,
    // non-fusionné. Littéraux -> pas d'injection.
    let where_state = match state {
        "open" => "AND status NOT IN ('resolved','closed','contained')",
        "resolved" => "AND status IN ('resolved','closed','contained')",
        _ => "",
    };
    let base = format!("FROM incident WHERE archived=0 AND merged_into IS NULL {where_state}");
    // `P10.7-g` (lot 95) — le compte et les lignes sont typés : une lecture ratée rend la liste NON ÉTABLIE
    // (`total: null`, cause de `P10.7-z`), jamais « aucun dossier ».
    let total: Result<i64, rusqlite::Error> = conn.query_row(&format!("SELECT COUNT(*) {base}"), [], |r| r.get(0));
    // Part B : `is_incident`/`acknowledged` calculés en SQL comme BOOLÉENS (IS NOT NULL) -> le tier brut et le
    // timestamp MTTA ne sont JAMAIS matérialisés côté Rust. Allowlist fermée : deux colonnes bool ajoutées, rien d'autre.
    let sql = format!(
        "SELECT id,ts,updated,COALESCE(title,''),status,severity,priority,closed_ts, \
                (sla_due IS NOT NULL AND ?1>sla_due AND status NOT IN ('resolved','closed','contained')) AS overdue, \
                (incident_tier IS NOT NULL) AS is_incident, (first_response_ts IS NOT NULL) AS acknowledged \
         {base} ORDER BY updated DESC LIMIT ?2 OFFSET ?3");
    let lues: Result<Vec<Value>, rusqlite::Error> = conn
        .prepare(&sql)
        .and_then(|mut s| {
            s.query_map(params![now_i, limit, offset], |r| {
                Ok(client_case_row(db_path, masks, r.get(0)?, r.get(1)?, r.get(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get::<_, i64>(8)? != 0, r.get::<_, i64>(9)? != 0, r.get::<_, i64>(10)? != 0))
            }).and_then(|x| x.collect())
        });
    match (total, lues) {
        (Ok(total), Ok(rows)) => json!({ "cases": rows, "total": total }),
        _ => crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "total": Value::Null }), "cases"),
    }
}

/// DÉTAIL CLIENT d'un case : la projection fermée + une timeline RESTREINTE aux événements de CYCLE DE VIE
/// (created/status/sla/merge) — JAMAIS les notes internes, actions, ni les refs alert/event (télémétrie interne).
/// Les auteurs analystes sont ANONYMISÉS ('SOC'). None si le case n'existe pas / est archivé / fusionné.
/// Borne de la ligne de temps servie au portail client (`P11.22-g`).
pub(crate) const CLIENT_CASE_TIMELINE_WINDOW: i64 = 500;
/// `P10.7-g` (lot 95) — la fiche est LUE ou NON LUE avant d'être présente ou absente : `Ok(None)` est une absence
/// ÉTABLIE (404), `Err` une lecture ratée (5xx nommé par le gestionnaire), jamais « case introuvable ».
pub(crate) fn client_case_get_lu(conn: &Connection, db_path: &str, masks: &guatx_core::soql::FieldMaskSet, id: i64, now_i: i64) -> Result<Option<Value>, rusqlite::Error> {
    let mut c = match conn.query_row(
        "SELECT id,ts,updated,COALESCE(title,''),status,severity,priority,closed_ts, \
                (sla_due IS NOT NULL AND ?2>sla_due AND status NOT IN ('resolved','closed','contained')), \
                (incident_tier IS NOT NULL), (first_response_ts IS NOT NULL) \
         FROM incident WHERE id=?1 AND archived=0 AND merged_into IS NULL",
        params![id, now_i],
        |r| Ok(client_case_row(db_path, masks, r.get(0)?, r.get(1)?, r.get(2)?, &r.get::<_, String>(3)?, &r.get::<_, String>(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get::<_, i64>(8)? != 0, r.get::<_, i64>(9)? != 0, r.get::<_, i64>(10)? != 0)),
    ) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    // Timeline CYCLE DE VIE uniquement (allowlist de kinds ; auteurs anonymisés ; body des notes/alertes EXCLU).
    // `P11.22-g` — LA LIGNE DE TEMPS D'UNE SURFACE EXTERNE dit sa coupe : lue avec sa ligne excédentaire,
    // posée par la seconde porte du fabricant (`timeline_served`, `timeline_window`, `timeline_truncated`).
    // Un client qui lit `timeline` seul lit ce qu'il lisait ; celui qui lit les trois voisines sait.
    let items: Vec<Value> = conn
        .prepare("SELECT ts,kind FROM incident_item WHERE incident_id=?1 AND kind IN ('created','status','sla','merge') ORDER BY ts,id LIMIT ?2")
        .and_then(|mut s| s.query_map(params![id, crate::handlers::liste_bornee::borne_avec_ligne_excedentaire(CLIENT_CASE_TIMELINE_WINDOW)], |r| {
            let kind: String = r.get(1)?;
            Ok(json!({ "ts": r.get::<_,i64>(0)?, "event": kind, "by": "SOC" }))
        }).and_then(|x| x.collect()))?;
    if let Some(obj) = c.as_object_mut() {
        crate::handlers::liste_bornee::poser_la_sous_liste(obj, "timeline", items, CLIENT_CASE_TIMELINE_WINDOW as usize);
    }
    Ok(Some(c))
}

/// Lecture aplatie pour les témoins existants : `None` couvre l'absence ET l'échec, ce que le gestionnaire ne fait plus.
#[cfg(test)]
pub(crate) fn client_case_get_json(conn: &Connection, db_path: &str, masks: &guatx_core::soql::FieldMaskSet, id: i64, now_i: i64) -> Option<Value> {
    client_case_get_lu(conn, db_path, masks, id, now_i).ok().flatten()
}

// ================================================================================================
// HANDLERS AXUM
// ================================================================================================

/// GET /api/cases/queues — résumé de charge par assignee (+ « my queue » côté UI via le filtre assignee de
/// /api/cases). Lecture (viewer+). Read-pool + watchdog (comme cases_list).
pub(crate) async fn case_queues(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(crate::handlers::portillon::corps_de_refus(json!({ "queues": [] }))),
    };
    let db_path = req_db_path(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "queues": [], "error": crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION }), move |conn| case_queues_json(conn, now_i)))
        .await
        .unwrap_or_else(|_| json!({ "queues": [], "error": crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE }));
    Json(res)
}

/// GET /api/cases/metrics[?from=&to=] — tableau de bord MTTA/MTTR (fenêtre, par assignee/severity). Lecture.
///
/// `P10.20-j` — UNE LECTURE QUI N'A PAS EU LIEU N'EST PLUS UN DEUX CENTS. Les deux défauts gardés (aucune connexion de
/// lecture, tâche de lecture interrompue) servaient `{error}` SEUL, en deux cents : un tableau de bord n'a pas de forme de
/// succès à garder, et un client qui lit le statut y lisait un succès. Ils rendent désormais un 503 nommé (la cause est
/// inchangée, `err_json` y ajoute l'identifiant qui la retrouve au journal). Le portillon CLOS garde la doctrine de
/// `P10.7-c` — deux cents, la forme PLUS la cause (`handlers/portillon.rs`, « PAS DE 503 ») —, mais sur une forme qui DIT
/// ce qu'elle ne porte pas (`overall: null`) au lieu d'un objet vide qui ne portait que la cause.
pub(crate) async fn case_metrics(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    let from = q.get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(crate::handlers::portillon::corps_de_refus(json!({ "overall": Value::Null }))).into_response(),
    };
    let db_path = req_db_path(&st, &au);
    let lu: Result<Value, &'static str> = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, lecture_des_metriques_non_faite(crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION), move |conn| Ok(case_metrics_json(conn, from, to)))
    })
    .await
    .unwrap_or_else(|_| lecture_des_metriques_non_faite(crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE));
    match lu {
        Ok(corps) => Json(corps).into_response(),
        Err(cause) => err_json(StatusCode::SERVICE_UNAVAILABLE, cause),
    }
}

/// AVEU : la lecture du tableau de bord MTTA/MTTR n'a pas eu lieu, et sa cause est portée jusqu'au 503 nommé que
/// `case_metrics` sert (`P10.20-j`). Un constructeur plutôt qu'un `Err(…)` écrit à la main : c'est la forme que la
/// garde des lectures non faites (`check_a_read_that_did_not_happen_is_never_served_as_a_fact.py`) lit comme un aveu, et
/// `err_json` ne peut pas tenir ce rôle — il journalise un 5xx dès qu'il est construit, donc à chaque lecture réussie.
fn lecture_des_metriques_non_faite(cause: &'static str) -> Result<Value, &'static str> {
    Err(cause)
}

/// POST /api/cases/{id}/merge {into} — fusion SOFT du case :id DANS `into`. Mutating (editor+). Ledgerisé,
/// non destructif (source conservée + réversible). 404 si un case manque / refus (déjà fusionné / cycle).
///
/// `P10.29-b` — chaque refus est nommé (`RefusDeFusion`) : 400 sans cible ou même dossier, 404 source ou cible absente,
/// 409 déjà fusionnée ou cycle, 503 lecture refusée. Le 204 est inchangé.
/// `P10.33-k` / `P10.31-u` — chronologie refusée : 503 `CAUSE_FUSION_NON_ECRITE` (fusion annulée) ; maillon manquant :
/// 200 `{ok, registre_sans_maillon}` (fusion faite). Même règle pour la défusion et la pose d'un lien.
pub(crate) async fn case_merge_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let into = b.get("into").and_then(|v| v.as_i64()).unwrap_or(0);
    if into <= 0 {
        return bad_req(CAUSE_FUSION_SANS_CIBLE);
    }
    with_write(&st, &au, |conn| {
        if let Err(refus) = juger_la_fusion(conn, id, into) {
            return refus.reponse();
        }
        match case_merge(&conn, id, into, &au.name) {
            IssueDeLaFusion::Ecrite => StatusCode::NO_CONTENT.into_response(),
            IssueDeLaFusion::EcriteSansTrace(cause) => crate::handlers::incidents::geste_fait_sans_trace(&cause),
            IssueDeLaFusion::Refusee => RefusDeFusion::NonLu("second jugement de la fusion".into()).reponse(),
            // `P10.20-l` (vague AI) — le second jugement non lu : le corps d'avant à l'octet, la cause du moteur au journal
            // avec l'identifiant servi.
            IssueDeLaFusion::DossierNonLu(cause) => {
                let (cid, refus) = err_json_et_identifiant(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("{} (second jugement de la fusion)", crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT),
                );
                eprintln!("[caseops] WARN dossier #{id} NON relu pour la fusion dans #{into}, rien n'est écrit ({}) : {cause}", cid.unwrap_or_default());
                refus
            }
            // `P10.20-w` — écriture refusée : 503 nommé (contrat neuf, assumé ; il rendait 204 sur une fusion non faite).
            // `P10.29-l` (vague AL) — la phrase seule `{error, id}`, la cause du moteur au journal avec l'identifiant.
            IssueDeLaFusion::NonEcrite(cause) => {
                crate::handlers::cases::refus_nomme_cause_au_journal(CAUSE_FUSION_NON_ECRITE, &format!("dossier #{id} : fusion dans #{into} NON écrite"), &cause)
            }
        }
    })
}

/// POST /api/cases/{id}/unmerge — dé-fusionne (réversibilité). Mutating (editor+). `P10.29-b` — refus nommés
/// (`juger_la_defusion`).
pub(crate) async fn case_unmerge_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    with_write(&st, &au, |conn| {
        if let Err(refus) = juger_la_defusion(conn, id) {
            return refus;
        }
        match case_unmerge(&conn, id, &au.name) {
            IssueDeLaFusion::Ecrite => StatusCode::NO_CONTENT.into_response(),
            IssueDeLaFusion::EcriteSansTrace(cause) => crate::handlers::incidents::geste_fait_sans_trace(&cause),
            IssueDeLaFusion::Refusee => crate::handlers::cases::refus_du_dossier_non_lu(&"relecture du dossier fusionné"),
            // `P10.20-l` (vague AI) — la relecture du dossier fusionné n'a pas eu lieu, aucune écriture tentée : le corps
            // d'avant à l'octet (jamais « défusion non écrite »), la cause du moteur au journal avec l'identifiant servi.
            IssueDeLaFusion::DossierNonLu(cause) => {
                let (cid, refus) = err_json_et_identifiant(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("{} (relecture du dossier fusionné)", crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT),
                );
                eprintln!("[caseops] WARN dossier #{id} NON relu pour la défusion, rien n'est écrit ({}) : {cause}", cid.unwrap_or_default());
                refus
            }
            // `P10.20-w` — écriture refusée : 503 nommé (contrat neuf, assumé ; il rendait 204 sur une défusion non faite).
            // `P10.29-l` (vague AL) — la phrase seule `{error, id}`, la cause du moteur au journal avec l'identifiant.
            IssueDeLaFusion::NonEcrite(cause) => {
                crate::handlers::cases::refus_nomme_cause_au_journal(CAUSE_DEFUSION_NON_ECRITE, &format!("dossier #{id} : défusion NON écrite"), &cause)
            }
        }
    })
}

/// GET /api/cases/{id}/links — liens du case. POST /api/cases/{id}/links {to,kind,note} — ajoute un lien.
pub(crate) async fn case_links_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "links": [], "error": crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION }), move |conn| case_links_json(conn, id)))
        .await
        .unwrap_or_else(|_| json!({ "links": [], "error": crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE }));
    Json(res)
}

/// `P10.20-w` — la ligne du lien n'a PAS pu être écrite : 503 nommé, et rien n'atteste le lien.
pub(crate) const CAUSE_LIEN_NON_POSE: &str =
    "LIEN NON POSÉ : la ligne n'a pas pu être écrite, donc les deux dossiers NE SONT PAS liés, leurs \
     timelines n'en portent rien et le registre non plus. Ce n'est PAS « ils étaient déjà liés » ni \
     « un des deux dossiers n'existe pas » : rien n'a été fait. Réessayez.";

/// `P10.29-b` — le corps d'une pose de lien ne désigne pas l'autre dossier.
pub(crate) const CAUSE_LIEN_SANS_CIBLE: &str = "LIEN REFUSÉ : le corps doit porter `to`, l'identifiant (entier positif) \
     de l'autre dossier. Rien n'a été fait.";
/// `P10.29-b` — un dossier ne se lie pas à lui-même.
pub(crate) const CAUSE_LIEN_AVEC_LE_MEME_DOSSIER: &str = "LIEN REFUSÉ, MÊME DOSSIER : un dossier ne se lie pas à \
     lui-même — `to` doit désigner un autre dossier. Rien n'a été fait.";
/// `P10.29-b` — l'un des deux dossiers à lier n'existe pas.
pub(crate) const CAUSE_LIEN_DOSSIER_INTROUVABLE: &str = "LIEN REFUSÉ, DOSSIER INTROUVABLE : l'un des deux dossiers \
     n'existe pas (la lecture a abouti et n'a trouvé aucune ligne). Rien n'a été fait.";
/// `P10.29-b` — aucun lien ne relie les deux dossiers.
pub(crate) const CAUSE_AUCUN_LIEN_ENTRE_CES_DOSSIERS: &str = "AUCUN LIEN ENTRE CES DEUX DOSSIERS : il n'y avait rien à \
     retirer (la suppression a abouti et n'a effacé aucune ligne).";

/// `P10.20-w` — la suppression du lien n'a PAS eu lieu : 503 nommé, et le lien est TOUJOURS là.
pub(crate) const CAUSE_LIEN_NON_RETIRE: &str =
    "LIEN NON RETIRÉ : la suppression n'a pas pu être écrite, donc les deux dossiers sont TOUJOURS \
     liés. Ce n'est PAS « aucun lien ne les reliait » : rien n'a été fait. Réessayez.";

pub(crate) async fn case_link_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let to = b.get("to").and_then(|v| v.as_i64()).unwrap_or(0);
    let kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("related").to_string();
    let note = b.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if to <= 0 {
        return bad_req(CAUSE_LIEN_SANS_CIBLE);
    }
    // Le chemin nominal est INCHANGÉ — lien posé ou déjà posé : 204. `P10.29-b` — les refus sont nommés : 400 même
    // dossier, 404 dossier absent (ÉTABLI), 503 lecture refusée ou écriture ratée ; ils rendaient 404 nu (sauf l'écriture).
    with_write(&st, &au, |conn| match case_link_add(conn, id, to, &kind, &note, &au.name) {
        LienDeDossier::Pose | LienDeDossier::DejaLie => StatusCode::NO_CONTENT.into_response(),
        LienDeDossier::PoseSansTrace(cause) => crate::handlers::incidents::geste_fait_sans_trace(&cause),
        LienDeDossier::MemeDossier => bad_req(CAUSE_LIEN_AVEC_LE_MEME_DOSSIER),
        LienDeDossier::DossierAbsent => not_found(CAUSE_LIEN_DOSSIER_INTROUVABLE),
        LienDeDossier::DossierNonLu(cause) => crate::handlers::cases::refus_du_dossier_non_lu(&cause),
        LienDeDossier::NonPose(cause) => err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_LIEN_NON_POSE} ({cause})")),
    })
}

pub(crate) async fn case_unlink_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, other)): Path<(i64, i64)>) -> Response {
    with_write(&st, &au, |conn| match case_link_remove(conn, id, other, &au.name) {
        LienRetire::Retire => StatusCode::NO_CONTENT.into_response(),
        // `P10.31-u` — lien retiré sans trace : 200 `{ok, registre_sans_maillon}`, jamais un 204 muet ; rien n'est annulé.
        LienRetire::RetireSansTrace(cause) => crate::handlers::incidents::geste_fait_sans_trace(&cause),
        LienRetire::AucunLien => not_found(CAUSE_AUCUN_LIEN_ENTRE_CES_DOSSIERS),
        LienRetire::NonRetire(cause) => err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_LIEN_NON_RETIRE} ({cause})")),
    })
}

// ---------- SLA policy CRUD (editor+ ; destructive delete = admin re-check dans le handler) ----------

/// GET /api/sla-policies — liste des politiques SLA multi-niveau. Lecture (viewer+).
pub(crate) async fn sla_policies_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    // `P10.7-z` — les trois sorties sans lecture AVOUENT : aucune connexion, exécution qui échoue, tâche qui ne rend rien.
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, json!({ "policies": [], "error": "lecture NON FAITE : aucune connexion de lecture disponible" }), |conn| {
        let lues: Result<Vec<Value>, rusqlite::Error> = conn
            .prepare("SELECT id,name,priority,ack_target_s,resolve_target_s,enabled FROM sla_policy ORDER BY priority")
            .and_then(|mut s| {
                s.query_map([], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "priority": r.get::<_, i64>(2)?,
                        "ack_target_s": r.get::<_, i64>(3)?, "resolve_target_s": r.get::<_, i64>(4)?, "enabled": r.get::<_, i64>(5)? != 0
                    }))
                })
                .and_then(|x| x.collect::<Result<Vec<Value>, _>>())
            });
        match lues {
            Ok(rows) => json!({ "policies": rows }),
            Err(_) => crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "policies"),
        }
    })).await.unwrap_or_else(|_| json!({ "policies": [], "error": "lecture NON FAITE : la tâche de lecture ne s'est pas terminée" }));
    Json(res)
}

/// PLAFOND du recalcul d'échéances déclenché par un upsert de politique. La lecture en demande UNE DE
/// PLUS : c'est cette ligne excédentaire — jamais recalculée — qui sépare « exactement le plafond, tout
/// est fait » de « il en restait, et des cases gardent leur ANCIENNE échéance ».
pub(crate) const SLA_RECOMPUTE_CAP: i64 = 5000;

/// CE QU'UN RECALCUL D'ÉCHÉANCES A RÉELLEMENT FAIT, et ce qu'il n'a PAS fait.
///
/// `manque` porte la raison, et RIEN D'AUTRE NE LA PORTE : un `recalcules` de 0 ne distingue pas
/// « aucun case actif à cette priorité » (rien à faire, donc tout est fait) de « la liste des cases n'a
/// pas pu être lue » (rien n'a été fait, et personne ne le sait). C'est exactement l'écart qui rendait la
/// route menteuse : elle répondait « fait » dans les deux cas.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct RecalculDesEcheances {
    pub(crate) recalcules: i64,
    /// `None` = tout ce qu'il fallait recalculer l'a été. `Some(raison)` = non, et voici pourquoi.
    pub(crate) manque: Option<String>,
}

impl RecalculDesEcheances {
    pub(crate) fn complet(&self) -> bool {
        self.manque.is_none()
    }
}

/// Recalcule les échéances des cases ACTIFS d'une priorité, au plafond de production.
pub(crate) fn sla_recalcule_la_priorite(conn: &Connection, priority: i64) -> RecalculDesEcheances {
    sla_recalcule_la_priorite_bornee(conn, priority, SLA_RECOMPUTE_CAP)
}

/// `P10.31-v` — LE RECALCUL D'UNE PRIORITÉ DONT LA POLITIQUE VIENT D'ÊTRE DÉSACTIVÉE (`sla_policy_upsert`, `enabled=0`) :
/// ne relit que les dossiers ACTIFS qui portent encore un `sla_policy_id`. Sans politique active pour la priorité,
/// `sla_apply_policy` rend `RienAFaire` sur un dossier à `sla_policy_id` NULL (son `UPDATE` est conditionné à une
/// politique portée) : les exclure ne change ni une écriture ni un compte. Ce qu'il change, c'est le PLAFOND : les
/// dossiers de la politique désactivée, déjà effacés dans la transaction, entraient dans la liste et faisaient dire
/// « les cases … au-delà gardent leur ANCIENNE échéance » d'une politique qui gouvernait plus de `SLA_RECOMPUTE_CAP`
/// dossiers, alors qu'aucun n'en gardait. L'aveu du plafond ne compte plus que des dossiers réellement à rendre au legacy.
pub(crate) fn sla_recalcule_la_priorite_desactivee(conn: &Connection, priority: i64) -> RecalculDesEcheances {
    sla_recalcule_la_priorite_bornee_selon(conn, priority, SLA_RECOMPUTE_CAP, true)
}

/// LE RECALCUL, ET SON AVEU. Fonction PURE sur `&Connection` (aucun `AppState`) -> les TROIS façons de ne
/// pas tout faire sont jouables en test, ce qui n'était pas le cas tant qu'elles vivaient dans le handler :
///   · la liste ne se LIT pas (table absente, base illisible, verrou) -> ZÉRO échéance recalculée ;
///   · UNE de ses lignes ne se DÉCODE pas (`P10.7-f` rang 3) -> même issue, et pour la même raison : un
///     dossier qu'on n'a pas su lire ne se distingue pas d'un dossier qui n'existe pas ;
///   · elle se lit mais DÉPASSE `plafond` -> les cases au-delà gardent leur ancienne échéance.
///
/// Le `plafond` est un paramètre pour que le témoin joue la borne sur trois lignes au lieu de cinq mille :
/// la propriété testée est « la borne mord et le dit », pas la valeur 5000.
pub(crate) fn sla_recalcule_la_priorite_bornee(conn: &Connection, priority: i64, plafond: i64) -> RecalculDesEcheances {
    sla_recalcule_la_priorite_bornee_selon(conn, priority, plafond, false)
}

/// Corps commun : `gouvernes_seulement` restreint la liste aux dossiers qui portent un `sla_policy_id`
/// (`sla_recalcule_la_priorite_desactivee`) ; faux, la requête est celle d'avant, octet pour octet.
fn sla_recalcule_la_priorite_bornee_selon(conn: &Connection, priority: i64, plafond: i64, gouvernes_seulement: bool) -> RecalculDesEcheances {
    // `P10.7-f` (rang 3) — LE PARCOURS EST SOLDÉ EN BLOC. Il s'écrivait
    // `.map(|x| x.flatten().collect())`, DEUX niveaux sous le `with_write` de l'appelant : l'aveu
    // ci-dessous ne couvrait que l'échec de la PRÉPARATION ou de l'EXÉCUTION, et une ligne dont le
    // mappeur échoue n'entrait ni dans `ids` ni dans `manque`. Le dossier sauté gardait son ANCIENNE
    // échéance pendant que la route rendait `204` = « tout recalculé » — le mensonge exact que
    // `RecalculDesEcheances` existe pour rendre impossible. Un dossier qu'on n'a pas su LIRE ne se
    // distingue pas d'un dossier qui n'existe pas : on ne recalcule donc RIEN, et on le dit.
    let requete = if gouvernes_seulement {
        "SELECT id FROM incident WHERE priority=?1 AND merged_into IS NULL \
           AND status NOT IN ('resolved','closed','contained') AND sla_policy_id IS NOT NULL ORDER BY id LIMIT ?2"
    } else {
        "SELECT id FROM incident WHERE priority=?1 AND merged_into IS NULL \
           AND status NOT IN ('resolved','closed','contained') ORDER BY id LIMIT ?2"
    };
    let lecture: rusqlite::Result<Vec<i64>> = conn
        .prepare(requete)
        .and_then(|mut s| {
            s.query_map(params![priority, plafond.max(0) + 1], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        });
    let ids = match lecture {
        Ok(v) => v,
        // L'ANCIEN `unwrap_or_default()` EST ICI, ET C'EST TOUT CE QU'IL DISAIT : une liste vide. La
        // boucle ne tournait pas, la route répondait « fait », et la politique n'était appliquée à AUCUN
        // case existant — seuls les cases créés ENSUITE l'auraient portée.
        Err(e) => {
            return RecalculDesEcheances {
                recalcules: 0,
                manque: Some(format!("liste des cases ILLISIBLE ({e}) — AUCUNE échéance recalculée")),
            }
        }
    };
    let depasse = ids.len() as i64 > plafond;
    // `P10.20-w` (reste) — `recalcules` = échéances ÉCRITES. Il comptait chaque appel, échéance refusée par la base
    // comprise ; un refus est désormais nommé dans `manque` (dossier par dossier, borné), et n'est jamais compté.
    let mut recalcules = 0i64;
    let mut refuses: Vec<String> = Vec::new();
    let mut nb_refuses = 0usize;
    let mut non_lus: Vec<String> = Vec::new();
    let mut nb_non_lus = 0usize;
    for cid in ids.into_iter().take(plafond.max(0) as usize) {
        match sla_apply_policy(conn, cid) {
            IssueDuChronoSla::Ecrit => recalcules += 1,
            IssueDuChronoSla::RienAFaire => {}
            IssueDuChronoSla::Refuse(cause) => {
                nb_refuses += 1;
                if refuses.len() < 5 {
                    refuses.push(format!("#{cid} ({cause})"));
                }
            }
            // `P10.20-b` (rang trois) — une lecture ratée (dossier ou politique) n'est plus un « rien à faire » muet :
            // le dossier n'est pas recalculé, jamais compté, et il est nommé.
            IssueDuChronoSla::NonLu(cause) => {
                nb_non_lus += 1;
                if non_lus.len() < 5 {
                    non_lus.push(format!("#{cid} ({cause})"));
                }
            }
        }
    }
    let mut manques: Vec<String> = Vec::new();
    if nb_refuses > 0 {
        manques.push(format!(
            "{nb_refuses} échéance(s) REFUSÉE(S) par la base — ces cases gardent leur ANCIENNE échéance : {}{}",
            refuses.join(", "),
            if nb_refuses > refuses.len() { ", …" } else { "" }
        ));
    }
    if nb_non_lus > 0 {
        manques.push(format!(
            "{nb_non_lus} échéance(s) NON RECALCULÉE(S) faute de LECTURE (dossier ou politique non lu) — ces cases gardent leur ANCIENNE échéance : {}{}",
            non_lus.join(", "),
            if nb_non_lus > non_lus.len() { ", …" } else { "" }
        ));
    }
    if depasse {
        manques.push(format!("plafond de {plafond} case(s) atteint — les cases de priorité {priority} au-delà gardent leur ANCIENNE échéance"));
    }
    RecalculDesEcheances { recalcules, manque: (!manques.is_empty()).then(|| manques.join(" ; ")) }
}

/// LA RÉPONSE DE L'UPSERT, ET SON SILENCE. Le chemin NOMINAL — politique écrite, toutes les échéances
/// recalculées — rend `204 SANS CORPS`, exactement comme avant : un aveu inconditionnel ne vaudrait rien,
/// et une route qui se justifie à chaque appel n'apprend rien à personne. Elle ne PARLE que quand « fait »
/// serait faux, et les deux façons de l'être n'ont pas le même code :
///   · la politique n'a PAS été écrite -> `500` : l'exploitant ne doit pas croire l'avoir posée ;
///   · elle l'a été mais le recalcul est INCOMPLET -> `200` + le corps qui dit ce qui manque. Pas un
///     `5xx` (qui ferait croire que la politique elle-même a échoué), pas un `204` (qui dirait « tout
///     est fait »). La politique EST posée ; ce sont les échéances des cases EXISTANTS qui ne le sont pas.
/// DEUX CHAMPS RETIRÉS LE 2026-08-31, ET LA RAISON EST CELLE QU'UNE GARDE DE CE DÉPÔT ÉCRIT
/// ELLE-MÊME : « s'il ne sert à personne, il n'avait pas à être écrit ». `policy_saved` était
/// ENTIÈREMENT déterminé par le code de statut (500 -> faux, 200 et 204 -> vrai), et AUCUN module
/// de la console ne le lisait — la console n'appelle même pas cette route. `recompute_complete`
/// était pire : TOUJOURS faux quand il était présent, donc constant, donc porteur d'aucune
/// information. Les deux ont été retirés plutôt que « branchés » sur un lecteur de façade : armer
/// un remède que personne n'attend aurait satisfait la garde EN LUI MENTANT. Les témoins n'y
/// perdent rien — ils assèrent le STATUT à chaque site, ce qu'un client lit vraiment, et
/// l'assertion sur le booléen répétait la ligne juste au-dessus.
/// `P10.29-l` (vague AL) — LE CINQ CENTS SANS LE TEXTE DU MOTEUR : `reason` servait `politique NON enregistrée (<moteur>)
/// — …` (noms de tables, motifs de contrainte, refus de transaction) à tout rôle qui écrit une politique. Désormais
/// `{recomputed: 0, reason: CAUSE_POLITIQUE_SLA_NON_ENREGISTREE, id}` (même statut, même préfixe ; `id` relie la demande
/// au journal) et la ligne `[caseops] WARN politique SLA NON enregistrée (<identifiant>) : <moteur>` au journal seul.
pub(crate) fn reponse_de_l_upsert_sla(ecriture: Result<(), String>, recalcul: &RecalculDesEcheances) -> Response {
    match ecriture {
        Err(e) => {
            let (cid, _) = err_json_et_identifiant(StatusCode::INTERNAL_SERVER_ERROR, CAUSE_POLITIQUE_SLA_NON_ENREGISTREE);
            let cid = cid.unwrap_or_default();
            eprintln!("[caseops] WARN politique SLA NON enregistrée ({cid}) : {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "recomputed": 0, "reason": CAUSE_POLITIQUE_SLA_NON_ENREGISTREE, "id": cid }))).into_response()
        }
        Ok(()) => match &recalcul.manque {
            None => StatusCode::NO_CONTENT.into_response(),
            Some(raison) => (
                StatusCode::OK,
                Json(json!({
                    "recomputed": recalcul.recalcules,
                    "reason": raison,
                })),
            )
                .into_response(),
        },
    }
}

/// `P10.29-l` (vague AL) — la politique n'a PAS été écrite : la phrase fixe du cinq cents de l'upsert (le moteur au journal).
pub(crate) const CAUSE_POLITIQUE_SLA_NON_ENREGISTREE: &str = "politique NON enregistrée — rien n'a été appliqué";

/// `P10.31-u` / `P10.31-v` — LA RÉPONSE DE L'UPSERT QUAND LA POLITIQUE EST ÉCRITE : `reponse_de_l_upsert_sla` si le
/// maillon `sla_policy.upsert` est inscrit (204 muet ou 200 + `reason`, contrat INCHANGÉ) ; sinon `200` + corps
/// `{recomputed, degouvernes, registre_sans_maillon[, reason]}`, patron de `sla_policy_delete` : le geste A EU LIEU
/// (politique écrite, dossiers dégouvernés), le refaire ne comblerait pas la trace — jamais un 204 muet sur une
/// politique que le registre ne porte pas.
pub(crate) fn reponse_de_l_upsert_sla_tracee(recalcul: &RecalculDesEcheances, degouvernes: usize, maillon: &MaillonDeRegistre) -> Response {
    let Some(cause) = maillon.cause_de_non_inscription() else {
        return reponse_de_l_upsert_sla(Ok(()), recalcul);
    };
    let mut corps = json!({ "recomputed": recalcul.recalcules, "degouvernes": degouvernes });
    if let Some(raison) = &recalcul.manque {
        corps["reason"] = json!(raison);
    }
    corps[CLE_REGISTRE_SANS_MAILLON] = json!(format!("{CAUSE_GESTE_SANS_TRACE} ({cause})"));
    (StatusCode::OK, Json(corps)).into_response()
}

/// `P10.29-l` — refus nommés de `sla_policy_upsert` (c'étaient deux `400` sans corps, indiscernables).
pub(crate) const CAUSE_POLITIQUE_SLA_PRIORITE_HORS_BORNES: &str =
    "POLITIQUE SLA REFUSÉE : `priority` doit être un entier de 1 à 4. Rien n'est écrit.";
pub(crate) const CAUSE_POLITIQUE_SLA_CIBLE_NULLE: &str =
    "POLITIQUE SLA REFUSÉE : `ack_target_s` et `resolve_target_s` doivent être des entiers strictement positifs \
     (secondes). Rien n'est écrit.";

/// POST /api/sla-policies {name,priority,ack_target_s,resolve_target_s,enabled?} — upsert par priorité. editor+.
/// Ledgerisé. Recompute les dues des cases ACTIFS de cette priorité (borné). priority hors 1..4 -> 400.
///
/// `204` = politique posée ET toutes les échéances recalculées. `200` + corps = politique posée, recalcul
/// INCOMPLET (cf. `reponse_de_l_upsert_sla`) ou maillon de registre manquant (`reponse_de_l_upsert_sla_tracee`).
/// `500` = rien n'a été posé.
///
/// `P10.31-v` (reste) — DÉSACTIVER UNE POLITIQUE DÉGOUVERNE TOUS SES DOSSIERS, DANS LA MÊME TRANSACTION. Le recalcul ne
/// parcourt que les dossiers ACTIFS non fusionnés de la priorité : un dossier TERMINAL ou FUSIONNÉ gardait
/// `sla_policy_id`, `ack_due` et `resolve_due` d'une politique désactivée, et une fois rouvert (le changement de statut
/// ne rejoue pas `sla_apply_policy`) ou défusionné (`case_unmerge` non plus), le tour le marquait et le NOTIFIAIT en
/// dépassement dès qu'une autre politique restait active. Même règle que `sla_policy_delete` : `enabled=0` efface les
/// trois colonnes de chaque dossier gouverné par CETTE politique, quel que soit son état. Le recalcul est REJOUÉ après
/// la transaction, désactivation comprise : sans politique active pour la priorité, `sla_apply_policy` rend au régime
/// legacy les dossiers ACTIFS qui portent encore un `sla_policy_id` pendant ou étranger (forme d'avant ce lot, que
/// l'effacement borné à CETTE politique ne couvre pas) ; ceux-là sont comptés dans `recomputed`, pas dans `degouvernes`
/// ni au registre ; ce recalcul de désactivation ne relit que les actifs à `sla_policy_id` non NULL
/// (`sla_recalcule_la_priorite_desactivee`), et son aveu de plafond ne vise donc jamais un dossier déjà effacé.
/// Écriture de la politique, effacement et maillon sont jugés ensemble (`jouer_le_geste_garde`) : un effacement refusé
/// annule la désactivation, un `BEGIN` ou un `COMMIT` refusé aussi (500, rien posé).
/// LIMITES ÉCRITES : marqueurs `ack_breached`/`resolve_breached` conservés et pause en cours conservée (mêmes limites
/// que `sla_apply_policy` et `sla_policy_delete`) ; RÉACTIVER la politique ne regouverne que les dossiers ACTIFS (le
/// recalcul), pas les terminaux ni les fusionnés.
/// `P10.31-u` — LE MAILLON EST CONSOMMÉ : son détail dit `enabled=0|1` (une désactivation n'est plus indiscernable
/// d'une modification au registre) et le nombre de dossiers dégouvernés ; manquant, il est avoué
/// (`reponse_de_l_upsert_sla_tracee`).
pub(crate) async fn sla_policy_upsert(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    let priority = b.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
    if !(1..=4).contains(&priority) {
        return bad_req(CAUSE_POLITIQUE_SLA_PRIORITE_HORS_BORNES);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let ack_s = b.get("ack_target_s").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let res_s = b.get("resolve_target_s").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let enabled = b.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as i64;
    if ack_s == 0 || res_s == 0 {
        return bad_req(CAUSE_POLITIQUE_SLA_CIBLE_NULLE);
    }
    with_write(&st, &au, |conn| {
        let t = now();
        let issue = jouer_le_geste_garde(conn, "caseops", &format!("écriture de la politique SLA P{priority}"), |conn| {
            // Le journal d'INTÉGRITÉ ne consigne que ce qui a EU LIEU : une écriture qui a échoué n'y
            // entre pas. L'ancien `let _ =` la ledgerisait quand même — le journal aurait porté une
            // politique que la base ne portait pas.
            conn.execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?6) \
                 ON CONFLICT(priority) DO UPDATE SET name=?1,ack_target_s=?3,resolve_target_s=?4,enabled=?5,updated=?6",
                params![name, priority, ack_s, res_s, enabled, t, au.name],
            )
            .map_err(|e| e.to_string())?;
            let degouvernes = if enabled == 0 {
                conn.execute(
                    "UPDATE incident SET sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL \
                     WHERE sla_policy_id=(SELECT id FROM sla_policy WHERE priority=?1)",
                    params![priority],
                )
                .map_err(|e| format!("effacement des échéances des dossiers de la politique désactivée refusé ({e})"))?
            } else {
                0
            };
            let mut detail = format!("P{priority} ack={ack_s}s resolve={res_s}s enabled={enabled} by {}", au.name);
            if degouvernes > 0 {
                detail.push_str(&format!(
                    " ; {degouvernes} dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)"
                ));
            }
            Ok::<_, String>((degouvernes, ledger_append(conn, "sla_policy.upsert", &detail)))
        });
        match issue {
            Issue::Valide((degouvernes, maillon)) => {
                // Rejoué AUSSI à la désactivation : l'effacement ci-dessus ne vise que `sla_policy_id` = CETTE politique ;
                // un dossier ACTIF de la priorité qui porte un identifiant pendant (politique supprimée avant `P10.31-v`,
                // aucune clé étrangère) ou étranger n'est rendu au régime legacy que par `sla_apply_policy`. À la
                // désactivation, seuls ceux-là sont relus : les dossiers déjà effacés ne comptent plus dans le plafond.
                let recalcul = if enabled == 0 {
                    sla_recalcule_la_priorite_desactivee(conn, priority)
                } else {
                    sla_recalcule_la_priorite(conn, priority)
                };
                reponse_de_l_upsert_sla_tracee(&recalcul, degouvernes, &maillon)
            }
            Issue::Refuse(e) => reponse_de_l_upsert_sla(Err(e), &RecalculDesEcheances::default()),
            Issue::NonOuvert(e) | Issue::NonValide(e) => reponse_de_l_upsert_sla(Err(e.to_string()), &RecalculDesEcheances::default()),
        }
    })
}

/// `P10.20-w` — la politique n'a PAS pu être supprimée : 503 nommé, et elle gouverne toujours.
pub(crate) const CAUSE_POLITIQUE_NON_SUPPRIMEE: &str =
    "POLITIQUE SLA NON SUPPRIMÉE : la suppression n'a pas pu être écrite, donc la politique GOUVERNE \
     TOUJOURS les échéances de sa priorité et le registre n'en porte aucune suppression. Ce n'est PAS \
     « aucune politique ne porte cet identifiant » : rien n'a été fait. Réessayez.";

/// `P10.31-v` — les dossiers gouvernés par la politique n'ont PAS pu être rendus au régime legacy : 503 nommé, la
/// politique est CONSERVÉE (suppression annulée dans la même transaction), rien n'est inscrit au registre.
pub(crate) const CAUSE_DOSSIERS_NON_DEGOUVERNES: &str =
    "POLITIQUE SLA NON SUPPRIMÉE : la base n'a pas pris l'effacement des échéances (politique, acquittement, \
     résolution) des dossiers qu'elle gouverne. Supprimer la politique sans cet effacement laisserait ces dossiers \
     jugés en dépassement sur les échéances d'une politique disparue : la suppression est ANNULÉE, la politique \
     GOUVERNE TOUJOURS, le registre n'en porte rien. Réessayez.";

/// `P10.29-l` — refus nommés de `sla_policy_delete` (c'étaient un `403` et un `404` sans corps).
pub(crate) const CAUSE_SUPPRESSION_DE_POLITIQUE_SLA_RESERVEE: &str =
    "SUPPRESSION REFUSÉE : supprimer une politique SLA est réservé à l'administrateur. Rien n'est supprimé.";
pub(crate) const CAUSE_POLITIQUE_SLA_INTROUVABLE: &str =
    "POLITIQUE SLA INTROUVABLE : aucune politique ne porte cet identifiant (la suppression a abouti sans toucher \
     aucune ligne). Rien n'est supprimé et le registre n'en porte aucune trace.";

/// DELETE /api/sla-policies/{id} — supprime une politique. ADMIN-ONLY (config gouvernante) : re-check handler.
///
/// `P10.20-w` — le chemin nominal est INCHANGÉ (204 sur suppression, 404 sur absence, nommé depuis `P10.29-l`) ; l'écriture
/// RATÉE, qui sortait en 404 — « cette politique n'existe pas » sur une politique bien vivante —, est
/// nommée par un 503.
///
/// `P10.31-v` (volet démon) — SUPPRIMER UNE POLITIQUE DÉGOUVERNE SES DOSSIERS, DANS LA MÊME TRANSACTION. Avant, seul
/// `DELETE FROM sla_policy` était écrit : `sla_policy_id`, `ack_due` et `resolve_due` posés par `sla_apply_policy`
/// survivaient, et `sla_multilevel_tick_par` — qui lit les échéances d'`incident` sans joindre `sla_policy` — marquait et
/// NOTIFIAIT ces dossiers en dépassement dès qu'une AUTRE politique restait active. Même règle que pour une priorité
/// sans politique (`sla_apply_policy`, `P10.20-w`) : les trois colonnes reviennent à NULL, le dossier retombe sur le
/// régime legacy. Suppression et effacement sont jugés ensemble (`jouer_le_geste_garde`) : effacement refusé ->
/// 503 `CAUSE_DOSSIERS_NON_DEGOUVERNES`, politique conservée, rien au registre ; `BEGIN`/`COMMIT` refusés -> 503
/// `CAUSE_POLITIQUE_NON_SUPPRIMEE`. Le registre (inscrit DANS la transaction) dit le nombre de dossiers dégouvernés
/// quand il y en a ; son maillon manquant est avoué sous `CLE_REGISTRE_SANS_MAILLON` (200 + corps : le geste a eu
/// lieu, le refaire ne comblerait pas la trace). Sans dossier gouverné et maillon inscrit : 204 et détail d'avant.
/// LIMITES ÉCRITES : `sla_due` legacy n'est PAS touché — il est entretenu indépendamment de toute politique
/// (`ts + sla_target_s(priority)` à la création et à chaque recalcul de `case_apply_update`), donc il est déjà celui du
/// régime de retour (témoin qui le relit) ; les marqueurs `ack_breached`/`resolve_breached` ne sont PAS remis à zéro
/// (un dépassement passé sous la politique reste un fait, son registre le porte — même limite que `sla_apply_policy`) ;
/// les dossiers TERMINAUX gouvernés perdent aussi leurs échéances (la politique qui les définissait n'existe plus) ;
/// une pause en cours (`sla_paused_since`) est conservée, `sla_on_status_change` la reprend sans politique portée.
/// HORS DE CE GESTE : une politique MODIFIÉE ou DÉSACTIVÉE (`sla_policy_upsert`) ; la console.
pub(crate) async fn sla_policy_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde as Issue};
    if !au.is_admin() {
        return forbidden(CAUSE_SUPPRESSION_DE_POLITIQUE_SLA_RESERVEE);
    }
    with_write(&st, &au, |conn| {
        let issue = jouer_le_geste_garde(conn, "caseops", &format!("suppression de la politique SLA #{id}"), |conn| {
            match conn.execute("DELETE FROM sla_policy WHERE id=?1", params![id]) {
                Ok(0) => return Err(not_found(CAUSE_POLITIQUE_SLA_INTROUVABLE)),
                Ok(_) => {}
                Err(e) => {
                    return Err(crate::handlers::cases::refus_nomme_cause_au_journal(
                        CAUSE_POLITIQUE_NON_SUPPRIMEE,
                        &format!("politique SLA #{id} NON supprimée"),
                        &e,
                    ));
                }
            }
            let degouvernes = match conn.execute(
                "UPDATE incident SET sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL WHERE sla_policy_id=?1",
                params![id],
            ) {
                Ok(n) => n,
                Err(e) => {
                    return Err(crate::handlers::cases::refus_nomme_cause_au_journal(
                        CAUSE_DOSSIERS_NON_DEGOUVERNES,
                        &format!("politique SLA #{id} : dossiers NON dégouvernés, suppression annulée"),
                        &e,
                    ));
                }
            };
            let mut detail = format!("#{id} by {}", au.name);
            if degouvernes > 0 {
                detail.push_str(&format!(
                    " ; {degouvernes} dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)"
                ));
            }
            Ok((degouvernes, ledger_append(conn, "sla_policy.delete", &detail)))
        });
        match issue {
            Issue::Valide((degouvernes, maillon)) => match maillon.cause_de_non_inscription() {
                None => StatusCode::NO_CONTENT.into_response(),
                Some(cause) => {
                    let mut corps = json!({ "degouvernes": degouvernes });
                    corps[CLE_REGISTRE_SANS_MAILLON] = json!(format!("{CAUSE_GESTE_SANS_TRACE} ({cause})"));
                    Json(corps).into_response()
                }
            },
            Issue::Refuse(reponse) => reponse,
            Issue::NonOuvert(e) | Issue::NonValide(e) => {
                crate::handlers::cases::refus_nomme_cause_au_journal(CAUSE_POLITIQUE_NON_SUPPRIMEE, &format!("politique SLA #{id} NON supprimée"), &e)
            }
        }
    })
}

// ---------- CLIENT-READ API handlers ----------

/// Masques EFFECTIFS de l'appelant client — VRAI tenant/role/env (jamais ""), comme /api/query & #60.
fn client_masks(st: &AppState, au: &AuthUser) -> guatx_core::soql::FieldMaskSet {
    effective_masks(req_db_path(st, au).as_str(), &au.role, &au.tenant, au.env_filter())
}

/// GET /api/client/cases[?state=open|resolved&limit=&offset=] — LISTE client read-only, tenant-scopée, masquée.
/// Cf. INVARIANT SÉCU en tête de module. Read-pool + watchdog. Jamais de mutation ni de SQL brut.
pub(crate) async fn client_cases_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let state = q.get("state").cloned().unwrap_or_default();
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(100).clamp(1, 500);
    let offset = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(crate::handlers::portillon::corps_de_refus(json!({ "cases": [], "total": 0 }))),
    };
    let db_path = req_db_path(&st, &au);
    let masks = client_masks(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || {
        let dbp = db_path.clone();
        read_with_watchdog(&db_path, json!({ "cases": [], "total": 0, "error": crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION }), move |conn| client_cases_list_json(conn, &dbp, &masks, now_i, &state, limit, offset))
    })
    .await
    .unwrap_or_else(|_| json!({ "cases": [], "total": 0, "error": crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE }));
    Json(res)
}

/// `P10.29-l` — absence établie d'un dossier client : 404 JSON nommé (c'était le texte `case introuvable`). La phrase
/// ne dit pas laquelle des trois causes (absent, archivé, fusionné) : le client n'en apprend pas plus qu'avant.
pub(crate) const CAUSE_DOSSIER_CLIENT_INTROUVABLE: &str =
    "DOSSIER INTROUVABLE : aucun dossier visible ne porte cet identifiant (absent, archivé ou fusionné ; la lecture a \
     abouti et n'a trouvé aucune ligne).";

/// GET /api/client/cases/{id} — DÉTAIL client (projection fermée + timeline cycle-de-vie anonymisée). 404 si
/// absent/archivé/fusionné. Tenant-scopé + masqué (INVARIANT).
pub(crate) async fn client_case_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    let db_path = req_db_path(&st, &au);
    let masks = client_masks(&st, &au);
    let now_i = now();
    let res = tokio::task::spawn_blocking(move || {
        let dbp = db_path.clone();
        // `P10.7-g` (lot 92) — une lecture NON FAITE n'est pas une absence : « case introuvable » (404) ne se sert
        // que sur une lecture aboutie qui n'a rien trouvé ; sans connexion, ou tâche interrompue, c'est un 5xx qui le dit.
        // `P10.29-l` (vague AL) — la lecture ratée rend la cause du moteur à part (`Err`), pour le journal seul.
        read_with_watchdog(&db_path, Ok(Some(json!({ "error": crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION, "lecture_non_faite": true }))), move |conn| {
            client_case_get_lu(conn, &dbp, &masks, id, now_i).map_err(|e| e.to_string())
        })
    })
    .await
    .unwrap_or_else(|_| Ok(Some(json!({ "error": crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE, "lecture_non_faite": true }))));
    match res {
        // `P10.29-l` (vague AL) — le cinq cents servait `dossier NON LU : la lecture a échoué (<moteur>) — …` au CLIENT
        // (rôle `client`, jeton externe) : noms de tables et de colonnes partaient hors de l'équipe. Même patron que la
        // fiche interne (`refus_de_la_fiche_non_lue`) : `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id, lecture_non_faite}`,
        // même statut, même préfixe, le moteur au journal avec l'identifiant servi.
        Err(moteur) => crate::handlers::cases::refus_de_la_fiche_non_lue(id, &moteur),
        Ok(Some(v)) if v.get("lecture_non_faite").is_some() => (StatusCode::INTERNAL_SERVER_ERROR, Json(v)).into_response(),
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => not_found(CAUSE_DOSSIER_CLIENT_INTROUVABLE),
    }
}
