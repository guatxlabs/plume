//! portillon — L'AVEU DU PORTILLON DE CONCURRENCE, ÉCRIT UNE SEULE FOIS (`P10.7-c`).
//!
//! LE DÉFAUT QUE CE MODULE REND NON-ÉCRIVABLE. Le portillon interactif
//! (`query_timing::acquire_query_permit`, seul point de passage vers `AppState::query_sem`) rend
//! `Err` quand le sémaphore est CLOS — l'arrêt du processus. Chaque route décidait alors, chez
//! elle, quoi rendre. Onze d'entre elles rendaient un corps 200 portant les clés attendues, toutes
//! VIDES, et rien d'autre : `{"alerts":[]}`, `{"hosts":[]}`, `{"columns":[],"rows":[]}`… Aucun
//! consommateur ne peut distinguer ce corps-là d'une absence ÉTABLIE — c'est-à-dire d'un fait.
//!
//! POURQUOI UNE FONCTION ET PAS UNE CONSIGNE. Le défaut a été fermé DEUX FOIS au cas par cas — sur
//! `/api/search` puis sur `/api/query` — et il est réapparu une troisième fois sur le Pivot
//! (`handlers/datamodels.rs`), puis MESURÉ le 2026-08-28 sur onze routes à la fois. Un remède qui
//! se rejoue route par route ne converge pas : il traite les occurrences connues et laisse la
//! forme intacte pour la suivante. Ici la phrase n'existe qu'à UN endroit, et une route ne peut
//! rendre un corps de refus qu'en passant par lui.
//!
//! CE QUE LA FORME PRÉSERVE, ET POURQUOI. Le corps GARDE les clés que le consommateur attend
//! (`rows`, `alerts`, `hosts`…) : un client qui lit `j.rows.length` continue de fonctionner au lieu
//! de tomber sur un `undefined`. Ce qui S'AJOUTE est la cause, sous la clé `error` — la même clé que
//! `bad_req`/`server_err` et que les deux routes déjà fermées, donc la clé que les consommateurs
//! testent DÉJÀ. L'ajout est strictement additif : aucune clé existante n'est retirée ni modifiée.
//!
//! PAS DE 503. L'acquisition n'a pas échoué SOUS LA CHARGE — le portillon fait attendre, il ne
//! rejette jamais un client de trop (`acquire_query_permit` : `try_acquire_owned` puis `.await`).
//! Le seul échec possible est un sémaphore CLOS, c'est-à-dire un processus qui se ferme. Un 503
//! « saturation » désignerait un levier faux, exactement comme `sem_wait_ms` le faisait avant
//! `P7.8-a`. C'est le choix déjà pris par `/api/query` et `/api/search`, et il est conservé ici.
//!
//! CE QUE CE MODULE NE TIENT PAS, ET QUI EST DIT PLUTÔT QUE SOUS-ENTENDU :
//!   * il ne tient QUE le portillon. Une lecture qui échoue plus loin (pool de lecture indisponible,
//!     watchdog, tâche bloquante paniquée) a ses propres défauts de `read_with_watchdog`, dont
//!     plusieurs sont encore des corps vides nus — c'est une autre famille, et elle reste ouverte ;
//!   * il ne tient pas ce que l'ANALYSTE voit. Le démon avoue ; un module de console qui ne lit
//!     jamais `error` affichera toujours une table vide. Mesuré le 2026-08-28 : sur les six modules
//!     de `web/` qui consomment ces routes, quatre ne lisent `error` nulle part.
use crate::*;

/// LA CAUSE, ÉCRITE UNE FOIS. Elle dit trois choses, et les trois sont nécessaires :
/// ce qui n'a PAS eu lieu (aucune lecture), POURQUOI (le processus se ferme), et surtout ce que le
/// corps n'établit PAS (une absence). Sans la troisième, un lecteur pressé relit le corps vide comme
/// avant.
pub(crate) const CAUSE_PORTILLON_CLOS: &str = "lecture NON EXÉCUTÉE : le service se ferme (portillon \
     de concurrence clos). Ce corps ne porte aucune ligne parce qu'AUCUNE n'a été lue — ce n'est pas \
     une absence établie.";

/// LE CORPS D'UN REFUS DU PORTILLON : la forme attendue par le consommateur, PLUS la cause.
///
/// `forme` est le corps que la route rendait — ses clés vides. Elles sont conservées telles quelles ;
/// `error` s'y ajoute. Une `forme` qui n'est pas un objet JSON (cas qu'aucune route n'écrit
/// aujourd'hui) est REMPLACÉE par un objet ne portant que la cause : mieux vaut perdre une forme que
/// rendre une valeur nue sans son aveu.
///
/// UNE ROUTE NE PEUT PAS ÉCRASER L'AVEU : si `forme` portait déjà une clé `error`, celle-ci est
/// remplacée par la cause du portillon — c'est bien le portillon qui a refusé, pas la route.
pub(crate) fn corps_de_refus(forme: Value) -> Value {
    let mut corps = match forme {
        Value::Object(_) => forme,
        _ => json!({}),
    };
    corps["error"] = json!(CAUSE_PORTILLON_CLOS);
    corps
}
