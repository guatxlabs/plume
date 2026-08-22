//! `P3.9-a` — UNE RÈGLE QUI NE PEUT PAS ÊTRE ÉVALUÉE EST UNE DÉTECTION ÉTEINTE, ET ELLE LE DIT.
//!
//! LE DÉFAUT QUE CE MODULE FERME. Depuis `P4.1-r`, l'ordonnanceur COMPTE les règles dues qu'il
//! abandonne (compilation refusée, évaluation en échec, fil en panique) et la surface d'état affiche
//! le compte du dernier tick. Ce compte est un fait de TICK : il ne sait pas qu'une MÊME règle est
//! abandonnée à chaque intervalle depuis des heures, et personne ne regarde un panneau système pendant
//! un incident. Une règle livrée, dont la donnée était présente dans chaque fenêtre, a ainsi gardé le
//! silence pendant tout un incident : chaque évaluation dépassait le budget ou le verrou sur un nœud
//! en thrash, et rien ne distinguait ce silence d'un calme.
//!
//! CE QUE CE MODULE TIENT, EN TROIS FAITS :
//!   * LA CAUSE DE L'ABANDON EST CONSERVÉE. `eval_value_budget` rendait `Option<f64>` : l'erreur de
//!     requête, le dépassement de budget, une cellule non numérique et une panique du fil se
//!     fondaient en un même `None`. Ici, une évaluation rend sa valeur ou son `AbandonDEvaluation`,
//!     dont la cause est une clé de l'ensemble FERMÉ `CAUSES_D_ABANDON` (la forme de `S32`) ;
//!   * LES ABANDONS CONSÉCUTIFS SONT COMPTÉS PAR RÈGLE ET PERSISTENT (`rule.abandons_consecutifs`,
//!     v116) : un redémarrage du démon ne remet pas le compte à zéro, puisqu'il ne change rien à la
//!     cause. Le compte est remis à zéro à la PREMIÈRE évaluation réussie ;
//!   * AU SEUIL, UNE ALERTE — par le chemin des alertes de capteur muet (`INSERT OR IGNORE` sur une
//!     clé de déduplication STABLE par règle, résolution qui libère la clé) : elle arrive dans la liste
//!     des alertes comme les autres, et la table `alert` n'est jamais purgée. Son titre nomme la
//!     règle, la cause et le nombre d'évaluations ; elle se RÉSOUT d'elle-même à la première évaluation
//!     réussie, par la même mécanique que le retour sous le seuil d'une règle.
//!
//! LE SEUIL EST DÉRIVÉ, PAS CHOISI : `seuil_d_abandons_consecutifs` rend le nombre d'intervalles de la
//! règle qui tiennent dans UNE HEURE — l'horizon que les autres signaux de santé non purgeables
//! utilisent déjà pour leur déduplication (`emit_disk_health`, `emit_ledger_unsigned`,
//! `emit_backup_symmetric_signal` : un seau horaire) — avec un plancher de DEUX : un abandon isolé est
//! le régime transitoire que la re-planification au prochain intervalle traite déjà, et une alerte
//! au premier abandon rendrait chaque contention passagère bruyante. Une règle évaluée toutes les dix
//! minutes est donc dite aveugle après six abandons consécutifs ; une règle horaire, après deux.
//!
//! CE QUE CE MODULE NE FAIT PAS : il n'évalue rien et ne décide pas de re-tenter — l'ordonnanceur
//! re-planifie comme avant. Il ne couvre que les règles qu'il est appelé à consigner ; les autres
//! évaluateurs (règles avancées, règles de risque) comptent leurs abandons sans les consigner ici,
//! et la garde `toute_replanification_sans_evaluation_passe_par_le_consignateur` nomme cet écart.
use rusqlite::{params, Connection};

/// La requête a tourné et a été INTERROMPUE par le chien de garde du budget temps.
pub(crate) const CAUSE_BUDGET_DEPASSE: &str = "budget_depasse";
/// La requête a été REFUSÉE ou a ÉCHOUÉ (préparation, table absente, verrou, mémoire, plafond).
pub(crate) const CAUSE_ERREUR_REQUETE: &str = "erreur_requete";
/// La requête a rendu une cellule qui n'est pas un nombre (ou aucune ligne).
pub(crate) const CAUSE_VALEUR_NON_NUMERIQUE: &str = "valeur_non_numerique";
/// La requête de la règle ne COMPILE pas (le compilateur SOQL l'a refusée).
pub(crate) const CAUSE_COMPILATION_REFUSEE: &str = "compilation_refusee";
/// Le fil d'évaluation a PANIQUÉ : la règle n'a pas été évaluée, et l'ordonnanceur a survécu.
pub(crate) const CAUSE_EVALUATEUR_EN_PANNE: &str = "evaluateur_en_panne";
/// L'ENSEMBLE FERMÉ des causes d'abandon d'une règle. Un témoin vérifie que chaque cause rendue par
/// `evaluer_valeur_de_regle` et par les constructeurs ci-dessous en fait partie.
pub(crate) const CAUSES_D_ABANDON: [&str; 5] = [
    CAUSE_BUDGET_DEPASSE,
    CAUSE_ERREUR_REQUETE,
    CAUSE_VALEUR_NON_NUMERIQUE,
    CAUSE_COMPILATION_REFUSEE,
    CAUSE_EVALUATEUR_EN_PANNE,
];

/// L'horizon de cécité toléré avant l'alerte : UNE HEURE, l'unité que les signaux de santé non
/// purgeables utilisent déjà pour se dédupliquer.
pub(crate) const HORIZON_DE_CECITE_S: i64 = 3600;
/// Sous ce nombre d'abandons consécutifs, aucune alerte : un abandon isolé est un incident
/// transitoire que la re-planification traite déjà.
pub(crate) const PLANCHER_D_ABANDONS: u32 = 2;

/// Le préfixe de la clé de déduplication des alertes de cécité — UNE clé par règle, stable pour la
/// durée de l'épisode, libérée à la résolution (la mécanique de `rule-{id}` et de `hb-{id}`).
pub(crate) const DEDUP_PREFIXE: &str = "regle-aveugle-";
/// La famille de l'alerte dans `alert.rule` : `heartbeat.` est la famille des signaux d'angle mort
/// (capteur muet, flotte muette) que le bulletin de support relit déjà, et qu'aucune jointure sur
/// `rule` ne prend pour un tir.
pub(crate) const FAMILLE_ALERTE: &str = "heartbeat.regle-aveugle";

/// CE QU'UNE ÉVALUATION ABANDONNÉE LAISSE : sa cause (clé fermée) et le détail lisible par l'analyste.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AbandonDEvaluation {
    pub(crate) cause: &'static str,
    pub(crate) detail: String,
}

impl AbandonDEvaluation {
    /// Le SEUL constructeur : une cause hors de l'ensemble fermé est une faute de programmation, pas
    /// une donnée — elle est refusée en débogage, et un témoin relit l'ensemble en production.
    fn de(cause: &'static str, detail: String) -> Self {
        debug_assert!(CAUSES_D_ABANDON.contains(&cause), "cause d'abandon hors de l'ensemble fermé : {cause}");
        Self { cause, detail }
    }
    pub(crate) fn compilation_refusee(erreur: &str) -> Self {
        Self::de(CAUSE_COMPILATION_REFUSEE, erreur.to_string())
    }
    pub(crate) fn evaluateur_en_panne() -> Self {
        Self::de(CAUSE_EVALUATEUR_EN_PANNE, "le fil d'évaluation a paniqué".to_string())
    }
    /// La cause d'une erreur rendue par `run_query_ex`, dérivée de son message : le chien de garde
    /// du budget est le SEUL à produire « requête interrompue (budget … dépassé) » ; tout le reste
    /// est une requête qui a échoué.
    pub(crate) fn erreur_de_requete(erreur: &str) -> Self {
        let cause = if erreur.starts_with("requête interrompue (budget") { CAUSE_BUDGET_DEPASSE } else { CAUSE_ERREUR_REQUETE };
        Self::de(cause, erreur.to_string())
    }
    pub(crate) fn valeur_non_numerique(cellule: &serde_json::Value) -> Self {
        Self::de(CAUSE_VALEUR_NON_NUMERIQUE, format!("la dernière cellule de la première ligne n'est pas un nombre : {cellule}"))
    }
}

/// ÉVALUE LE SCALAIRE D'UNE RÈGLE — la valeur, ou l'abandon AVEC SA CAUSE. C'est la seule porte par
/// laquelle l'ordonnanceur évalue une règle ; `eval_value_budget` n'en est que la projection en
/// `Option` pour les appelants qui n'ont pas (encore) d'usage de la cause.
pub(crate) fn evaluer_valeur_de_regle(db_path: &str, sql: &str, budget_ms: u64) -> Result<f64, AbandonDEvaluation> {
    let v = crate::run_query_ex(db_path, sql, budget_ms, None).map_err(|e| AbandonDEvaluation::erreur_de_requete(&e))?;
    let cellule = v
        .get("rows")
        .and_then(|r| r.as_array())
        .and_then(|r| r.first())
        .and_then(|l| l.as_array())
        .and_then(|l| l.last())
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    cellule
        .as_f64()
        .or_else(|| cellule.as_i64().map(|n| n as f64))
        .ok_or_else(|| AbandonDEvaluation::valeur_non_numerique(&cellule))
}

/// LE SEUIL, DÉRIVÉ DE L'INTERVALLE DE LA RÈGLE : le nombre d'intervalles qui tiennent dans
/// `HORIZON_DE_CECITE_S`, arrondi vers le haut, jamais sous `PLANCHER_D_ABANDONS`. Un intervalle nul
/// ou négatif (une règle due à chaque tick) compte comme une seconde.
pub(crate) fn seuil_d_abandons_consecutifs(interval_s: i64) -> u32 {
    let intervalle = interval_s.max(1);
    let n = (HORIZON_DE_CECITE_S + intervalle - 1) / intervalle;
    u32::try_from(n).unwrap_or(u32::MAX).max(PLANCHER_D_ABANDONS)
}

pub(crate) fn cle_dedup(id: i64) -> String {
    format!("{DEDUP_PREFIXE}{id}")
}

/// Le titre de l'alerte : la règle, la cause et le nombre — ce qu'un analyste lit dans une liste.
pub(crate) fn titre(nom: &str, cause: &str, n: u32) -> String {
    format!("détection aveugle : {nom} — {cause}, {n} évaluations")
}

/// Ce que l'ordonnanceur a consigné pour une règle abandonnée : le compte consécutif atteint, et si
/// l'alerte est posée (ou rafraîchie) à ce tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct AbandonConsigne {
    pub(crate) consecutifs: u32,
    pub(crate) seuil: u32,
    pub(crate) alerte_posee: bool,
}

/// CONSIGNE UN ABANDON : re-planifie la règle (`last_run`), incrémente son compte consécutif, et dès
/// que ce compte atteint le seuil dérivé de son intervalle, pose l'alerte de cécité — `INSERT OR
/// IGNORE` sur la clé stable (no-op si l'épisode est déjà ouvert) puis rafraîchissement du titre, de
/// l'horodatage et du détail SANS toucher `notified` (pas de re-notification à chaque intervalle).
///
/// `None` si la règle n'a pas pu être relue après l'écriture : rien n'est posé, et l'abandon reste
/// compté par l'appelant (`P4.1-r`) — une alerte sur un compte qu'on n'a pas lu serait inventée.
pub(crate) fn consigner_abandon(
    conn: &Connection,
    id: i64,
    nom: &str,
    severity: i64,
    now_ts: i64,
    abandon: &AbandonDEvaluation,
) -> Option<AbandonConsigne> {
    let _ = conn.execute(
        "UPDATE rule SET last_run=?1, abandons_consecutifs=abandons_consecutifs+1 WHERE id=?2",
        params![now_ts, id],
    );
    let (consecutifs, interval_s): (u32, i64) = conn
        .query_row("SELECT abandons_consecutifs, interval_s FROM rule WHERE id=?1", params![id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })
        .ok()
        .map(|(n, i)| (u32::try_from(n).unwrap_or(u32::MAX), i))?;
    let seuil = seuil_d_abandons_consecutifs(interval_s);
    if consecutifs < seuil {
        return Some(AbandonConsigne { consecutifs, seuil, alerte_posee: false });
    }
    let dedup = cle_dedup(id);
    let titre = titre(nom, abandon.cause, consecutifs);
    let detail = format!(
        "La règle n'a pas pu être évaluée {consecutifs} fois de suite (seuil {seuil} : {HORIZON_DE_CECITE_S} s d'horizon \
         pour un intervalle de {interval_s} s). Dernière cause : {} — {}. Tant que cette alerte est ouverte, cette \
         détection est ÉTEINTE : elle ne peut ni tirer ni se résoudre. Elle se résout d'elle-même à la première \
         évaluation réussie.",
        abandon.cause, abandon.detail
    );
    // L'IMPUTATION est l'inconnu NOMMÉ : cette alerte se rapporte à une RÈGLE, pas à un flux — lui
    // imputer une source ferait basculer la pastille d'une source qui n'a rien fait (cf. flotte muette).
    let sources = crate::imputation_encoder(&[crate::SOURCE_INDETERMINABLE.to_string()]);
    let _ = conn.execute(
        "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,sources) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![now_ts, format!("{FAMILLE_ALERTE}.{id}"), severity, titre, detail, dedup, sources],
    );
    let _ = conn.execute(
        "UPDATE alert SET ts=?1, title=?2, detail=?3 WHERE dedup=?4 AND status IN ('new','ack')",
        params![now_ts, titre, detail, dedup],
    );
    Some(AbandonConsigne { consecutifs, seuil, alerte_posee: true })
}

/// CONSIGNE UNE ÉVALUATION RÉUSSIE : `last_run` et `last_value` comme avant, le compte consécutif
/// remis à zéro, et l'épisode de cécité RÉSOLU — la clé est libérée, un futur épisode se ré-arme.
pub(crate) fn consigner_evaluation_reussie(conn: &Connection, id: i64, now_ts: i64, valeur: f64) {
    let _ = conn.execute(
        "UPDATE rule SET last_run=?1, last_value=?2, abandons_consecutifs=0 WHERE id=?3",
        params![now_ts, valeur, id],
    );
    let _ = conn.execute(
        "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
        params![cle_dedup(id)],
    );
}
