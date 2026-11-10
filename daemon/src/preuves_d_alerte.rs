//! `P11.25-g` — LES PREUVES D'UNE ALERTE DE RÈGLE : les entités que son nombre compte, lues à l'instant où l'alerte
//! est levée, et servies avec elle.
//!
//! LE DÉFAUT. Une règle d'agrégat (« attaquant actif non banni », SQL natif) rend UN NOMBRE d'adresses ; l'alerte ne
//! portait que « nom : valeur > seuil » et le texte de la requête. Le forage de la console recentre une recherche sur
//! la fenêtre de la règle : pour une requête SQL qui rend un seul compte, il ne montre que ce compte, et l'exploitant
//! ne pouvait pas remonter aux adresses comptées.
//!
//! LE MÉCANISME, GÉNÉRIQUE. Une règle PEUT déclarer une requête de preuves (`rule.evidence_query`, v126, NULL = aucune) :
//! les lignes que son nombre compte, de même nature que sa requête (`is_soql` de la règle). Elle est jouée par le MÊME
//! chemin que la requête de la règle — même compilation (`rule_sql_a_l_instant`, même substitution de fenêtre), même
//! porte de lecture (`run_query_ex` : connexion du pool en lecture seule, autoriseur, budget interactif de
//! l'ordonnanceur) — pour les seules règles qui tirent, et le verdict est écrit sur l'alerte à sa levée
//! (`alert.evidence`, v126, un objet JSON). Aucun nom de règle n'est lu ici.
//!
//! CE QUI EST DIT, TOUJOURS : l'instant (`at`, celui de la levée de l'alerte) et la fenêtre ; puis l'une de trois
//! issues, chacune avec sa phrase :
//!   * `established` — les lignes, dans l'ordre de la requête, coupées à `BORNE_DES_PREUVES_D_ALERTE` ; la coupe est
//!     un fait dit (`total` lu, `served`, `truncated`, `total_exact` faux si le plafond de lecture a coupé avant) ;
//!   * `no_rows` — la lecture a réussi et n'a rien rendu (l'activité a cessé entre l'évaluation et cette lecture) ;
//!   * `not_established` — la lecture a échoué : une cause de l'ensemble fermé `CAUSES_D_ABANDON`
//!     (`detection_aveugle`), jamais le texte du moteur ni la requête. L'alerte est levée quand même.
//!
//! LES PREUVES SONT UN FAIT DATÉ : écrites par l'`INSERT` qui lève l'alerte, jamais par le rafraîchissement d'un
//! épisode ouvert (`run_due_rules`) ; la phrase servie le dit.
use serde_json::{json, Value};

/// Le nombre de lignes de preuves écrites sur une alerte (et donc servies avec elle). Au-delà, la coupe est dite.
pub(crate) const BORNE_DES_PREUVES_D_ALERTE: usize = 50;

/// Les états servis sous `evidence.state`. Les trois premiers sont écrits à la levée ; les deux derniers ne sont posés
/// qu'au service (`alerts.rs`).
pub(crate) const ETAT_PREUVES_ETABLIES: &str = "established";
pub(crate) const ETAT_PREUVES_SANS_LIGNE: &str = "no_rows";
pub(crate) const ETAT_PREUVES_NON_ETABLIES: &str = "not_established";
pub(crate) const ETAT_PREUVES_RETENUES: &str = "withheld";
pub(crate) const ETAT_PREUVES_ILLISIBLES: &str = "unreadable";

pub(crate) const PHRASE_PREUVES_ETABLIES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la \
fenêtre de la règle : toutes les lignes lues sont servies. Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_COUPEES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la \
fenêtre de la règle, COUPÉES : served lignes servies sur total lues (total_exact faux : au moins autant, le plafond de \
lecture a coupé avant). Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_SANS_LIGNE: &str = "Aucune ligne de preuve à l'instant où l'alerte a été levée (at) : \
la lecture a réussi et n'a rien rendu, l'activité comptée par la règle a cessé entre son évaluation et cette lecture. \
Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_NON_ETABLIES: &str = "Preuves NON ÉTABLIES : leur lecture a échoué à l'instant où \
l'alerte a été levée (at), pour la cause dite. L'alerte est levée quand même. Fait daté : elles ne sont pas réécrites \
aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_RETENUES: &str = "Preuves retenues : un filtre de champs est actif pour votre rôle, et \
les preuves, lues sans masque par l'ordonnanceur, ne peuvent pas être masquées après coup.";
pub(crate) const PHRASE_PREUVES_ILLISIBLES: &str = "Preuves écrites sur l'alerte mais illisibles en base : rien n'en \
est servi.";

/// L'issue de la lecture des preuves.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Preuves {
    /// Au moins une ligne. `lignes` = TOUTES les lignes lues (bornées par le plafond de lecture) ; la borne des preuves
    /// est appliquée à l'écriture (`en_json`). `total_exact` faux : le plafond de lecture a coupé avant la fin.
    Etablies { colonnes: Vec<Value>, lignes: Vec<Value>, total_exact: bool },
    /// La lecture a réussi, zéro ligne.
    SansLigne { colonnes: Vec<Value> },
    /// La lecture a échoué : une cause de `detection_aveugle::CAUSES_D_ABANDON`.
    NonEtablies { cause: &'static str },
}

/// Les preuves d'une alerte, datées : l'instant de la levée et la fenêtre de la règle.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PreuvesDatees {
    pub(crate) instant: i64,
    pub(crate) window_s: i64,
    pub(crate) preuves: Preuves,
}

impl PreuvesDatees {
    /// La cause, quand les preuves ne sont pas établies (pour la ligne de journal de la levée).
    pub(crate) fn cause_non_etablie(&self) -> Option<&'static str> {
        match self.preuves {
            Preuves::NonEtablies { cause } => Some(cause),
            Preuves::Etablies { .. } | Preuves::SansLigne { .. } => None,
        }
    }

    /// L'objet écrit dans `alert.evidence` et servi tel quel sous la clé `evidence` de `/api/alerts`.
    pub(crate) fn en_json(&self) -> Value {
        let from = if self.window_s > 0 { self.instant - self.window_s } else { 0 };
        match &self.preuves {
            Preuves::Etablies { colonnes, lignes, total_exact } => {
                let total = lignes.len();
                let servies = total.min(BORNE_DES_PREUVES_D_ALERTE);
                let coupees = servies < total || !total_exact;
                json!({
                    "state": ETAT_PREUVES_ETABLIES,
                    "phrase": if coupees { PHRASE_PREUVES_COUPEES } else { PHRASE_PREUVES_ETABLIES },
                    "at": self.instant, "from": from, "window_s": self.window_s,
                    "columns": colonnes, "rows": &lignes[..servies],
                    "total": total, "total_exact": total_exact, "served": servies, "truncated": coupees,
                })
            }
            Preuves::SansLigne { colonnes } => json!({
                "state": ETAT_PREUVES_SANS_LIGNE,
                "phrase": PHRASE_PREUVES_SANS_LIGNE,
                "at": self.instant, "from": from, "window_s": self.window_s,
                "columns": colonnes, "rows": [],
                "total": 0, "total_exact": true, "served": 0, "truncated": false,
            }),
            Preuves::NonEtablies { cause } => json!({
                "state": ETAT_PREUVES_NON_ETABLIES,
                "phrase": PHRASE_PREUVES_NON_ETABLIES,
                "at": self.instant, "from": from, "window_s": self.window_s,
                "cause": cause,
            }),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Le nombre de lectures de preuves faites sur ce fil (l'ordonnanceur les fait sur le sien, en séquence).
    pub(crate) static LECTURES_DE_PREUVES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// LIT LES PREUVES d'une règle qui tire, à l'instant `instant` (celui de la levée), par le chemin de la règle : même
/// compilation (`rule_sql_a_l_instant`), même porte de lecture et même budget que son évaluation (`run_query_ex`,
/// budget interactif). Ne rend jamais d'erreur : un échec est une issue (`NonEtablies`, cause fermée).
pub(crate) fn lire_les_preuves(db_path: &str, requete: &str, is_soql: bool, window_s: i64, instant: i64) -> PreuvesDatees {
    #[cfg(test)]
    LECTURES_DE_PREUVES.with(|n| n.set(n.get() + 1));
    let preuves = match crate::handlers::detection::rule_sql_a_l_instant(requete, is_soql, window_s, instant) {
        Err(_) => Preuves::NonEtablies { cause: crate::detection_aveugle::CAUSE_COMPILATION_REFUSEE },
        Ok(sql) => match crate::run_query_ex(db_path, &sql, crate::query_budget_interactive_ms(), None) {
            Err(e) => Preuves::NonEtablies { cause: crate::detection_aveugle::AbandonDEvaluation::erreur_de_requete(&e).cause },
            Ok(v) => {
                let colonnes = v.get("columns").and_then(Value::as_array).cloned().unwrap_or_default();
                let lignes = v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
                // `run_query_ex` pose toujours `stats.truncated` ; tout autre état que `false` est dit « au moins ».
                let total_exact = v.pointer("/stats/truncated") == Some(&Value::Bool(false));
                if lignes.is_empty() {
                    Preuves::SansLigne { colonnes }
                } else {
                    Preuves::Etablies { colonnes, lignes, total_exact }
                }
            }
        },
    };
    PreuvesDatees { instant, window_s, preuves }
}

/// CE QUE `/api/alerts` SERT D'UNE COLONNE `alert.evidence` NON NULLE : l'objet écrit à la levée, ou, s'il ne se relit
/// pas, l'état `unreadable` (jamais le texte en base).
pub(crate) fn preuves_servies(ecrites: &str) -> Value {
    match serde_json::from_str::<Value>(ecrites) {
        Ok(v) if v.is_object() => v,
        Ok(_) | Err(_) => json!({ "state": ETAT_PREUVES_ILLISIBLES, "phrase": PHRASE_PREUVES_ILLISIBLES }),
    }
}

/// CE QUE `/api/alerts` SERT À LA PLACE DES PREUVES quand un filtre de champs est actif pour l'appelant.
pub(crate) fn preuves_retenues() -> Value {
    json!({ "state": ETAT_PREUVES_RETENUES, "phrase": PHRASE_PREUVES_RETENUES })
}
