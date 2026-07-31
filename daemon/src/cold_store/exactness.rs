//! cold_store::exactness — L'INVARIANT DE CORRECTION DU TIER FROID, RENDU NON REPRÉSENTABLE.
//!
//! LE DÉFAUT QU'IL FERME. Le chemin d'union hot∪cold (`reader::open_cold_union`) hydrate le froid
//! dans SQLite BORNÉ à `cold_hydrate_row_cap` (= `PLUME_QUERY_MAX`, défaut 5 000) puis exécute le SQL
//! compilé SUR CET ÉCHANTILLON. Mesuré (banc du 31/07, même requête, même fenêtre, même binaire) :
//!
//!     sans tier froid : search source=auditd severity>=2 | stats count -> 58 747
//!     avec tier froid : la MÊME requête                              ->    289
//!
//! Un drapeau `truncated` accompagnait le nombre. Ça ne suffit pas : un drapeau à côté d'un nombre
//! faux laisse le nombre lisible, copiable, traçable dans un graphe. Ce n'était pas un plantage —
//! c'était une PERTE D'HISTORIQUE SILENCIEUSE.
//!
//! LA DISTINCTION QUI FONDE LA CORRECTION.
//!   • Tronquer une MATÉRIALISATION est LÉGITIME. L'utilisateur demande des lignes ; il en reçoit
//!     une partie ; chaque ligne rendue est un ÉVÉNEMENT VRAI ; `truncated` dit qu'il en manque.
//!     Rien à réparer.
//!   • Tronquer un AGRÉGAT est un RÉSULTAT FAUX. À « combien ? », une valeur calculée sur un
//!     échantillon n'est pas une réponse partielle : c'est un MAUVAIS NOMBRE. Il n'existe aucune
//!     façon honnête de le rendre.
//!
//! L'INVARIANT : **aucune valeur dérivée d'un ensemble tronqué ne doit JAMAIS être rendue comme un
//! nombre.**
//!
//! POURQUOI NON REPRÉSENTABLE PLUTÔT QU'ÉNUMÉRÉ. La forme naïve — `if truncated { … }` à chaque site
//! d'agrégat — se réfute toute seule : le prochain agrégat ajouté n'aura pas le `if`, et personne ne
//! le remarquera (c'est la leçon la plus chère de ce projet). Ici :
//!   1. `ColdAnswer::Truncated` SÉQUESTRE son `Value` : il n'y a AUCUN accesseur qui rende un
//!      `Value` sérialisable sans passer par `render`.
//!   2. `render` EXIGE une `AnswerShape`.
//!   3. Une `AnswerShape` n'a AUCUN constructeur public : elle ne s'obtient que par DÉRIVATION
//!      depuis la requête (`AnswerShape::of_gxql`) ou par l'aveu qu'on ne peut rien dériver
//!      (`AnswerShape::undecidable`, qui vaut REFUS). Un site d'appel ne peut donc pas AFFIRMER
//!      « ma requête ne dérive rien » : il ne peut que le faire ÉTABLIR.
//!   4. La dérivation est DÉFAUT-REFUS : tout étage de pipeline hors de la liste des étages
//!      PAR-ÉVÉNEMENT — y compris un étage AJOUTÉ DEMAIN, y compris un agrégat qui n'existe pas
//!      encore — est `SetDerived`. Un futur `| stats p95(latence)` est couvert sans être nommé ici.
//!
//! Conséquence : le seul moyen de rendre un agrégat tronqué serait d'ajouter un étage à
//! `PER_EVENT_STAGES` — c'est-à-dire d'AFFIRMER qu'il est par-événement, dans le fichier qui porte
//! l'invariant, sous les yeux du test qui l'exerce.

use super::*;

// ====================================================================================================
// LA FORME D'UNE RÉPONSE — DÉRIVÉE de la requête, jamais déclarée par le site d'appel.
// ====================================================================================================

/// Étages de pipeline GXQL dont CHAQUE ligne de sortie est fonction d'UN SEUL événement d'entrée,
/// plus les étages purement POSITIONNELS (`head`/`limit`). Sur un ensemble tronqué, un tel résultat
/// ne contient que des événements VRAIS : il est INCOMPLET (ce que `truncated` dit), jamais FAUX.
///
/// CE QUI N'Y EST PAS, ET POURQUOI — chaque exclusion est une valeur qui dépend des AUTRES lignes :
///   `stats`/`timechart`/`top`/`rare`  agrègent (count/sum/avg/dc/min/max/…) ;
///   `eventstats`/`rate`               ajoutent une COLONNE calculée sur l'ensemble ;
///   `dedup`                           choisit un représentant EN FONCTION des autres lignes ;
///   `join`/`append`/`lookup`          introduisent des lignes étrangères ;
///   `sort`                            ne fabrique aucune valeur, mais son « les N premiers » porte
///                                     sur l'ensemble : sur un préfixe, l'extremum affiché n'est pas
///                                     l'extremum. Exclu — c'est un classement, donc une dérivation.
/// Et surtout : TOUT LE RESTE, connu ou non. La liste est la SEULE porte d'entrée.
const PER_EVENT_STAGES: &[&str] = &["where", "head", "limit", "eval", "rex", "rename", "table", "fields"];

/// Ce qu'une réponse peut PROMETTRE vis-à-vis de l'ensemble sur lequel elle a été calculée.
/// Volontairement PRIVÉ : voir `AnswerShape`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// Chaque ligne rendue EST un événement d'entrée (projeté/filtré/limité).
    PerEvent,
    /// Au moins une valeur rendue est calculée SUR L'ENSEMBLE.
    SetDerived,
}

/// La forme d'une réponse. **Aucun constructeur littéral** : les variantes sont privées, donc un
/// appelant ne peut pas écrire `AnswerShape::PerEvent`. Il ne dispose que de `of_gxql` (dérivation)
/// et de `undecidable` (aveu d'ignorance = refus). C'est CE point qui rend l'invariant non
/// représentable plutôt que discipliné.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct AnswerShape(Shape);

impl AnswerShape {
    /// DÉRIVE la forme d'une requête GXQL. DÉFAUT = REFUS : un seul étage hors de
    /// `PER_EVENT_STAGES` — inconnu compris — suffit à rendre la réponse `SetDerived`.
    /// Un `|` à l'intérieur d'une valeur citée peut produire un FAUX `SetDerived` : c'est le
    /// côté SÛR (au pire un refus de trop, jamais un nombre faux de trop).
    pub(crate) fn of_gxql(soql: &str) -> Self {
        for stage in soql.split('|').skip(1) {
            let cmd = stage.trim().split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if cmd.is_empty() {
                continue; // pipe terminal / étage vide
            }
            if !PER_EVENT_STAGES.contains(&cmd.as_str()) {
                return Self(Shape::SetDerived);
            }
        }
        Self(Shape::PerEvent)
    }

    /// AVEU : on ne peut RIEN dériver de cette requête (SQL brut admin, forme non analysable).
    /// Vaut REFUS — on ne rend pas un nombre dont on ne sait pas s'il est dérivé.
    pub(crate) fn undecidable() -> Self {
        Self(Shape::SetDerived)
    }

    /// La réponse est-elle par-événement ? (Lecture seule : observer ne fabrique rien.)
    pub(crate) fn is_per_event(self) -> bool {
        self.0 == Shape::PerEvent
    }
}

// ====================================================================================================
// LA RÉPONSE — le `Value` d'un ensemble TRONQUÉ est séquestré derrière `render`.
// ====================================================================================================

/// REFUS motivé : la requête dérive une valeur d'un ensemble qui a été tronqué. Porte de quoi
/// NOMMER la cause et PROPOSER la voie exacte — une erreur qui ne dit pas quoi faire est un mur.
#[derive(Debug)]
pub(crate) struct TruncatedAggregate {
    pub(crate) rows_hydrated: usize,
    pub(crate) cap: usize,
}

impl TruncatedAggregate {
    /// Message rendu au client. Il NOMME la cause (le plafond et sa variable), et il propose les
    /// DEUX voies exactes — celles que le produit sait réellement servir.
    pub(crate) fn message(&self) -> String {
        format!(
            "refus de rendre un nombre FAUX : cette requête calcule une valeur (count/sum/dc/stats … by …) \
             sur l'historique froid, mais la lecture froide a dû s'arrêter à {} lignes (plafond RAM \
             PLUME_QUERY_MAX={}) — la valeur porterait sur cet échantillon, pas sur la fenêtre demandée. \
             Voies EXACTES : restreindre la fenêtre sous le plafond, ou poser la question sous une forme \
             que le moteur colonnaire agrège côté froid (« search <filtres> | stats count [by <colonnes \
             réelles>] », colonnes réelles = ts/severity/source/category/host/src_ip/dst_ip/url/xff/message).",
            self.rows_hydrated, self.cap
        )
    }
}

/// Réponse issue d'une lecture qui A PU tronquer son ensemble source.
///
/// `#[must_use]` : une `ColdAnswer` ignorée serait une réponse jetée en silence.
#[must_use]
pub(crate) enum ColdAnswer {
    /// L'ensemble a été lu INTÉGRALEMENT -> la valeur est exacte, quelle que soit la requête.
    Exact { value: Value, total: Option<i64> },
    /// L'ensemble a été TRONQUÉ. Le `Value` est SÉQUESTRÉ : `render` est le seul chemin de sortie.
    Truncated { value: Value, rows_hydrated: usize, cap: usize },
}

/// Ce qu'un handler a le droit de sérialiser.
pub(crate) struct Rendered {
    pub(crate) value: Value,
    /// Total de pagination. `None` sur un ensemble tronqué : un `COUNT(*)` de pagination est
    /// TOUJOURS une valeur dérivée de l'ensemble — sur un ensemble tronqué il est FAUX, donc il
    /// n'est pas rendu (le client pagine alors sans numéros, comme pour tout total best-effort).
    pub(crate) total: Option<i64>,
    /// L'ensemble source était incomplet (vrai UNIQUEMENT pour une réponse par-événement — une
    /// réponse dérivée tronquée n'arrive jamais jusqu'ici, elle est refusée).
    pub(crate) truncated: bool,
}

impl ColdAnswer {
    /// Construit la réponse à partir du drapeau de couverture du lecteur. C'est le SEUL point où un
    /// `truncated` booléen se transforme en type : après lui, l'incomplétude n'est plus une donnée
    /// qu'on peut oublier de regarder, c'est une variante qu'il faut traiter.
    pub(crate) fn new(value: Value, total: Option<i64>, truncated: bool, cap: usize, rows_hydrated: usize) -> Self {
        if truncated {
            ColdAnswer::Truncated { value, rows_hydrated, cap }
        } else {
            ColdAnswer::Exact { value, total }
        }
    }

    /// SORTIE UNIQUE vers la sérialisation. Rend `Err` — donc une erreur NOMMÉE au client — dès
    /// qu'une valeur dérivée reposerait sur un ensemble tronqué. Une erreur vaut mieux qu'un nombre
    /// faux : c'est la position de repli, pas l'échec.
    pub(crate) fn render(self, shape: AnswerShape) -> Result<Rendered, TruncatedAggregate> {
        match self {
            ColdAnswer::Exact { value, total } => Ok(Rendered { value, total, truncated: false }),
            ColdAnswer::Truncated { value, rows_hydrated, cap } => {
                if shape.is_per_event() {
                    // Lignes VRAIES, en nombre incomplet -> réponse partielle honnête. Le total de
                    // pagination, lui, reste écarté (c'est un COUNT, donc dérivé).
                    Ok(Rendered { value, total: None, truncated: true })
                } else {
                    Err(TruncatedAggregate { rows_hydrated, cap })
                }
            }
        }
    }

    /// Réponse d'un chemin STRUCTURELLEMENT exact (aucune hydratation froide n'a eu lieu : la
    /// fenêtre passée au lecteur est vide côté froid). Un `Truncated` ici serait un BUG du chemin
    /// appelant, pas une requête trop large -> `Err` fail-closed, jamais une valeur.
    pub(crate) fn expect_exact(self, what: &str) -> Result<(Value, Option<i64>), String> {
        match self {
            ColdAnswer::Exact { value, total } => Ok((value, total)),
            ColdAnswer::Truncated { rows_hydrated, .. } => Err(format!(
                "{what}: troncature INATTENDUE sur un chemin sans hydratation froide ({rows_hydrated} lignes) — \
                 refus de rendre un résultat dont la complétude n'est pas prouvée"
            )),
        }
    }

    /// TEST SEULEMENT — expose la valeur SÉQUESTRÉE, pour que le harnais puisse PROUVER qu'elle est
    /// fausse (c'est ainsi qu'on mesure le ×203) et pour que les tests P3, qui portent sur le SQL
    /// EXÉCUTÉ (masquage, authorizer, union) et non sur la correction, restent lisibles. Aucun chemin
    /// de production ne l'appelle : le nom dit ce qu'il vaut. Le `total` d'un ensemble tronqué est
    /// rendu `None` ici comme en production — il n'est même pas conservé.
    #[cfg(test)]
    pub(super) fn into_value_even_if_wrong(self) -> (Value, Option<i64>) {
        match self {
            ColdAnswer::Exact { value, total } => (value, total),
            ColdAnswer::Truncated { value, .. } => (value, None),
        }
    }

    #[cfg(test)]
    pub(super) fn is_truncated(&self) -> bool {
        matches!(self, ColdAnswer::Truncated { .. })
    }
}
