//! liste_bornee — L'AVEU D'UNE LISTE BORNÉE, ÉCRIT UNE SEULE FOIS (`P11.22-f`).
//!
//! LE DÉFAUT QUE CE MODULE REND NON-ÉCRIVABLE. Une route qui sert au plus `N` lignes d'un registre
//! qui en porte davantage rend, sans un mot, un corps IDENTIQUE à celui d'un registre qui n'en porte
//! que `N`. L'exploitant qui n'y trouve pas ce qu'il cherche conclut que ça n'existe pas. La forme
//! honnête — `served` / `window` / `total` / `total_capped`, le total MESURÉ par un comptage borné et
//! rendu `null` (jamais `0`) quand il n'a pas pu être lu — existait déjà. Elle existait QUATRE FOIS,
//! recopiée dans `actions.rs`, `engagement.rs`, `rba.rs` et `threat_intel.rs`.
//!
//! POURQUOI UN FABRICANT ET PAS UNE CINQUIÈME COPIE. Le recensement du 2026-08-30 (`P11.22-e`) a
//! trouvé une VINGTAINE de listes bornées muettes. Fermer la vingt-et-unième en recopiant la forme
//! une cinquième fois, c'est convertir un défaut de silence en un défaut de divergence : cinq
//! écritures d'une même règle vieillissent séparément, et la première qui change laisse les autres
//! derrière. C'est exactement le raisonnement de `handlers::portillon` (l'aveu du portillon de
//! concurrence, écrit une fois pour onze routes), et la même forme est reprise ici : un module
//! minuscule, aucun ré-export à la racine, un appel par chemin explicite.
//!
//! CE QUE LE TYPE INTERDIT D'ÉCRIRE, ET C'EST LÀ QUE VIT LA GARANTIE :
//!   1. `TotalBorne` n'a **aucun constructeur littéral** de plafonnement. On l'obtient par
//!      `depuis_un_comptage_borne` (une lecture SQL arrêtée à `plafond + 1`) ou par
//!      `depuis_un_recensement_borne` (une passe de lignes arrêtée au même endroit). Le plafonnement
//!      est donc TOUJOURS dérivé de l'existence d'une ligne EXCÉDENTAIRE, jamais déduit de la
//!      longueur de ce qui est servi : une base qui porte PILE la borne n'est pas écourtée, et le lui
//!      faire dire serait un aveu inconditionnel, donc sans valeur.
//!   2. `Lignes` sépare `Lues` de `Illisible`. Une lecture ratée ne peut plus entrer ici sous la
//!      forme d'un vecteur vide — c'est-à-dire sous la forme d'un fait établi. C'est la TROISIÈME
//!      distinction, celle que `SourcesConnues` (`P11.22-e`) déclare ne pas tenir : « bornée » vs
//!      « complète » y est séparé, « vide » vs « illisible » ne l'est pas.
//!
//! CE QUE LA TROISIÈME DISTINCTION COÛTE, MESURÉ PLUTÔT QU'ESTIMÉ :
//!   * à l'exécution : RIEN. `Lignes` est consommé par valeur, il n'y a ni allocation ni lecture de
//!     plus. Le corps servi est BYTE-IDENTIQUE dans les deux cas où il l'était déjà — liste complète
//!     ou tranche légitimement VIDE.
//!   * sur le fil : UNE clé, `error`, et SEULEMENT quand la lecture a échoué. Strictement additive :
//!     aucune clé existante ne change de nom, de type ni de valeur. C'est la clé que `portillon`,
//!     `bad_req` et `server_err` posent déjà, donc celle que les consommateurs testent DÉJÀ.
//!   * chez l'appelant : quatre sites cessaient d'avoir le droit d'écrire `unwrap_or_default()` sur
//!     leur lecture de lignes. C'est la seule dépense, et elle est de trois lignes par site.
//!
//! CE QUE CE MODULE NE TIENT PAS, DIT PLUTÔT QUE SOUS-ENTENDU :
//!   * il ne tient pas la ligne INDIVIDUELLE. `query_map(..).flatten()` laisse tomber une ligne dont
//!     le mappeur échoue, en silence, et ce module conserve ce comportement (l'alternative — perdre
//!     la liste entière pour une ligne — échangerait une troncature contre une indisponibilité).
//!     Une liste amputée d'une ligne se déclare donc toujours `Lues`. C'est une autre famille.
//!   * il ne tient pas ce que la CONSOLE affiche. Le démon avoue ; un module de `web/` qui ne lit ni
//!     `total_capped` ni `error` continuera de montrer une table muette.
//!   * il ne tient pas les listes qu'il ne sert pas : les lots de fond (relances, notifications,
//!     forwards) sont bornés eux aussi, mais leur borne se draine par répétition — elle n'est pas une
//!     troncature présentée à un lecteur.
use crate::*;

/// CE QU'UN COMPTAGE BORNÉ A RENDU. Deux états, et le premier ne se construit qu'à partir d'une
/// lecture réellement arrêtée à `plafond + 1`.
pub(crate) enum TotalBorne {
    /// `brut` = `min(vrai_total, plafond + 1)`, tel qu'une lecture bornée l'a rendu.
    Lu { brut: i64, plafond: i64 },
    /// La lecture n'a pas abouti. « Non compté » et « aucun » sont deux faits différents.
    Illisible,
}

impl TotalBorne {
    /// DEPUIS UN COMPTAGE SQL BORNÉ (`sql_du_comptage_borne`). Une erreur de lecture rend `Illisible`,
    /// jamais un zéro rassurant.
    pub(crate) fn depuis_un_comptage_borne(lu: Result<i64, rusqlite::Error>, plafond: i64) -> Self {
        match lu {
            Ok(brut) => TotalBorne::Lu { brut, plafond },
            Err(_) => TotalBorne::Illisible,
        }
    }

    /// DEPUIS UNE PASSE DE LIGNES BORNÉE au même endroit. Nécessaire parce qu'une route peut avoir
    /// besoin de DEUX chiffres d'une seule passe (le total ET un compte sous prédicat) : refaire un
    /// `COUNT` à côté relirait les mêmes pages. `lignes_vues` doit être le nombre de lignes rendues
    /// par un énoncé portant `LIMIT plafond + 1` — c'est la même ligne excédentaire qui fonde l'aveu.
    pub(crate) fn depuis_un_recensement_borne(lignes_vues: i64, plafond: i64) -> Self {
        TotalBorne::Lu { brut: lignes_vues, plafond }
    }

    /// AVEU : aucune passe n'a pu être faite (base indisponible, prédicat illisible).
    pub(crate) fn sans_lecture() -> Self {
        TotalBorne::Illisible
    }


    /// LE COUPLE SERVI : `(total, total_capped)`. `(null, null)` quand rien n'a été lu — jamais
    /// `(0, false)`, qui se lirait « registre vide, et c'est établi ».
    pub(crate) fn en_json(&self) -> (Value, Value) {
        match self {
            TotalBorne::Lu { brut, plafond } => {
                let capped = brut > plafond;
                (json!(if capped { *plafond } else { *brut }), json!(capped))
            }
            TotalBorne::Illisible => (Value::Null, Value::Null),
        }
    }
}

/// LES LIGNES SERVIES, TELLES QU'ELLES ONT ÉTÉ OBTENUES. `Illisible` n'est pas `Lues(vec![])` : le
/// second est un FAIT (le registre ne porte rien), le premier est un aveu (on n'a rien pu voir).
pub(crate) enum Lignes {
    Lues(Vec<Value>),
    Illisible,
}

/// LA CAUSE, ÉCRITE UNE FOIS. Elle dit ce qui n'a pas eu lieu ET ce que le corps n'établit PAS —
/// sans la seconde moitié, un lecteur pressé relit la liste vide comme avant.
pub(crate) const CAUSE_LISTE_ILLISIBLE: &str = "liste NON LUE : la lecture de cette liste a échoué. \
     Ce corps n'en porte aucune ligne parce qu'AUCUNE n'a été lue — ce n'est pas une absence établie.";

/// LE SEUL FABRICANT DU SQL D'UN COMPTAGE BORNÉ. `SELECT 1` ne demande aucune colonne et
/// `LIMIT plafond + 1` ARRÊTE le balayage juste au-dessus du plafond : sous le plafond le total est
/// EXACT, au-dessus il est plafonné ET la ligne excédentaire — jamais servie — le PROUVE.
/// `depuis_et_filtre` porte la table et, s'il y en a un, son `WHERE` (p. ex. `"ledger WHERE ts>=?1"`).
pub(crate) fn sql_du_comptage_borne(depuis_et_filtre: &str) -> String {
    format!(
        "SELECT COUNT(*) FROM (SELECT 1 FROM {depuis_et_filtre} LIMIT {})",
        borne_avec_ligne_excedentaire(PAGINATION_COUNT_CAP)
    )
}

/// LA BORNE D'UNE LECTURE QUI VEUT POUVOIR AVOUER : `plafond + 1`, la ligne EXCÉDENTAIRE comprise.
/// Le `+ 1` n'est écrit QU'ICI : c'est lui qui sépare « le registre porte pile la borne » (rien à
/// avouer) de « il en portait davantage » (aveu fondé). Un site qui l'oublierait rendrait un aveu
/// INCONDITIONNEL — le défaut exactement symétrique de celui que ce module ferme.
pub(crate) fn borne_avec_ligne_excedentaire(plafond: i64) -> i64 {
    plafond + 1
}

/// LIT une liste bornée. Une préparation ou une exécution qui échoue rend `Illisible` — jamais un
/// vecteur vide, qui se lirait « aucune ligne ». Les lignes dont le mappeur échoue sont écartées
/// (cf. l'en-tête : ce module ne tient pas la ligne individuelle).
pub(crate) fn lire<F>(conn: &Connection, sql: &str, mappeur: F) -> Lignes
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
{
    match conn.prepare(sql) {
        Ok(mut stmt) => match stmt.query_map([], mappeur) {
            Ok(rows) => Lignes::Lues(rows.flatten().collect()),
            Err(_) => Lignes::Illisible,
        },
        Err(_) => Lignes::Illisible,
    }
}

/// LE CORPS D'UNE LISTE BORNÉE, ÉCRIT UNE FOIS POUR TOUTES.
///
/// `cle` est le nom sous lequel la route sert ses lignes (`"iocs"`, `"actions"`, …) ; `borne` est la
/// borne de la route, RENDUE pour que la vue la reçoive au lieu de la deviner. `served` et `window`
/// dits ensemble sont ce qui apprend au lecteur que la borne MORD : leur égalité est le signal.
///
/// Une lecture `Illisible` conserve la FORME (la clé de liste existe, vide) et y ajoute `error` : un
/// client qui lit `j.<cle>.length` continue de fonctionner, et celui qui teste `error` apprend que
/// ce vide n'est pas un fait. Une liste `Lues` — fût-elle vide — n'ajoute RIEN.
pub(crate) fn corps(cle: &str, lignes: Lignes, borne: i64, total: TotalBorne) -> Value {
    let (total_json, capped_json) = total.en_json();
    let (rows, illisible) = match lignes {
        Lignes::Lues(v) => (v, false),
        Lignes::Illisible => (Vec::new(), true),
    };
    let servies = rows.len();
    let mut sortie = serde_json::Map::new();
    sortie.insert(cle.to_string(), Value::Array(rows));
    sortie.insert(String::from("served"), json!(servies));
    sortie.insert(String::from("window"), json!(borne));
    sortie.insert(String::from("total"), total_json);
    sortie.insert(String::from("total_capped"), capped_json);
    if illisible {
        sortie.insert(String::from("error"), json!(CAUSE_LISTE_ILLISIBLE));
    }
    Value::Object(sortie)
}

/// LA COUPE D'UNE SOUS-LISTE, MESURÉE PAR SA LIGNE EXCÉDENTAIRE. L'appelant lit `borne + 1` lignes ;
/// on en rend `borne`, et l'EXISTENCE de la ligne de trop — jamais servie — fonde l'aveu. Une base
/// qui porte PILE la borne rend `false` : l'aveu est mesuré, jamais déduit d'une longueur.
///
/// Sert les listes qui vivent DANS un corps plus grand, là où `corps` ne s'applique pas parce que la
/// réponse porte plusieurs listes à la fois.
pub(crate) fn couper_a_la_borne(mut lues: Vec<Value>, borne: usize) -> (Vec<Value>, bool) {
    let ecourtee = lues.len() > borne;
    lues.truncate(borne);
    (lues, ecourtee)
}
