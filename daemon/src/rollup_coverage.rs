//! rollup_coverage — CE QUE LE ROLLUP COUVRE, RENDU NON DÉCLARABLE PAR UN SITE D'APPEL.
//!
//! LE DÉFAUT QU'IL FERME. La route de rollups sert un `stats count by source,severity` depuis un
//! CORPS lu dans `event_rollup` et deux PARTIELS lus en brut dans `event`. Le corps n'est juste que
//! si `event_rollup` est une IMAGE d'`event` sur la plage servie. Jusqu'ici la route dérivait ce
//! droit du seul watermark `event_rollup_wm` — or ce watermark ne dit PAS ça. Il dit « le job est
//! passé par là », pas « le job a agrégé tout ce qu'`event` porte là ». Les deux divergent dès
//! qu'une ligne est écrite SOUS le watermark après son passage : import d'historique, agent qui
//! rattrape un tampon hors-ligne, relais syslog en retard, source horodatée en décalé.
//! `rollup_events` avançait alors le watermark PAR-DESSUS ces lignes sans jamais y revenir : le trou
//! n'était pas un retard, il était DÉFINITIF.
//!
//! MESURÉ (2026-07-31, base de banc de 1 440 007 événements, binaire du dépôt, fenêtre `au-dela-7d`
//! = [end_ts-28j, end_ts-7j]) :
//!
//!     search | stats count by source,severity  -> 164 165   (`approx:false`, `served_from:rollup`)
//!     search | stats count            (brut)   -> 1 080 321
//!     SUM(n) sur event_rollup, mêmes buckets   ->   162 456
//!
//! soit un SOUS-COMPTE de ×6,6 présenté comme EXACT. Et il ne se rattrape pas : sur 15 minutes et
//! 7 ticks de la boucle de rollups, le watermark a sauté de 1785412800 à 1785510000 — donc PAR-DESSUS
//! toute la fenêtre — pendant que `SUM(n)` restait à 162 456, à l'unité près. Ce n'était pas de la
//! fraîcheur : c'était une couverture SUPPOSÉE.
//!
//! VÉRIFIÉ APRÈS CORRECTIF, même base, même machine, binaire de ce commit (2026-07-31) :
//!   avant le premier tick (couverture ABSENTE, l'état de toute base d'avant ce correctif) la route
//!   DÉCLINE -> `served_from:"raw"` -> 1 080 321, soit la vérité brute ;
//!   au premier tick la table est RÉPARÉE (`SUM(n)` sur ces buckets : 162 456 -> 1 082 346, l'écart
//!   avec 1 080 321 étant la sur-couverture horaire des bords, servie en brut par le merge) et la
//!   couverture est publiée (`event_rollup_cov_id=1440007`) ;
//!   ensuite la route REPREND -> `served_from:"rollup"` -> 1 080 321, identique au brut, 68 groupes
//!   des deux côtés (contre 59 avant). Pendant la réparation, la réponse reste JUSTE : la couverture
//!   est effacée AVANT que la table ne soit touchée (« rétracter d'abord, réparer ensuite »).
//!
//! L'INVARIANT (le même que `cold_store::exactness`, par un autre chemin) : **aucune valeur dérivée
//! d'un ensemble incomplet n'est rendue comme un nombre exact.** Ici l'ensemble incomplet n'est pas
//! un échantillon tronqué, c'est une table pré-agrégée en retard sur sa source ; le mensonge est le
//! même.
//!
//! POURQUOI UN TYPE PLUTÔT QU'UN `i64`. La route recevait la borne du corps sous forme d'entier nu.
//! Un entier nu s'invente : `handlers/dashboards.rs` passait `i64::MAX` — c'est-à-dire qu'un site
//! d'appel AFFIRMAIT que le rollup couvrait tout l'historique, sans rien pour l'établir, avec un
//! commentaire pour l'excuser. C'est exactement la forme qui se réfute toute seule : le prochain
//! appelant réécrira le même entier. Ici :
//!   1. la borne n'est accessible que par une `RollupCoverage` ;
//!   2. `RollupCoverage` n'a AUCUN constructeur littéral — ses variantes sont privées ;
//!   3. on ne l'obtient que par DÉRIVATION depuis la base (`of`, qui lit ce que le job a PUBLIÉ) ou
//!      par l'AVEU qu'on ne peut rien établir (`unproven`, qui vaut « aucun corps rollup ») ;
//!   4. la dérivation est DÉFAUT-REFUS : couverture absente, illisible, ou publiée à moitié ->
//!      `unproven` -> le corps s'effondre -> la route décline -> le chemin brut sert (exact).
//! Un appelant ne peut donc plus AFFIRMER une couverture ; il peut seulement la faire ÉTABLIR, ou
//! avouer qu'il n'en a pas. Le seul moyen de rendre un corps rollup exact est que `rollup_events`
//! ait réellement publié la couverture — dans la transaction où il a fini d'agréger.
//!
//! CE QUE LA COUVERTURE PORTE, ET POURQUOI DEUX FAITS ET NON UN. Une couverture établie dit :
//! « `event_rollup` est une image d'`event` pour `ts < below`, **des lignes `id <= at_id** ». Les
//! deux sont INSÉPARABLES (variante unique) parce que la borne temporelle seule est précisément
//! l'affirmation trop forte qui a causé le défaut : elle ne dit rien des lignes arrivées APRÈS. Le
//! `at_id` rend cet « après » ADRESSABLE — `event.id` est le rowid, donc monotone à l'insertion —
//! et la route s'en sert pour ajouter au MERGE un fragment brut qui rattrape exactement ces lignes.

use crate::*;

/// Clé `meta` du watermark d'agrégation : borne haute (exclusive) de la bande qu'`rollup_events` a
/// finie d'agréger. HISTORIQUE — elle existait déjà ; ce qui change est qu'elle ne vaut plus
/// couverture toute seule.
pub(crate) const META_ROLLUP_WM: &str = "event_rollup_wm";
/// Clé `meta` de la COUVERTURE : plus grand `event.id` que l'agrégation ayant établi `META_ROLLUP_WM`
/// a vu. Écrite ENSEMBLE avec elle, effacée ENSEMBLE avec elle. Son absence est ce qui rend
/// fail-closed toute base antérieure à ce correctif (dont le rollup peut être arbitrairement en
/// retard) : rien n'est établi -> rien n'est servi depuis le corps.
pub(crate) const META_ROLLUP_COV_ID: &str = "event_rollup_cov_id";

/// Ce que le job a PUBLIÉ. Volontairement privé : voir `RollupCoverage`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Coverage {
    /// `event_rollup` est une image d'`event` pour `ts < below`, des lignes `id <= at_id`.
    Established { below: i64, at_id: i64 },
    /// Rien n'est établi. Ce n'est pas « couverture nulle » : c'est « on ne sait pas », et ça vaut refus.
    Unproven,
}

/// La couverture du rollup. **Aucun constructeur littéral** : un appelant ne peut pas écrire
/// `RollupCoverage::Established { .. }`. Il ne dispose que de `of` (dérivation depuis la base) et de
/// `unproven` (aveu). C'est CE point qui rend l'invariant non représentable plutôt que discipliné.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RollupCoverage(Coverage);

impl RollupCoverage {
    /// DÉRIVE la couverture de la base : lit ce que `rollup_events` a publié. DÉFAUT = REFUS — il
    /// faut les DEUX faits (watermark ET borne d'identifiant) pour qu'une couverture existe ; l'un
    /// sans l'autre est une base d'avant ce correctif, un tick interrompu, ou une écriture partielle,
    /// et dans les trois cas on ne sait rien. Lecture indexée (PK `meta`), coût négligeable.
    pub(crate) fn of(conn: &Connection) -> Self {
        let read = |k: &str| -> Option<i64> {
            conn.query_row("SELECT value FROM meta WHERE key=?1", params![k], |r| r.get::<_, String>(0))
                .ok()
                .and_then(|s| s.parse().ok())
        };
        match (read(META_ROLLUP_WM), read(META_ROLLUP_COV_ID)) {
            (Some(below), Some(at_id)) => Self(Coverage::Established { below, at_id }),
            _ => Self::unproven(),
        }
    }

    /// AVEU : ce site d'appel ne peut RIEN établir (aucune connexion sous la main, fonction pure,
    /// table absente…). Vaut « aucun corps rollup » -> la route décline -> le chemin brut sert. C'est
    /// le SEUL constructeur qu'un appelant sans base puisse écrire, et il est du côté sûr.
    pub(crate) fn unproven() -> Self {
        Self(Coverage::Unproven)
    }

    /// Borne HAUTE (exclusive) sous laquelle le corps rollup peut être lu. `i64::MIN` quand rien
    /// n'est établi : le corps s'effondre (`body_hi <= body_lo`) et la route décline d'elle-même —
    /// aucune branche à ajouter, aucun `if` à oublier.
    pub(crate) fn covered_below(self) -> i64 {
        match self.0 {
            Coverage::Established { below, .. } => below,
            Coverage::Unproven => i64::MIN,
        }
    }

    /// Plus grand `event.id` couvert. Toute ligne `id >` celui-ci est POSTÉRIEURE à la couverture :
    /// elle n'est pas dans le corps rollup et doit être rattrapée en brut. `None` quand rien n'est
    /// établi (il n'y a alors pas de corps, donc rien à rattraper).
    pub(crate) fn late_floor_id(self) -> Option<i64> {
        match self.0 {
            Coverage::Established { at_id, .. } => Some(at_id),
            Coverage::Unproven => None,
        }
    }

    /// TEST SEULEMENT — fabrique une couverture ARBITRAIRE, pour exercer les plans de merge sans
    /// passer par un tick réel. Le nom dit ce qu'il vaut : `cfg(test)`, donc AUCUN chemin de
    /// production ne peut affirmer une couverture (miroir de `ColdAnswer::into_value_even_if_wrong`).
    #[cfg(test)]
    pub(crate) fn asserted_by_the_test(below: i64, at_id: i64) -> Self {
        Self(Coverage::Established { below, at_id })
    }
}
