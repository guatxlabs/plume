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

// =====================================================================================
// LE JUMEAU : `event_dim_rollup`. MÊME watermark, MÊME divergence — et un TROU EN PLUS.
// =====================================================================================
//
// CE QUI DIFFÈRE DE `event_rollup`, ET POURQUOI ÇA N'EST PAS LE MÊME DÉFAUT. La ROUTE B
// (`search source=X | stats count by <dim>`) s'est TOUJOURS déclarée `approx:true, truncated:true` :
// le cap top-N/(bucket,source,dim) abandonne délibérément la queue des valeurs. Elle ne MENT donc
// pas, et le correctif `RollupCoverage` (qui ferme un `approx:false` faux) ne s'y transpose pas tel
// quel. Ce qui est mesuré ci-dessous n'est pas un mensonge : c'est un ZÉRO.
//
// MESURÉ (2026-07-31, base de banc 1 440 007 événements sur 28 jours, binaire du dépôt, daemon
// laissé tourner jusqu'à ce que sa boucle de rollups tique) :
//
//     event                                          -> 1 440 007 lignes, ts sur 28 jours
//     event_rollup            SUM(n)                 -> 1 440 007   (réparé par `rollup_events`)
//     event_dim_rollup        SUM(n)                 ->    19 991   sur 36 couples (source,dim)
//     event_dim_rollup        buckets                -> [1785319200, 1785409200] = 25 HEURES
//     meta.event_dim_rollup_wm                       -> 1785520800  = « passé » sur les 28 jours
//
// et ce que la route en sert, contre l'oracle brut (même daemon, même instant, la même question
// posée de façon non routable) :
//
//     search source=k8s-log | stats count by ns      fenêtre 28 j : route  1 745  brut 271 456  (×155)
//     search source=ufw     | stats count by dport   fenêtre 28 j : route    329  brut  41 976  (×128)
//     search source=web     | stats count by status  fenêtre au-delà de 7 j : route 0  brut 5 696
//
// LE DERNIER EST LE CAS QUI TRANCHE. `0` n'est pas une approximation d'un compte : c'est la phrase
// « il ne s'est rien passé », et c'est exactement celle sur laquelle un analyste agit. Un drapeau
// `truncated` dit « des VALEURS peuvent manquer » ; il ne dit pas « cette bande de temps n'a JAMAIS
// été agrégée ». Rien, dans la réponse, ne permet de distinguer un vrai zéro d'un zéro de couverture.
//
// LA CAUSE, ET ELLE EST LA MÊME QU'EN HAUT. `event_dim_rollup_wm` disait « le job est passé par là ».
// Le job, lui, ne remontait JAMAIS plus loin que `PLUME_ROLLUP_DIM_BACKFILL` (24 h) sous l'heure
// courante, PUIS posait le watermark à l'heure courante — donc PAR-DESSUS tout ce qu'il n'avait pas
// agrégé. Trois trous, tous DÉFINITIFS et aucun rattrapé :
//   1. DÉMARRAGE À FROID (base restaurée, import d'historique, premier démarrage sur une base
//      remplie) : tout ce qui est plus vieux que 24 h n'est jamais agrégé. C'est le cas mesuré.
//   2. INDISPONIBILITÉ > 24 h : `max(watermark, heure-24h)` SAUTE la bande entre les deux.
//   3. ÉCRITURE RÉTRO-DATÉE sous le watermark (tampon d'agent hors-ligne, relais en retard) : jamais
//      ré-agrégée, exactement le défaut d'`event_rollup` corrigé plus haut.
// Le commentaire du job affirmait que « le reste se remplit en forward-fill au fil des ticks » : c'est
// FAUX, et sept ticks de la boucle sur la base de banc n'ont pas bougé les 19 991 d'un événement.
//
// LA RÉPARATION, EN UNE SEULE RÈGLE (et non trois rustines). Le job ne pose plus un watermark : il
// entretient une BANDE `[from, below)` dont il peut témoigner, et cette bande bouge par TROIS
// mouvements bornés, tous dérivés du même paramètre `PLUME_ROLLUP_DIM_BACKFILL` :
//   - elle MONTE  d'au plus `dim_backfill` par tick (donc elle ne SAUTE plus une indisponibilité) ;
//   - elle DESCEND d'au plus `dim_backfill` par tick jusqu'à `MIN(event.ts)` (donc un démarrage à
//     froid finit par tout couvrir, sans jamais le scan bloquant que le plafond de 24 h évitait) ;
//   - elle SE RÉTRACTE au bucket de la plus vieille ligne écrite SOUS elle depuis sa publication
//     (`id > at_id` — `event.id` est le rowid, monotone à l'insertion), et la remontée la reconstruit.
// Le coût par tick reste borné par construction : au plus deux tranches de `dim_backfill`.
//
// CE QUE LA ROUTE EN FAIT, ET CE QU'ELLE NE FAIT PAS. Elle ne se met pas à prétendre l'exactitude :
// `approx:true, truncated:true` sont INCHANGÉS (le cap top-N reste). Elle change sur deux points, et
// deux seulement : (1) elle ne lit QUE des buckets dont la couverture témoigne — donc plus jamais un
// `0` de couverture rendu comme un `0` de données ; (2) quand une partie de la fenêtre demandée n'est
// pas couverte, elle le DIT AVEC SES BORNES ET SA PROPORTION, au lieu du seul mot « approximatif ».
// Couverture non établie (toute base d'avant ce correctif) -> plus AUCUN bucket témoigné -> la route
// DÉCLINE -> le chemin brut sert, exact.

/// Clé `meta` de la COUVERTURE du rollup PAR DIMENSION : `"<from>|<below>|<hot_from>|<at_id>"`. UNE
/// SEULE ligne, et non quatre clés : la publication d'une couverture est alors atomique PAR
/// CONSTRUCTION (il n'existe pas d'état « publiée à moitié » à traiter). Absente = rien d'établi.
pub(crate) const META_DIM_ROLLUP_COV: &str = "event_dim_rollup_cov";
/// HISTORIQUE : le watermark seul des versions antérieures. Il ne vaut PAS couverture — c'est tout le
/// sujet — et le job le SUPPRIME pour qu'aucune lecture ne puisse le reprendre pour telle.
pub(crate) const META_DIM_ROLLUP_WM_LEGACY: &str = "event_dim_rollup_wm";

/// Ce que le job a PUBLIÉ pour `event_dim_rollup`. Privé : voir `DimRollupCoverage`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DimCoverage {
    /// `event_dim_rollup` est une image d'`event` (au cap top-N près) pour les buckets de
    /// `[from, below)`, des lignes `id <= at_id` ; ET la bande VOLATILE `[hot_from, ∞)` est
    /// ré-agrégée intégralement à CHAQUE tick (fraîcheur d'un tick, jamais un trou).
    Established { from: i64, below: i64, hot_from: i64, at_id: i64 },
    /// Rien n'est établi : « on ne sait pas », et ça vaut refus.
    Unproven,
}

/// La couverture du rollup par dimension. **Aucun constructeur littéral** — mêmes trois portes que
/// `RollupCoverage` : `of` (dérivation depuis la base), `unproven` (aveu), et un fabricant `cfg(test)`.
/// Un site d'appel ne peut donc pas AFFIRMER qu'une bande est agrégée ; il peut seulement la faire
/// ÉTABLIR par le job, ou avouer qu'il n'en sait rien — et l'aveu vaut refus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct DimRollupCoverage(DimCoverage);

/// Ce que la couverture TÉMOIGNE d'une fenêtre : les bandes de buckets réellement servables, et
/// celles qui manquent. Les deux sont rendues — une absence est une donnée, pas un silence.
pub(crate) struct DimWitness {
    /// Bandes `[lo, hi)` servables depuis `event_dim_rollup`. `hi == i64::MAX` = pas de borne haute.
    /// JAMAIS vide (sinon `witness` renvoie None et la route décline).
    pub(crate) served: Vec<(i64, i64)>,
    /// Bandes `[lo, hi)` de la fenêtre demandée dont la couverture ne témoigne PAS. Vide = fenêtre
    /// entièrement couverte.
    pub(crate) missing: Vec<(i64, i64)>,
}

impl DimRollupCoverage {
    /// DÉRIVE la couverture de la base. DÉFAUT = REFUS : clé absente, illisible, mal formée, ou bande
    /// vide (`below <= from` ET pas de bande volatile utile) -> `unproven`. Lecture indexée (PK `meta`).
    pub(crate) fn of(conn: &Connection) -> Self {
        let raw: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![META_DIM_ROLLUP_COV], |r| r.get::<_, String>(0))
            .ok();
        let Some(raw) = raw else { return Self::unproven() };
        let p: Vec<&str> = raw.split('|').collect();
        if p.len() != 4 {
            return Self::unproven(); // format inconnu -> on ne sait rien
        }
        let (Ok(from), Ok(below), Ok(hot_from), Ok(at_id)) =
            (p[0].parse::<i64>(), p[1].parse::<i64>(), p[2].parse::<i64>(), p[3].parse::<i64>())
        else {
            return Self::unproven();
        };
        Self(DimCoverage::Established { from, below, hot_from, at_id })
    }

    /// AVEU : ce site d'appel ne peut RIEN établir (fonction pure, aucune connexion sous la main).
    /// Vaut « aucun bucket témoigné » -> la route décline -> le chemin brut sert.
    pub(crate) fn unproven() -> Self {
        Self(DimCoverage::Unproven)
    }

    /// La bande PROUVÉE `[from, below)` et le plancher de la bande VOLATILE, ou None. Consommée par le
    /// JOB pour savoir d'où repartir ; la route passe par `witness`.
    pub(crate) fn band(self) -> Option<(i64, i64, i64)> {
        match self.0 {
            DimCoverage::Established { from, below, hot_from, .. } => Some((from, below, hot_from)),
            DimCoverage::Unproven => None,
        }
    }

    /// Plus grand `event.id` que l'agrégation ayant établi cette bande a vu. Toute ligne `id >` celui-ci
    /// et tombant DANS la bande est une RETARDATAIRE : c'est elle qui rétracte la bande au tick suivant.
    pub(crate) fn late_floor_id(self) -> Option<i64> {
        match self.0 {
            DimCoverage::Established { at_id, .. } => Some(at_id),
            DimCoverage::Unproven => None,
        }
    }

    /// PUBLIE la couverture — en UN statement, donc jamais à moitié. N'est appelée qu'après une
    /// agrégation RÉUSSIE (fail-closed : sur échec la clé reste absente et la route décline).
    pub(crate) fn publish(conn: &Connection, from: i64, below: i64, hot_from: i64, at_id: i64) {
        let _ = conn.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![META_DIM_ROLLUP_COV, format!("{from}|{below}|{hot_from}|{at_id}")],
        );
    }

    /// RÉTRACTE la couverture. Appelée AVANT de toucher la table (« rétracter d'abord, réparer
    /// ensuite ») : pendant la reconstruction la route décline et le brut sert, donc la réponse reste
    /// juste.
    pub(crate) fn retract(conn: &Connection) {
        let _ = conn.execute("DELETE FROM meta WHERE key=?1", params![META_DIM_ROLLUP_COV]);
    }

    /// REMONTE le plancher de la bande à `floor`. La RÉTENTION supprime des buckets sous son cutoff : la
    /// bande publiée ne peut plus témoigner d'eux. On remonte donc son plancher AU LIEU de tout rétracter
    /// — rétracter ferait repartir le front bas de zéro à chaque purge (horaire), ce qui condamnerait la
    /// bande à ne jamais tenir. CONSERVATEUR : un index à rétention plus longue garde ses buckets, mais on
    /// ne les témoigne pas (on n'en sait rien ici) — l'aveu est du côté sûr. Bande vidée -> rétractation.
    pub(crate) fn raise_floor(conn: &Connection, floor: i64) {
        let DimCoverage::Established { from, below, hot_from, at_id } = Self::of(conn).0 else { return };
        if from >= floor {
            return; // la purge n'a rien enlevé de ce que la bande témoigne
        }
        if floor >= below {
            Self::retract(conn); // plus rien de prouvé sous la bande volatile
        } else {
            Self::publish(conn, floor, below, hot_from, at_id);
        }
    }

    /// CE QUE LA COUVERTURE TÉMOIGNE de la fenêtre `[lo, hi)` (bornes en BUCKETS ; `hi == i64::MAX` =
    /// pas de borne haute). L'ensemble couvert est `[from, below) ∪ [hot_from, ∞)` : la bande prouvée
    /// et la bande volatile que le tick ré-agrège INTÉGRALEMENT (elles sont contiguës en régime
    /// établi, `below == hot_from` -> une seule bande).
    ///
    /// `None` = la fenêtre demandée ne rencontre AUCUN bucket témoigné. La route DOIT alors décliner :
    /// servir `SUM(n)` sur une bande vide rendrait `0`, indiscernable d'un vrai zéro. C'est le cas
    /// mesuré (`fenêtre au-delà de 7 j` -> `0` contre 5 696), et c'est aussi le cas de TOUTE base
    /// d'avant ce correctif (couverture absente -> `Unproven` -> None -> brut).
    pub(crate) fn witness(self, lo: i64, hi: i64) -> Option<DimWitness> {
        let DimCoverage::Established { from, below, hot_from, .. } = self.0 else {
            return None; // aveu -> aucun bucket témoigné
        };
        if hi <= lo {
            return None; // fenêtre vide
        }
        // Les deux bandes couvertes, intersectées avec la fenêtre. `below <= hot_from` par construction
        // (le job publie `below = min(recent, …)` et `hot_from = recent`) -> elles ne se chevauchent pas.
        let inter = |a: (i64, i64)| -> Option<(i64, i64)> {
            let (x, y) = (a.0.max(lo), a.1.min(hi));
            (y > x).then_some((x, y))
        };
        let mut served: Vec<(i64, i64)> = [inter((from, below)), inter((hot_from, i64::MAX))].into_iter().flatten().collect();
        served.sort_unstable();
        // Fusionne deux bandes contiguës (régime établi : `below == hot_from`) -> une seule condition SQL.
        if served.len() == 2 && served[0].1 >= served[1].0 {
            let merged = (served[0].0, served[1].1);
            served = vec![merged];
        }
        if served.is_empty() {
            return None;
        }
        // Le COMPLÉMENT dans la fenêtre : ce que la route devra NOMMER au lieu de le taire.
        let mut missing = Vec::new();
        let mut cursor = lo;
        for (s_lo, s_hi) in &served {
            if *s_lo > cursor {
                missing.push((cursor, *s_lo));
            }
            cursor = cursor.max(*s_hi);
        }
        if cursor < hi {
            missing.push((cursor, hi));
        }
        Some(DimWitness { served, missing })
    }

    /// TEST SEULEMENT — fabrique une couverture ARBITRAIRE (miroir de
    /// `RollupCoverage::asserted_by_the_test`) : `cfg(test)`, donc aucun chemin de production ne peut
    /// affirmer une bande.
    #[cfg(test)]
    pub(crate) fn asserted_by_the_test(from: i64, below: i64, hot_from: i64, at_id: i64) -> Self {
        Self(DimCoverage::Established { from, below, hot_from, at_id })
    }

    /// TEST SEULEMENT — la couverture MAXIMALE (toute borne témoignée). Elle existe pour les tests qui
    /// n'interrogent PAS la ROUTE B et ne doivent donc pas être perturbés par sa garde ; un test qui veut
    /// éprouver la garde construit une bande PRÉCISE avec `asserted_by_the_test`.
    #[cfg(test)]
    pub(crate) fn all_asserted_by_the_test() -> Self {
        Self::asserted_by_the_test(i64::MIN, i64::MAX, i64::MAX, i64::MAX)
    }
}
