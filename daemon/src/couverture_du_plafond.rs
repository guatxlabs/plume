//! LA COUVERTURE DU PLAFOND : le plafond mémoire de SQLite est-il SOUS ce qui tue le processus ?
//!
//! Module FEUILLE extrait de `sqlite_plafond` par déplacement pur (`P7.18-a`) : le type `Couverture`
//! (quatre verdicts exclusifs — protégé, dépassé, sans limite, illisible), la confrontation PURE
//! `couverture_pour` entre le budget et la limite lue par `limite_cgroup`, et la phrase de la bannière
//! (mot de verdict stable `[couverture=…]`, alerte DÉRIVÉE du seul verdict qui protège).
//!
//! DÉPENDANCES, DANS LES DEUX SENS. Il ne lit que `LimiteCgroup` (feuille `limite_cgroup`) et ne dépend
//! de RIEN dans `sqlite_plafond`. `sqlite_plafond` l'importe par un `use` PRIVÉ (pas de ré-export) pour
//! `rapport()` ; ses tests internes l'atteignent par `use super::*`, les autres par
//! `crate::couverture_du_plafond::…`.
//!
//! IL NE DÉCIDE D'AUCUN RÉGLAGE MÉMOIRE DU MOTEUR. Le type `Plafond`, qui GRAVE le plafond de tas, reste
//! dans `sqlite_plafond.rs`, seul auteur du budget : cette feuille n'a AUCUNE exception dans la garde du
//! budget, et un réglage écrit ici y est accusé.
use crate::limite_cgroup::LimiteCgroup;

/// UN PLAFOND NE PROTÈGE QUE S'IL EST SOUS CE QUI NOUS TUE. Un budget de 1088 Mio dans un conteneur limité
/// à 1 Gio est une protection IMAGINAIRE : l'OOM-killer arrive avant l'allocateur. La bannière ne peut donc
/// pas se contenter d'annoncer le budget — elle doit le CONFRONTER à la limite réelle, ou dire lequel des
/// deux empêchements l'en prive. QUATRE cas EXCLUSIFS, `match` exhaustif : c'est la seule façon que « je
/// ne sais pas » ne se déguise ni en « tout va bien », ni en « il n'y a pas de limite ».
///
/// CE QUI SE PASSE QUAND LA LECTURE ÉCHOUE — décision, et sa raison. NI refus de démarrage, NI défaut
/// prudent : FONCTIONNEMENT DÉGRADÉ ANNONCÉ.
///   * REFUSER DE DÉMARRER serait faux au regard des modes de déploiement revendiqués. Un service système
///     natif sans `MemoryMax=` n'a légitimement AUCUNE limite ; faire d'une lecture impossible une panne
///     transformerait des installations correctes en incidents.
///   * UN DÉFAUT PRUDENT (supposer une limite basse) INVENTERAIT un nombre. Il ferait refuser des requêtes
///     qui tiennent, et surtout il PRÉTENDRAIT une mesure : c'est exactement la faute que ce bloc ferme.
///   * CE QUI RESTE TENU SANS CETTE LECTURE, et c'est pourquoi le dégradé est acceptable : le plafond dur
///     de SQLite ne dépend PAS d'elle — il est posé, et une requête qui le franchit refuse, lecture du
///     cgroup ou pas. Ce que la lecture apporte est la CONFRONTATION : savoir si ce plafond est SOUS ce
///     qui tue. Sans elle, la protection interne survit ; c'est sa VÉRIFICATION qui manque, et c'est
///     exactement cela qui est annoncé — ni plus, ni moins.
pub(crate) enum Couverture {
    /// Le budget tient sous la limite mesurée : le refus arrive AVANT l'OOM-killer.
    Protege { limite: i64 },
    /// La limite existe et le budget ne tient pas dessous. Le processus mourra avant de refuser.
    Depasse { limite: i64 },
    /// L'interface a été LUE : il n'y a AUCUNE limite de cgroup. Rien d'extérieur ne borne le processus.
    SansLimite,
    /// La lecture a échoué ou n'a pas été comprise. On ne prétend RIEN, et on dit ce qui a été tenté.
    Illisible(String),
}

/// PURE : la confrontation, séparée de la LECTURE, donc exerçable dans les quatre états sans cgroup sous
/// la main. `limite` vient de `limite_cgroup`.
pub(crate) fn couverture_pour(budget: i64, limite: LimiteCgroup) -> Couverture {
    match limite {
        LimiteCgroup::Octets(l) if budget < l => Couverture::Protege { limite: l },
        LimiteCgroup::Octets(l) => Couverture::Depasse { limite: l },
        LimiteCgroup::Aucune => Couverture::SansLimite,
        LimiteCgroup::Illisible(pourquoi) => Couverture::Illisible(pourquoi),
    }
}

impl Couverture {
    /// LE MOT DE VERDICT — stable, sans espace, un par cas : c'est LUI le signal. La bascule d'une
    /// protection annoncée à une protection absente change ce mot dans la ligne `[plafond]` du démarrage,
    /// donc une supervision qui l'observe la VOIT ; une phrase en prose, elle, se relit à l'œil et ne se
    /// surveille pas. Ces quatre valeurs sont un contrat : les renommer casse ce qui les observe.
    pub(crate) fn verdict(&self) -> &'static str {
        match self {
            Couverture::Protege { .. } => "protege",
            Couverture::Depasse { .. } => "depasse",
            Couverture::SansLimite => "sans-limite",
            Couverture::Illisible(_) => "illisible",
        }
    }

    /// Le plafond protège-t-il RÉELLEMENT de ce qui tue ? Un seul des quatre verdicts le permet. DÉRIVÉ,
    /// jamais énuméré une seconde fois : c'est ce prédicat qui décide du mot d'alerte de la phrase, donc
    /// un cas ajouté demain est bruyant par défaut au lieu d'être silencieusement rangé du bon côté.
    pub(crate) fn protege(&self) -> bool {
        matches!(self, Couverture::Protege { .. })
    }

    pub(crate) fn phrase(&self) -> String {
        let alerte = if self.protege() { "" } else { "AVERTISSEMENT " };
        let verdict = self.verdict();
        let corps = match self {
            Couverture::Protege { limite } => {
                format!("sous la limite mémoire du cgroup ({} Mio)", limite / 1048576)
            }
            Couverture::Depasse { limite } => format!(
                "la limite mémoire du cgroup est {} Mio : LE PLAFOND NE PROTÈGE PAS — l'OOM-killer \
                 arrivera avant le refus. Baisser PLUME_SQLITE_BUDGET_MB sous cette limite.",
                limite / 1048576
            ),
            Couverture::SansLimite =>
                "AUCUNE limite mémoire de cgroup n'est posée — l'interface a été LUE, et elle ne borne \
                 rien. Ce n'est PAS une panne de mesure : le plafond ci-dessus borne SQLite, mais RIEN \
                 n'arrête le processus avant la RAM de l'hôte, et le budget de 2 Gio du produit n'est \
                 alors qu'une intention. Le poser : MemoryMax= (unité systemd), --memory (conteneur), \
                 limits.memory (orchestrateur)."
                    .to_string(),
            Couverture::Illisible(pourquoi) => format!(
                "limite mémoire du cgroup NON LISIBLE ({pourquoi}) : impossible de dire si ce budget \
                 protège de l'OOM-killer. Ce n'est PAS « il n'y a pas de limite », c'est « il n'y a pas \
                 de mesure » — le plafond SQLite reste appliqué, sa couverture n'est pas vérifiée."
            ),
        };
        format!(", {alerte}[couverture={verdict}] {corps}")
    }
}
