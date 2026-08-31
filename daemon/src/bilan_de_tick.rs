//! `P4.1-r` — CE QU'UN TICK DE FOND REND : le nombre d'éléments dus qu'il a ABANDONNÉS, ou l'aveu qu'il
//! n'a pas pu lire sa liste.
//!
//! LE DÉFAUT QUE CE MODULE FERME. Chaque évaluateur périodique du démon — règles, règles avancées,
//! règles de risque, corrélations, lignes de base, playbooks, connecteurs, destinations, rapports —
//! lisait sa liste d'éléments dus par un `prepare` puis un `query_map`, et RENDAIT LA MAIN sur le
//! premier échec (`Err(_) => return`). Le fil planificateur, lui, marquait quand même son tick
//! (`SCHED_RULE_LAST_TS`), si bien que la santé « détection » restait verte pendant qu'AUCUNE règle
//! n'était évaluée. Même forme un cran plus bas : une règle dont la requête ne compile plus, ou dont
//! l'évaluation échoue, était sautée (`continue`) en avançant `last_run`, donc sans que rien ne la
//! distingue d'une règle évaluée et calme. Une ligne qui ne se décode pas (`.flatten()`) disparaissait
//! du tick sans même que `last_run` bouge. C'est la famille de `P4.1-q` — une détection qui s'ÉTEINT
//! sans trace — portée au démon.
//!
//! LA FORME EST CELLE DE `S32` (`mesure_environnement::Mesure`), et pour la même raison : « je n'ai pas
//! pu lire la liste » et « j'ai lu la liste et j'ai abandonné n éléments » sont deux faits qu'aucun
//! nombre seul ne sépare — un zéro d'abandons sur une liste illisible serait la valeur la plus
//! rassurante. Donc :
//!   * `Mesure::Illisible { cause, detail }` quand la liste des dus n'a pas pu être lue. Le tick est
//!     AVEUGLE pour cette famille, et `cause` est une clé de l'ensemble fermé `CAUSES` ;
//!   * `Mesure::Lue(n)` quand la liste a été lue, `n` étant le nombre d'éléments dus qui n'ont PAS été
//!     évalués (compilation refusée, évaluation en échec, ligne indécodable). Un `Lue(0)` est un VRAI
//!     zéro : tout ce qui était dû a été évalué.
//!
//! LE PLANIFICATEUR ABSORBE les bilans de toutes les familles et de tous les tenants d'un même tick, et
//! PUBLIE le résultat : la somme des abandons, ou l'aveu dès qu'UNE famille a été aveugle (un compte
//! partiel serait plus petit que la réalité). La surface d'état (`metrics::component_health`) lit ce
//! bilan et ne peut plus dire « détection : verte » sur un tick qui n'a rien évalué.
//!
//! CE QUE CE MODULE NE DÉCIDE PAS : quoi faire d'une règle abandonnée. Elle est re-tentée au prochain
//! intervalle, comme avant ; ce qui change est qu'elle est COMPTÉE, et que le compte est visible.
use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE};

/// Ce qu'un évaluateur périodique rend à son planificateur.
pub(crate) type BilanDeTick = Mesure<u32>;

/// LA CAUSE, DÉRIVÉE DE L'ERREUR SQLITE — un seul auteur, comme `cause_io` pour les erreurs d'E/S.
/// « no such table » / « no such column » est une FORME que la base ne présente pas (schéma en
/// retard, migration non appliquée) ; tout le reste est une lecture qui a échoué.
pub(crate) fn cause_sql(e: &rusqlite::Error) -> &'static str {
    match e {
        rusqlite::Error::SqliteFailure(_, Some(msg)) if msg.starts_with("no such ") => CAUSE_FORME_INCONNUE,
        _ => CAUSE_SOURCE_ILLISIBLE,
    }
}

/// Le tick d'une famille est AVEUGLE : sa liste d'éléments dus n'a pas pu être lue. `famille` nomme
/// ce qui n'a pas été évalué (« règles », « corrélations »…), parce qu'un aveu sans le sujet ne se
/// répare pas.
pub(crate) fn tick_aveugle(famille: &str, e: &rusqlite::Error) -> BilanDeTick {
    Mesure::Illisible { cause: cause_sql(e), detail: format!("{famille} : liste des éléments dus illisible ({e})") }
}

/// LE BILAN D'UN TICK DU PLANIFICATEUR, toutes familles et tous tenants confondus. Additif : chaque
/// famille y verse son bilan, et le résultat reste ILLISIBLE dès qu'une seule l'a été — la première
/// cause est conservée, le détail accumule les familles aveugles.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct BilanDuPlanificateur {
    abandonnes: u64,
    aveugle: Option<(&'static str, Vec<String>)>,
}

impl BilanDuPlanificateur {
    pub(crate) fn absorber(&mut self, b: BilanDeTick) {
        match b {
            Mesure::Lue(n) => self.abandonnes += u64::from(n),
            Mesure::Illisible { cause, detail } => match &mut self.aveugle {
                Some((_, details)) => details.push(detail),
                None => self.aveugle = Some((cause, vec![detail])),
            },
        }
    }

    /// Un corps de tick qui a PANIQUÉ (capturé par le planificateur) n'a rien évalué de ce qu'il
    /// restait à faire : c'est un tick aveugle, pas un tick calme.
    pub(crate) fn panique(&mut self, tenant: &str) {
        self.absorber(Mesure::Illisible {
            cause: CAUSE_SOURCE_ILLISIBLE,
            detail: format!("tenant {tenant} : le corps du tick a paniqué, le reste des familles n'a pas été évalué"),
        });
    }

    /// Le même bilan, au format d'UNE famille — pour une boucle qui absorbe des sous-bilans (une
    /// destination par destination) et rend le sien. La somme d'un tick tient dans `u32` ; un
    /// dépassement est saturé, jamais replié sur zéro.
    pub(crate) fn bilan_de_tick(&self) -> BilanDeTick {
        match self.mesure() {
            Mesure::Lue(n) => Mesure::Lue(u32::try_from(n).unwrap_or(u32::MAX)),
            Mesure::Illisible { cause, detail } => Mesure::Illisible { cause, detail },
        }
    }

    /// La mesure publiable : le compte des abandons, ou l'aveu.
    pub(crate) fn mesure(&self) -> Mesure<u64> {
        match &self.aveugle {
            None => Mesure::Lue(self.abandonnes),
            Some((cause, details)) => Mesure::Illisible {
                cause,
                detail: format!(
                    "{} famille(s) aveugle(s) ce tick — {} ; abandons comptés par ailleurs : {}",
                    details.len(),
                    details.join(" ; "),
                    self.abandonnes
                ),
            },
        }
    }
}

/// LE DERNIER BILAN PUBLIÉ PAR BOUCLE DE FOND, lu par la surface d'état. Clé = le nom de la boucle
/// (« regles », « connecteurs »…). Avant le premier tick d'une boucle, il n'y a PAS de bilan : `dernier`
/// rend `None`, que la surface distingue d'un bilan lu (elle dit déjà « idle » sur un tick jamais
/// marqué). Un `Mutex` standard plutôt qu'un atomique : le bilan porte un détail textuel.
static DERNIERS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<&'static str, Mesure<u64>>>> =
    std::sync::OnceLock::new();

fn derniers() -> &'static std::sync::Mutex<std::collections::HashMap<&'static str, Mesure<u64>>> {
    DERNIERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub(crate) fn publier(boucle: &'static str, bilan: Mesure<u64>) {
    derniers().lock().unwrap_or_else(|e| e.into_inner()).insert(boucle, bilan);
}

pub(crate) fn dernier(boucle: &str) -> Option<Mesure<u64>> {
    derniers().lock().unwrap_or_else(|e| e.into_inner()).get(boucle).cloned()
}

/// Les noms des boucles qui publient un bilan — ÉCRITS UNE FOIS, lus par le planificateur qui publie
/// et par la surface qui expose, pour qu'une faute de frappe ne fasse pas d'une boucle une inconnue.
pub(crate) const BOUCLE_REGLES: &str = "regles";
/// Les incidents de risque tournent dans la boucle de rollup, pas dans celle des règles — un bilan à part.
pub(crate) const BOUCLE_RISQUE: &str = "risque";
pub(crate) const BOUCLE_CONNECTEURS: &str = "connecteurs";
pub(crate) const BOUCLE_DESTINATIONS: &str = "destinations";
pub(crate) const BOUCLE_RAPPORTS: &str = "rapports";
pub(crate) const BOUCLE_INGEST: &str = "ingest";

/// `P10.7-x` — CE QUE LA SURFACE PARCOURT N'EST PLUS UNE LISTE ÉCRITE À LA MAIN.
///
/// CE QUI A ÉTÉ MESURÉ, LE 2026-08-31, AVANT DE CORRIGER. `BOUCLES` était un `[&str; 6]` recopié à
/// côté des six constantes ci-dessus, et c'est LUI que `metrics::gather_json` et `metrics::gather_prom`
/// parcouraient. Or HUIT clés étaient publiées dans ce registre par du code de PRODUCTION : les six de
/// la table, plus `retention` (`server::boucles_de_fond::BOUCLE_RETENTION` — la boucle qui ANCRE la
/// chaîne d'intégrité, à qui `P10.7-w` venait de donner un bilan en ÉCRIVANT que sa clé manquait ici)
/// et `overlays` (`overlays_adossement::PASSE_OVERLAYS`, la passe `config.d`). Deux aveux JUSTES,
/// lisibles par `dernier()`, servis par AUCUNE surface. Ce n'était pas deux accidents : c'est ce que
/// produit une table qu'il faut PENSER à tenir, et une troisième passe l'aurait rouverte en silence.
///
/// LA TABLE EST DONC DÉRIVÉE DU REGISTRE LUI-MÊME — il CONTIENT déjà l'ensemble exact des passes qui
/// ont publié. `publier` devient le seul geste : ce qui publie est servi, sans qu'aucune liste ait à
/// l'apprendre. Même figure que `ingest::pubsub::AckDrop::TOUTES` côté raisons d'ack-drop.
///
/// TROIS CONSÉQUENCES MESURÉES, écrites parce qu'elles changent la sortie :
///   1. une passe ajoutée demain est servie le jour où elle publie ; l'oubli n'est plus offert ;
///   2. UNE FAUSSE ACCUSATION DISPARAÎT, et elle n'avait pas été demandée. La table écrite nommait les
///      six boucles DÈS LE DÉMARRAGE, avant leur premier tick ; `poser_bilan(None)` ne posait alors
///      aucune clé, et le helper `lisible()` de l'exposition Prometheus retombe sur
///      `VERDICT_ILLISIBLE` quand il ne trouve pas son verdict — soit six jauges
///      `plume_scheduler_<boucle>_bilan_lisible 0` au boot, c'est-à-dire « ce tick était AVEUGLE » sur
///      des boucles qui n'avaient pas encore tourné. Dérivée, la table ne porte que des clés PUBLIÉES,
///      dont le verdict existe toujours : l'accusation ne peut plus être portée à vide ;
///   3. LE REGISTRE NE CONTIENT PAS QUE DES BOUCLES. `overlays` est une passe de DÉMARRAGE, appelée
///      une seule fois (`server::run` -> `load_overlays`) : son bilan est un verdict de boot qui vaut
///      jusqu'au redémarrage. La surface ne doit donc RIEN supposer d'une cadence.
///
/// CE QUE ÇA NE FAIT PAS : prouver qu'une passe TOURNE. Un fil mort ne publie rien, et l'absence reste
/// lue « pas encore » — délibérément, un bilan inventé avant le premier passage étant un zéro rassurant.
pub(crate) fn boucles_publiees() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = derniers().lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
    // ORDRE STABLE : un relevé Prometheus et le JSON du panneau se comparent d'une lecture à l'autre,
    // et l'ordre d'itération d'un `HashMap` ne se compare même pas à lui-même.
    v.sort_unstable();
    v
}

/// LE NOM DE SÉRIE D'UNE PASSE — sa clé réduite à l'alphabet qu'un nom de métrique Prometheus admet.
/// LA DÉRIVATION A UN COÛT, ET IL EST PAYÉ ICI : la table écrite portait six noms choisis à la main,
/// tous conformes ; dérivée, elle prend ce que le code publie. Un caractère hors `[a-zA-Z0-9_]` dans
/// une clé produirait un nom INVALIDE, et Prometheus rejette alors le relevé ENTIER — pas seulement la
/// série fautive : toute l'observabilité du démon disparaîtrait d'un coup.
/// CE QUE ÇA NE TIENT PAS, ÉCRIT : la réduction n'est pas injective. Deux clés ne différant que par un
/// caractère non conforme se rejoindraient sur le même nom de métrique ; seul le composant de santé,
/// qui porte les noms BRUTS, les distinguerait alors.
pub(crate) fn nom_de_serie(passe: &str) -> String {
    passe.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// LA CLÉ D'UNE PASSE, ÉCHAPPÉE POUR UN POINTEUR JSON (RFC 6901) : `~` -> `~0`, `/` -> `~1`. L'objet
/// JSON garde la clé BRUTE — il n'a pas l'alphabet contraint de Prometheus — mais l'exposition la
/// retrouve par un POINTEUR, dont `/` est le séparateur de niveau : une clé portant un `/` ferait du
/// pointeur DEUX niveaux, la valeur ne serait jamais retrouvée, et la série DISPARAÎTRAIT du relevé
/// sans que rien ne le dise. MESURÉ : le témoin de nom de série l'a fait rougir au premier tir — la
/// table écrite cachait le piège derrière six noms choisis à la main.
pub(crate) fn jeton_de_pointeur(passe: &str) -> String {
    passe.replace('~', "~0").replace('/', "~1")
}

/// LES COMPOSANTS DE LA SURFACE D'ÉTAT ET LES PASSES QU'ILS PORTENT — LE SEUL ENDROIT OÙ CE LIEN EST
/// ÉCRIT. La surface ne nomme plus une passe : elle nomme SON composant et demande ce qu'il porte.
///
/// POURQUOI CETTE TABLE-CI PEUT RESTER ÉCRITE ALORS QUE L'AUTRE NON. « Quel composant nommé porte
/// quelle passe » est une question de SENS : que les règles et les incidents de risque soient tous
/// deux « la détection » ne se déduit d'aucune propriété du code. Mais son OUBLI ne fait plus
/// disparaître personne — ce qu'elle ne revendique pas tombe dans `bilans_orphelins()`, qui est le
/// COMPLÉMENT (`publiées − revendiquées`) et que la surface porte dans un composant à part. La pire
/// faute possible ici est donc « montré deux fois », jamais « montré nulle part ».
pub(crate) const COMPOSANT_INGEST: &str = "ingest";
pub(crate) const COMPOSANT_DETECTION: &str = "detection";
pub(crate) const COMPOSANT_FORWARDER: &str = "forwarder";
/// LE COMPOSANT DU COMPLÉMENT — il porte tout ce qu'aucun composant nommé ne revendique, et il existe
/// TOUJOURS : son absence se lirait « rien à signaler ».
pub(crate) const COMPOSANT_PASSES_DE_FOND: &str = "passes_de_fond";
pub(crate) const COMPOSANTS: [(&str, &[&str]); 3] = [
    (COMPOSANT_INGEST, &[BOUCLE_INGEST]),
    (COMPOSANT_DETECTION, &[BOUCLE_REGLES, BOUCLE_RISQUE]),
    (COMPOSANT_FORWARDER, &[BOUCLE_DESTINATIONS]),
];

/// LE BILAN DE PLUSIEURS BOUCLES, VU COMME UN SEUL — la détection tourne dans deux boucles (règles,
/// risque) et la surface n'a qu'un composant « détection ». `None` tant qu'AUCUNE des boucles n'a
/// publié (démarrage) : la surface dit déjà « idle » sur un tick jamais marqué, et un bilan inventé
/// avant le premier tick serait un zéro rassurant. Dès qu'une boucle a publié, le bilan EXISTE, et une
/// boucle encore muette n'y pèse rien (elle n'a encore rien abandonné ni rien manqué).
pub(crate) fn combiner(boucles: &[&str]) -> Option<Mesure<u64>> {
    let mut acc = BilanDuPlanificateur::default();
    let mut vu = false;
    for b in boucles {
        if let Some(m) = dernier(b) {
            vu = true;
            acc.absorber(match m {
                Mesure::Lue(n) => Mesure::Lue(u32::try_from(n).unwrap_or(u32::MAX)),
                Mesure::Illisible { cause, detail } => Mesure::Illisible { cause, detail },
            });
        }
    }
    vu.then(|| acc.mesure())
}

/// LE BILAN CONSOLIDÉ DES PASSES QU'UN COMPOSANT NOMMÉ PORTE. `None` = aucune d'elles n'a encore
/// publié (démarrage) — jamais un zéro inventé. Un composant absent de `COMPOSANTS` ne porte RIEN,
/// et c'est la garde `toute_passe_publiee_est_portee_par_un_composant_de_la_surface` qui interdit
/// qu'un nom vive dans la table sans exister sur la surface (une faute de frappe y ferait taire un
/// composant sans rien casser ailleurs).
pub(crate) fn bilan_du_composant(composant: &str) -> Option<Mesure<u64>> {
    let portees: &[&str] =
        COMPOSANTS.iter().find(|(nom, _)| *nom == composant).map(|(_, portees)| *portees).unwrap_or(&[]);
    combiner(portees)
}

/// LES BILANS QU'AUCUN COMPOSANT NOMMÉ NE REVENDIQUE — `publiées − revendiquées`. C'EST CETTE
/// SOUSTRACTION QUI FERME LE TROU : une passe qui publie sans que personne l'ait revendiquée tombe
/// ICI, et son aveu atteint la surface sans que quiconque ait eu à y penser. Écrire deux entrées de
/// plus dans une liste aurait laissé la troisième s'oublier en silence.
pub(crate) fn bilans_orphelins() -> Vec<(&'static str, Mesure<u64>)> {
    boucles_publiees()
        .into_iter()
        .filter(|passe| !COMPOSANTS.iter().any(|(_, portees)| portees.contains(passe)))
        .filter_map(|passe| dernier(passe).map(|m| (passe, m)))
        .collect()
}

/// CE QUE LA SURFACE DIT DES PASSES QU'AUCUN COMPOSANT NOMMÉ NE PORTE. Fonction PURE de ses bilans :
/// aucun registre de processus, aucune base, aucune horloge — donc exerçable sur des entrées
/// FABRIQUÉES, y compris les états qu'un arbre sain ne produit qu'exceptionnellement.
///
/// L'ORDRE DES CAS EST L'ORDRE DE GRAVITÉ, et le premier doit passer devant : une passe AVEUGLE n'a
/// PAS fait ce qu'elle devait — c'est l'état d'un fil bloqué, pas d'un fil calme — tandis qu'un
/// abandon est une part du dû qui sera re-tentée. Zéro abandon est VERT et NOMME ce qui est couvert,
/// sans rien avouer : un aveu inconditionnel n'est pas un aveu.
pub(crate) fn etat_des_passes_orphelines(bilans: &[(&'static str, Mesure<u64>)]) -> (&'static str, String) {
    if bilans.is_empty() {
        return ("idle", "aucune passe de fond hors composant nommé n'a encore publié de bilan".to_string());
    }
    let aveugles: Vec<String> = bilans
        .iter()
        .filter_map(|(nom, m)| match m {
            Mesure::Illisible { detail, .. } => Some(format!("{nom} ({detail})")),
            Mesure::Lue(_) => None,
        })
        .collect();
    if !aveugles.is_empty() {
        return (
            "red",
            format!(
                "passage(s) AVEUGLE(S) — {} ; ces passes ne sont portées par aucun composant nommé, et \
                 leur dernier passage n'a PAS fait ce qu'il devait",
                aveugles.join(" ; ")
            ),
        );
    }
    let abandons: Vec<String> = bilans
        .iter()
        .filter_map(|(nom, m)| match m {
            Mesure::Lue(n) if *n > 0 => Some(format!("{nom} : {n}")),
            _ => None,
        })
        .collect();
    if !abandons.is_empty() {
        return (
            "yellow",
            format!(
                "élément(s) dû(s) ABANDONNÉ(S) au dernier passage ({}) — non traités, re-tentés au suivant",
                abandons.join(" ; ")
            ),
        );
    }
    (
        "green",
        format!(
            "{} passe(s) de fond hors composant nommé, 0 abandon au dernier passage : {}",
            bilans.len(),
            bilans.iter().map(|(nom, _)| *nom).collect::<Vec<_>>().join(", ")
        ),
    )
}

/// `P10.7-n` — LA MÊME FIGURE QUE `etat_de_surface`, MAIS QUAND LE SERVICE CONTINUE SUR L'ÉTAT
/// PRÉCÉDENT. `etat_de_surface` traite un bilan de TICK : illisible y veut dire « rien n'a été
/// évalué », donc ROUGE. Une mesure de RECHARGEMENT ne dit pas cela — le jeu précédent est CONSERVÉ
/// et le service continue, sur un jeu qui vieillit à chaque échec. ROUGE y serait une SUR-ACCUSATION
/// (la détection n'est pas éteinte), VERT un mensonge : c'est JAUNE, l'état qui appelle un regard, et
/// le détail dit sur quoi on tourne encore. Aucune mesure (démarrage) et une mesure SAINE rendent
/// l'état et le détail INTACTS : le chemin sain reste muet.
pub(crate) fn etat_de_surface_jeu_conserve(
    etat: &'static str,
    detail: String,
    quoi: &str,
    mesure: Option<&Mesure<u64>>,
) -> (&'static str, String) {
    match mesure {
        Some(Mesure::Illisible { detail: pourquoi, .. }) => (
            crate::metrics::pire_des_deux(etat, "yellow"),
            format!(
                "{detail} ; {quoi} tourne sur un jeu PÉRIMÉ : {pourquoi} — le dernier jeu lu ENTIÈREMENT \
                 est CONSERVÉ et le service continue, mais il vieillit à chaque rechargement raté"
            ),
        ),
        _ => (etat, detail),
    }
}

/// CE QUE LA SURFACE D'ÉTAT DIT D'UN BILAN, et ce que ça change à l'état du composant. Un tick AVEUGLE
/// est ROUGE : rien n'a été évalué, c'est l'état d'un planificateur bloqué, pas d'un planificateur
/// calme — et c'est précisément ce que le tick marqué « à l'heure » laissait passer pour vert. Des
/// abandons sont JAUNES : une partie de ce qui était dû n'a pas été évalué, et sera re-tentée. Zéro
/// abandon ne change rien à l'état dérivé de la fraîcheur du tick. Aucun bilan (démarrage) non plus.
pub(crate) fn etat_de_surface(
    etat: &'static str,
    detail: String,
    bilan: Option<&Mesure<u64>>,
) -> (&'static str, String) {
    match bilan {
        None => (etat, detail),
        Some(Mesure::Lue(0)) => (etat, detail),
        Some(Mesure::Lue(n)) => (
            crate::metrics::pire_des_deux(etat, "yellow"),
            format!("{detail} ; {n} élément(s) dû(s) ABANDONNÉ(S) au dernier tick (non évalués, re-tentés au suivant)"),
        ),
        Some(Mesure::Illisible { detail: pourquoi, .. }) => (
            "red",
            format!("{detail} ; tick AVEUGLE : {pourquoi} — ce tick n'a PAS évalué ce qu'il devait, et un tick marqué à l'heure ne le disait pas"),
        ),
    }
}

/// Pose le bilan dans un objet de la surface, sous la convention de `S32` (`<cle>`, `<cle>_verdict`,
/// `<cle>_cause`, `<cle>_detail`). Sans bilan (démarrage), RIEN n'est posé : l'absence des quatre clés
/// est lisible comme « pas encore de tick », jamais comme un zéro.
pub(crate) fn poser_bilan(objet: &mut serde_json::Map<String, serde_json::Value>, cle: &str, bilan: Option<&Mesure<u64>>) {
    match bilan {
        Some(b) => b.poser_dans(objet, cle),
        None => {}
    }
}
