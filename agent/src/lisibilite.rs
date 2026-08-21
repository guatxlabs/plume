//! `S36` — À L'ENTRÉE AUSSI, UNE LECTURE QUI ÉCHOUE NE REND PAS LA VALEUR LA PLUS RASSURANTE.
//!
//! LE DÉFAUT QUE CE MODULE FERME, ET POURQUOI IL EST PIRE ICI QUE DANS LE DÉMON. Un lecteur de source
//! rendait `Vec::new()` sur CHACUN de ses chemins d'échec : binaire de collecte absent, journal refusé,
//! fichier illisible, poll HTTP en erreur, lecture interrompue en cours de lot. Le cycle appelant lit
//! alors « aucun enregistrement » — c'est-à-dire EXACTEMENT ce que rend une source lue dont il ne s'est
//! rien passé. Un lot vide est la valeur la plus calme de cette série ; publiée au moment où la source
//! cesse d'être lisible, elle fait lire un bon signal là où il n'y a PLUS AUCUN SIGNAL. C'est la même
//! figure que `S28`/`S32`/`S33`, mais posée là où la donnée ENTRE : ce qui s'éteint ici n'est pas un
//! panneau de supervision, ce sont les règles de détection qui s'arment de ces événements.
//!
//! LA FORME EST CELLE DU DÉMON, REPRISE ET NON DOUBLÉE (`daemon/src/mesure_environnement.rs`) :
//!   1. UN TYPE À PLUSIEURS CAS, SANS VALEUR PAR DÉFAUT. `Lecture<T>` est soit `Lue`, soit `Illisible`
//!      avec une CAUSE. Aucun constructeur ne rend une valeur faute de savoir, et `Releve` — le
//!      résultat d'un lot — n'a ni `Default` ni conversion depuis un `Vec` : un lecteur ne PEUT PAS
//!      rendre un lot sans dire s'il a lu.
//!   2. DES FONCTIONS PARAMÉTRÉES SUR LEURS SOURCES. `identite_hote_depuis` reçoit son fichier ET ses
//!      variables : la suite exerce les quatre combinaisons sans dépendre du nom de la machine qui
//!      l'exécute.
//!   3. UN VOCABULAIRE DE CAUSES FERMÉ, AUX MÊMES MOTS QUE LE DÉMON. `source_absente`,
//!      `source_refusee`, `source_illisible`, `forme_inconnue`, `aucune` — un exploitant qui lit les
//!      deux surfaces reconnaît le même vocabulaire, et `cause_io` traduit l'erreur système une seule
//!      fois pour tous les sites.
//!   4. UN INDICATEUR QUI ACCOMPAGNE L'ABSENCE. La valeur n'est pas remplacée par du rassurant : elle
//!      DISPARAÎT, et un aveu prend sa place.
//!
//! L'AVEU PASSE PAR LE CANAL DÉJÀ LIVRÉ, ON N'INVENTE RIEN. `collectors/lib.sh` publie depuis `S27` un
//! événement `category=config` portant `fields.collect_status=unavailable`, et la règle livrée
//! `config.d/rules/catalog/de-collector-unavailable.json` ALERTE dessus (`search category=config
//! collect_status=unavailable`). Une source d'agent devenue illisible emprunte EXACTEMENT ce canal :
//! même catégorie, même champs, même forme de clé de dédoublonnage horaire. Elle lève donc l'alerte
//! existante et bascule la pastille de SA source (imputation par la donnée, cf. `S7`) sans qu'aucune
//! règle, aucune métrique ni aucune catégorie nouvelle soit créée.
//!
//! DEUX VOCABULAIRES, ET C'EST DÉLIBÉRÉ. `reason` reste le mot GROSSIER du contrat shell (ensemble
//! fermé : `missing-dependency`, `missing-source`, `missing-config`, `subsystem-absent`, `unreachable`,
//! `disabled`) — c'est lui que la requête et le tableau livrés savent lire. `cause` porte le mot FIN du
//! démon. Les fondre aurait cassé l'un ou appauvri l'autre.

use crate::source::Event;
use serde_json::json;

// =================================================================================================
// LE VOCABULAIRE DE CAUSES — LES MOTS DU DÉMON, À LA LETTRE
// =================================================================================================

/// La cause quand il n'y en a pas. Présente en permanence (plutôt qu'absente sur succès) : une forme
/// de champ unique n'a pas de trou à expliquer.
pub const CAUSE_AUCUNE: &str = "aucune";
/// La source n'existe pas : binaire de collecte introuvable, fichier ou répertoire disparu, compte
/// absent. C'est le cas qui se lisait « rien à signaler ».
pub const CAUSE_SOURCE_ABSENTE: &str = "source_absente";
/// La source existe mais son accès est refusé. Distinct de l'absence : la première se répare en
/// recréant la source, la seconde en corrigeant des droits ou un profil de confinement.
pub const CAUSE_SOURCE_REFUSEE: &str = "source_refusee";
/// La source existe, l'accès est permis, la lecture échoue quand même (E/S, flux coupé en cours de
/// lot, sous-processus qui meurt, poll réseau en erreur).
pub const CAUSE_SOURCE_ILLISIBLE: &str = "source_illisible";
/// La source a été LUE mais sa forme n'est pas comprise (référence corrompue, message que le décodeur
/// refuse, réponse hors contrat). `S28` a montré que ce cas se perd le plus facilement : l'appelant
/// conclut comme si rien n'avait été trouvé.
pub const CAUSE_FORME_INCONNUE: &str = "forme_inconnue";

/// L'ENSEMBLE FERMÉ DES CAUSES. C'est lui qui borne ce qui peut apparaître en champ requêtable ; une
/// cause ajoutée hors de cette table est invisible du test qui compte, ce qui est la raison de l'écrire.
pub const CAUSES: [&str; 5] =
    [CAUSE_AUCUNE, CAUSE_SOURCE_ABSENTE, CAUSE_SOURCE_REFUSEE, CAUSE_SOURCE_ILLISIBLE, CAUSE_FORME_INCONNUE];

/// Le mot de verdict quand la lecture a eu lieu. Stable, sans espace : c'est LUI le signal côté
/// consommateur. Le renommer casse ce qui l'observe.
#[allow(dead_code)] // moitié LUE du couple : exercée par la suite, et le pendant de `VERDICT_ILLISIBLE`
pub const VERDICT_LU: &str = "lu";
/// Le mot de verdict quand la source n'est pas lisible. Ce mot est la seule chose qui sépare « la
/// source était calme » de « je ne sais pas lire la source ».
pub const VERDICT_ILLISIBLE: &str = "illisible";

// --- vocabulaire GROSSIER du contrat d'indisponibilité déjà livré (collectors/lib.sh) --------------

/// Un prérequis EXÉCUTABLE manque (le binaire de collecte n'est pas sur cet hôte).
pub const RAISON_DEPENDANCE_ABSENTE: &str = "missing-dependency";
/// La SOURCE de la collecte manque ou n'est pas lisible (fichier, répertoire, journal, compte).
pub const RAISON_SOURCE_ABSENTE: &str = "missing-source";
/// Un RÉGLAGE obligatoire manque ou n'est pas exploitable (identité, certificat, chemin).
pub const RAISON_CONFIG_ABSENTE: &str = "missing-config";
/// Le SOUS-SYSTÈME attendu n'existe pas sur cet hôte (interface noyau, service absent).
pub const RAISON_SOUS_SYSTEME_ABSENT: &str = "subsystem-absent";
/// Un point d'accès distant ne répond pas, ou répond hors contrat.
pub const RAISON_INJOIGNABLE: &str = "unreachable";

/// L'ensemble fermé des raisons — celui de `collectors/lib.sh`, mot pour mot. `disabled` n'y figure
/// pas : il désigne un interrupteur d'opérateur, et aucun lecteur de cette surface n'en porte.
pub const RAISONS: [&str; 5] = [
    RAISON_DEPENDANCE_ABSENTE,
    RAISON_SOURCE_ABSENTE,
    RAISON_CONFIG_ABSENTE,
    RAISON_SOUS_SYSTEME_ABSENT,
    RAISON_INJOIGNABLE,
];

// =================================================================================================
// LE TYPE
// =================================================================================================

/// CE QU'UNE LECTURE DE SOURCE PEUT VALOIR. Deux cas, exclusifs, et AUCUNE valeur par défaut : il
/// n'existe pas de constructeur qui rende une valeur faute de savoir. C'est la propriété que le type
/// tient et qu'un `Option<T>` déplié par `unwrap_or(…)` ne tenait pas.
#[derive(Debug, Clone, PartialEq)]
pub enum Lecture<T> {
    /// La source a été lue et comprise. La valeur peut parfaitement être vide ou nulle — et c'est
    /// alors un VRAI vide, ce que le consommateur doit pouvoir distinguer du cas suivant.
    Lue(T),
    /// La source n'a pas pu être lue, ou pas comprise. `cause` est une clé stable et bornée,
    /// publiable ; `detail` est du texte libre pour un lecteur humain (il porte des chemins et des
    /// messages système : aucune borne de cardinalité, il ne sert jamais de clé).
    Illisible { cause: &'static str, detail: String },
}

/// LES ACCESSEURS DU CONTRAT. Ils sont exercés par la suite et lus par tout appelant qui publie un
/// verdict ; le `match` sur les variantes reste possible, mais passer par ces noms garde une seule
/// traduction verdict/cause pour toute la surface.
#[allow(dead_code)] // contrat public du type — tous n'ont pas encore d'appelant hors suite
impl<T> Lecture<T> {
    /// Le mot de verdict — stable, un par cas.
    pub fn verdict(&self) -> &'static str {
        match self {
            Lecture::Lue(_) => VERDICT_LU,
            Lecture::Illisible { .. } => VERDICT_ILLISIBLE,
        }
    }

    /// La cause, en clé. `CAUSE_AUCUNE` quand la lecture a eu lieu.
    pub fn cause(&self) -> &'static str {
        match self {
            Lecture::Lue(_) => CAUSE_AUCUNE,
            Lecture::Illisible { cause, .. } => cause,
        }
    }

    /// La valeur, si et seulement si elle a été lue. Le SEUL chemin vers une valeur publiable — il
    /// n'en existe pas d'autre, et c'est ce qui empêche un appelant de retomber sur un repli calme.
    pub fn valeur(&self) -> Option<&T> {
        match self {
            Lecture::Lue(v) => Some(v),
            Lecture::Illisible { .. } => None,
        }
    }

    /// Le détail libre — pour l'aveu et le journal, jamais pour une clé.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Lecture::Lue(_) => None,
            Lecture::Illisible { detail, .. } => Some(detail),
        }
    }

    /// `true` seulement si la source a été lue.
    pub fn est_lue(&self) -> bool {
        matches!(self, Lecture::Lue(_))
    }
}

/// LA CAUSE, DÉRIVÉE DE L'ERREUR SYSTÈME — un seul auteur pour cette traduction, comme dans le démon.
/// Chaque site de lecture qui l'appelle hérite du même vocabulaire, et un site suivant n'a pas à
/// réinventer ses propres clés : c'est ainsi que l'ensemble reste fermé sans que personne n'y pense.
pub fn cause_io(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => CAUSE_SOURCE_ABSENTE,
        std::io::ErrorKind::PermissionDenied => CAUSE_SOURCE_REFUSEE,
        _ => CAUSE_SOURCE_ILLISIBLE,
    }
}

// =================================================================================================
// LE RÉSULTAT D'UN LOT — UN LECTEUR NE PEUT PLUS RENDRE « RIEN » SANS DIRE S'IL A LU
// =================================================================================================

/// LE RÉSULTAT D'UNE LECTURE DE LOT : ce qui a été lu, ET le verdict de lisibilité de la source.
///
/// POURQUOI LES DEUX ENSEMBLE, ET POURQUOI AUCUN `Default`. Le lot seul ne distingue pas « la source
/// était calme » de « la source n'est plus lisible » : c'est exactement la confusion que ce lot ferme.
/// Le verdict seul perdrait les enregistrements déjà lus quand une lecture s'interrompt EN COURS de
/// lot — or un lot partiel est un fait double : ce qui a été lu doit partir, et l'incomplétude doit se
/// dire. `Releve` porte donc les deux, et n'expose que trois constructeurs NOMMÉS. Il n'implémente ni
/// `Default`, ni `From<Vec<_>>` : un lecteur écrit demain ne peut pas rendre un lot vide « par
/// inadvertance », il doit CHOISIR entre `lu`, `illisible` et `partiel`.
#[derive(Debug)]
pub struct Releve {
    /// Les enregistrements effectivement lus (éventuellement aucun — c'est alors un VRAI aucun).
    pub records: Vec<crate::source::NativeRecord>,
    /// Le verdict de lisibilité de la source pour CE lot.
    pub lisibilite: Lecture<()>,
    /// Le mot GROSSIER du contrat shell, choisi PAR LE SITE : un binaire de collecte absent est une
    /// dépendance manquante, un journal refusé est une source manquante, un poll non-2xx est un point
    /// d'accès injoignable. Sur un lot LU il vaut `RAISON_SOURCE_ABSENTE` et n'est jamais consulté.
    pub raison: &'static str,
}

impl Releve {
    /// La source a été lue jusqu'au bout. `records` peut être vide : c'est un vrai « rien de neuf ».
    pub fn lu(records: Vec<crate::source::NativeRecord>) -> Self {
        Self { records, lisibilite: Lecture::Lue(()), raison: RAISON_SOURCE_ABSENTE }
    }

    /// La source n'a pas pu être lue du tout. AUCUN enregistrement, et les DEUX mots sont nommés.
    pub fn illisible(raison: &'static str, cause: &'static str, detail: impl Into<String>) -> Self {
        Self {
            records: Vec::new(),
            lisibilite: Lecture::Illisible { cause, detail: detail.into() },
            raison,
        }
    }

    /// La lecture s'est interrompue EN COURS de lot : ce qui a été lu part quand même, et
    /// l'incomplétude est avouée. Un lot tronqué en silence est plus petit que la réalité — pour un
    /// consommateur qui compte, c'est aussi dangereux qu'un lot vide.
    pub fn partiel(
        records: Vec<crate::source::NativeRecord>,
        raison: &'static str,
        cause: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self { records, lisibilite: Lecture::Illisible { cause, detail: detail.into() }, raison }
    }

    /// Le lecteur n'a rien à faire ce tour-ci (cadence non échue, lot de taille nulle demandé) : la
    /// source n'a pas été INTERROGÉE, donc rien n'a échoué. C'est `lu` avec zéro enregistrement, et
    /// ce n'est pas un abus : le consommateur n'a aucune raison de s'alarmer d'un tour sans travail.
    pub fn rien_a_faire() -> Self {
        Self::lu(Vec::new())
    }
}

// =================================================================================================
// L'AVEU — LE CANAL D'INDISPONIBILITÉ DÉJÀ LIVRÉ, À L'IDENTIQUE
// =================================================================================================

/// FNV-1a 64 bits — même empreinte déterministe que la dédup des sources génériques. Sert ici à
/// stabiliser la clé de l'aveu : deux aveux au même contenu, dans la même heure, portent la même clé.
fn empreinte(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// L'AVEU D'UNE SOURCE QUI NE PEUT PAS ÊTRE LUE, AU CONTRAT DE `collectors/lib.sh`.
///
/// LE CONTRAT REPRIS MOT POUR MOT — parce que c'est ce que la règle livrée sait lire :
///   `category=config`, `severity=2`, `fields.type="collector-availability"`,
///   `fields.collect_status="unavailable"`, `fields.reason=<vocabulaire fermé shell>`,
///   `fields.detail=<texte libre>`. S'y ajoutent DEUX champs propres à cette surface :
///   `fields.cause` (le mot FIN, celui du démon) et `fields.verdict` (`illisible`).
///
/// LA CLÉ DE DÉDOUBLONNAGE PORTE UN SEAU HORAIRE, comme celle du shell : un agent cadencé à la minute
/// qui reste aveugle écrit ainsi ~24 lignes par jour au lieu de 1440, tout en RÉ-AFFIRMANT son
/// incapacité chaque heure — une clé purement de contenu ferait vieillir l'aveu jusqu'à le rendre
/// invisible. Elle ne porte rien de propre à la machine : le central cloisonne déjà `event.dedup` par
/// l'hôte ATTESTÉ à l'écriture (cf. `dedup_scoped_by_host`), donc deux hôtes au même trou ne
/// s'effacent pas l'un l'autre.
pub fn event_indisponibilite(
    source: &str,
    host: &str,
    raison: &'static str,
    cause: &'static str,
    detail: &str,
    ts: i64,
) -> Event {
    // LES DEUX ENSEMBLES FERMÉS SONT TENUS ICI, pas seulement écrits : un mot hors table ferait de ces
    // champs une surface libre, et c'est ainsi qu'une dimension de recherche devient inexploitable. En
    // production le contrôle s'efface (aucun coût par événement) ; en développement et dans la suite,
    // il fait tomber le premier site qui inventerait une clé.
    debug_assert!(RAISONS.contains(&raison), "raison hors de l'ensemble fermé du contrat shell : {raison:?}");
    debug_assert!(CAUSES.contains(&cause), "cause hors de l'ensemble fermé du démon : {cause:?}");
    debug_assert!(cause != CAUSE_AUCUNE, "un aveu d'indisponibilité sans cause n'avoue rien");
    let fields = json!({
        "type": "collector-availability",
        "collector": source,
        "collect_status": "unavailable",
        "reason": raison,
        "cause": cause,
        "verdict": VERDICT_ILLISIBLE,
        "detail": detail,
    });
    let dd = format!("avail-{source}-{:x}-{}", empreinte(&fields.to_string()), ts / 3600);
    Event {
        ts,
        host: host.to_string(),
        source: source.to_string(),
        category: "config".to_string(),
        // Sévérité 2 (avertissement), comme `plume_unavailable` : ce n'est pas une attaque, c'est un
        // TROU DE COUVERTURE — et un trou de couverture doit se voir.
        severity: 2,
        message: format!("source {source} illisible : {cause} ({raison}) — {detail}"),
        fields,
        dedup: Some(dd),
    }
}

// =================================================================================================
// L'IDENTITÉ DE L'HÔTE — LA MÊME LECTURE QUE `S33`, SUR LA SURFACE D'ENTRÉE
// =================================================================================================

/// LE NOM PUBLIÉ QUAND L'IDENTITÉ N'A PAS PU ÊTRE LUE. Ce n'est PAS un repli : c'est le VERDICT, mis
/// à la place de la valeur.
///
/// POURQUOI PAS `unknown`, QUI ÉTAIT LÀ. Un nom d'hôte plausible ment mieux qu'un zéro : il est
/// indiscernable d'une lecture réussie, y compris pour qui relit le code, et TOUTES les machines qui
/// échouent y tombent — leurs séries se confondent en une seule, et une machine réellement nommée
/// `unknown` se voit attribuer les événements des autres. Le mot ci-dessous ne peut être le nom
/// d'aucune machine (il n'est pas un nom d'hôte valide : il porte le mot de verdict du démon), il
/// se cherche tel quel, et il n'arrive JAMAIS seul — l'aveu d'indisponibilité part avec lui.
///
/// CE QUE CE CAS NE COÛTE PAS : les événements continuent de partir. Un agent qui refuserait
/// d'expédier faute de connaître son propre nom transformerait une panne d'IDENTITÉ en perte totale de
/// télémétrie, ce qui est strictement pire. Et lorsque le jeton de l'agent est LIÉ, le central écrase
/// de toute façon ce champ par l'hôte attesté : le cas dangereux est celui du jeton non lié, où le
/// nom déclaré est publié tel quel — c'est précisément celui-là qu'un nom plausible rendait muet.
pub const HOTE_NON_LU: &str = "hote-illisible";

/// L'IDENTITÉ DE CET HÔTE, LUE OU AVOUÉE — jamais inventée.
///
/// PARAMÉTRÉE SUR SES DEUX SOURCES — le fichier ET les variables arrivent en argument. Une suite de
/// tests exerce donc toutes les combinaisons sans dépendre du nom de la machine qui l'exécute, ce
/// qu'une fonction lisant `/proc/sys/kernel/hostname` en dur n'aurait su faire dans aucun cas.
///
/// LA PRÉCÉDENCE EST CELLE D'AVANT, À LA LETTRE : le fichier d'abord, les variables ensuite, dans
/// l'ordre donné. Ce qui change est le DERNIER cas — il n'y a plus de troisième valeur, il y a un aveu.
///
/// UN FICHIER PRÉSENT MAIS VIDE N'EST PAS UNE IDENTITÉ. Il est lu, il est compris, et ce qu'il porte
/// n'est pas un nom d'hôte : c'est `forme_inconnue`, pas `source_absente`. La distinction n'est pas
/// cosmétique — la première se répare en écrivant le fichier, la seconde en le créant.
pub fn identite_hote_depuis(
    chemin: Option<&std::path::Path>,
    variables: &[Option<&str>],
) -> Lecture<String> {
    let mut echec_fichier: Option<(&'static str, String)> = None;
    if let Some(p) = chemin {
        match std::fs::read_to_string(p) {
            Ok(t) => {
                let t = t.trim().to_string();
                if !t.is_empty() {
                    return Lecture::Lue(t);
                }
                echec_fichier = Some((
                    CAUSE_FORME_INCONNUE,
                    format!("{} : lu, mais ne porte aucun nom d'hôte (vide ou blancs)", p.display()),
                ));
            }
            Err(e) => echec_fichier = Some((cause_io(&e), format!("{} : {e}", p.display()))),
        }
    }
    for v in variables {
        if let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) {
            return Lecture::Lue(v.to_string());
        }
    }
    match echec_fichier {
        Some((cause, detail)) => Lecture::Illisible {
            cause,
            detail: format!("{detail} ; et aucune variable d'environnement de repli renseignée"),
        },
        None => Lecture::Illisible {
            cause: CAUSE_SOURCE_ABSENTE,
            detail: "aucune source d'identité sur cette plateforme : ni fichier de nom d'hôte, ni \
                     variable d'environnement renseignée"
                .to_string(),
        },
    }
}

/// L'IDENTITÉ RÉELLE DE CET HÔTE. Le seul endroit du module qui nomme un chemin système ou une
/// variable — tout le reste travaille sur des paramètres, donc s'exerce.
pub fn identite_hote() -> Lecture<String> {
    #[cfg(target_os = "linux")]
    let chemin: Option<&std::path::Path> = Some(std::path::Path::new("/proc/sys/kernel/hostname"));
    #[cfg(not(target_os = "linux"))]
    let chemin: Option<&std::path::Path> = None;
    let h = std::env::var("HOSTNAME").ok();
    let c = std::env::var("COMPUTERNAME").ok();
    identite_hote_depuis(chemin, &[h.as_deref(), c.as_deref()])
}

#[cfg(test)]
mod tests;
