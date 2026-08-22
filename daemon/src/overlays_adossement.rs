//! `P4.1-r` — CE QUI ADOSSE UN OVERLAY À UN FICHIER : le listing d'un sous-dossier de `config.d`, lu ou
//! AVOUÉ ; le bilan d'un chargement ; et le REFUS d'élaguer sur un adossement qu'on n'a pas pu lire.
//!
//! LE DÉFAUT QUE CE MODULE FERME. `overlay_files` rendait la liste VIDE quand `read_dir` échouait, et
//! sautait (`flatten`) toute entrée que l'énumération refusait. Deux consommateurs en faisaient deux
//! fautes distinctes :
//!   * au DÉMARRAGE, les chargeurs ne chargeaient rien, et la ligne de résumé — imprimée seulement quand
//!     un compte est positif — ne disait rien non plus. Les règles livrées (`config.d/rules`, `sigma`)
//!     n'existaient pas, et rien ne le montrait : sur une base neuve, AUCUNE détection ;
//!   * à l'ÉLAGAGE (`prune_orphan_overlays`), une liste vide se lisait « plus aucun fichier adossé », et
//!     TOUTES les règles, parseurs et playbooks `managed=1` étaient SUPPRIMÉS de la base. Un dossier
//!     momentanément illisible effaçait l'ensemble des détections de l'opérateur, sans erreur.
//! Même forme un cran plus bas : un fichier de règle illisible ou invalide au moment de l'élagage ne
//! rendait pas de nom, donc sa règle était élaguée comme orpheline.
//!
//! LA FORME EST CELLE DE `S32` : un dossier ABSENT est un fait (`Lue(vide)` — les sous-dossiers sont
//! optionnels, c'est le contrat documenté) ; un dossier qu'on ne sait pas LIRE en est un autre
//! (`Illisible`, cause dans l'ensemble fermé `CAUSES`) ; et un parcours interrompu n'est pas un
//! parcours complet — une entrée illisible rend le listing entier `Illisible`, parce qu'un listing
//! partiel est exactement ce qui ferait élaguer les règles manquantes.
use crate::mesure_environnement::{cause_io, Mesure, CAUSE_FORME_INCONNUE};
use std::path::{Path, PathBuf};

/// LE LISTING d'un sous-dossier d'overlays, trié (ordre déterministe), filtré par `retenu`.
pub(crate) fn lister(dir: &Path, retenu: fn(&Path) -> bool) -> Mesure<Vec<PathBuf>> {
    // ABSENT est un FAIT, pas une panne : les sous-dossiers de `config.d` sont optionnels, et un dossier
    // qui n'existe pas ne contient rien. C'est `NotFound` SEUL qui vaut absence — un parent refusé, un
    // lien cassé ou une E/S tombent dans `read_dir`, qui AVOUE. Testé comme un fait (et non comme la
    // branche d'échec d'un `match`), parce que c'en est un.
    if matches!(std::fs::metadata(dir), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Mesure::Lue(Vec::new());
    }
    let entrees = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", dir.display()) },
    };
    let mut v = Vec::new();
    for entree in entrees {
        let p = match entree {
            Ok(e) => e.path(),
            Err(e) => {
                return Mesure::Illisible {
                    cause: cause_io(&e),
                    detail: format!(
                        "{} : parcours interrompu ({e}) — un listing partiel ferait passer les fichiers manquants pour retirés",
                        dir.display()
                    ),
                }
            }
        };
        if p.is_file() && retenu(&p) {
            v.push(p);
        }
    }
    v.sort();
    Mesure::Lue(v)
}

/// CE QU'UN CHARGEUR D'OVERLAYS REND : ce qu'il a chargé, ce qu'il a IGNORÉ, et si le listing lui-même a
/// pu être lu. Les deux compteurs sont des CHAMPS, incrémentés par `+= 1` au site même de l'abandon :
/// c'est la forme que la garde `check_coverage_loss_is_never_silent.py` reconnaît comme une trace, et
/// une méthode qui cacherait l'incrément la rendrait aveugle à ce qu'elle doit voir.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Chargement {
    pub(crate) charges: u32,
    /// Fichiers présents mais NON chargés : illisibles, JSON invalide, sans `name`, motif ou requête qui
    /// ne compile pas, document Sigma intraduisible.
    pub(crate) ignores: u32,
    /// `Lue(())` : le dossier a été listé (absent compris). `Illisible` : il n'a pas pu l'être — rien n'a
    /// été chargé ni compté, et c'est cet aveu qui domine.
    pub(crate) listing: Mesure<()>,
}

impl Chargement {
    /// Ouvre le listing d'un sous-dossier : rend les fichiers à parcourir, et le chargement déjà posé
    /// (vide si le listing est illisible — l'aveu est dans `listing`, le chargeur n'a rien à parcourir).
    pub(crate) fn ouvrir(dir: &Path, retenu: fn(&Path) -> bool) -> (Vec<PathBuf>, Chargement) {
        match lister(dir, retenu) {
            Mesure::Lue(fichiers) => (fichiers, Chargement { charges: 0, ignores: 0, listing: Mesure::Lue(()) }),
            Mesure::Illisible { cause, detail } => {
                (Vec::new(), Chargement { charges: 0, ignores: 0, listing: Mesure::Illisible { cause, detail } })
            }
        }
    }

    /// Le bilan au format d'un tick : `Illisible` si le listing l'est, sinon le compte des ignorés.
    pub(crate) fn bilan(&self) -> Mesure<u32> {
        match &self.listing {
            Mesure::Lue(()) => Mesure::Lue(self.ignores),
            Mesure::Illisible { cause, detail } => Mesure::Illisible { cause, detail: detail.clone() },
        }
    }
}

/// LE BILAN DE TOUT UN `config.d` : la somme des chargements, et l'aveu dès qu'un listing l'exige.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ChargementTotal {
    pub(crate) charges: u32,
    acc: crate::bilan_de_tick::BilanDuPlanificateur,
}

impl ChargementTotal {
    pub(crate) fn absorber(&mut self, c: Chargement) -> u32 {
        self.charges += c.charges;
        self.acc.absorber(c.bilan());
        c.charges
    }

    /// Deux racines ou deux familles de sous-dossiers (overlays de détection, objets OAC) : un seul bilan.
    pub(crate) fn fusionner(&mut self, autre: ChargementTotal) {
        self.charges += autre.charges;
        self.acc.absorber(autre.acc.bilan_de_tick());
    }

    /// Ignorés (ou listing illisible), au format publié par la surface d'état.
    pub(crate) fn mesure(&self) -> Mesure<u64> {
        self.acc.mesure()
    }
}

/// POURQUOI UN ÉLAGAGE EST REFUSÉ. Un adossement qu'on n'a pas pu lire — dossier illisible, fichier
/// illisible, invalide ou intraduisible — n'est PAS « plus de fichier » : élaguer dessus supprimerait des
/// règles que l'opérateur a toujours. L'élagage est donc REFUSÉ en nommant le fichier, et c'est à
/// l'opérateur de réparer ou retirer le fichier, jamais au démon de deviner.
#[derive(Debug)]
pub(crate) enum RefusDePrune {
    Base(rusqlite::Error),
    Adossement { cause: &'static str, detail: String },
}

impl From<rusqlite::Error> for RefusDePrune {
    fn from(e: rusqlite::Error) -> Self {
        RefusDePrune::Base(e)
    }
}

impl std::fmt::Display for RefusDePrune {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefusDePrune::Base(e) => write!(f, "base : {e}"),
            RefusDePrune::Adossement { cause, detail } => write!(
                f,
                "adossement illisible ({cause}) : {detail} — élagage REFUSÉ, rien n'a été supprimé (un fichier qu'on ne sait pas lire n'est pas un fichier retiré)"
            ),
        }
    }
}

impl RefusDePrune {
    /// Un listing illisible, porté tel quel.
    pub(crate) fn listing(cause: &'static str, detail: String) -> Self {
        RefusDePrune::Adossement { cause, detail }
    }

    /// Un fichier dont le nom adossé ne peut pas être établi : `forme_inconnue` quand il a été lu mais
    /// pas compris (JSON invalide, Sigma intraduisible, sans `name`), la cause d'E/S quand il n'a pas pu
    /// être lu.
    pub(crate) fn fichier(path: &Path, cause: &'static str, pourquoi: &str) -> Self {
        RefusDePrune::Adossement { cause, detail: format!("{} : {pourquoi}", path.display()) }
    }

    pub(crate) fn forme(path: &Path, pourquoi: &str) -> Self {
        Self::fichier(path, CAUSE_FORME_INCONNUE, pourquoi)
    }
}

/// Le `Mesure<Vec<_>>` d'un listing, converti en `Result` pour un consommateur qui REFUSE sur illisible.
pub(crate) fn fichiers_ou_refus(dir: &Path, retenu: fn(&Path) -> bool) -> Result<Vec<PathBuf>, RefusDePrune> {
    match lister(dir, retenu) {
        Mesure::Lue(v) => Ok(v),
        Mesure::Illisible { cause, detail } => Err(RefusDePrune::listing(cause, detail)),
    }
}

/// Le prédicat des overlays JSON (`*.json`).
pub(crate) fn est_json(p: &Path) -> bool {
    p.extension().and_then(|s| s.to_str()) == Some("json")
}

/// Le prédicat des overlays Sigma (`*.yml` / `*.yaml` / `*.json` — un fichier peut porter plusieurs
/// documents YAML).
pub(crate) fn est_sigma(p: &Path) -> bool {
    matches!(p.extension().and_then(|s| s.to_str()), Some("yml" | "yaml" | "json"))
}

/// Le nom sous lequel la surface d'état publie le bilan du dernier chargement d'overlays.
pub(crate) const PASSE_OVERLAYS: &str = "overlays";
