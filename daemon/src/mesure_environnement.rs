//! `S32` — UNE MESURE QUI ÉCHOUE NE REND PAS LA VALEUR LA PLUS RASSURANTE.
//!
//! LE DÉFAUT QUE CE MODULE FERME. Deux lectures d'environnement publiaient un ZÉRO quand leur source
//! n'était pas lisible : le couple temps processeur / mémoire résidente du processus (`unwrap_or((0.0,
//! 0))` sur `/proc/self`) et la profondeur de la file d'ingest (`Err(_) => 0` sur le répertoire de
//! spool). Une file vide et une file qu'on ne sait pas lire sont deux faits OPPOSÉS ; les confondre
//! transforme une panne d'observabilité en bonne nouvelle. Le zéro est en outre la valeur la plus
//! calme de chacune de ces séries : un tableau de bord qui les regarde voit « rien à signaler »
//! précisément quand la mesure a disparu, et l'absence de signal s'y lit comme un bon signal.
//!
//! LA FORME EST CELLE DE `S28` (`sqlite_plafond`), et ce n'est pas une coïncidence de style : c'est la
//! même figure, donc le même remède. Trois pièces, dans cet ordre :
//!   1. UN TYPE À PLUSIEURS CAS. `Mesure<T>` n'a pas de valeur par défaut : soit la mesure a été LUE,
//!      soit elle est ILLISIBLE et porte alors une CAUSE. Le `match` est exhaustif, donc « je ne sais
//!      pas » ne peut pas se ranger silencieusement du côté « tout va bien ».
//!   2. DES FONCTIONS PARAMÉTRÉES SUR LEURS CHEMINS ET SUR LES CONSTANTES DE L'HÔTE. Aucune des
//!      fonctions de lecture ne nomme `/proc` ni ne lit `sysconf` : la racine, la fréquence
//!      d'horloge et la taille de page arrivent en argument. Une suite de tests peut donc fabriquer
//!      chaque forme dans un temporaire possédé et obtenir le MÊME verdict sur n'importe quelle
//!      machine — y compris une machine sans `/proc`, ou une machine dont `/proc` répond
//!      parfaitement (c'est ce second témoin qui interdit qu'une fonction rendant TOUJOURS
//!      « illisible » passe pour correcte).
//!   3. UN MOT STABLE DANS LA SORTIE. `verdict()` rend `lu` ou `illisible`, et `cause()` rend une clé
//!      d'un ensemble FERMÉ. Ces mots sont un contrat de supervision : les renommer casse ce qui les
//!      observe.
//!
//! CE QUE LE CONSOMMATEUR VOIT, ET POURQUOI CE CHOIX-LÀ. La règle appliquée est : une mesure qu'on ne
//! sait pas prendre n'est JAMAIS publiée comme un nombre. Elle disparaît de la série, et un indicateur
//! de LISIBILITÉ prend sa place. Les deux ensemble, parce qu'aucun des deux seul ne suffit :
//!   * l'ABSENCE seule est honnête pour Prometheus (une série absente y est un premier concept, et ce
//!     dépôt s'en sert déjà — l'âge d'un exercice de restauration jamais fait est ABSENT plutôt que
//!     zéro, « publier 0 dirait restauré à l'instant ») ; mais elle ne distingue pas « la lecture a
//!     échoué » de « le scrape n'a pas eu lieu », et elle ne dit pas POURQUOI ;
//!   * l'INDICATEUR seul laisserait la série numérique à zéro, c'est-à-dire le défaut lui-même.
//! Donc : série numérique ABSENTE + jauge `…_lisible` à 0 portant la cause en étiquette. C'est
//! exactement la forme déjà retenue pour la ventilation de la base (`plume_db_ventilation_ok{cause=…}`).
//!
//! CARDINALITÉ, ET SON PIRE CAS. L'étiquette `cause` ne prend ses valeurs que dans `CAUSES` — cinq
//! clés, fermées, vérifiées par un test. Chaque série `…_lisible` vaut donc AU PLUS 5 séries de
//! sortie, et une seule à la fois puisque les cas sont exclusifs (la valeur précédente disparaît du
//! scrape suivant). Le détail libre — message d'erreur du système, chemin tenté — ne part JAMAIS en
//! étiquette : il n'a aucune borne. Il vit dans le JSON du panneau, où il est lu par un humain.
use crate::*;

/// LA CAUSE QUAND IL N'Y EN A PAS. Une étiquette toujours présente (plutôt qu'absente sur succès)
/// garde une forme de série UNIQUE : un `by cause` n'a pas de trou à expliquer.
pub(crate) const CAUSE_AUCUNE: &str = "aucune";
/// La source n'existe pas. Cas de la file d'ingest dont le répertoire a disparu, et du conteneur qui
/// masque `/proc`. C'est le cas qui se lisait « file vide ».
pub(crate) const CAUSE_SOURCE_ABSENTE: &str = "source_absente";
/// La source existe mais son accès est refusé. Distinct de l'absence : la première se répare en
/// recréant un répertoire, la seconde en corrigeant des droits ou un profil de confinement.
pub(crate) const CAUSE_SOURCE_REFUSEE: &str = "source_refusee";
/// La source existe, l'accès est permis, la lecture échoue quand même (E/S, système de fichiers
/// démonté sous les pieds du processus, entrée de répertoire illisible en cours de parcours).
pub(crate) const CAUSE_SOURCE_ILLISIBLE: &str = "source_illisible";
/// La source a été LUE mais sa forme n'est pas comprise. `S28` a montré que ce cas se perd le plus
/// facilement : un fichier présent dont le format a changé était ignoré en silence, et l'appelant
/// concluait comme si rien n'avait été trouvé. Il porte donc une clé à lui.
pub(crate) const CAUSE_FORME_INCONNUE: &str = "forme_inconnue";

/// L'ENSEMBLE FERMÉ DES CAUSES — c'est LUI qui borne la cardinalité de toutes les séries `…_lisible`.
/// Une cause ajoutée sans passer par cette table est invisible du test qui compte, ce qui est
/// exactement la raison d'écrire la table.
pub(crate) const CAUSES: [&str; 5] =
    [CAUSE_AUCUNE, CAUSE_SOURCE_ABSENTE, CAUSE_SOURCE_REFUSEE, CAUSE_SOURCE_ILLISIBLE, CAUSE_FORME_INCONNUE];

/// CE QU'UNE LECTURE D'ENVIRONNEMENT PEUT VALOIR. Deux cas, exclusifs, et AUCUNE valeur par défaut :
/// il n'existe pas de constructeur qui rende un zéro faute de savoir. C'est la propriété que le type
/// tient et qu'un `Option<T>` déplié par `unwrap_or(0)` ne tenait pas.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Mesure<T> {
    /// La source a été lue et comprise. La valeur peut parfaitement être zéro — et c'est alors un
    /// VRAI zéro, ce que le consommateur doit pouvoir distinguer du cas suivant.
    Lue(T),
    /// La source n'a pas pu être lue, ou pas comprise. `cause` est une clé stable et bornée,
    /// publiable en étiquette ; `detail` est du texte libre pour un lecteur humain, JAMAIS une
    /// étiquette (il porte des chemins et des messages système : aucune borne de cardinalité).
    Illisible { cause: &'static str, detail: String },
}

/// LE MOT DE VERDICT quand la mesure a été prise. Stable, sans espace : c'est LUI le signal côté
/// consommateur, comme les quatre mots de `S28`. Le renommer casse ce qui l'observe.
pub(crate) const VERDICT_LU: &str = "lu";
/// LE MOT DE VERDICT quand la source n'est pas lisible. Ce mot est la seule chose qui sépare « la file
/// est vide » de « je ne sais pas lire la file ».
pub(crate) const VERDICT_ILLISIBLE: &str = "illisible";

impl<T> Mesure<T> {
    /// LE MOT DE VERDICT — stable, un par cas. La bascule d'une mesure prise à une mesure perdue
    /// change ce mot, donc une supervision qui l'observe la VOIT.
    pub(crate) fn verdict(&self) -> &'static str {
        match self {
            Mesure::Lue(_) => VERDICT_LU,
            Mesure::Illisible { .. } => VERDICT_ILLISIBLE,
        }
    }

    /// La cause, en clé d'étiquette. `CAUSE_AUCUNE` quand la mesure a été prise.
    pub(crate) fn cause(&self) -> &'static str {
        match self {
            Mesure::Lue(_) => CAUSE_AUCUNE,
            Mesure::Illisible { cause, .. } => cause,
        }
    }

    /// La valeur, si et seulement si elle a été lue. Le SEUL chemin vers un nombre publiable — il n'en
    /// existe pas d'autre, et c'est ce qui empêche un appelant de retomber sur un zéro par défaut.
    pub(crate) fn valeur(&self) -> Option<&T> {
        match self {
            Mesure::Lue(v) => Some(v),
            Mesure::Illisible { .. } => None,
        }
    }

    /// Le détail libre — pour le panneau et le journal, JAMAIS pour une étiquette (il porte des
    /// chemins et des messages système : aucune borne de cardinalité).
    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Mesure::Lue(_) => None,
            Mesure::Illisible { detail, .. } => Some(detail),
        }
    }

    /// LE VERDICT ET SA CAUSE, POSÉS À CÔTÉ D'UNE VALEUR QUI N'EST ÉCRITE QUE SI ELLE A ÉTÉ LUE.
    /// Un seul auteur pour cette convention de nommage : `<cle>`, `<cle>_verdict`, `<cle>_cause`,
    /// `<cle>_detail`. Un consommateur qui trouve `<cle>` absente sait où lire pourquoi.
    pub(crate) fn poser_dans(&self, objet: &mut serde_json::Map<String, Value>, cle: &str)
    where
        T: Copy + Into<Value>,
    {
        if let Some(v) = self.valeur() {
            objet.insert(cle.to_string(), (*v).into());
        }
        objet.insert(format!("{cle}_verdict"), json!(self.verdict()));
        objet.insert(format!("{cle}_cause"), json!(self.cause()));
        if let Some(d) = self.detail() {
            objet.insert(format!("{cle}_detail"), json!(d));
        }
    }
}

/// L'INDICATEUR DE LISIBILITÉ, en Prometheus : une jauge 1/0 étiquetée par la cause. Publiée dans les
/// DEUX cas — une jauge qui n'apparaîtrait qu'en panne serait elle-même absente quand tout va bien, et
/// on ne saurait pas la distinguer d'un scrape manqué.
///
/// DÉRIVÉE DU MOT DE VERDICT et non recalculée : la valeur de la jauge et le champ JSON ne peuvent pas
/// diverger, puisqu'ils viennent de la même chaîne. Tout ce qui n'est pas `lu` vaut 0 — un verdict
/// ajouté demain est donc bruyant par défaut, jamais rangé du bon côté par inadvertance.
pub(crate) fn exposition_prom_lisible(nom: &str, quoi: &str, verdict: &str, cause: &str) -> String {
    // LA BORNE DE CARDINALITÉ EST TENUE ICI, pas seulement écrite : une cause hors de l'ensemble fermé
    // ferait de l'étiquette une surface libre, et c'est ainsi qu'une série de supervision explose. En
    // production le contrôle s'efface (aucun coût par relevé) ; en développement et dans la suite, il
    // fait tomber le premier site qui inventerait une clé.
    debug_assert!(CAUSES.contains(&cause), "cause hors de l'ensemble fermé — cardinalité non bornée : {cause:?}");
    format!(
        "# HELP {nom} 1 si {quoi} a été LUE, 0 si sa source n'est pas lisible (cause en étiquette ; la \
         série de valeur est alors ABSENTE, jamais zéro)\n# TYPE {nom} gauge\n{nom}{{cause=\"{cause}\"}} {}\n",
        u8::from(verdict == VERDICT_LU),
    )
}

/// LA CAUSE, DÉRIVÉE DE L'ERREUR SYSTÈME — un seul auteur pour cette traduction. Chaque site de
/// lecture qui l'appelle hérite du même vocabulaire, et un site suivant n'a pas à réinventer ses
/// propres clés (c'est ainsi que la cardinalité reste bornée sans que personne n'y pense).
pub(crate) fn cause_io(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => CAUSE_SOURCE_ABSENTE,
        std::io::ErrorKind::PermissionDenied => CAUSE_SOURCE_REFUSEE,
        _ => CAUSE_SOURCE_ILLISIBLE,
    }
}

/// Lit un fichier et rend `Mesure::Illisible` NOMMÉE en cas d'échec — avec le chemin tenté, parce
/// qu'un aveu sans le chemin ne se répare pas.
fn texte<T>(chemin: &std::path::Path) -> Result<String, Mesure<T>> {
    std::fs::read_to_string(chemin).map_err(|e| Mesure::Illisible {
        cause: cause_io(&e),
        detail: format!("{} : {e}", chemin.display()),
    })
}

// =================================================================================================
// LE COUPLE TEMPS PROCESSEUR / MÉMOIRE RÉSIDENTE DU PROCESSUS
// =================================================================================================

/// PURE — le décodage seul, sans aucun accès au système de fichiers ni à `sysconf`. La fréquence
/// d'horloge et la taille de page arrivent en argument : deux constantes de l'hôte qui, laissées
/// implicites, rendraient le résultat dépendant de la machine qui exécute la suite.
///
/// `stat` : la forme de `/proc/<pid>/stat`. Le champ `comm` (2e) peut contenir des espaces ET des
/// parenthèses — le décodage repart donc APRÈS la DERNIÈRE `)`, jamais après la première.
/// `statm` : la forme de `/proc/<pid>/statm`, dont le 2e champ est le nombre de pages résidentes.
///
/// Toute forme non reconnue rend `CAUSE_FORME_INCONNUE` et NON un zéro : un `/proc` dont le format
/// changerait doit se voir, pas se lire « processus au repos ».
pub(crate) fn cpu_rss_depuis_textes(stat: &str, statm: &str, hz: f64, taille_page: u64) -> Mesure<(f64, u64)> {
    let inconnue = |quoi: &str| Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: quoi.to_string() };
    let Some(fin_comm) = stat.rfind(')') else {
        return inconnue("stat : aucune parenthèse fermante (champ `comm` absent)");
    };
    let champs: Vec<&str> = stat[fin_comm + 1..].split_whitespace().collect();
    // Après la `)` : index 0 = state (champ 3). utime = champ 14 -> index 11 ; stime = champ 15 -> index 12.
    let (Some(u), Some(s)) = (champs.get(11), champs.get(12)) else {
        return inconnue("stat : moins de 15 champs après `comm` (utime/stime absents)");
    };
    let (Ok(utime), Ok(stime)) = (u.parse::<u64>(), s.parse::<u64>()) else {
        return inconnue("stat : utime/stime non numériques");
    };
    if hz <= 0.0 {
        return inconnue("fréquence d'horloge nulle ou négative : le temps processeur serait inventé");
    }
    let Some(pages) = statm.split_whitespace().nth(1) else {
        return inconnue("statm : moins de 2 champs (pages résidentes absentes)");
    };
    let Ok(pages) = pages.parse::<u64>() else {
        return inconnue("statm : pages résidentes non numériques");
    };
    Mesure::Lue(((utime + stime) as f64 / hz, pages.saturating_mul(taille_page)))
}

/// PARAMÉTRÉE SUR SA RACINE — c'est ce qui la rend exerçable. `racine_proc` est `/proc` en
/// production ; une suite de tests lui présente une arborescence fabriquée dans un temporaire
/// possédé, et joue chaque forme sans dépendre de l'hôte.
pub(crate) fn cpu_rss_depuis(racine_proc: &std::path::Path, hz: f64, taille_page: u64) -> Mesure<(f64, u64)> {
    let stat = match texte(&racine_proc.join("self").join("stat")) {
        Ok(t) => t,
        Err(m) => return m,
    };
    let statm = match texte(&racine_proc.join("self").join("statm")) {
        Ok(t) => t,
        Err(m) => return m,
    };
    cpu_rss_depuis_textes(&stat, &statm, hz, taille_page)
}

/// Les valeurs RÉELLES. Le seul endroit du module qui nomme `/proc` et interroge `sysconf` — tout le
/// reste travaille sur des paramètres, donc s'exerce.
pub(crate) fn cpu_rss() -> Mesure<(f64, u64)> {
    // SÛRETÉ : `sysconf` ne lit qu'une constante du système et n'écrit rien. Même forme que l'appel
    // déjà présent dans `vieillissement_serie` pour `clock_gettime`.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // Une constante système non renseignée n'est pas remplacée par une valeur d'usage : elle est
    // passée telle quelle, et le décodage la refuse en nommant `forme_inconnue`. Inventer 100 Hz ou
    // 4 Kio ici reviendrait à publier un temps processeur et un RSS calculés sur une supposition.
    cpu_rss_depuis(std::path::Path::new("/proc"), hz as f64, page.max(0) as u64)
}

// =================================================================================================
// LA PROFONDEUR DE LA FILE D'INGEST
// =================================================================================================

/// Une entrée de spool compte-t-elle dans la profondeur de file ? PURE, et dérivée du même prédicat
/// que le consommateur du spool : fichiers `.json`/`.ndjson`, jamais un temporaire (préfixe `.`).
pub(crate) fn entree_de_spool_comptee(nom: &str) -> bool {
    !nom.starts_with('.') && (nom.ends_with(".json") || nom.ends_with(".ndjson"))
}

/// PROFONDEUR DE LA FILE D'INGEST — paramétrée sur le répertoire, donc exerçable dans les deux sens :
/// un répertoire fabriqué et VIDE rend `Lue(0)` (un vrai zéro), un répertoire absent rend
/// `Illisible{source_absente}`. C'est cette distinction qui manquait : un répertoire disparu se
/// lisait « aucun retard d'ingest ».
///
/// UN PARCOURS INTERROMPU N'EST PAS UN PARCOURS COMPLET. Une entrée illisible en cours de route était
/// jusqu'ici sautée en silence (`flatten()`), ce qui rend un compte PLUS PETIT que la réalité —
/// c'est-à-dire, encore une fois, la valeur la plus rassurante. Le compte partiel est donc refusé.
pub(crate) fn profondeur_file_depuis(spool: &std::path::Path) -> Mesure<u64> {
    let entrees = match std::fs::read_dir(spool) {
        Ok(e) => e,
        Err(e) => {
            return Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", spool.display()) }
        }
    };
    let mut n = 0u64;
    for entree in entrees {
        match entree {
            Ok(e) => {
                if entree_de_spool_comptee(&e.file_name().to_string_lossy()) {
                    n += 1;
                }
            }
            Err(e) => {
                return Mesure::Illisible {
                    cause: cause_io(&e),
                    detail: format!("{} : parcours interrompu ({e}) — un compte partiel serait plus petit que la file réelle", spool.display()),
                }
            }
        }
    }
    Mesure::Lue(n)
}

// =================================================================================================
// LA TAILLE DE LA BASE
// =================================================================================================

/// TAILLE DE LA BASE (fichier principal + journal d'écriture), en octets. `stat` seulement, jamais un
/// `COUNT(*)`.
///
/// L'ASYMÉTRIE ENTRE LES DEUX FICHIERS EST DÉLIBÉRÉE, et c'est tout le contenu de cette fonction :
///   * le fichier PRINCIPAL introuvable est une ANOMALIE — la base est ouverte, son fichier devrait
///     exister. Rendre zéro annoncerait une base vide au moment où elle est en fait injoignable.
///   * le journal d'écriture ABSENT est un VRAI ZÉRO : hors mode WAL, ou après un checkpoint qui l'a
///     retiré, il n'y a légitimement aucun octet de journal. Le confondre avec une panne ferait
///     disparaître la taille de la base pour un état parfaitement normal — l'erreur symétrique.
///   * toute AUTRE erreur sur le journal (droits, E/S) reste une panne de mesure.
/// Chemin vide (aucune base configurée) : pas une mesure ratée, une absence de sujet -> `Lue(0)`.
pub(crate) fn taille_base_depuis(chemin: &std::path::Path) -> Mesure<u64> {
    if chemin.as_os_str().is_empty() {
        return Mesure::Lue(0);
    }
    let principal = match std::fs::metadata(chemin) {
        Ok(m) => m.len(),
        Err(e) => {
            return Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", chemin.display()) }
        }
    };
    let journal = std::path::PathBuf::from(format!("{}-wal", chemin.display()));
    let journal = match std::fs::metadata(&journal) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            return Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", journal.display()) }
        }
    };
    Mesure::Lue(principal + journal)
}
