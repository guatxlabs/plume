//! attente_serie — CE QU'UNE PASSE DE VIEILLISSEMENT COÛTE À UN ANALYSTE, DANS LE TEMPS.
//!
//! LE TROU QU'IL FERME (`P10.11-a`). L'attente d'une requête derrière le verrou de la connexion
//! partagée était mesurée — mais rendue DANS LA RÉPONSE de cette requête (`query_timing`), donc
//! visible d'un seul client, une seule fois, et corrélable par rien. Un exploitant qui voit une
//! requête lente ne peut pas répondre à « une passe de vieillissement tournait-elle ? » : les deux
//! faits ne vivent pas sur la même échelle de temps, et l'un des deux ne vit nulle part.
//!
//! POURQUOI UNE MOYENNE EST DISQUALIFIÉE D'AVANCE, ET POURQUOI LES QUANTILES LE SONT AUSSI.
//! L'exposition est RARE et TRÈS CONCENTRÉE : la passe tient le verrou pendant une petite fraction
//! de l'heure, et seules les requêtes qui arrivent DANS cette fraction attendent. Reproduit sur banc
//! local le 2026-08-20 (chaîne complète permis -> verrou partagé -> travail, borne interactive à 3,
//! arrivées régulières, une passe qui tient le verrou au milieu de la fenêtre) :
//!
//! | régime | moyenne | p95 | p99 | max | part portée par 5 échantillons |
//! |---|---|---|---|---|---|
//! | 200 req / 5 s, passe = 5 % de la fenêtre | 3,4 ms | 0,000 ms | 203 ms | 250 ms | **98,8 %** |
//! | 2 000 req / 5 s, passe = 0,5 % de la fenêtre | 0,09 ms | 0,000 ms | **0,000 ms** | 25 ms | 57,5 % |
//! | 2 000 req / 5 s, AUCUNE passe (témoin) | 0,000 ms | 0,000 ms | 0,000 ms | 0,0 ms | — |
//!
//! Deux conclusions, et ce sont elles qui choisissent la FORME de cette série :
//!   1. la moyenne sous-estime le pire échantillon d'un facteur **73** (3,4 ms contre 250 ms). Une
//!      série moyennée reproduirait exactement le défaut qu'on ferme ;
//!   2. **le p99 lui-même est AVEUGLE** au régime le plus proche de l'exploitation (une passe qui
//!      couvre une petite fraction de la fenêtre) : il rend 0,000 ms là où un analyste a attendu
//!      25 ms. Un quantile ne voit la queue que si la queue est plus épaisse que 1 − q, ce qui
//!      dépend de la CHARGE — une grandeur que la série ne connaît pas. Les quantiles sont donc
//!      écartés par la mesure, pas par goût.
//! Et une raison structurelle qui va dans le même sens : ces points sont agrégés par
//! `metric_rollup` (bucket horaire) en `AVG/MIN/MAX/COUNT`. Un quantile ne se ré-agrège PAS (la
//! moyenne de trente p99 ne veut rien dire) ; un MAX se ré-agrège exactement, et un COMPTE DE SEAU
//! se retrouve par `AVG × COUNT`. La forme retenue est celle qui SURVIT au rollup :
//!   * des **seaux** à bornes fixes (combien de requêtes ont attendu ≥ 1 ms, ≥ 10 ms, ≥ 100 ms…),
//!     qui rendent la concentration LISIBLE — « 6 requêtes sur 200 ont attendu plus de 100 ms » ;
//!   * un **maximum de fenêtre**, le seul chiffre qui ne dilue jamais l'échantillon unique ;
//!   * les **cumuls** par terme, qui disent ce que l'attente a coûté EN TOUT ;
//!   * le **compte d'observations**, sans lequel un seau ne se lit pas (5 sur 10 ≠ 5 sur 10 000).
//!
//! LA COMPOSITION AVEC L'ATTENTE DU PERMIT EST POSSIBLE, ET ELLE EST MAJORITAIRE. La borne
//! interactive et le verrou partagé sont deux files que la MÊME requête traverse l'une APRÈS
//! l'autre, sur la même tâche : leurs intervalles sont disjoints par construction, donc leur somme
//! ne double-compte rien (garde : `la_composition_ne_double_compte_pas`, qui oppose la somme au
//! temps mural de la requête). Elle n'est pas un raffinement : mesuré sur le même banc, dans le
//! régime chargé, l'attente du VERROU cumule 930 ms quand l'attente du PERMIT en cumule **16 400** —
//! la passe bloque les quelques porteurs de permit, et tout le reste de la charge fait la queue
//! DERRIÈRE eux. Publier le seul verrou aurait donc rendu **~5 %** du coût réel pour un analyste.
//! C'est le sens exact de « la mesure ne traverse pas le sémaphore » : ce n'est pas une nuance de
//! bord, c'est le gros du coût.
//!
//! POURQUOI DANS `metric` ET PAS SEULEMENT DANS `/metrics`. La corrélation est la raison d'être de
//! cette clé, et la fenêtre de vieillissement est publiée dans `metric` (`vieillissement_serie`).
//! Deux séries dans deux systèmes ne se corrèlent pas ; une série et une réponse HTTP encore moins.
//! Le raisonnement complet (pas de Prometheus dans le cluster, un fichier n'a aucun lecteur) est
//! écrit une fois pour toutes en tête de `ventilation_serie` : on l'HÉRITE, jusqu'à la voie
//! d'écriture partagée (`ecrire_points`). `/metrics` reçoit EN PLUS les cumuls de vie, à côté de
//! `plume_query_permit_wait_ms_total` — c'est là que les deux termes de la composition se lisent
//! l'un sous l'autre.
//!
//! CE QUI REND LA CORRÉLATION POSSIBLE, ET QUI EST LE VRAI CONTENU DE CETTE CLÉ.
//! `plume_cold_aging_duree_ms` dit qu'une passe a duré N ms, mais elle est écrite UNE FOIS, à
//! l'horodatage de la passe : sur une cadence horaire, elle ne dit pas dans QUELLE fenêtre de
//! publication la passe tombait. Cette série publie donc, à chaque fenêtre et sur la MÊME échelle
//! de temps que les attentes, le nombre de millisecondes de la fenêtre pendant lesquelles une
//! fenêtre de vieillissement était OUVERTE (`vieillissement_serie::chevauchement_us`). La question
//! « cette requête était-elle lente parce qu'une passe tournait ? » devient une lecture de deux
//! points portant le même horodatage :
//!     `metric plume_query_attente_fenetre_seaux by seau | timechart span=5m sum(value)`
//!     `metric plume_query_attente_fenetre_vieillissement_ms | timechart span=5m max(value)`
//!
//! LA CARDINALITÉ EST BORNÉE PAR CONSTRUCTION, ET C'EST DIT ICI : **onze** couples (nom, étiquette)
//! au plus, dans `metric` comme dans `/metrics` — six seaux, deux termes, trois séries nues. AUCUNE
//! étiquette ne vient d'une requête : ni route, ni URL, ni utilisateur, ni tenant. Ce n'est pas un
//! plafond qu'on tient, c'est une énumération fermée écrite dans le code, donc elle ne peut pas
//! croître avec le trafic ni avec la taille du routeur. (Le découpage PAR ROUTE existe déjà et vit
//! dans `semaphore_interactif`, où il est plafonné ; le refaire ici multiplierait les lignes de
//! `metric` par le nombre de gabarits pour une information déjà servie ailleurs.)
//!
//! CE QUE CETTE MESURE NE DIT PAS — écrit ici, dans le `# HELP` de chaque série, et dans l'index
//! public. Elle reste une BORNE INFÉRIEURE du coût pour un analyste :
//!   * elle ne compte que les requêtes qui passent par `QueryClock` (le chemin GXQL et la barre de
//!     recherche). Une route qui touche la connexion partagée sans horloge n'est pas comptée — son
//!     attente existe et reste invisible ;
//!   * elle ne compte QUE de l'attente : le travail RALENTI par une passe (cache de pages évincé,
//!     disque saturé) n'est pas de l'attente de verrou et n'apparaît nulle part ici ;
//!   * elle ne couvre pas les requêtes qui n'ont jamais obtenu de permit (arrêt du démon) ;
//!   * le chevauchement publié est la fenêtre de MESURE de la passe, pas la durée pendant laquelle
//!     elle tenait réellement le verrou : c'est une borne SUPÉRIEURE de l'exposition, et un
//!     indicateur de présence, pas une durée de verrou ;
//!   * l'accumulateur est de PROCESSUS, pas par tenant : en mode multi-tenant les attentes de tous
//!     les tenants s'additionnent et sont écrites dans la base par défaut, comme l'alerte de
//!     saturation disque qui partage ce tick ;
//!   * une requête est attribuée à la fenêtre où elle se TERMINE, pas à celle où elle a attendu.
//!     Une attente à cheval sur deux fenêtres tombe entière dans la seconde ;
//!   * sans le tier froid (feature absente, ou éteinte par configuration), AUCUNE fenêtre de
//!     vieillissement ne s'ouvre : le chevauchement publié est alors un zéro MESURÉ — il n'y a pas
//!     de passe — et non un trou. Les attentes, elles, restent mesurées : la boucle de rollups tient
//!     le même verrou, et c'était déjà elle que la mesure d'origine avait attrapée.
//!
//! CE QUE ÇA COÛTE AU CHEMIN CHAUD. Une observation = SIX GESTES ATOMIQUES — quatre compteurs
//! incrémentés, deux maximums relevés (chacun une lecture puis, tant que la valeur monte, un
//! échange) — sur un chemin qui vient de faire une acquisition de sémaphore et une requête SQL.
//! Aucune allocation, aucun format, aucune horloge lue en plus : les deux durées sont DÉJÀ mesurées
//! par `query_timing`, cette série ne fait que les recevoir.
//!
//! CE COMPTE EST COMPTÉ, PAS CHRONOMÉTRÉ, et c'est le sujet de `Compteur` ci-dessous :
//! `une_observation_ne_fait_que_six_gestes_atomiques_et_n_alloue_rien` rend des égalités EXACTES sur
//! le nombre de gestes et sur les octets de tas (zéro). La forme précédente ANNONÇAIT ce nombre et
//! ASSERTAIT un rapport de DURÉES ; ce n'est pas la même grandeur, et une durée mesure aussi la
//! machine.

use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};

// UNE seule définition de ce qu'est un point de série, UNE seule voie d'écriture dans `metric` :
// celles que `ventilation_serie` a posées. Les redéclarer ici dupliquerait la décision « `host`
// NULL » (une série qui décrit LA BASE ne doit pas inventer une machine dans l'inventaire de flotte)
// et sa raison.
use crate::ventilation_serie::{ecrire_points, Point};

// =================================================================================================
// LES NOMS DE SÉRIE — stables : ils sont l'interface que lisent SOQL, les panneaux et les règles.
// Le préfixe `..._fenetre_` n'est pas décoratif : il dit que la valeur est un DELTA de la fenêtre de
// publication et non un cumul de vie. Deux séries qui se ressembleraient sans le dire seraient lues
// l'une pour l'autre, et un cumul lu comme un delta ne fait que monter.
// =================================================================================================

/// Requêtes OBSERVÉES pendant la fenêtre. Publiée MÊME à zéro, et c'est le point : sans elle, un
/// trou dans les seaux serait indiscernable d'une fenêtre sans trafic. Les seaux se lisent AVEC
/// elle, jamais seuls — la même règle de lecture que `retard_lignes` avec `retard_ok`.
pub(crate) const NOM_REQUETES: &str = "plume_query_attente_fenetre_requetes";
/// Requêtes de la fenêtre par SEAU d'attente totale (permit + verrou partagé), étiquette `seau` =
/// borne BASSE du seau en millisecondes. C'est cette série qui rend la CONCENTRATION lisible.
pub(crate) const NOM_SEAUX: &str = "plume_query_attente_fenetre_seaux";
/// Plus longue attente TOTALE observée dans la fenêtre (ms). Le seul chiffre qu'un échantillon
/// unique ne peut pas diluer — et le seul que `metric_rollup` conserve exactement (`MAX`).
pub(crate) const NOM_MAX: &str = "plume_query_attente_fenetre_ms_max";
/// Attente cumulée de la fenêtre (ms) par `terme` : `permis` / `verrou_partage`. C'est la
/// DÉCOMPOSITION de la composition — sans elle, on saurait que ça attend, pas derrière quoi.
pub(crate) const NOM_MS: &str = "plume_query_attente_fenetre_ms";
/// Millisecondes de la fenêtre pendant lesquelles une fenêtre de vieillissement était OUVERTE.
/// C'est l'axe de CORRÉLATION : il met l'état de la passe sur l'échelle de temps des attentes.
pub(crate) const NOM_VIEILLISSEMENT: &str = "plume_query_attente_fenetre_vieillissement_ms";

/// Le terme « file d'attente de la borne interactive ».
pub(crate) const TERME_PERMIS: &str = "permis";
/// Le terme « file d'attente du verrou de la connexion partagée ».
pub(crate) const TERME_VERROU: &str = "verrou_partage";

/// LES BORNES DES SEAUX (µs), décadaires. Le premier seau est « aucune attente mesurable », le
/// dernier est ouvert vers le haut — une passe qui tient le verrou des dizaines de secondes doit
/// tomber DANS un seau et non hors de l'échelle.
pub(crate) const BORNES_US: [u64; NB_SEAUX] = [0, 1_000, 10_000, 100_000, 1_000_000, 10_000_000];
/// Les étiquettes correspondantes (borne basse en ms), pré-calculées : la publication ne formate
/// rien, et l'étiquette d'un seau ne peut pas diverger de sa borne par une faute de frappe.
pub(crate) const ETIQUETTES_SEAU: [&str; NB_SEAUX] = ["0", "1", "10", "100", "1000", "10000"];
/// Nombre de seaux — l'énumération est FERMÉE, c'est de là que vient la borne de cardinalité.
pub(crate) const NB_SEAUX: usize = 6;

/// LE SEAU D'UNE ATTENTE — PURE, donc opposable à des témoins sans monter d'accumulateur.
/// Le seau `i` contient les attentes de `BORNES_US[i]` (inclus) à `BORNES_US[i+1]` (exclu).
pub(crate) fn seau_de(us: u64) -> usize {
    let mut k = 0;
    for (i, b) in BORNES_US.iter().enumerate() {
        if us >= *b {
            k = i;
        }
    }
    k
}

// =================================================================================================
// L'ACCUMULATEUR — une STRUCTURE, pas un `static`
// =================================================================================================

/// L'ÉTAT LU À LA PUBLICATION PRÉCÉDENTE. Les compteurs sont cumulatifs (c'est ce que `/metrics`
/// attend d'un `counter`) ; la fenêtre est leur DIFFÉRENCE. Garder la photo précédente ici, plutôt
/// que remettre les compteurs à zéro, évite qu'un scrape Prometheus tombé entre deux publications
/// voie un compteur reculer — un compteur qui recule est lu comme un redémarrage.
#[derive(Debug, Clone, Copy)]
struct Precedent {
    instant: Instant,
    seaux: [u64; NB_SEAUX],
    observations: u64,
    permis_us: u64,
    verrou_us: u64,
    chevauchement_us: u64,
}

/// CE QUE LES REQUÊTES ONT ATTENDU. Taille FIXE (onze atomiques et une photo), quel que soit le
/// trafic : c'est ce qui rend l'instrumentation compatible avec le budget de 2 Gio.
///
/// Une STRUCTURE et non un `static`, pour la même raison que le registre de `semaphore_interactif` :
/// une propriété qui ne se prouve que sur l'instance globale du processus est une propriété dont
/// l'essai pollue tout le reste — ici, chaque essai monte le sien.
#[derive(Debug)]
pub(crate) struct Accumulateur {
    seaux: [Compteur; NB_SEAUX],
    observations: Compteur,
    permis_us: Compteur,
    verrou_us: Compteur,
    /// Maximum depuis le démarrage — jamais remis à zéro (c'est la jauge de `/metrics`).
    max_vie_us: Compteur,
    /// Maximum DE LA FENÊTRE — échangé contre zéro à chaque publication.
    max_fenetre_us: Compteur,
    precedent: Mutex<Precedent>,
}

// =================================================================================================
// CE QU'UNE OBSERVATION FAIT AUX ATOMIQUES — UN COMPTE, PAS UNE DURÉE
// =================================================================================================

/// UNE ATOMIQUE DE L'ACCUMULATEUR, ET LE SEUL CHEMIN VERS ELLE. `AtomicU64` est PRIVÉ : hors de ce
/// type, rien dans la caisse ne peut incrémenter, lire ni échanger une des onze atomiques de
/// l'accumulateur. Ce n'est pas une convention, c'est le compilateur — un geste ajouté sur un
/// compteur EXISTANT est donc compté par construction, et ne peut pas passer à côté du témoin.
///
/// LA BORNE, ÉCRITE POUR ÊTRE OPPOSABLE : une atomique NEUVE, déclarée à côté de celles-ci en
/// `AtomicU64` nu, échapperait au compte. C'est la seule porte qui reste, et elle est étroite : la
/// structure ci-dessus ne porte aucun champ de ce type.
///
/// QUATRE GESTES, ET LEUR SÉPARATION EST LA MESURE. `ajouter` et `relever_le_maximum` sont le chemin
/// d'OBSERVATION (chaud, une fois par requête) ; `lire` et `prendre` sont le chemin de PUBLICATION
/// (froid, une fois par fenêtre). Les compter séparément est ce qui permet d'exiger que
/// l'observation ne fasse AUCUNE lecture et AUCUNE prise — un compteur unique dirait « six gestes »
/// pour une composition tout autre.
#[derive(Debug)]
pub(crate) struct Compteur(AtomicU64);

impl Compteur {
    fn zero() -> Self {
        Compteur(AtomicU64::new(0))
    }

    /// AJOUTE — un `fetch_add` relâché. Le geste est noté AVANT l'atomique : ce sont les TENTATIVES
    /// qu'on compte, comme pour les lectures de `/proc` dans `vieillissement_serie`.
    #[inline]
    fn ajouter(&self, de: u64) {
        noter_un_ajout();
        self.0.fetch_add(de, Ordering::Relaxed);
    }

    /// RELÈVE LE MAXIMUM — une lecture, puis un échange TANT QUE la valeur monte.
    ///
    /// C'EST UN SEUL GESTE, ET LE NOMBRE D'ÉCHANGES N'EN EST PAS UN. Le nombre d'itérations dépend
    /// de la concurrence et, sur les architectures à LL/SC, des échecs SPONTANÉS de
    /// `compare_exchange_weak` : c'est une grandeur de MACHINE, pas de composition, et elle n'est
    /// donc pas assertable. Les échanges tentés sont comptés à part et seulement RAPPORTÉS.
    #[inline]
    fn relever_le_maximum(&self, v: u64) {
        noter_un_releve_de_maximum();
        let mut vu = self.0.load(Ordering::Relaxed);
        while v > vu {
            noter_un_echange_tente();
            match self.0.compare_exchange_weak(vu, v, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actuel) => vu = actuel,
            }
        }
    }

    /// LIT — chemin de PUBLICATION uniquement. Une lecture apparue dans le compte d'une observation
    /// est une régression : elle voudrait dire que le chemin chaud s'est mis à consulter l'état.
    #[inline]
    fn lire(&self) -> u64 {
        noter_une_lecture();
        self.0.load(Ordering::Relaxed)
    }

    /// PREND ET REMET À ZÉRO — l'échange de fin de fenêtre. ÉCHANGE, pas lecture-puis-écriture : une
    /// observation concurrente ne peut pas être effacée.
    #[inline]
    fn prendre(&self) -> u64 {
        noter_une_prise();
        self.0.swap(0, Ordering::Relaxed)
    }
}

/// LE TÉMOIN NE PÈSE RIEN SUR LE BINAIRE LIVRÉ — corps VIDE et `inline(always)` sous `cfg(not(test))`
/// — ET LE SITE D'APPEL EST LE MÊME DANS LES DEUX COMPILATIONS : seule change la présence d'un corps.
///
/// LE PRIX, NOMMÉ : la composition est prouvée sur une compilation qui n'est pas exactement celle
/// qu'on livre, et le REPÈRE en durée imprimé par le témoin porte donc sur une observation ALOURDIE
/// de six écritures dans un `Cell` de fil. Ce repère MAJORE le coût livré ; il ne conclut rien.
#[cfg(test)]
#[inline]
fn noter_un_ajout() {
    temoin_de_composition::note(temoin_de_composition::Geste::Ajout);
}
#[cfg(not(test))]
#[inline(always)]
fn noter_un_ajout() {}

#[cfg(test)]
#[inline]
fn noter_un_releve_de_maximum() {
    temoin_de_composition::note(temoin_de_composition::Geste::ReleveDeMaximum);
}
#[cfg(not(test))]
#[inline(always)]
fn noter_un_releve_de_maximum() {}

#[cfg(test)]
#[inline]
fn noter_un_echange_tente() {
    temoin_de_composition::note(temoin_de_composition::Geste::EchangeTente);
}
#[cfg(not(test))]
#[inline(always)]
fn noter_un_echange_tente() {}

#[cfg(test)]
#[inline]
fn noter_une_lecture() {
    temoin_de_composition::note(temoin_de_composition::Geste::Lecture);
}
#[cfg(not(test))]
#[inline(always)]
fn noter_une_lecture() {}

#[cfg(test)]
#[inline]
fn noter_une_prise() {
    temoin_de_composition::note(temoin_de_composition::Geste::Prise);
}
#[cfg(not(test))]
#[inline(always)]
fn noter_une_prise() {}

/// LE TÉMOIN DE COMPOSITION — il COMPTE les gestes atomiques faits par une portion de code, PAR FIL.
/// Compilé UNIQUEMENT sous `cfg(test)`.
///
/// POURQUOI IL EXISTE, ET CE QU'IL REMPLACE. La propriété gardée est un NOMBRE — « une observation
/// fait quatre ajouts et deux relevés de maximum, et rien d'autre ». La forme précédente l'approchait
/// par un RAPPORT DE DURÉES, `médiane(observer) / médiane(fetch_add)`, plafonné au TRIPLE du compte
/// d'atomiques. Ce n'est pas la même grandeur : une durée mesure aussi la machine. Le jumeau de ce
/// témoin, dans `vieillissement_serie`, a rendu **13,50** sur un rapport de même forme, sur la
/// machine de build en train de compiler, alors que sa composition était INTACTE — une accusation
/// FAUSSE (`P11.23-a`).
///
/// PAR FIL, ET CE N'EST PAS UN DÉTAIL : `cargo test` est multi-fils et plusieurs essais observent.
/// Un compteur global ferait entrer les gestes des voisins dans le compte de l'essai qui mesure, et
/// le verdict redeviendrait fonction de l'ordonnancement — précisément le défaut qu'on corrige. Sous
/// `--test-threads=1` tous les essais partagent UN fil : d'où `releve`, qui referme la mesure.
///
/// IL N'ALLOUE PAS : le `thread_local!` est initialisé en `const` et ne porte que des `Cell<u64>`
/// sans `Drop`, donc son premier accès ne passe pas par l'allocateur — que la suite instrumente
/// (`tas_du_fil`), et sur lequel ce témoin s'appuie pour prouver « zéro octet ».
///
/// CE QU'IL NE VOIT PAS, ÉCRIT POUR ÊTRE OPPOSABLE : une atomique NEUVE déclarée hors de `Compteur`,
/// tout geste vivant dans un bloc `cfg(not(test))`, et TOUT CE QUI N'EST PAS ATOMIQUE — un verrou
/// pris, une attente, un appel système, une horloge lue. Le tas est tenu à part, par `tas_du_fil`.
#[cfg(test)]
pub(crate) mod temoin_de_composition {
    use std::cell::Cell;

    /// Le geste noté. Une énumération et non cinq fonctions : elle FERME la liste des gestes qu'un
    /// `Compteur` peut faire, et un geste ajouté demain doit s'y déclarer pour être compté.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Geste {
        Ajout,
        ReleveDeMaximum,
        EchangeTente,
        Lecture,
        Prise,
    }

    /// Ce qu'une portion de code a fait aux atomiques de l'accumulateur, SUR LE FIL COURANT.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    pub(crate) struct Composition {
        /// `fetch_add` relâchés — le chemin chaud en fait QUATRE par observation.
        pub(crate) ajouts: u64,
        /// Entrées dans `relever_le_maximum` — DEUX par observation.
        pub(crate) releves_de_maximum: u64,
        /// `compare_exchange_weak` TENTÉS. Grandeur de machine : rapportée, jamais assertée.
        pub(crate) echanges_tentes: u64,
        /// Lectures — chemin de PUBLICATION. Zéro par observation.
        pub(crate) lectures: u64,
        /// Échanges contre zéro — chemin de PUBLICATION. Zéro par observation.
        pub(crate) prises: u64,
    }

    /// LES CINQ COMPTES DU FIL, CHACUN DANS SA PROPRE CELLULE — et ce n'est pas un détail de style.
    /// Une seule `Cell<Composition>` obligeait chaque geste à COPIER les cinq compteurs en entrée et
    /// en sortie : quarante octets par geste, deux cent quarante par observation. MESURÉ : le repère
    /// imprimé par le témoin passait de x8 à **x19,04**, AU-DESSUS DU PLAFOND DE 18 que la forme
    /// précédente assertait — l'instrument coûtait plus cher que ce qu'il mesure. Ici, un geste touche
    /// HUIT octets, et le repère retombe à **x15,07**.
    ///
    /// ET C'EST UNE MESURE DE PLUS CONTRE LA FORME PRÉCÉDENTE : compter, avec cinq `Cell<u64>` de fil,
    /// ce qu'elle prétendait déjà borner suffisait à faire franchir son plafond. Une grandeur qu'on ne
    /// peut pas instrumenter sans la faire sortir de ses bornes n'était pas la bonne grandeur.
    struct Compteurs {
        ajouts: Cell<u64>,
        releves_de_maximum: Cell<u64>,
        echanges_tentes: Cell<u64>,
        lectures: Cell<u64>,
        prises: Cell<u64>,
    }

    thread_local! {
        static COMPTEURS: Compteurs = const {
            Compteurs {
                ajouts: Cell::new(0),
                releves_de_maximum: Cell::new(0),
                echanges_tentes: Cell::new(0),
                lectures: Cell::new(0),
                prises: Cell::new(0),
            }
        };
    }

    pub(super) fn note(geste: Geste) {
        COMPTEURS.with(|c| {
            let compteur = match geste {
                Geste::Ajout => &c.ajouts,
                Geste::ReleveDeMaximum => &c.releves_de_maximum,
                Geste::EchangeTente => &c.echanges_tentes,
                Geste::Lecture => &c.lectures,
                Geste::Prise => &c.prises,
            };
            compteur.set(compteur.get().saturating_add(1));
        });
    }

    pub(crate) fn releve() -> Composition {
        COMPTEURS.with(|c| Composition {
            ajouts: c.ajouts.replace(0),
            releves_de_maximum: c.releves_de_maximum.replace(0),
            echanges_tentes: c.echanges_tentes.replace(0),
            lectures: c.lectures.replace(0),
            prises: c.prises.replace(0),
        })
    }
}

impl Accumulateur {
    pub(crate) fn neuf() -> Self {
        Self {
            seaux: std::array::from_fn(|_| Compteur::zero()),
            observations: Compteur::zero(),
            permis_us: Compteur::zero(),
            verrou_us: Compteur::zero(),
            max_vie_us: Compteur::zero(),
            max_fenetre_us: Compteur::zero(),
            precedent: Mutex::new(Precedent {
                instant: Instant::now(),
                seaux: [0; NB_SEAUX],
                observations: 0,
                permis_us: 0,
                verrou_us: 0,
                chevauchement_us: 0,
            }),
        }
    }

    /// OBSERVE UNE REQUÊTE TERMINÉE — les DEUX files qu'elle a traversées, jamais une seule.
    ///
    /// Les deux durées viennent de `query_timing`, qui les a déjà mesurées pour la réponse : aucune
    /// horloge n'est lue ici, donc la série et la réponse ne peuvent pas se contredire.
    pub(crate) fn observer(&self, permis_us: u64, verrou_us: u64) {
        let total = permis_us.saturating_add(verrou_us);
        self.observations.ajouter(1);
        self.permis_us.ajouter(permis_us);
        self.verrou_us.ajouter(verrou_us);
        self.seaux[seau_de(total)].ajouter(1);
        self.max_vie_us.relever_le_maximum(total);
        self.max_fenetre_us.relever_le_maximum(total);
    }

    /// Observations depuis le démarrage — pour les essais et l'exposition.
    pub(crate) fn observations(&self) -> u64 {
        self.observations.lire()
    }

    /// Comptes de vie par seau.
    pub(crate) fn seaux(&self) -> [u64; NB_SEAUX] {
        std::array::from_fn(|i| self.seaux[i].lire())
    }

    /// LES POINTS D'UNE FENÊTRE — et la fenêtre est CLOSE par cet appel (la photo est avancée).
    ///
    /// `chevauchement_us` est PASSÉ et non lu ici : cet accumulateur mesure des attentes, il ne
    /// connaît ni le tier froid ni ses fenêtres. Le passer force l'appelant à en fournir un sur
    /// chaque chemin, et rend la fonction opposable sans monter de passe de vieillissement.
    ///
    /// PUBLIÉ DANS TOUS LES CAS : le compte d'observations et le chevauchement — une fenêtre qui a
    /// eu lieu doit laisser une trace, même vide, sinon « pas de trafic » et « plus de publication »
    /// se ressemblent. PUBLIÉ SEULEMENT s'il y a eu au moins une observation : les seaux, le maximum
    /// et les cumuls. Six lignes de zéros par fenêtre sur une base au repos coûteraient des lignes
    /// pour toujours et ne diraient rien que `..._requetes = 0` ne dise déjà.
    pub(crate) fn points_de_fenetre(&self, chevauchement_us: u64) -> Vec<Point> {
        let mut p = self.precedent.lock();
        let maintenant = Instant::now();
        let fenetre_us = maintenant.duration_since(p.instant).as_micros().min(u64::MAX as u128) as u64;
        let seaux = self.seaux();
        let observations = self.observations.lire();
        let permis_us = self.permis_us.lire();
        let verrou_us = self.verrou_us.lire();
        // ÉCHANGE, pas lecture-puis-remise-à-zéro : une observation concurrente ne peut pas être
        // effacée. Au pire elle tombe dans la fenêtre SUIVANTE — un décalage, jamais une perte.
        let max_us = self.max_fenetre_us.prendre();
        let d_observations = observations.saturating_sub(p.observations);
        // Le chevauchement est PLAFONNÉ à la durée de la fenêtre : une passe ouverte depuis plus
        // longtemps que la fenêtre ne peut pas avoir couvert plus que la fenêtre elle-même, et un
        // chiffre supérieur se lirait comme un instrument cassé — ce qu'il serait.
        let d_chevauchement = chevauchement_us.saturating_sub(p.chevauchement_us).min(fenetre_us);
        let mut out = Vec::with_capacity(NB_SEAUX + 5);
        out.push(Point { nom: NOM_REQUETES, etiquettes: None, valeur: d_observations as f64 });
        out.push(Point {
            nom: NOM_VIEILLISSEMENT,
            etiquettes: None,
            valeur: dur_ms(Duration::from_micros(d_chevauchement)),
        });
        if d_observations > 0 {
            for (i, e) in ETIQUETTES_SEAU.iter().enumerate() {
                out.push(Point {
                    nom: NOM_SEAUX,
                    etiquettes: etiquette("seau", e),
                    valeur: seaux[i].saturating_sub(p.seaux[i]) as f64,
                });
            }
            out.push(Point {
                nom: NOM_MAX,
                etiquettes: None,
                valeur: dur_ms(Duration::from_micros(max_us)),
            });
            for (terme, v) in [
                (TERME_PERMIS, permis_us.saturating_sub(p.permis_us)),
                (TERME_VERROU, verrou_us.saturating_sub(p.verrou_us)),
            ] {
                out.push(Point {
                    nom: NOM_MS,
                    etiquettes: etiquette("terme", terme),
                    valeur: dur_ms(Duration::from_micros(v)),
                });
            }
        }
        *p = Precedent {
            instant: maintenant,
            seaux,
            observations,
            permis_us,
            verrou_us,
            chevauchement_us,
        };
        out
    }

    /// EXPOSITION PROMETHEUS — les CUMULS DE VIE, à côté de `plume_query_permit_wait_ms_total`.
    ///
    /// Lecture d'atomiques uniquement : un scrape ne coûte rien à la base. Ce que la série NE DIT
    /// PAS part dans le `# HELP`, donc sous les yeux de qui lit le verdict, et pas seulement dans un
    /// commentaire que personne n'ouvrira.
    pub(crate) fn exposition_prom(&self, chevauchement_us: u64) -> String {
        let mut o = String::with_capacity(1024);
        o.push_str(
            "# HELP plume_query_attente_observations_total Requêtes dont l'attente a été observée \
             (chemin GXQL et barre de recherche uniquement : BORNE INFÉRIEURE du coût analyste)\n\
             # TYPE plume_query_attente_observations_total counter\n",
        );
        o.push_str(&format!("plume_query_attente_observations_total {}\n", self.observations()));
        o.push_str(
            "# HELP plume_query_attente_seaux_total Requêtes par seau d'attente TOTALE (permit + \
             verrou partagé), étiquette = borne basse du seau en ms. Des seaux et non une moyenne : \
             l'exposition est rare et concentrée, une moyenne la masque et un p99 aussi\n\
             # TYPE plume_query_attente_seaux_total counter\n",
        );
        let seaux = self.seaux();
        for (i, e) in ETIQUETTES_SEAU.iter().enumerate() {
            o.push_str(&format!("plume_query_attente_seaux_total{{seau=\"{e}\"}} {}\n", seaux[i]));
        }
        o.push_str(
            "# HELP plume_query_attente_ms_total Attente cumulée par terme (ms). NE COMPTE QUE DE \
             L'ATTENTE : un travail ralenti par une passe n'y figure pas\n\
             # TYPE plume_query_attente_ms_total counter\n",
        );
        for (terme, v) in [
            (TERME_PERMIS, self.permis_us.lire()),
            (TERME_VERROU, self.verrou_us.lire()),
        ] {
            o.push_str(&format!(
                "plume_query_attente_ms_total{{terme=\"{terme}\"}} {}\n",
                us_en_ms(v)
            ));
        }
        o.push_str(
            "# HELP plume_query_attente_ms_max Plus longue attente TOTALE observée depuis le \
             démarrage (ms)\n\
             # TYPE plume_query_attente_ms_max gauge\n",
        );
        o.push_str(&format!(
            "plume_query_attente_ms_max {}\n",
            us_en_ms(self.max_vie_us.lire())
        ));
        o.push_str(
            "# HELP plume_query_attente_vieillissement_ms_total Temps cumulé pendant lequel une \
             fenêtre de vieillissement froid était ouverte (ms) — présence de la passe, BORNE \
             SUPÉRIEURE de sa détention du verrou, jamais sa durée de verrou\n\
             # TYPE plume_query_attente_vieillissement_ms_total counter\n",
        );
        o.push_str(&format!(
            "plume_query_attente_vieillissement_ms_total {}\n",
            us_en_ms(chevauchement_us)
        ));
        o
    }
}

fn etiquette(cle: &str, valeur: &str) -> Option<String> {
    Some(format!("{{\"{cle}\":\"{valeur}\"}}"))
}

fn us_en_ms(us: u64) -> String {
    format!("{:.3}", dur_ms(Duration::from_micros(us)))
}

static ACCUMULATEUR: std::sync::OnceLock<Accumulateur> = std::sync::OnceLock::new();

/// L'accumulateur du processus.
pub(crate) fn accumulateur() -> &'static Accumulateur {
    ACCUMULATEUR.get_or_init(Accumulateur::neuf)
}

/// OBSERVE UNE REQUÊTE TERMINÉE. Appelé UNIQUEMENT à la libération de `QueryTimings` — la fin du
/// découpage EST la fin de la requête, sur tous les chemins de retour, y compris ceux qui n'ont
/// jamais rendu de réponse. Un appel posé sur un `return` particulier serait faux la moitié du temps.
pub(crate) fn observer(permis_us: u64, verrou_us: u64) {
    accumulateur().observer(permis_us, verrou_us);
}

/// PUBLIE LA FENÊTRE ÉCOULÉE dans `metric`. Prend le verrou d'écriture par l'APPELANT, et pour les
/// seuls `INSERT` (onze lignes au plus).
pub(crate) fn publier_fenetre(conn: &Connection, ts: i64) -> usize {
    let pts = accumulateur().points_de_fenetre(crate::vieillissement_serie::chevauchement_us());
    ecrire_points(conn, ts, &pts)
}

/// L'exposition Prometheus du processus.
pub(crate) fn exposition_prom() -> String {
    accumulateur().exposition_prom(crate::vieillissement_serie::chevauchement_us())
}
