//! L'EMPREINTE DU JOURNAL D'ÉCRITURE ANTICIPÉE — ce que le WAL laisse derrière lui entre deux rafales.
//!
//! CE QUI EST BORNÉ ICI, ET CE QUI NE L'EST PAS. C'est la première chose à lire, parce que la
//! confusion entre les deux ferait promettre à ce module quelque chose qu'aucun réglage de SQLite
//! ne sait tenir :
//!   * **LA CRÊTE** — la taille que le `-wal` atteint PENDANT une rafale — N'EST PAS BORNÉE. Elle ne
//!     dépend pas du volume écrit mais de la durée pendant laquelle un lecteur EMPÊCHE le checkpoint
//!     de réinitialiser le journal. Tant qu'une transaction de lecture est tenue, SQLite ne peut ni
//!     replier ni tronquer : il n'y a rien à borner, il n'y a qu'à écrire à la suite.
//!   * **LE RÉSIDU** — la taille que le fichier GARDE une fois la rafale finie — EST borné, et c'est
//!     lui qu'on porte au budget. Sans borne, le `-wal` reste ad vitam à sa plus haute crête : SQLite
//!     réutilise le fichier depuis le début sans jamais le rétrécir. Le pic d'une nuit devient
//!     l'empreinte permanente de la semaine.
//!
//! LA MESURE QUI TRANCHE (banc local, 2026-08-20 ; schéma réel, profil de cardinalité de production,
//! lots de 1 000, 200 000 événements par bras, base de 118,4 Mo, un lecteur INTERMITTENT qui tient une
//! transaction de lecture — la forme exacte qui empêche le point de reprise. Trente-trois répétitions
//! du témoin, dix-huit de la borne, sur quatre campagnes) :
//!
//! | bras | crête du `-wal` | résidu après la rafale | appels `write` |
//! |---|---|---|---|
//! | témoin, aucune borne (n=33) | 67,9 Mo — **57 % de la base** | **67,9 Mo — 57 % de la base** | 193 875 |
//! | borne dérivée = 35 844 000 o (n=18) | 66,6 Mo — 56 % | **35 844 000 o — 30 %**, à l'octet | 194 131 (**+0,13 %**) |
//!
//! Quand le lecteur ne relâche JAMAIS pendant la rafale, l'écart n'est plus du même ordre : le résidu
//! mesuré est de **319,1 Mo — 270 % de la taille de la base** sans borne, contre 16,8 Mo avec une borne
//! de 16 Mio. C'est le cas qui justifie le chantier : le fichier ne redescend pas tout seul.
//!
//! ET LE PHÉNOMÈNE ÉTAIT DÉJÀ DANS UNE SÉRIE PUBLIÉE, SANS QUE PERSONNE NE LA LISE COMME ÇA.
//! `bench/results/ingest_rate-quiet-2g.csv` échantillonne `wal_bytes` à côté de `db_bytes` : le journal
//! y monte par paliers jusqu'à 148 583 712 octets, puis **ne bouge plus d'un octet sur les quatorze
//! derniers échantillons** pendant que la base passe de 756 à 1 272 Mo. Ce n'est pas une oscillation
//! qui « se rend sans dérive nette » : c'est un cliquet. Le fichier a atteint sa marque et l'a gardée.
//!
//! Trois lectures, et elles sont l'ossature de ce module :
//!   1. LA CRÊTE EST INCHANGÉE. 66,6 Mo contre 67,9 Mo — dans une étendue de témoin qui va de 29,6 à
//!      73,0 Mo. La borne ne la touche pas, et rien dans SQLite ne le pourrait.
//!   2. LE RÉSIDU DEVIENT LA BORNE, À L'OCTET. 35 844 000 o exactement, sur seize répétitions sur
//!      dix-huit (les deux autres n'avaient pas atteint la borne). Deux autres bornes essayées le
//!      confirment : 15 161 632 o et 4 194 304 o rendent exactement leur valeur.
//!   3. LA BORNE N'AJOUTE AUCUN TRAVAIL D'ÉCRITURE. +0,13 % d'appels `write` et +0,24 % d'octets
//!      écrits — quand deux mesures du MÊME témoin s'écartent déjà de 0,75 % entre elles.
//!
//! CE QUE LE BANC N'A PAS PU TRANCHER, ET IL FAUT LE DIRE PLUTÔT QUE DE PUBLIER UN CHIFFRE : LE DÉBIT.
//! Le témoin a été mesuré DEUX FOIS dans la même campagne, et il s'écarte de LUI-MÊME de 17,4 % en CPU
//! par événement (bande de 139,6 % sur douze répétitions) — la machine portait d'autres charges. Aucun
//! effet de quelques pour cent n'est lisible sous ce bruit, et une moyenne le maquillerait. Ce qui
//! reste opposable est le compteur du NOYAU (appels `write`, octets écrits), qui ne dépend pas de la
//! charge de la machine ; et, comme majorant du coût, la comparaison des MINIMA — la répétition la
//! moins perturbée de chaque bras : 36,69 µs de CPU par événement pour le témoin, 38,02 µs pour la
//! borne, soit **au plus +3,6 %**, borne haute et non estimation.
//!
//! LE PIÈGE, NOMMÉ ET RÉFUTÉ PAR MESURE. Le danger d'une campagne comme celle-ci est d'échanger une
//! crête d'espace MESURÉE contre une contention d'écriture NON MESURÉE : borner un journal en forçant
//! des points de reprise plus fréquents. C'est ce que ferait le levier VOISIN — abaisser
//! `wal_autocheckpoint` — et c'est pourquoi il a été mesuré ET écarté (même banc, mêmes bras, n=9) :
//! passer le seuil de 1 000 à 100 pages coûte **+7,0 % d'appels `write` et +11,5 % d'octets écrits**,
//! et ne réduit **ni la crête ni le résidu** — le fichier reste à sa plus haute marque, exactement
//! comme le témoin (64,0 Mo, 54 % de la base). On paierait la contention sans rien acheter — et sur
//! une des répétitions le débit s'est effondré à 9 520 événements par seconde là où les deux témoins de
//! la MÊME campagne médianent 22 020 et 18 829, avec une latence médiane de commit de 99,3 ms contre
//! 38,1 et 46,8 ms. Ce point-là n'est pas publié comme une mesure du levier (le bruit de la campagne
//! l'interdit) : il est publié comme ce qu'il est, la forme que prend le risque quand il se réalise.
//!
//! `journal_size_limit` ne fait PAS ça, et la différence est de nature. Il ne DÉCLENCHE aucun
//! checkpoint : il agit APRÈS un checkpoint qui a déjà réussi à réinitialiser le journal, au moment
//! où SQLite s'apprête de toute façon à réécrire le fichier depuis le début. Le seul travail ajouté
//! est un `ftruncate` — compté de 0 à 4 fois par rafale de 200 000 événements (médiane 3 ; les zéros
//! sont les rafales dont la crête n'a jamais atteint la borne), sous le seuil de détection du compteur
//! d'appels système.
//!
//! CE QUE LE RÉSIDU COÛTE QUAND IL N'EST PAS BORNÉ, AUX POINTS DE REPRISE. Un journal deux fois plus
//! gros, c'est un `wal_checkpoint(TRUNCATE)` deux fois plus long — et la base est GELÉE pendant. Mesuré
//! sur le même banc, base en clair et cache chaud (donc un PLANCHER, pas le prix réel sous SQLCipher) :
//! 5,3 ms pour 15,8 Mo de journal, 12,0 ms pour 35,5 Mo, 22,6 ms pour 70,7 Mo, 44,5 ms pour 141,0 Mo —
//! une droite à ~0,32 ms par Mio. Ces points de reprise ne sont pas rares : démarrage, arrêt, chaque
//! sauvegarde, chaque fusion de rollups.
//!
//! CE QUE ÇA N'ACHÈTE PAS, ÉCRIT POUR ÊTRE OPPOSABLE : **de la RAM, presque pas.** L'index du journal
//! (`-shm`), lui, est bien de la mémoire partagée résidente, mais il ne pèse presque rien : mesuré
//! 32 Kio pour 15,8 Mo de journal et 294 Kio pour 141,0 Mo, soit ~2 Kio par Mio. Sous 2 Gio, ce que la
//! borne rend est du DISQUE et du temps de gel aux points de reprise — pas un poste de mémoire. Le
//! prétendre serait exactement le genre de chiffre annoncé que rien ne tient.
//!
//! CE QUE ÇA NE COUVRE PAS, ÉCRIT POUR ÊTRE OPPOSABLE : les connexions d'ÉCRITURE qui ne passent pas
//! par `server::tune`. `journal_size_limit` est un réglage de CONNEXION : il agit quand c'est CETTE
//! connexion-là qui réinitialise le journal. Les sous-commandes en ligne de commande ouvrent leur
//! propre connexion sans cette politique — un point de reprise déclenché par l'une d'elles réinitialise
//! donc le journal SANS le tronquer. Ce n'est pas une fuite : ce sont des processus courts, et le
//! démon retronque à sa réinitialisation suivante. C'est écrit ici pour que personne ne conclue d'un
//! `-wal` resté gros après une commande que la borne ne fonctionne pas.
//!
//! CE QUE ÇA NE FERME PAS : la crête elle-même. La seule façon de la réduire est de raccourcir les
//! transactions de LECTURE qui empêchent le checkpoint — et le démon en tient une longue, délibérément
//! (le parcours `dbstat` de la série du budget, cf. `ventilation_serie::mesurer_une_fois`, qui déclare
//! sa contrepartie : « pendant ces ~35 s le WAL ne peut pas être remis à zéro par un checkpoint »).
//! Le refus de checkpoint qui en résulte n'est pas une panne : il est NOMMÉ et JOURNALISÉ par la voie
//! unique (`db_open::checkpoint_wal_tronque` -> `Checkpoint::Refuse`). Ce module ne le change pas, et
//! `la_borne_ne_change_pas_le_verdict_de_la_voie_unique` le prouve dans les deux états.
use crate::*;

/// LE SEUIL D'AUTO-CHECKPOINT, EN PAGES — décidé ICI et nulle part ailleurs, parce que la borne en est
/// DÉRIVÉE. Deux littéraux (celui du PRAGMA et celui de la formule) finiraient par diverger, et la
/// borne mesurerait alors une configuration que personne ne déploie — la faute déjà payée par les
/// quatre `cache_size` que `sqlite_plafond` a dû réunir.
pub(crate) const SEUIL_AUTOCHECKPOINT_PAGES: i64 = 1000;

/// L'EN-TÊTE D'UNE TRAME DU JOURNAL, EN OCTETS. Le `-wal` ne contient pas des pages nues : chaque page
/// y est précédée de 24 octets (format du WAL, `sqlite3.c`). Un journal de N trames pèse donc
/// `32 + N × (page_size + 24)`, jamais `N × page_size` — l'oublier sous-estime la borne de ~0,6 %.
const ENTETE_TRAME: i64 = 24;

/// TRAMES DE JOURNAL POUR MILLE ÉVÉNEMENTS, AU LOT MAXIMAL. Ce n'est pas un chiffre CHOISI, c'est un
/// chiffre CONSTATÉ : banc local du 2026-08-20 (table `event` avec ses six index, index plein texte à
/// contenu externe et son déclencheur, profil de cardinalité de production, base préremplie de
/// 300 000 lignes pour que les b-trees soient en régime établi) — **7 696 trames pour 50 000
/// événements en UNE transaction**, soit 31 707 552 octets.
///
/// POURQUOI CALIBRÉ AU LOT MAXIMAL, ET PAS AILLEURS. Le nombre de trames par événement DÉCROÎT quand
/// le lot grossit (les mêmes pages de b-tree sont salies plusieurs fois et ne comptent qu'une) :
/// mesuré 384 trames pour 1 000 événements (0,384/ev), 1 039 pour 5 000 (0,208/ev), 7 696 pour 50 000
/// (0,154/ev). La borne doit couvrir LA PLUS GROSSE transaction acceptable, donc c'est là qu'on
/// calibre. Aux lots plus petits le ratio est plus élevé mais le total est plus petit, et c'est la
/// réserve d'auto-checkpoint ci-dessous qui l'absorbe.
///
/// LA CONSTANTE EST RE-MESURÉE PAR LA SUITE, SUR LE SCHÉMA RÉEL — un coefficient calibré sur un banc
/// dont le schéma serait une imitation ne vaudrait rien. `la_borne_couvre_une_transaction_reelle`
/// écrit une transaction sur `db/schema.sql` PLUS toute la chaîne de migrations et publie son
/// résultat : **7 572 592 octets pour 12 000 événements**, soit 1 838 trames — **0,153 trame par
/// événement**, le même coefficient à moins de 1 % près. Ce n'est pas une coïncidence agréable, c'est
/// la seule raison pour laquelle la borne par défaut est opposable.
const TRAMES_POUR_MILLE_EVENEMENTS: i64 = 154;

/// D'OÙ VIENT LA BORNE — la formule, isolée pour être EXERCÉE. Sans elle, « la borne est dérivée »
/// resterait une affirmation de commentaire.
///
/// Deux termes, et chacun répond à une question que la campagne posait :
///   * `evenements_max × TRAMES_POUR_MILLE_EVENEMENTS / 1000` — **la plus grosse rafale qu'on veut
///     absorber sans dégrader**. Une transaction d'ingest est indivisible : si la borne était plus
///     petite qu'elle, le fichier serait tronqué puis immédiatement réétendu à chaque passage, ce qui
///     est du travail pur ;
///   * `SEUIL_AUTOCHECKPOINT_PAGES` — **la réserve que SQLite s'accorde de toute façon** entre deux
///     points de reprise. Borner en dessous rendrait la troncature systématique au lieu
///     d'exceptionnelle.
/// La somme est donc « ce que le journal contient légitimement au pire », et pas un nombre rond.
pub(crate) fn borne_octets_pour(evenements_max: i64, page_size: i64) -> i64 {
    let trames_du_lot = (evenements_max.max(0) * TRAMES_POUR_MILLE_EVENEMENTS + 999) / 1000;
    (SEUIL_AUTOCHECKPOINT_PAGES + trames_du_lot) * (page_size.max(512) + ENTETE_TRAME)
}

/// CE QUE LE DÉMON FAIT DE SON JOURNAL. Trois cas EXCLUSIFS, d'où un type et des `match` EXHAUSTIFS
/// (aucun bras `_`) : une quatrième situation inventée demain ne compilera pas tant que sa valeur, son
/// PRAGMA et sa phrase de journal ne seront pas écrits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Borne {
    /// DÉFAUT. La borne est DÉRIVÉE du plafond d'événements par requête et du seuil d'auto-checkpoint.
    /// Relever `PLUME_INGEST_MAX_EVENTS` la déplace du même geste : les deux ne peuvent pas diverger.
    Derivee(i64),
    /// `PLUME_WAL_LIMITE_MB=<n>` : un exploitant a IMPOSÉ la valeur. On l'applique et on le DIT — un
    /// chiffre imposé qui se présenterait comme dérivé ferait chercher la faute dans la formule.
    Imposee(i64),
    /// `PLUME_WAL_LIMITE_MB=0` : comportement d'AVANT cette campagne. Le journal garde sa plus haute
    /// crête jusqu'au prochain `wal_checkpoint(TRUNCATE)` explicite (démarrage, arrêt, sauvegarde).
    Aucune,
}

impl Borne {
    /// Le fragment de PRAGMA. `Aucune` n'écrit RIEN plutôt que `journal_size_limit=-1` : ne pas poser
    /// le réglage et poser sa valeur neutre sont la même chose pour SQLite, mais pas pour la garde
    /// dérivée — qui compte les endroits où ce PRAGMA est écrit.
    pub(crate) fn pragma(&self) -> String {
        match self {
            Borne::Derivee(o) | Borne::Imposee(o) => format!(" PRAGMA journal_size_limit={o};"),
            Borne::Aucune => String::new(),
        }
    }

    /// LA PHRASE DU JOURNAL DE DÉMARRAGE. Une borne qu'on ne peut pas LIRE en exploitation n'est pas
    /// opposable — et celle-ci doit dire ce qu'elle ne borne PAS, sans quoi elle promet la crête.
    pub(crate) fn phrase(&self) -> String {
        match self {
            Borne::Derivee(o) => format!(
                "residu du journal borne a {} Mio (derive : {} evenements par transaction au plus + \
                 {SEUIL_AUTOCHECKPOINT_PAGES} pages de reserve d'auto-checkpoint). La CRETE pendant une \
                 rafale n'est PAS bornee : elle depend des lecteurs qui empechent le checkpoint",
                o / 1048576,
                evenements_max()
            ),
            // UNE BORNE IMPOSEE SE CONFRONTE A LA DERIVATION, elle ne se contente pas de s'annoncer :
            // sous la derivation, le journal est tronque puis reetendu a CHAQUE lot d'ingest — du
            // travail pur, et c'est exactement le piege que ce chantier existe pour eviter. On le DIT
            // plutot que de refuser : c'est une decision d'exploitant, elle doit rester possible.
            Borne::Imposee(o) => {
                let d = borne_derivee_octets();
                let avertissement = if *o < d {
                    " — SOUS la derivation : le journal sera tronque puis reetendu a chaque lot \
                     d'ingest, c'est du travail d'ecriture pur"
                } else {
                    ""
                };
                format!(
                    "residu du journal borne a {} Mio (IMPOSE par PLUME_WAL_LIMITE_MB, pas derive ; la \
                     derivation aurait donne {} Mio){avertissement}. La CRETE pendant une rafale n'est \
                     PAS bornee",
                    o / 1048576,
                    d / 1048576
                )
            }
            Borne::Aucune => format!(
                "residu du journal NON BORNE (PLUME_WAL_LIMITE_MB=0) : le fichier -wal garde sa plus \
                 haute crete jusqu'au prochain checkpoint TRUNCATE explicite. La derivation aurait \
                 donne {} Mio",
                borne_derivee_octets() / 1048576
            ),
        }
    }
}

/// Le plafond d'événements d'UNE transaction d'ingest — lu là où il est décidé (`disk`), jamais
/// recopié. `ingest_events_batch` ouvre une transaction par lot : c'est donc bien la plus grosse
/// quantité de trames qu'un seul `COMMIT` peut produire.
pub(crate) fn evenements_max() -> i64 {
    let conf = load_config();
    cfg(&conf, "PLUME_INGEST_MAX_EVENTS", &disk::INGEST_MAX_EVENTS_DEFAUT.to_string())
        .trim()
        .parse::<i64>()
        .unwrap_or(disk::INGEST_MAX_EVENTS_DEFAUT as i64)
        .max(0)
}

/// La borne DÉRIVÉE, en octets, pour la taille de page par défaut de SQLite. `pragmas_journal` en
/// utilise la taille RÉELLE de la base ; cette variante sert aux phrases de journal, qui n'ont pas de
/// connexion sous la main et n'ont pas besoin de la précision d'une page.
pub(crate) fn borne_derivee_octets() -> i64 {
    borne_octets_pour(evenements_max(), 4096)
}

/// PURE, donc exerçable dans les trois états sans toucher à l'environnement du processus (un test qui
/// mute `std::env` empoisonne les tests qui tournent en parallèle — ça s'est déjà payé ailleurs).
/// `None` = la variable n'est pas posée -> dérivation. `Some(0)` = désactivation explicite.
pub(crate) fn borne_pour(impose_mo: Option<i64>, derivee: i64) -> Borne {
    match impose_mo {
        None => Borne::Derivee(derivee),
        Some(0) => Borne::Aucune,
        Some(mo) => Borne::Imposee(mo.max(1) * 1048576),
    }
}

/// Ce que l'exploitant a posé, s'il a posé quelque chose. Une valeur illisible est traitée comme
/// ABSENTE (donc dérivation) plutôt que comme `0` : une faute de frappe ne doit pas désarmer la borne
/// en silence.
fn impose_mo() -> Option<i64> {
    let conf = load_config();
    let brut = cfg(&conf, "PLUME_WAL_LIMITE_MB", "");
    let brut = brut.trim();
    if brut.is_empty() {
        return None;
    }
    brut.parse::<i64>().ok().map(|v| v.max(0))
}

/// La borne courante, telle que le processus l'appliquera.
pub(crate) fn borne_courante() -> Borne {
    borne_pour(impose_mo(), borne_derivee_octets())
}

/// LES PRAGMA DU JOURNAL D'ÉCRITURE — le seul endroit du démon qui décide de la politique de WAL.
/// `page_size` vient de la connexion appelante : la borne est un nombre d'OCTETS, et une base en pages
/// de 8 Kio n'a pas la même arithmétique qu'une base en pages de 4 Kio.
///
/// L'ORDRE EST SIGNIFICATIF et il n'est pas cosmétique : `journal_size_limit` ne prend effet qu'en mode
/// WAL (hors WAL il borne le journal de rollback, ce qui n'est pas ce qu'on veut dire), donc il vient
/// APRÈS `journal_mode=WAL` — que `server::tune` pose en tête de son lot.
pub(crate) fn pragmas_journal(page_size: i64) -> String {
    let borne = match borne_courante() {
        Borne::Derivee(_) => Borne::Derivee(borne_octets_pour(evenements_max(), page_size)),
        autre => autre,
    };
    format!("PRAGMA wal_autocheckpoint={SEUIL_AUTOCHECKPOINT_PAGES};{}", borne.pragma())
}

/// LA TAILLE DE PAGE DE CETTE BASE, LUE et non supposée. `512` est le plancher que SQLite lui-même
/// impose ; un échec de lecture retombe sur le défaut de compilation plutôt que sur zéro, qui
/// produirait une borne nulle — c'est-à-dire une troncature à chaque checkpoint.
pub(crate) fn page_size_de(conn: &Connection) -> i64 {
    conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0)).unwrap_or(4096).max(512)
}
