//! LE QUOTA DU DÉVERSEMENT (`P10.1-b`) : ce qui est écrit en clair hors de la base chiffrée est BORNÉ,
//! ou le refus est DIT.
//!
//! Module FEUILLE extrait de `sqlite_plafond` par déplacement pur (`P7.18-a`) : la mesure de ce que le
//! processus détient sous le répertoire de déversement (`octets_ouverts_sous`), son contrôle positif au
//! démarrage, le verdict (`QuotaDeversement`), sa phrase, la note de refus par fil et le rappel de
//! progression qui l'impose. Il ne dépend pas de `sqlite_plafond` ; `sqlite_plafond` le consomme
//! (`deversement_init`, `banniere`, `message_erreur`, `armer_avec`) et RÉ-EXPORTE ses symboles publics,
//! de sorte que tous les chemins `crate::sqlite_plafond::…` restent valides. Les tests qui l'exercent
//! vivent dans `tests/quota_de_deversement.rs`.
use crate::*;

// ═══════════════════════════════════════════════════════════════════════════════════
// P10.1-b — LE QUOTA DU DÉVERSEMENT : CE QUI EST ÉCRIT EN CLAIR EST BORNÉ, OU LE REFUS EST DIT
// ═══════════════════════════════════════════════════════════════════════════════════
//
// CE QUI MANQUAIT. `P10.1-a` a tranché que le déversement est OPT-IN — au défaut, aucune valeur
// d'événement ne quitte la base chiffrée. Mais une fois l'échange pris, RIEN ne bornait la TAILLE de
// ce qui est écrit : le budget mémoire ne protège pas le volume, une requête pathologique le remplit,
// et un volume plein n'est plus un échange, c'est une panne — pour toutes les sessions, pas seulement
// pour la requête fautive.
//
// LES TROIS VOIES ONT ÉTÉ PESÉES, ET DEUX SONT RÉFUTÉES PAR LA MESURE :
//
//   1. UN PLAFOND PASSÉ AU MOTEUR — IL N'EN EXISTE PAS. Le moteur vendoré (3.39.4) n'expose aucune
//      limite de taille de temporaire : `sqlite3_limit()` n'a pas d'identifiant pour ça,
//      `SQLITE_MAX_PMASZ` ne borne que le TAMPON RAM d'une passe de tri avant déversement (pas le
//      total écrit), et `SQLITE_FCNTL_SIZE_LIMIT` ne s'adresse qu'au VFS des bases EN MÉMOIRE.
//
//   2. UNE SURVEILLANCE DU RÉPERTOIRE DE DÉVERSEMENT — ELLE NE VOIT RIEN, ET C'EST PAR CONSTRUCTION.
//      SQLite DÉLIE son temporaire aussitôt après l'avoir ouvert (`unixOpen` : `if( isDelete )
//      osUnlink(zName)`). Pendant qu'un tri déverse, le répertoire est donc VIDE de tout nom : lister
//      son contenu rend zéro alors que des centaines de Mio y sont écrits. C'est la même propriété
//      dont `residus_de_deversement` tire son sens — un nom qui SUBSISTE est un résidu, jamais le
//      déversement en cours. Une garde bâtie sur `read_dir` aurait donc été un no-op silencieux.
//
//   3. UN REFUS EN AMONT DÉRIVÉ DU VOLUME ESTIMÉ — il refuserait des requêtes qui aboutissent et en
//      laisserait passer qui ne le devraient pas : l'estimation du planner porte sur des LIGNES, pas
//      sur les octets qu'un trieur matérialise, et elle ne sait rien de ce que les autres requêtes en
//      vol détiennent déjà. Un quota qui se trompe des deux côtés n'en est pas un.
//
// CE QUE LE PRODUIT PEUT RÉELLEMENT OBSERVER, ET C'EST CE QUI DÉCIDE DE LA FORME. Le temporaire est
// délié mais il reste OUVERT : le processus en détient le descripteur, et le système publie pour
// chacun de ses descripteurs le chemin visé et la taille courante. Le produit peut donc mesurer, à
// tout instant et sans coopération du moteur, LA SOMME DES OCTETS QU'IL DÉTIENT LUI-MÊME sous le
// répertoire de déversement QU'IL A CHOISI. La mesure est exacte et imputable : elle ne compte ni ce
// qu'un autre processus écrit, ni ce qui traîne ailleurs sur le volume.
//
// CE QUI IMPOSE LE QUOTA. Le rappel de progression du moteur est la SEULE prise sur une instruction
// EN COURS : il est appelé toutes les N instructions de la machine virtuelle, sur le chemin même que
// prend la boucle qui alimente le trieur, et un retour non nul ARRÊTE l'instruction. Au franchissement
// la requête est donc REFUSÉE, avec ce qui a été mesuré, le quota et le levier nommés — au lieu d'un
// volume saturé en silence.
//
// CE QUE CE QUOTA NE BORNE PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//   * LE DÉPASSEMENT ENTRE DEUX MESURES. Le rappel ne tombe qu'aux multiples de `PAS_DE_MESURE_VM` :
//     ce qui est écrit d'ici là passe le quota avant d'être vu. Le dépassement est borné par ce que le
//     trieur écrit dans cet intervalle, c'est-à-dire au plus une passe de tri, elle-même bornée par le
//     budget RAM du trieur (`cache_size`).
//   * LA FUSION FINALE. Le tri fusionne ses passes DANS UNE SEULE instruction, pendant laquelle le
//     rappel ne peut pas tomber ; elle écrit un fichier de l'ordre de ce qui est déjà accumulé. La
//     crête disque d'une requête refusée peut donc approcher le DOUBLE du quota. Dimensionner le
//     volume en conséquence.
//   * L'IMPUTATION. Le quota borne ce que le PROCESSUS détient, pas ce qu'une requête écrit : deux
//     tris qui déversent en même temps le partagent, et c'est celui qui atteint le point de mesure qui
//     est arrêté — pas forcément celui qui a le plus écrit. Une écriture d'ingest peut donc être
//     arrêtée par le tri d'un voisin. C'est délibéré : ce qu'il faut protéger est le volume, qui est
//     COMMUN — et un volume plein arrêterait de toute façon cette écriture-là, sans le dire. Le refus
//     NOMME l'approximation au lieu de l'accuser d'avoir écrit ce qu'elle n'a pas écrit.
//   * CE QU'UN AUTRE PROCESSUS ÉCRIT sur le même volume. Rien ici ne l'observe.

/// LE QUOTA PAR DÉFAUT, EN MIO. Chiffre de CONCEPTION et non relevé d'installation : il donne au
/// déversement une borne dès qu'il est activé, pour qu'aucun déploiement n'hérite du défaut « rien ne
/// borne ». Un exploitant qui a le volume le relève ; `0` retire le quota, et la bannière le DIT.
const QUOTA_DEVERSEMENT_DEFAUT_MO: i64 = 1024;

/// LE LEVIER, écrit UNE fois : le refus le NOMME, la bannière le NOMME, et un renommage les déplace
/// ensemble. Un refus qui ne nomme pas son levier n'est pas actionnable.
pub(crate) const LEVIER_QUOTA_DEVERSEMENT: &str = "PLUME_SQLITE_DEVERSEMENT_QUOTA_MO";

/// COMBIEN D'INSTRUCTIONS DE LA MACHINE VIRTUELLE ENTRE DEUX MESURES. Le compromis est explicite : plus
/// c'est petit, plus le dépassement toléré est faible et plus la mesure coûte (un parcours des
/// descripteurs du processus) ; plus c'est grand, plus le trieur peut écrire avant d'être vu. La valeur
/// est du même ordre que ce que le moteur exécute en quelques millisecondes, et la mesure ne tourne QUE
/// sur le chemin opt-in.
const PAS_DE_MESURE_VM: std::os::raw::c_int = 20_000;

/// Le quota effectif, en octets. Même ordre de résolution que tout le reste du daemon (`env > fichier
/// > défaut`). Une valeur non numérique retombe sur le défaut plutôt que sur « aucun quota » : une
/// faute de frappe ne doit pas retirer une borne.
pub(crate) fn quota_deversement_octets() -> i64 {
    let conf = load_config();
    let mo: i64 = cfg(&conf, LEVIER_QUOTA_DEVERSEMENT, &QUOTA_DEVERSEMENT_DEFAUT_MO.to_string())
        .trim()
        .parse()
        .unwrap_or(QUOTA_DEVERSEMENT_DEFAUT_MO);
    mo.max(0).saturating_mul(1048576)
}

/// LE RÉPERTOIRE OÙ LE SYSTÈME PUBLIE LES DESCRIPTEURS DU PROCESSUS — le SEUL endroit de ce module qui
/// le nomme. Tout le reste le reçoit en argument, de sorte qu'une suite puisse éprouver la mesure sur
/// une machine quelconque, et qu'une machine sans cette interface produise un verdict et non un zéro.
fn descripteurs_du_processus() -> std::path::PathBuf {
    std::path::PathBuf::from("/proc/self/fd")
}

/// CE QUE LE PROCESSUS DÉTIENT D'OUVERT SOUS UNE CIBLE. Deux nombres, parce qu'une surveillance qui
/// abandonne un objet sans le dire est le défaut que ce dépôt poursuit.
#[derive(Debug, PartialEq)]
pub(crate) struct OctetsDetenus {
    /// La somme des tailles, en octets. C'est la grandeur que le quota borne.
    pub(crate) octets: i64,
    /// Les descripteurs DISPARUS entre le listage et leur lecture. Ils ne manquent PAS au compte — un
    /// descripteur fermé ne détient plus de fichier, donc zéro octet est la bonne réponse pour lui —
    /// mais ils sont RENDUS quand même : un compte qui les tairait ne se distinguerait pas d'un compte
    /// qui les aurait vus, et un nombre qui monterait sans raison dirait quelque chose de l'hôte.
    pub(crate) disparus: u32,
}

/// CE QUE LE PROCESSUS DÉTIENT D'OUVERT SOUS `cible` — la seule mesure qui voie un déversement en
/// cours, puisque le fichier n'a plus de nom dans l'arborescence.
///
/// PARAMÉTRÉE SUR SES DEUX CHEMINS (`S32`) : elle ne nomme ni `/proc` ni le répertoire de déversement,
/// donc elle s'éprouve avec un fichier délié fabriqué par la suite, et son témoin NÉGATIF — un fichier
/// ouvert AILLEURS n'est pas compté — interdit qu'une fonction rendant toujours un grand nombre passe
/// pour correcte.
///
/// CE QUI REND `Illisible`, CE QUI EST COMPTÉ À PART, ET POURQUOI LA DISTINCTION N'EST PAS COSMÉTIQUE :
///   * le répertoire des descripteurs non listable, ou dont le PARCOURS s'interrompt -> `Illisible`. On
///     ne sait alors RIEN, et un zéro serait la valeur la plus calme de la série, donc exactement le
///     défaut que `S32` a fermé ;
///   * un descripteur DISPARU entre le listage et sa lecture -> compté dans `disparus`. Il ne détient
///     plus rien : l'ignorer n'est pas un compte partiel. Il est rendu à l'appelant plutôt que tu ;
///   * toute autre erreur de lecture d'un descripteur, et tout descripteur qui vise BIEN la cible mais
///     dont la taille ne se lit pas -> `Illisible`. C'est le seul cas où continuer reviendrait à
///     sous-compter précisément ce qu'on prétend borner.
pub(crate) fn octets_ouverts_sous(
    descripteurs: &std::path::Path,
    cible: &std::path::Path,
) -> crate::mesure_environnement::Mesure<OctetsDetenus> {
    use crate::mesure_environnement::{cause_io, Mesure};
    let entrees = match std::fs::read_dir(descripteurs) {
        Ok(e) => e,
        Err(e) => {
            return Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", descripteurs.display()) }
        }
    };
    let prefixe = format!("{}/", cible.display());
    let mut octets: i64 = 0;
    let mut disparus: u32 = 0;
    for entree in entrees {
        let entree = match entree {
            Ok(e) => e,
            Err(e) => {
                return Mesure::Illisible {
                    cause: cause_io(&e),
                    detail: format!(
                        "{} : parcours interrompu ({e}) — un compte partiel serait plus petit que ce qui \
                         est détenu",
                        descripteurs.display()
                    ),
                }
            }
        };
        let chemin = entree.path();
        let vise = match std::fs::read_link(&chemin) {
            Ok(v) => v,
            // Le descripteur a été fermé depuis le listage : il ne détient plus rien, et c'est COMPTÉ.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // COMPTÉ, jamais tu. Le compte est borné par le nombre de descripteurs listés, donc il
                // ne peut pas déborder son type.
                disparus += 1;
                continue;
            }
            Err(e) => {
                return Mesure::Illisible {
                    cause: cause_io(&e),
                    detail: format!("{} : cible illisible ({e})", chemin.display()),
                }
            }
        };
        if !vise.to_string_lossy().starts_with(&prefixe) {
            continue;
        }
        match std::fs::metadata(&chemin) {
            Ok(m) if m.is_file() => octets = octets.saturating_add(m.len() as i64),
            Ok(_) => continue,
            Err(e) => {
                return Mesure::Illisible {
                    cause: cause_io(&e),
                    detail: format!(
                        "{} vise {} et sa taille ne se lit pas ({e}) — un compte qui l'ignorerait serait \
                         plus petit que ce qui est écrit",
                        chemin.display(),
                        vise.display()
                    ),
                }
            }
        }
    }
    Mesure::Lue(OctetsDetenus { octets, disparus })
}

/// CE QUE LE PROCESSUS FERA DE LA TAILLE DE SON DÉVERSEMENT. Quatre cas EXCLUSIFS, d'où un type et des
/// `match` EXHAUSTIFS (aucun bras `_`) : un cinquième ajouté demain ne compile pas tant que sa phrase
/// n'est pas écrite.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum QuotaDeversement {
    /// Le déversement est ÉTEINT : il n'y a rien à borner, aucun octet ne quitte la base chiffrée.
    SansObjet,
    /// ARMÉ à N octets, et la mesure qui l'impose a été VALIDÉE au démarrage par contrôle positif.
    Arme(i64),
    /// Le levier vaut `0` : AUCUN quota. C'est le comportement d'avant, laissé accessible à qui préfère
    /// l'autre côté de l'échange — mais il est DIT, jamais subi par défaut.
    Aucun,
    /// Demandé et NON praticable : la mesure ne se prend pas sur cet hôte. Rien n'est borné, et c'est le
    /// cas qui mérite l'alerte — un quota qu'on croit armé et qui ne mesure rien est pire qu'aucun.
    NonMesurable { quota: i64, cause: String },
}

/// LE CONTRÔLE POSITIF DE LA MESURE — on ne l'AFFIRME pas praticable, on lui fait voir un fichier
/// FABRIQUÉ EXACTEMENT COMME CEUX QU'ELLE DEVRA VOIR : créé dans le répertoire de déversement, ouvert,
/// puis DÉLIÉ pendant qu'on le tient — ce que SQLite fait de chacun de ses temporaires.
///
/// TROIS TEMPS, ET LE PREMIER COMPTE AUTANT QUE LE DEUXIÈME. On mesure AVANT (référence), on mesure
/// avec le fichier délié en main (la référence doit avoir monté d'au moins ce qu'on y a écrit), puis
/// après l'avoir relâché (retour à la référence). Sans le premier et le troisième, une mesure qui
/// rendrait toujours un grand nombre passerait le contrôle.
pub(crate) fn controle_positif_de_la_mesure(dir: &std::path::Path) -> Result<(), String> {
    use crate::mesure_environnement::Mesure;
    let descripteurs = descripteurs_du_processus();
    let lire = |quand: &str| -> Result<i64, String> {
        match octets_ouverts_sous(&descripteurs, dir) {
            Mesure::Lue(d) => Ok(d.octets),
            Mesure::Illisible { cause, detail } => Err(format!("mesure {quand} : {cause} ({detail})")),
        }
    };
    let reference = lire("de référence")?;

    let sonde = dir.join(SONDE_QUOTA);
    let charge = vec![0u8; TAILLE_SONDE_QUOTA];
    std::fs::write(&sonde, &charge).map_err(|e| format!("écriture de la sonde dans {} : {e}", dir.display()))?;
    let tenu = std::fs::File::open(&sonde).map_err(|e| format!("ouverture de la sonde : {e}"))?;
    // DÉLIÉ PENDANT QU'ON LE TIENT : à partir d'ici le fichier n'a plus de nom, exactement comme un
    // temporaire du moteur. Un `read_dir` du répertoire ne le verrait plus.
    std::fs::remove_file(&sonde).map_err(|e| format!("déliaison de la sonde : {e}"))?;
    let vu = lire("sonde en main");
    drop(tenu);
    sonde_vue(dir, reference, vu?)?;
    mesure_redescendue(reference, lire("sonde relâchée")?)
}

/// DEUXIÈME TEMPS du contrôle, PUR : la mesure prise sonde en main doit avoir monté d'au moins ce qu'on
/// y a écrit. Séparé pour que son refus s'éprouve sans fabriquer une mesure fausse (`P10.1-b`).
pub(crate) fn sonde_vue(dir: &std::path::Path, reference: i64, vu: i64) -> Result<(), String> {
    if vu < reference + TAILLE_SONDE_QUOTA as i64 {
        return Err(format!(
            "un fichier délié de {} o tenu ouvert dans {} n'a pas été vu (référence {reference} o, \
             mesure {vu} o) : le quota ne pourrait rien borner",
            TAILLE_SONDE_QUOTA,
            dir.display()
        ));
    }
    Ok(())
}

/// TROISIÈME TEMPS du contrôle, PUR : sonde relâchée, la mesure doit revenir à la référence. Une mesure
/// qui rendrait toujours un grand nombre passerait le deuxième temps ; c'est celui-ci qui la refuse.
pub(crate) fn mesure_redescendue(reference: i64, apres: i64) -> Result<(), String> {
    if apres > reference {
        return Err(format!(
            "la mesure ne redescend pas après relâchement (référence {reference} o, après {apres} o) : \
             elle ne suit pas ce que le processus détient"
        ));
    }
    Ok(())
}

/// La taille de la sonde, lisible des témoins qui éprouvent les deux temps purs du contrôle.
#[cfg(test)]
pub(crate) const TAILLE_SONDE_QUOTA_POUR_TEMOIN: i64 = TAILLE_SONDE_QUOTA as i64;

/// Le nom de la sonde de quota, et sa taille. UN SEUL auteur pour chacun : la mesure des résidus doit
/// ignorer ce nom par le MÊME nom que le contrôle l'écrit — et de toute façon la sonde est déliée avant
/// toute lecture, donc elle ne peut pas passer pour un résidu.
pub(crate) const SONDE_QUOTA: &str = ".sonde-quota";
const TAILLE_SONDE_QUOTA: usize = 65536;

/// LE VERDICT DU QUOTA, résolu UNE FOIS au démarrage. PUR sur ses entrées (le nombre déjà lu, le
/// contrôle déjà joué), donc ses quatre branches s'éprouvent sans toucher au disque.
pub(crate) fn quota_pour(quota: i64, controle: Result<(), String>) -> QuotaDeversement {
    if quota <= 0 {
        return QuotaDeversement::Aucun;
    }
    match controle {
        Ok(()) => QuotaDeversement::Arme(quota),
        Err(cause) => QuotaDeversement::NonMesurable { quota, cause },
    }
}

/// LA PHRASE DU JOURNAL. Un quota qu'on ne peut pas LIRE en exploitation n'est pas opposable, et les
/// deux cas qui ne bornent RIEN doivent se distinguer d'un coup d'œil de celui qui borne.
pub(crate) fn phrase_du_quota(q: &QuotaDeversement) -> String {
    match q {
        QuotaDeversement::SansObjet => String::new(),
        QuotaDeversement::Arme(o) => format!(
            "Quota de déversement ARMÉ à {} Mio, MESURÉ sur les descripteurs que ce processus détient \
             sous ce répertoire (le temporaire est délié aussitôt ouvert : lister le répertoire ne \
             verrait rien) : la requête qui le franchit est REFUSÉE, le volume ne se remplit pas en \
             silence. {LEVIER_QUOTA_DEVERSEMENT} le redimensionne.",
            o / 1048576
        ),
        QuotaDeversement::Aucun => format!(
            "Quota de déversement AUCUN ({LEVIER_QUOTA_DEVERSEMENT}=0) : RIEN ne borne la taille de ce \
             qui est écrit en clair ici — une seule requête peut remplir le volume, et un volume plein \
             n'est plus un échange, c'est une panne pour toutes les sessions."
        ),
        QuotaDeversement::NonMesurable { quota, cause } => format!(
            "Quota de déversement DEMANDÉ à {} Mio mais NON MESURABLE ({cause}) : il n'est PAS appliqué. \
             Rien ne borne la taille de ce qui est écrit en clair ici.",
            quota / 1048576
        ),
    }
}

/// LE QUOTA QUE LES CONNEXIONS DEVRONT TENIR — figé au démarrage, parce que `armer` est appelé sur
/// chaque connexion et n'a pas à re-jouer un contrôle de disque. `None` quand rien n'est à imposer :
/// déversement éteint, quota retiré, ou mesure non praticable (les trois sont DITS par la bannière).
static QUOTA_A_TENIR: std::sync::OnceLock<Option<(std::path::PathBuf, i64)>> = std::sync::OnceLock::new();

pub(crate) fn figer_le_quota(dir: &std::path::Path, q: &QuotaDeversement) {
    let a_tenir = match q {
        QuotaDeversement::Arme(o) => Some((dir.to_path_buf(), *o)),
        QuotaDeversement::SansObjet | QuotaDeversement::Aucun | QuotaDeversement::NonMesurable { .. } => None,
    };
    let _ = QUOTA_A_TENIR.set(a_tenir);
}

// CE QUE LA DERNIÈRE REQUÊTE DE CE FIL S'EST VU REFUSER, ET POURQUOI. Le rappel de progression tourne
// sur le fil qui exécute la requête, donc c'est ce fil qui lira la note — aucun verrou, aucune
// association entre une connexion et un identifiant de requête.
thread_local! {
    static REFUS_DE_QUOTA: std::cell::Cell<Option<(i64, i64)>> = const { std::cell::Cell::new(None) };
}

/// EFFACE une note qui n'aurait pas été consommée. Appelée à l'entrée de l'exécution d'une requête : une
/// note laissée par une requête précédente ferait passer une interruption d'annulation ou de budget pour
/// un franchissement de quota, c'est-à-dire un refus qui nomme la mauvaise cause.
pub(crate) fn oublier_refus_de_quota() {
    REFUS_DE_QUOTA.with(|c| c.set(None));
}

/// LE REFUS, EN MOTS D'EXPLOITANT, et il n'est rendu QU'UNE FOIS (la note est consommée) : ce qui est
/// détenu, ce qui était concédé, ce qui n'a pas eu lieu, et les DEUX leviers — celui qui agrandit la
/// borne et celui qui retire le déversement.
///
/// IL N'ACCUSE PAS LA REQUÊTE QU'IL ARRÊTE, ET C'EST DÉLIBÉRÉ. Le quota borne ce que le PROCESSUS
/// détient, seule grandeur qui protège le volume ; l'instruction arrêtée est celle qui a atteint le
/// point de mesure, pas forcément celle qui a le plus écrit — une écriture d'ingest peut donc être
/// arrêtée par le tri d'un voisin. Écrire « cette requête a écrit tant » serait une imputation fausse ;
/// la phrase dit ce qui est vrai et NOMME l'approximation, plutôt que de la masquer.
pub(crate) fn refus_de_quota_de_deversement() -> Option<String> {
    REFUS_DE_QUOTA.with(|c| c.take()).map(|(octets, quota)| {
        format!(
            "quota de déversement dépassé : les tris de ce processus détiennent {} Mio en clair hors de \
             la base chiffrée, au-delà des {} Mio concédés, et cette instruction est ARRÊTÉE pour que le \
             volume ne se remplisse pas. Elle n'est pas forcément celle qui a le plus écrit : la borne \
             porte sur ce que le processus détient, pas sur ce qu'une requête écrit. AUCUN résultat \
             n'est rendu : un résultat partiel serait FAUX sans le dire. Réduisez la fenêtre de temps, \
             ajoutez un filtre, ou groupez sur une clé de plus faible cardinalité. Un exploitant qui a \
             le volume relève {LEVIER_QUOTA_DEVERSEMENT} ; PLUME_SQLITE_DEVERSEMENT=0 retire le \
             déversement — plus rien en clair hors de la base, au prix des tris qui échoueront alors au \
             plafond mémoire.",
            octets / 1048576,
            quota / 1048576
        )
    })
}

/// POSE LA SURVEILLANCE SUR UNE CONNEXION — le rappel de progression, seule prise du moteur sur une
/// instruction EN COURS. Un retour vrai l'ARRÊTE ; la note dit alors ce qui a été mesuré.
///
/// UNE MESURE DEVENUE ILLISIBLE N'ARRÊTE RIEN, ET NE SE TAIT PAS. Refuser toute requête parce que la
/// mesure a disparu transformerait une panne d'observabilité en panne de service ; ne rien dire
/// laisserait croire à une borne qui n'existe plus. La cause est donc écrite UNE FOIS sur la sortie
/// d'erreur, et le quota cesse d'être opposable — ce que le démarrage avait justement validé.
pub(crate) fn poser_la_surveillance_du_quota(conn: &Connection, dir: std::path::PathBuf, quota: i64) {
    use crate::mesure_environnement::Mesure;
    let descripteurs = descripteurs_du_processus();
    conn.progress_handler(
        PAS_DE_MESURE_VM,
        Some(move || match octets_ouverts_sous(&descripteurs, &dir) {
            Mesure::Lue(d) if d.octets > quota => {
                REFUS_DE_QUOTA.with(|c| c.set(Some((d.octets, quota))));
                true
            }
            Mesure::Lue(_) => false,
            Mesure::Illisible { cause, detail } => {
                static UNE_FOIS: std::sync::Once = std::sync::Once::new();
                UNE_FOIS.call_once(|| {
                    eprintln!(
                        "[plafond] quota de déversement NON OPPOSABLE en cours d'exécution ({cause} : \
                         {detail}) : la mesure validée au démarrage ne se prend plus, plus rien ne borne \
                         la taille écrite en clair."
                    )
                });
                false
            }
        }),
    );
}

/// Arme le quota sur une connexion, s'il y a quelque chose à tenir. Appelée par `armer`, donc par TOUTE
/// connexion de production sur un fichier — la même voie unique que les pragmas de mémoire.
pub(crate) fn armer_le_quota(conn: &Connection) {
    if let Some(Some((dir, quota))) = QUOTA_A_TENIR.get() {
        poser_la_surveillance_du_quota(conn, dir.clone(), *quota);
    }
}
