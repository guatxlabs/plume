//! CE QUE COÛTE UN VIEILLISSEMENT FROID — la série, parce qu'un succès muet n'est pas une mesure.
//!
//! CE QUI ÉTAIT CASSÉ, ET CE QUE ÇA A COÛTÉ. Relevé sur la PRODUCTION le 2026-08-10 : un vieillissement
//! libère **120 Mio** dans la base chaude (données −77, index −27, FTS5 −16, freelist +120) et écrit
//! **3,70 Mio** de Parquet — **sans émettre une seule ligne de journal**. Le seul message `[cold]` de
//! tout le journal est la bannière de DÉMARRAGE. Le code n'est pourtant pas muet : il parle quand il
//! ÉCHOUE (legal-hold, clé absente, jour différé par la garde H1, `age_one_day` en erreur, unlink raté)
//! et il émet deux signaux de santé (`aging-stall`, `seal-stuck`). Il ne dit RIEN quand il RÉUSSIT, et
//! rien non plus quand il n'a RIEN à faire. Conséquence directe et mesurée : **quatre axes de coût sont
//! INCONNUS** pour cette seule raison — durée du vieillissement, temps CPU, crête RAM imputable, effet
//! sur la latence des requêtes chaudes.
//!
//! POURQUOI UNE LIGNE DE JOURNAL NE SUFFIT PAS, ET OÙ VA DONC LA SÉRIE. Une ligne se lit une fois, à la
//! main, dans un pod qui la perd au redémarrage : c'est exactement ce qui a laissé la ventilation
//! invisible jusqu'à `P10.8-a`. La série mesurable va donc là où elle a déjà des LECTEURS — la table
//! `metric` du tenant, puis `metric_rollup` (bucket horaire, 90 j), interrogeable en SOQL sans rien
//! relever :
//!     `metric plume_cold_aging_octets_froid | timechart span=1d max(value)`
//!     `metric plume_cold_aging_jours by issue | timechart span=1d sum(value)`
//! Les mêmes lignes alimentent les panneaux et les règles -> un seuil est possible sans nouveau tuyau.
//! Le raisonnement complet (pas de Prometheus dans le cluster, un fichier n'a aucun lecteur, une table
//! neuve n'en aurait pas non plus) est écrit une fois pour toutes en tête de `ventilation_serie` ; on ne
//! le refait pas, on l'HÉRITE — jusqu'à la voie d'écriture, partagée (`ecrire_points`).
//!
//! UN SUCCÈS SILENCIEUX EST UN DÉFAUT ; UN ÉCHEC MUET EST PIRE. Trois états, portés par le TYPE :
//!   * `Issue::Balaye` -> la passe a EU LIEU. « 0 jour candidat » est alors un RÉSULTAT publié (un zéro
//!     honnête : on a regardé, il n'y avait rien), pas un silence.
//!   * `Issue::Suspendu(cause)` -> la passe ne s'est PAS faite (legal-hold, clé absente, rétention trop
//!     courte). AUCUN compteur de travail n'est publié : la série porte un TROU, et `..._ok{cause}=0`
//!     le NOMME. Publier des zéros ici dirait « le vieillissement a tourné et n'a rien trouvé », ce qui
//!     est une autre affirmation, et fausse.
//!   * absence totale de point -> le tick n'a pas eu lieu (démon arrêté, tier froid éteint). Un trou
//!     veut dire « pas mesuré », JAMAIS « zéro ».
//! Et la comptabilité des jours doit FERMER (`candidats == agés + différés + échoués + écartés`) : si
//! elle ne ferme pas, les compteurs de travail ne sont PAS publiés et la cause est nommée. Un compteur
//! faux serait pire que pas de compteur — c'est la même règle que le refus de `db_ventilation`.
//!
//! CE QUE ÇA COÛTE, ET POURQUOI CE N'EST PAS RÉGLABLE. Tout est accumulé dans un `Compte` (dix `i64`)
//! pendant un travail qui, lui, dure des secondes ; la publication est de ~16 `INSERT` d'une ligne, une
//! fois PAR VIEILLISSEMENT (cadence de `retention_run` : horaire). Il n'y a AUCUNE boucle chaude
//! touchée, AUCUNE ligne retenue en mémoire (le `Compte` est de taille FIXE, quel que soit le volume
//! agé — contrainte des 2 Gio), et donc AUCUN réglage à tenir : la borne est structurelle, pas un knob.
//!
//! LA CRÊTE RSS, ET LE PIÈGE DANS LEQUEL LA MESURE DU 2026-08-10 EST TOMBÉE. `VmHWM` est un maximum
//! CUMULÉ DEPUIS LE DÉMARRAGE du processus : le lire après un vieillissement ne dit RIEN de ce que ce
//! vieillissement a coûté — il rend le plus gros pic de toute la vie du démon, qui peut être une requête
//! d'il y a trois jours. On le RAMÈNE donc à la fenêtre : `echo 5 > /proc/self/clear_refs` remet
//! `VmHWM` au RSS courant (proc(5), noyau >= 4.0) ; la valeur relue à la fin est alors le maximum
//! atteint PENDANT la fenêtre, tenu par le noyau (aucun échantillonnage, donc aucun pic manqué).
//! VALIDÉ, le 2026-08-10, par une lecture directe de `/proc/self/status` autour d'allocations touchées
//! page par page (noyau 7.1.4-zen) : après un transitoire de 300 Mio, `VmHWM` = 319 256 kio ; après le
//! reset, 12 164 kio (= `VmRSS`) ; puis 120 Mio alloués DANS la fenêtre rendent `VmHWM` = 135 024 kio
//! alors que `VmRSS` était retombé à 12 164 kio. Sans le reset, cette fenêtre aurait été rapportée à
//! 319 Mio. Le test `la_crete_rss_est_bornee_a_la_fenetre` REJOUE cette validation à chaque suite (avec
//! son témoin négatif), de sorte qu'elle ne dépende pas d'une trace que personne ne rejouera.
//! TROIS LIMITES, ÉCRITES POUR ÊTRE OPPOSABLES :
//!   1. le pic est celui du PROCESSUS, pas du seul vieillissement : une rafale d'ingest concurrente
//!      l'inflate. C'est donc une BORNE SUPÉRIEURE de ce que le vieillissement a coûté, et le nom de la
//!      série le dit (`..._crete_rss_processus_octets`) ;
//!   2. le reset est un effet de bord PROCESSUS : `VmHWM` (et `getrusage(RUSAGE_SELF).ru_maxrss`, même
//!      champ noyau) ne comptent plus depuis le démarrage mais depuis le dernier vieillissement. AUCUN
//!      consommateur dans ce dépôt ne les lit (`metrics.rs` lit le RSS COURANT via `/proc/self/statm`,
//!      pas `VmHWM`) ; les métriques mémoire de k8s viennent du cgroup, pas de ce champ ;
//!   3. deux fenêtres qui se chevaucheraient se voleraient leur ligne de base -> la seconde ne mesure
//!      PAS (drapeau `FENETRE_ACTIVE`, cause `fenetre_concurrente`) au lieu de rendre un chiffre faux.
//! Et l'instrument se VALIDE lui-même : si le reset n'a pas pris (`/proc` absent, écriture refusée,
//! noyau ancien), la ligne de base relue reste très au-dessus du RSS courant -> la crête n'est PAS
//! publiée et la cause est nommée. C'est précisément le cas où un `VmHWM` non remis à zéro aurait menti.
//!
//! LE TEMPS CPU EST CELUI DU FIL, pas du processus (`CLOCK_THREAD_CPUTIME_ID`) : `cold_age_run` est
//! SYNCHRONE sur le fil de la boucle de rétention, qui ne fait rien d'autre pendant ce temps -> le delta
//! est IMPUTABLE. Un CPU-processus, lui, aurait compté l'ingest concurrent. Garde : si la fenêtre se
//! ferme sur un AUTRE fil qu'elle ne s'est ouverte (découpage futur), le temps CPU n'est pas publié.
//! Ce que ça ne couvre PAS : un travail que le vieillissement ferait faire à un AUTRE fil. Il n'y en a
//! pas aujourd'hui — `parquet` est tiré `default-features = false` (codecs zstd/snap seuls, pas d'arrow,
//! pas de rayon) et tout le chemin d'écriture/vérification est en ligne sur le fil appelant.
//!
//! CE QUE CE MODULE NE FERME PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//!   * **la latence des requêtes chaudes pendant un vieillissement reste un axe OUVERT.** La série dit
//!     désormais QUAND la passe a eu lieu et COMBIEN DE TEMPS elle a duré — c'est le préalable pour
//!     jamais l'imputer — mais elle ne mesure aucune requête. `query_timing` découpe bien l'attente du
//!     verrou (`db_lock_wait_ms`), seulement il la rend DANS LA RÉPONSE d'une requête : ce n'est pas une
//!     série, donc rien ne se corrèle encore tout seul.
//!   * aucune EXPOSITION Prometheus ni aucun bloc JSON de panneau. `ventilation_serie` en a parce que
//!     `/metrics` et le panneau « Système » servent sa dernière mesure ; ici personne ne la demande, et
//!     un cache de « dernière passe » serait un état de processus de plus, à tenir, pour zéro lecteur.
//!   * l'EXPIRY des jour-files hors rétention (`expire_cold_days`) n'est PAS comptée : ce n'est pas le
//!     vieillissement, c'est le ménage qui le suit. Ses échecs d'`unlink` restent sur stderr seulement.
//!   * la SÉRIE est par-tenant, comme la base : en mode multi-tenant chaque base porte la sienne, et
//!     rien n'agrège les tenants.
use crate::*;
use std::sync::atomic::{AtomicBool, Ordering};

// UNE seule définition de ce qu'est un point de série, UNE seule voie d'écriture dans `metric` : celles
// que `ventilation_serie` a posées en `P10.8-a`. Les redéclarer ici dupliquerait la décision « `host`
// NULL » (une série qui décrit LA BASE ne doit pas inventer une machine dans l'inventaire de flotte) et
// sa raison — deux endroits à corriger le jour où la voie change.
use crate::ventilation_serie::{ecrire_points, Point};

// =================================================================================================
// LES NOMS DE SÉRIE — stables : ils sont l'interface que lisent SOQL, les panneaux et les règles.
// =================================================================================================

/// 1 = la passe a eu lieu et ses compteurs sont publiés ; 0 = elle ne l'a pas été (étiquette `cause`).
pub(crate) const NOM_OK: &str = "plume_cold_aging_ok";
/// Jours, par `issue` : `candidat` / `age` / `differe` / `echoue` / `ecarte`. La somme des quatre
/// derniers FAIT le premier — c'est la comptabilité qui doit fermer.
pub(crate) const NOM_JOURS: &str = "plume_cold_aging_jours";
/// Lignes, par `sens` : `ecrites` (dans le Parquet, phase 1) / `retirees_du_chaud` (phase 2, compte
/// RÉEL des lignes supprimées, pas l'espéré du seal).
pub(crate) const NOM_LIGNES: &str = "plume_cold_aging_lignes";
/// Fichiers cold, par `etat` : `ecrits` (scellés cette passe) / `purges` (dont le chaud a été supprimé).
pub(crate) const NOM_FICHIERS: &str = "plume_cold_aging_fichiers";
/// Octets écrits au froid cette passe (taille sur disque des fichiers scellés, relevée après `rename`).
pub(crate) const NOM_OCTETS_FROID: &str = "plume_cold_aging_octets_froid";
/// Durée de bout en bout de la passe (ms) — découverte, écriture, suppression, expiry, détecteurs.
pub(crate) const NOM_DUREE: &str = "plume_cold_aging_duree_ms";
/// Temps CPU DU FIL pendant la passe (ms). Absent si non imputable (cf. bandeau).
pub(crate) const NOM_CPU: &str = "plume_cold_aging_cpu_fil_ms";
/// Crête RSS du PROCESSUS pendant la fenêtre (octets) — borne SUPÉRIEURE du coût du vieillissement.
pub(crate) const NOM_CRETE: &str = "plume_cold_aging_crete_rss_processus_octets";
/// Surcroît de cette crête au-dessus de la ligne de base prise à l'ouverture de la fenêtre (octets).
pub(crate) const NOM_CRETE_SURCROIT: &str = "plume_cold_aging_crete_rss_surcroit_octets";
/// 1 = la crête a été mesurée ; 0 = elle ne l'a pas été, et `cause` dit pourquoi. Sans cette ligne, un
/// trou dans la crête serait indiscernable d'un tick jamais exécuté.
pub(crate) const NOM_CRETE_OK: &str = "plume_cold_aging_crete_rss_ok";

/// La cause publiée quand tout va bien. Une étiquette TOUJOURS présente (plutôt qu'absente sur succès)
/// garde une forme de série unique : un `by cause` n'a pas de trou à expliquer.
pub(crate) const CAUSE_AUCUNE: &str = "aucune";
/// Un legal-hold actif (ou indéterminé) suspend le vieillissement — délibéré, fail-safe.
pub(crate) const CAUSE_LEGAL_HOLD: &str = "legal_hold";
/// `PLUME_DB_KEY` indisponible -> pas de chiffrement at-rest possible -> rien n'est agé (fail-closed).
pub(crate) const CAUSE_CLE_ABSENTE: &str = "cle_absente";
/// Rétention globale <= 1 j : aucune fenêtre chaude distinguable, la passe ne peut rien ager.
pub(crate) const CAUSE_RETENTION_COURTE: &str = "retention_courte";
/// La comptabilité des jours ne ferme pas -> compteurs de travail NON publiés (un compteur faux serait
/// pire qu'un trou). N'arrive que sur un défaut d'accumulation : c'est un aveu, pas un état normal.
pub(crate) const CAUSE_COMPTABILITE: &str = "comptabilite_jours";
/// La REQUÊTE DE DÉCOUVERTE des jours agéables a échoué (table absente, base verrouillée, ligne
/// illisible). Sans cette cause, l'échec sortait comme « 0 jour candidat » — un zéro MESURÉ pour une
/// passe qui n'a rien pu regarder. C'est la forme la plus coûteuse du défaut que ce module ferme.
pub(crate) const CAUSE_DECOUVERTE: &str = "decouverte_impossible";

/// `/proc` illisible (noyau non-Linux, `hidepid`, sandbox) -> aucune crête.
pub(crate) const CRETE_PROC_ABSENT: &str = "proc_absent";
/// L'écriture de `clear_refs` a échoué, OU elle n'a pas pris (ligne de base restée au-dessus du RSS
/// courant) -> la crête aurait été celle de TOUTE la vie du processus : on ne la publie pas.
pub(crate) const CRETE_RESET_REFUSE: &str = "reset_refuse";
/// Une autre fenêtre était déjà ouverte -> les deux se voleraient leur ligne de base.
pub(crate) const CRETE_FENETRE_CONCURRENTE: &str = "fenetre_concurrente";
/// La passe a été suspendue : une crête décrirait une fenêtre où RIEN n'a été agé, et se lirait comme un
/// coût de vieillissement très bas. On ne la publie pas.
pub(crate) const CRETE_SUSPENDU: &str = "aging_suspendu";

/// Écart toléré entre la ligne de base relue et le RSS courant juste après le reset. Il couvre ce que le
/// processus peut allouer ENTRE les deux lectures (quelques microsecondes). Au-delà, on conclut que le
/// reset n'a PAS pris — et c'est exactement le seul cas où un `VmHWM` périmé pourrait mentir. Corollaire
/// ASSUMÉ : la ligne de base peut être surévaluée de jusqu'à cette valeur, donc le SURCROÎT publié peut
/// être sous-évalué d'autant. Borne connue et bornée.
pub(crate) const TOLERANCE_RESET_OCTETS: u64 = 4 * 1024 * 1024;

// =================================================================================================
// CE QU'UNE PASSE A FAIT — des types, pas des `bool` et des tuples
// =================================================================================================

/// L'ISSUE D'UNE PASSE. Deux variantes, pas trois : « le tick n'a pas eu lieu » n'est pas une variante,
/// c'est l'ABSENCE de point dans la série (un trou). Les trois états sont donc exhaustifs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Issue {
    /// La passe a été faite jusqu'au bout. Ses compteurs décrivent ce qui s'est passé — y compris zéro.
    Balaye,
    /// La passe ne s'est pas faite. La clé est stable (étiquette), la phrase est pour le journal.
    Suspendu(&'static str),
}

/// LES COMPTEURS D'UNE PASSE — taille FIXE (dix `i64`), jamais une ligne retenue en mémoire : c'est ce
/// qui rend l'instrumentation compatible avec le budget de 2 Gio quel que soit le volume agé.
///
/// ILS S'INCRÉMENTENT AU FUR ET À MESURE, jamais à la fin : un échec au milieu d'un jour conserve ce qui
/// a RÉELLEMENT été fait avant lui (fichiers scellés, lignes déjà retirées du chaud). Un compte calculé
/// « à la fin » perdrait exactement les cas qu'on cherche à voir.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Compte {
    /// (env_id, jour) découverts dans la bande éligible.
    pub(crate) jours_candidats: i64,
    /// Jours traités sans erreur (y compris « rien à écrire » et « déjà scellé, seule la phase 2 restait »).
    pub(crate) jours_ages: i64,
    /// Jours DIFFÉRÉS par la garde H1 (le jour détient le tail du compteur de rowid) — sans perte.
    pub(crate) jours_differes: i64,
    /// Jours dont le traitement a rendu une erreur (lignes conservées chaudes, retenté au tick suivant).
    pub(crate) jours_echoues: i64,
    /// Jours écartés avant traitement : `env_id` non conforme, ou hors de la rétention de LEUR index.
    pub(crate) jours_ecartes: i64,
    /// Fichiers Parquet écrits ET scellés pendant cette passe.
    pub(crate) fichiers_ecrits: i64,
    /// Fichiers dont la tranche chaude a été supprimée pendant cette passe (phase 2).
    pub(crate) fichiers_purges: i64,
    /// Lignes écrites dans les fichiers Parquet de cette passe.
    pub(crate) lignes_ecrites: i64,
    /// Lignes RÉELLEMENT supprimées du chaud (compte rendu par le DELETE, pas l'espéré du seal).
    pub(crate) lignes_retirees: i64,
    /// Octets des fichiers scellés cette passe, relevés SUR DISQUE après `rename` (taille réelle, donc
    /// après compression et chiffrement — c'est ce que le volume coûte vraiment).
    pub(crate) octets_froid: i64,
}

impl Compte {
    /// LA COMPTABILITÉ DES JOURS FERME-T-ELLE ? Tout jour candidat est dans EXACTEMENT une des quatre
    /// suites possibles. Si ce n'est pas le cas, un chemin a été ajouté sans être compté : les
    /// compteurs ne sont plus une description de la passe, et on refuse de les publier.
    pub(crate) fn comptabilite_jours_fermee(&self) -> bool {
        self.jours_candidats == self.jours_ages + self.jours_differes + self.jours_echoues + self.jours_ecartes
    }
}

/// LA CRÊTE RSS DE LA FENÊTRE — mesurée, ou pas, et alors on dit pourquoi.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Crete {
    /// `pic` = maximum atteint pendant la fenêtre ; `base` = ligne de base à son ouverture.
    Mesuree { pic: u64, base: u64 },
    /// Pas de crête : la clé nomme la raison (jamais un zéro, qui se lirait « ça n'a rien coûté »).
    NonMesuree(&'static str),
}

/// LE BILAN D'UNE PASSE — tout ce qui sera publié, et rien d'autre. Sans horloge ni global : les
/// fonctions qui le transforment sont PURES, donc testables sans processus.
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Bilan {
    pub(crate) issue: Issue,
    pub(crate) compte: Compte,
    pub(crate) duree_ms: u64,
    /// `None` = non imputable (fil changé, `/proc` illisible) -> trou, jamais un zéro.
    pub(crate) cpu_ms: Option<u64>,
    pub(crate) crete: Crete,
}

// =================================================================================================
// CE QUI EST PUBLIÉ — fonctions PURES : c'est ici que vivent les invariants
// =================================================================================================

/// LE VERDICT DE PUBLICATION — PURE, et c'est le point unique où se décide « ces compteurs décrivent-ils
/// vraiment une passe ? ». `Err(cause)` -> aucun compteur de travail n'est publié et la cause NOMME le
/// trou. Deux raisons seulement : la passe n'a pas eu lieu, ou sa comptabilité ne ferme pas.
pub(crate) fn verdict(b: &Bilan) -> Result<(), &'static str> {
    match b.issue {
        Issue::Suspendu(cause) => Err(cause),
        Issue::Balaye if !b.compte.comptabilite_jours_fermee() => Err(CAUSE_COMPTABILITE),
        Issue::Balaye => Ok(()),
    }
}

fn etiquette(cle: &str, valeur: &str) -> Option<String> {
    Some(format!("{{\"{cle}\":\"{valeur}\"}}"))
}

/// LES POINTS À ÉCRIRE — PURE.
///
/// Publiés DANS TOUS LES CAS (une passe qui a eu lieu doit laisser une trace, même vide) : `ok` (avec sa
/// cause), la durée, et le temps CPU s'il est imputable. Publiés SEULEMENT si le verdict est `Ok` : les
/// compteurs de travail et la crête. Un zéro de compteur veut alors dire « mesuré, et c'est zéro ».
pub(crate) fn points(b: &Bilan) -> Vec<Point> {
    let travail = verdict(b);
    let mut out = Vec::with_capacity(16);
    out.push(Point {
        nom: NOM_OK,
        etiquettes: etiquette("cause", travail.err().unwrap_or(CAUSE_AUCUNE)),
        valeur: if travail.is_ok() { 1.0 } else { 0.0 },
    });
    out.push(Point { nom: NOM_DUREE, etiquettes: None, valeur: b.duree_ms as f64 });
    if let Some(cpu) = b.cpu_ms {
        out.push(Point { nom: NOM_CPU, etiquettes: None, valeur: cpu as f64 });
    }
    if travail.is_ok() {
        let c = &b.compte;
        for (issue, v) in [
            ("candidat", c.jours_candidats),
            ("age", c.jours_ages),
            ("differe", c.jours_differes),
            ("echoue", c.jours_echoues),
            ("ecarte", c.jours_ecartes),
        ] {
            out.push(Point { nom: NOM_JOURS, etiquettes: etiquette("issue", issue), valeur: v as f64 });
        }
        for (sens, v) in [("ecrites", c.lignes_ecrites), ("retirees_du_chaud", c.lignes_retirees)] {
            out.push(Point { nom: NOM_LIGNES, etiquettes: etiquette("sens", sens), valeur: v as f64 });
        }
        for (etat, v) in [("ecrits", c.fichiers_ecrits), ("purges", c.fichiers_purges)] {
            out.push(Point { nom: NOM_FICHIERS, etiquettes: etiquette("etat", etat), valeur: v as f64 });
        }
        out.push(Point { nom: NOM_OCTETS_FROID, etiquettes: None, valeur: c.octets_froid as f64 });
    }
    // LA CRÊTE. Une passe suspendue n'en publie AUCUNE (elle décrirait une fenêtre où rien n'a été agé,
    // et une valeur basse s'y lirait comme un coût de vieillissement bas — l'inverse de la vérité).
    match (travail.is_ok(), b.crete) {
        (true, Crete::Mesuree { pic, base }) => {
            out.push(Point { nom: NOM_CRETE_OK, etiquettes: etiquette("cause", CAUSE_AUCUNE), valeur: 1.0 });
            out.push(Point { nom: NOM_CRETE, etiquettes: None, valeur: pic as f64 });
            out.push(Point {
                nom: NOM_CRETE_SURCROIT,
                etiquettes: None,
                valeur: pic.saturating_sub(base) as f64,
            });
        }
        (true, Crete::NonMesuree(cause)) => {
            out.push(Point { nom: NOM_CRETE_OK, etiquettes: etiquette("cause", cause), valeur: 0.0 });
        }
        (false, _) => {
            out.push(Point { nom: NOM_CRETE_OK, etiquettes: etiquette("cause", CRETE_SUSPENDU), valeur: 0.0 });
        }
    }
    out
}

/// Mio à deux décimales, virgule française — pour le JOURNAL seulement (la série, elle, porte des
/// octets bruts : un arrondi dans une série est une perte définitive).
fn mio(octets: i64) -> String {
    format!("{:.2}", octets as f64 / (1024.0 * 1024.0)).replace('.', ",")
}

/// LA LIGNE DE JOURNAL — PURE. Elle dit la même chose que la série, dans la phrase que quelqu'un lira
/// dans `kubectl logs` sans requête à écrire. Elle est émise à CHAQUE passe, y compris la passe vide :
/// c'est ce qui distingue « le vieillissement a tourné et n'avait rien à faire » de « il ne tourne plus ».
pub(crate) fn phrase(b: &Bilan) -> String {
    // La durée et le CPU sont mesurés dans TOUS les cas ; la crête, elle, ne se dit que si la passe a eu
    // lieu — exactement comme dans la série. Une phrase qui annoncerait une crête pour une passe
    // suspendue ferait lire « le vieillissement a coûté si peu » là où il n'a rien fait du tout.
    let temps = format!(
        "{} ms{}",
        b.duree_ms,
        match b.cpu_ms {
            Some(c) => format!(" (CPU fil {c} ms)"),
            None => " (CPU fil NON IMPUTABLE)".to_string(),
        }
    );
    let cout = format!(
        "{temps}, {}",
        match b.crete {
            Crete::Mesuree { pic, base } => format!(
                "crête RSS processus {} Mio (+{} Mio sur la fenêtre)",
                mio(pic as i64),
                mio(pic.saturating_sub(base) as i64)
            ),
            Crete::NonMesuree(cause) => format!("crête RSS NON MESURÉE ({cause})"),
        }
    );
    match verdict(b) {
        Err(cause) => format!(
            "[cold] vieillissement NON EXÉCUTÉ ({cause}) — {temps} ; aucun compteur publié, la série \
             porte un trou NOMMÉ (jamais un zéro)"
        ),
        Ok(()) => {
            let c = &b.compte;
            format!(
                "[cold] vieillissement : {} jour(s) agé(s) sur {} candidat(s) ({} différé(s), {} échoué(s), \
                 {} écarté(s)) — {} ligne(s) / {} fichier(s) / {} Mio écrits au froid, {} ligne(s) retirée(s) \
                 du chaud ({} fichier(s) purgé(s)) — {cout}",
                c.jours_ages,
                c.jours_candidats,
                c.jours_differes,
                c.jours_echoues,
                c.jours_ecartes,
                c.lignes_ecrites,
                c.fichiers_ecrits,
                mio(c.octets_froid),
                c.lignes_retirees,
                c.fichiers_purges,
            )
        }
    }
}

/// ÉCRIT la série de cette passe. Prend le verrou d'écriture POUR LES SEULS `INSERT` (une poignée de
/// lignes) : jamais pendant le vieillissement lui-même, qui dure des secondes.
pub(crate) fn publier(db: &Arc<Mutex<Connection>>, ts: i64, b: &Bilan) -> usize {
    let conn = db.lock();
    ecrire_points(&conn, ts, &points(b))
}

// =================================================================================================
// LA FENÊTRE DE MESURE — le seul état de processus du module, et il est rendu même sur panique
// =================================================================================================

/// Une seule fenêtre à la fois : le reset de `VmHWM` est PROCESSUS, deux fenêtres imbriquées se
/// voleraient leur ligne de base. La seconde ne mesure alors PAS (au lieu de rendre un chiffre faux).
static FENETRE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// LA FENÊTRE OUVERTE AUTOUR D'UNE PASSE : durée, CPU du fil, et crête RSS ramenée à la fenêtre.
/// Le drapeau d'exclusivité est rendu par `Drop` — donc AUSSI si la passe panique. Sans ça, une seule
/// panique condamnerait toutes les mesures suivantes à `fenetre_concurrente`, silencieusement.
pub(crate) struct Fenetre {
    t0: Instant,
    fil: std::thread::ThreadId,
    cpu0_ns: Option<u64>,
    /// Ligne de base (`VmHWM` relu APRÈS le reset) ; `None` si l'instrument ne s'est pas validé.
    base: Option<u64>,
    cause_crete: Option<&'static str>,
    exclusive: bool,
}

impl Drop for Fenetre {
    fn drop(&mut self) {
        if self.exclusive {
            FENETRE_ACTIVE.store(false, Ordering::Release);
        }
    }
}

impl Fenetre {
    /// OUVRE la fenêtre : prend l'exclusivité, arme la crête, PUIS démarre les chronomètres. L'ordre
    /// compte : `t0` est pris APRÈS l'armement, donc la durée publiée est celle de la PASSE et non celle
    /// de l'instrument (~180 µs mesurés le 2026-08-10, cf. `ouvrir_et_clore_une_fenetre_ne_coute_presque_rien`).
    pub(crate) fn ouvrir() -> Fenetre {
        let exclusive = FENETRE_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        let (base, cause_crete) =
            if exclusive { armer_crete() } else { (None, Some(CRETE_FENETRE_CONCURRENTE)) };
        Fenetre {
            t0: Instant::now(),
            fil: std::thread::current().id(),
            cpu0_ns: cpu_du_fil_ns(),
            base,
            cause_crete,
            exclusive,
        }
    }

    /// FERME la fenêtre et rend le bilan. `self` est consommé -> le drapeau est rendu ici (via `Drop`).
    pub(crate) fn clore(self, issue: Issue, compte: Compte) -> Bilan {
        let duree_ms = self.t0.elapsed().as_millis().min(u64::MAX as u128) as u64;
        // Le CPU d'un AUTRE fil ne dit rien du nôtre : si la fenêtre change de fil, on ne publie pas.
        let meme_fil = std::thread::current().id() == self.fil;
        let cpu_ms = match (meme_fil, self.cpu0_ns, cpu_du_fil_ns()) {
            (true, Some(avant), Some(apres)) => Some(apres.saturating_sub(avant) / 1_000_000),
            _ => None,
        };
        let crete = match (self.base, self.cause_crete) {
            (Some(base), _) => match champ_status_octets("VmHWM:") {
                Some(pic) => Crete::Mesuree { pic: pic.max(base), base },
                None => Crete::NonMesuree(CRETE_PROC_ABSENT),
            },
            (None, Some(cause)) => Crete::NonMesuree(cause),
            // Inatteignable par construction (`armer_crete` rend toujours l'un ou l'autre) ; nommé
            // plutôt que `unreachable!()` : une mesure ne doit jamais faire tomber le démon.
            (None, None) => Crete::NonMesuree(CRETE_PROC_ABSENT),
        };
        Bilan { issue, compte, duree_ms, cpu_ms, crete }
    }
}

/// ARME la crête : remet `VmHWM` au RSS courant, puis VALIDE que le reset a bien pris. Rend la ligne de
/// base, ou la cause du refus. C'est le seul endroit qui écrit dans `/proc`.
fn armer_crete() -> (Option<u64>, Option<&'static str>) {
    if champ_status_octets("VmRSS:").is_none() {
        return (None, Some(CRETE_PROC_ABSENT)); // `/proc` illisible -> on ne prétend rien.
    }
    if std::fs::write("/proc/self/clear_refs", b"5").is_err() {
        return (None, Some(CRETE_RESET_REFUSE));
    }
    let (Some(hwm), Some(rss)) = (champ_status_octets("VmHWM:"), champ_status_octets("VmRSS:")) else {
        return (None, Some(CRETE_PROC_ABSENT));
    };
    if !reset_effectif(hwm, rss) {
        // Le reset n'a pas pris : la « crête de la fenêtre » serait le pic de TOUTE la vie du processus.
        return (None, Some(CRETE_RESET_REFUSE));
    }
    (Some(hwm), None)
}

/// LA VALIDATION DE L'INSTRUMENT — PURE. Après un reset EFFECTIF, `VmHWM` vaut le RSS de l'instant du
/// reset ; il ne peut donc pas dépasser le RSS relu juste après de plus que ce que le processus a pu
/// allouer entre les deux lectures. Au-delà, le reset n'a pas eu lieu — et c'est le SEUL cas où la
/// mesure mentirait, puisqu'elle rapporterait un pic antérieur à la fenêtre.
pub(crate) fn reset_effectif(hwm_apres_reset: u64, rss_apres_reset: u64) -> bool {
    hwm_apres_reset <= rss_apres_reset.saturating_add(TOLERANCE_RESET_OCTETS)
}

/// Lit un champ `Vm*` de `/proc/self/status` (exprimé en kio) et le rend en OCTETS. `None` si `/proc`
/// est illisible ou le champ absent -> l'appelant en fait un trou nommé, jamais un zéro.
fn champ_status_octets(cle: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ligne = status.lines().find(|l| l.starts_with(cle))?;
    let kio: u64 = ligne.split_whitespace().nth(1)?.parse().ok()?;
    Some(kio * 1024)
}

/// Temps CPU DU FIL COURANT (ns). `CLOCK_THREAD_CPUTIME_ID` : le seul horodateur qui n'attrape pas le
/// CPU des autres fils (l'ingest tourne pendant le vieillissement).
fn cpu_du_fil_ns() -> Option<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SÛRETÉ : `clock_gettime` n'écrit que dans `ts`, dont nous possédons le stockage pour la durée de
    // l'appel. Même forme que `libc::sysconf` déjà employé par `metrics.rs`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64))
}
