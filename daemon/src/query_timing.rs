//! query_timing — LE TEMPS D'UNE REQUÊTE, DÉCOUPÉ LÀ OÙ IL EST RÉELLEMENT PASSÉ.
//!
//! LE DÉFAUT QU'IL FERME. `stats.sem_wait_ms` prétendait mesurer l'attente du sémaphore interactif.
//! Il mesurait le temps écoulé entre l'ENTRÉE du handler et l'obtention du permit — c'est-à-dire
//! l'attente du permit PLUS tout le travail fait avant lui, dont une lecture de base qui prend le
//! verrou de la connexion PARTAGÉE (le même que tient la boucle de rollups toutes les 120 s, cf.
//! `server::spawn_rollup_loop`, et l'`ANALYZE` de démarrage). Le champ additionnait donc deux
//! attentes de natures opposées :
//!
//!   * l'attente d'un PERMIT, bornée par `PLUME_QUERY_CONCURRENCY` — qu'on réduit en AUGMENTANT le
//!     sémaphore ;
//!   * l'attente d'un VERROU, qui a lieu AVANT la borne de concurrence et qu'aucun sémaphore ne
//!     borne — qu'augmenter le sémaphore ne réduit PAS, et aggrave (plus de monde sur le verrou).
//!
//! MESURÉ (2026-08-01, base de banc de ~1,44 M d'événements, `bench/results/`) : jusqu'à **10,2 s**
//! publiés en `sem_wait_ms` à des niveaux où AUCUNE file n'était possible (autant de permis que
//! d'analystes), et **3,8 s en passe SOLO** — un seul client
//! (`concurrency-2026-08-01.jsonl`). REPRODUIT le jour du correctif sur la même base, même
//! binaire d'avant : **16,5 s en solo** (`concurrency-reproduction-2026-08-01.jsonl`). Une valeur
//! structurellement impossible : avec un permit libre, une requête ne peut pas attendre son tour.
//! La métrique désignait donc précisément le levier qu'il ne fallait pas toucher — la même campagne
//! mesure qu'à `query_sem=8` contre 3, sur le MÊME travail, le débit tombe (×0,46), le p95 passe de
//! 27 s à 50 s, la RSS crête gagne 725 Mio, et le daemon est TUÉ par le noyau à 10 analystes.
//!
//! CE QUE C'ÉTAIT, MESURÉ (`concurrency-attribution-2026-08-01.jsonl`, binaire à découpage, verrou
//! encore en place) : à 1 analyste pour 3 permis, l'attente du permit tombe à **0,000 ms** et
//! **2 876 ms** réapparaissent en `db_lock_wait_ms` ; en solo, jusqu'à **3 421 ms**, atteints par
//! `C6-filter-host` — une requête qui s'EXÉCUTE en 14 ms et qui attendait donc 240 fois son propre
//! travail, derrière un tick de la boucle de rollups.
//!
//! UN NOM QUI MENT EST PIRE QU'UNE ABSENCE DE MÉTRIQUE, parce qu'il inspire confiance. On ne l'a
//! donc pas renommé : on a rendu la valeur conforme au nom, et publié À CÔTÉ ce qu'elle contenait.
//!
//! POURQUOI UN TYPE PLUTÔT QU'UNE DISCIPLINE. Le défaut n'était pas une ligne fausse, c'était une
//! FORME : un `Instant` nu, démarré à un endroit, lu à un autre, et un `json!` qui accepte
//! n'importe quel nombre sous n'importe quel nom. Rien n'empêchait le prochain lecteur de refaire
//! exactement la même chose. Ici :
//!   1. la durée d'attente d'un permit n'est portée que par `PermitWait` ;
//!   2. `PermitWait` n'a AUCUN constructeur public, ni `Default`, ni `From<Duration>` ;
//!   3. la seule fonction qui en produit une est `acquire_query_permit`, qui ENCADRE le `.await`
//!      d'acquisition — le chronomètre ne peut donc pas commencer ailleurs ;
//!   4. mieux : quand un permit est LIBRE, il est pris sans attendre (`try_acquire_owned`) et
//!      l'attente vaut le ZÉRO CONSTANT — aucune horloge n'intervient, donc rien ne peut la
//!      contaminer. La propriété « autant de permis que de clients ⇒ attente nulle » cesse d'être
//!      une mesure à vérifier : elle devient la CONSTRUCTION de la valeur ;
//!   5. `QueryTimings` — le seul écrivain des champs `stats` de temps — ne s'obtient QUE par
//!      `QueryClock::permit`, qui consomme l'horloge d'entrée et passe par (3). Écrire le chrono
//!      d'entrée dans `sem_wait_ms` ne compile pas.
//!
//! CE QUE `stats` PUBLIE MAINTENANT, et pourquoi c'est un DÉCOUPAGE et pas un champ de plus :
//!
//! | champ | ce qu'il mesure |
//! |---|---|
//! | `server_ms` | tout le handler, de l'entrée à la réponse (inchangé) |
//! | `prepare_ms` | AVANT le permit : lecture du corps, masques, couverture des rollups, compilation |
//! | `sem_wait_ms` | l'attente du PERMIT, et rien d'autre. `0` exact quand un permit était libre |
//! | `db_lock_wait_ms` | le temps passé à OBTENIR le verrou de la connexion PARTAGÉE (jamais celui passé à le tenir) — la sérialisation que personne ne voyait |
//! | `exec_ms` | le RESTE : `server_ms - prepare_ms - sem_wait_ms` |
//!
//! `exec_ms` est le reste, jamais une troisième horloge : l'identité
//! `prepare + sem_wait + exec == server` tient donc par CONSTRUCTION, pas par vigilance. Et
//! `db_lock_wait_ms` n'est pas un quatrième terme de la somme : c'est une PART de `prepare_ms` (ou
//! d'`exec_ms` selon où le verrou est pris), publiée à part parce que c'est elle qui dit à
//! l'exploitant que le sémaphore n'est pas le levier.
//!
//! LA SÉRIALISATION ELLE-MÊME A ÉTÉ RETIRÉE, une fois qu'elle a été MESURÉE (cf. le commentaire de
//! `handlers/query.rs` sur la lecture de couverture des rollups, qui est passée au pool de lecture).
//! Le chronomètre reste : il n'était pas là pour ce correctif-là, il est là pour que le PROCHAIN
//! verrou pris sur ce chemin soit visible au lieu d'être imputé au sémaphore.

use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};
// `OwnedSemaphorePermit` n'est PLUS nommé ici : le permit nu ne quitte plus ce fichier, il repart
// enveloppé dans `semaphore_interactif::PermitMesure` (qui publie sa détention à la libération).
use tokio::sync::{AcquireError, Semaphore, TryAcquireError};

/// L'ATTENTE D'UN PERMIT, et rien d'autre. Microsecondes.
///
/// **Aucun constructeur public, aucun `Default`, aucun `From<Duration>`.** Un site d'appel ne peut
/// pas fabriquer cette valeur : il ne peut que la RECEVOIR de `acquire_query_permit`. C'est ce qui
/// rend l'ancien défaut non représentable — un `Instant` démarré à l'entrée du handler ne peut pas
/// devenir un `PermitWait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermitWait(u64);

impl PermitWait {
    /// LE ZÉRO STRUCTUREL — la valeur d'une acquisition qui n'a PAS attendu.
    ///
    /// Privé, et c'est le point : il n'est produit que par la branche `try_acquire_owned` réussie de
    /// `acquire_query_permit`. Aucune horloge n'est lue sur ce chemin, donc aucune durée étrangère
    /// ne peut s'y glisser — même pas une microseconde d'ordonnancement.
    fn none() -> Self {
        Self(0)
    }

    /// L'attente, en millisecondes, au format des autres champs `stats` (3 décimales).
    pub(crate) fn ms(self) -> f64 {
        dur_ms(Duration::from_micros(self.0))
    }
}

/// LE SEUL CHEMIN qui produit une `PermitWait` — et il ENCADRE l'acquisition, rien de plus.
///
/// DEUX CHEMINS, ET C'EST LA GARDE :
///   * un permit est LIBRE -> `try_acquire_owned` le prend sans jamais suspendre la tâche ->
///     l'attente est le ZÉRO CONSTANT. Tant qu'il y a au moins autant de permis que de clients
///     simultanés, c'est toujours ce chemin qui est pris : la propriété « aucune attente possible »
///     est donc CONSTRUITE, pas mesurée puis espérée.
///   * aucun permit libre -> il faut réellement faire la queue. Le chronomètre démarre ICI, juste
///     avant le `.await`, et s'arrête juste après. Il ne peut couvrir que la file.
///
/// ÉQUITÉ PRÉSERVÉE : le sémaphore de tokio remet les permits libérés AUX ATTENDEURS déjà en file
/// (sous son propre verrou), et non au compteur. `try_acquire_owned` ne peut donc pas doubler une
/// requête qui attend : il ne réussit que lorsqu'il reste de la capacité VRAIMENT libre.
///
/// CE POINT DE PASSAGE PUBLIE AUSSI (P7.8-a). Toute acquisition passe ici — c'est donc ici, et
/// nulle part ailleurs, que la borne interactive est comptée pour l'exploitant
/// (`semaphore_interactif` : attente, travail permit en main, saturation, par gabarit de route).
/// Aucune route ne porte de ligne de mesure, et une route ajoutée demain est mesurée sans que
/// personne y pense. Le permit rendu est le permit MESURÉ : le permit nu ne ressort pas d'ici, donc
/// une détention non comptée n'est pas représentable.
pub(crate) async fn acquire_query_permit(
    sem: &Arc<Semaphore>,
) -> Result<(crate::semaphore_interactif::PermitMesure, PermitWait), AcquireError> {
    match sem.clone().try_acquire_owned() {
        Ok(p) => return Ok((crate::semaphore_interactif::permis_pris(p, None), PermitWait::none())),
        Err(TryAcquireError::NoPermits) => {}
        Err(TryAcquireError::Closed) => {
            // Sémaphore fermé (arrêt) : on rend l'erreur CANONIQUE de tokio plutôt qu'une erreur
            // fabriquée ici — `AcquireError` n'a pas de constructeur public, et un appelant doit
            // recevoir exactement ce qu'il recevait avant ce module.
            return Err(sem
                .clone()
                .acquire_owned()
                .await
                .err()
                .expect("un sémaphore fermé ne délivre pas de permit"));
        }
    }
    let t = Instant::now();
    let p = sem.clone().acquire_owned().await?;
    // UNE seule lecture d'horloge sert les deux publications (le champ `stats` de l'appelant et la
    // série d'exploitation) : deux lectures pourraient diverger, et la question « pourquoi la
    // réponse et /metrics ne disent-ils pas la même attente ? » n'a pas de bonne réponse.
    let attente = t.elapsed();
    Ok((crate::semaphore_interactif::permis_pris(p, Some(attente)), PermitWait(attente.as_micros() as u64)))
}

/// LE TEMPS PASSÉ À OBTENIR LE VERROU DE LA CONNEXION PARTAGÉE — la sérialisation que personne ne
/// voyait.
///
/// Ce n'est PAS le temps passé à tenir le verrou (qui est du travail), c'est le temps passé à
/// l'ATTENDRE (qui est de la file d'attente déguisée). La distinction est tout l'enjeu : la
/// première grandeur baisse en optimisant la requête, la seconde ne baisse qu'en cessant de
/// partager le verrou — et surtout, aucune des deux ne baisse en augmentant le sémaphore.
///
/// Cumulatif (`AtomicU64`, microsecondes) parce qu'un chemin de requête peut prendre le verrou
/// plusieurs fois ; `Send + Sync` parce que la valeur traverse des `.await`.
#[derive(Debug, Default)]
pub(crate) struct SharedDbWait(AtomicU64);

impl SharedDbWait {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Prend le verrou de la connexion partagée EN CHRONOMÉTRANT L'ATTENTE. À utiliser partout où le
    /// chemin d'une requête interactive doit toucher la connexion partagée : sans ça, l'attente
    /// redevient invisible et retombe dans un autre champ, qui mentira à son tour.
    pub(crate) fn lock<'a>(&self, m: &'a Mutex<Connection>) -> parking_lot::MutexGuard<'a, Connection> {
        let t = Instant::now();
        let g = m.lock();
        self.0.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        g
    }

    fn micros(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// L'HORLOGE D'UNE REQUÊTE, démarrée à l'entrée du handler.
///
/// Elle ne sait rendre QUE le temps total écoulé. Pour obtenir un découpage il faut passer par
/// `permit` — c'est-à-dire par l'acquisition elle-même. Une horloge d'entrée ne peut donc pas
/// devenir une attente de sémaphore.
pub(crate) struct QueryClock {
    entry: Instant,
    db: SharedDbWait,
}

impl QueryClock {
    pub(crate) fn start() -> Self {
        Self { entry: Instant::now(), db: SharedDbWait::new() }
    }

    /// Le chronomètre des verrous de la connexion PARTAGÉE pris sur ce chemin de requête.
    pub(crate) fn db(&self) -> &SharedDbWait {
        &self.db
    }

    /// LA SEULE PORTE VERS `QueryTimings`, et elle passe par l'acquisition du permit.
    ///
    /// `prepare` est figé JUSTE AVANT la demande de permit, `sem_wait` vient de l'acquisition
    /// elle-même : les deux ne peuvent pas se chevaucher, et aucun des deux ne peut absorber
    /// l'autre. C'est cette signature — `self` consommé, `PermitWait` non fabricable — qui rend le
    /// défaut d'origine impossible à réécrire.
    pub(crate) async fn permit(
        self,
        sem: &Arc<Semaphore>,
    ) -> Result<(crate::semaphore_interactif::PermitMesure, QueryTimings), AcquireError> {
        let prepare = self.entry.elapsed();
        let (permit, wait) = acquire_query_permit(sem).await?;
        // Le compteur de verrous est DÉPLACÉ, pas recopié : un verrou pris APRÈS le permit compte
        // dans le même total. Sinon la même attente serait visible ou invisible selon l'endroit où
        // le verrou est pris — c'est-à-dire selon un détail que l'exploitant ne peut pas connaître.
        Ok((permit, QueryTimings { entry: self.entry, prepare, permit: wait, db: self.db }))
    }
}

/// LE DÉCOUPAGE PUBLIÉ. Seul écrivain des champs de temps de `stats` (garde de source :
/// `only_query_timings_publishes_the_time_split`).
pub(crate) struct QueryTimings {
    entry: Instant,
    prepare: Duration,
    permit: PermitWait,
    db: SharedDbWait,
}

/// LA FIN D'UNE REQUÊTE EST UNE OBSERVATION (`P10.11-a`). Le découpage part dans la réponse — donc
/// vers UN client, une fois ; il part AUSSI, ici, dans une série d'exploitation qui, elle, se corrèle
/// avec la fenêtre de vieillissement.
///
/// POURQUOI `Drop` ET PAS UN APPEL EN FIN DE HANDLER : c'est la même raison qui a fait de
/// `PermitMesure` un type. Un handler a autant de sorties que de `return` et de `?` ; huit sites
/// écrivent aujourd'hui le découpage dans une réponse, et une requête qui échoue après avoir attendu
/// n'en écrit aucune — son attente a pourtant eu lieu. Ici la libération de la valeur EST la fin de
/// la requête, sur tous les chemins de retour, par construction.
///
/// LES DEUX TERMES PARTENT ENSEMBLE, jamais l'un sans l'autre : l'attente du permit et l'attente du
/// verrou partagé sont deux files que la même tâche traverse l'une APRÈS l'autre, donc deux
/// intervalles disjoints dont la somme est le coût d'attente de cette requête. Publier le seul
/// verrou rendrait une fraction du coût réel — et c'est le terme MINORITAIRE dès que la borne
/// interactive sature derrière la passe.
impl Drop for QueryTimings {
    fn drop(&mut self) {
        crate::attente_serie::observer(self.permit.0, self.db.micros());
    }
}

impl QueryTimings {
    /// L'attente du PERMIT. `0.0` exact quand un permit était libre.
    #[allow(dead_code)]
    pub(crate) fn sem_wait_ms(&self) -> f64 {
        self.permit.ms()
    }

    /// Le chronomètre des verrous partagés, pour les verrous pris APRÈS le permit (c'est le cas de
    /// `/api/search`, qui prend son permit AVANT de toucher la base — l'ordre qu'on veut partout).
    pub(crate) fn db(&self) -> &SharedDbWait {
        &self.db
    }

    /// L'attente du VERROU de la connexion partagée, cumulée sur tout le chemin.
    pub(crate) fn db_lock_wait_ms(&self) -> f64 {
        dur_ms(Duration::from_micros(self.db.micros()))
    }

    /// ÉCRIT le découpage dans `stats`. `exec_ms` est le RESTE (jamais une 3e horloge) : l'identité
    /// `prepare + sem_wait + exec == server` tient par construction.
    pub(crate) fn stamp(&self, v: &mut Value) {
        let server = dur_ms(self.entry.elapsed());
        let prepare = dur_ms(self.prepare);
        let sem_wait = self.permit.ms();
        // Le reste, plancher à 0 : les trois durées sont arrondies à la microseconde près, la
        // soustraction peut donc rendre -0.001 sur une requête instantanée. Un temps négatif publié
        // serait un chiffre faux ; le plancher est une conséquence de l'arrondi, pas une correction.
        let exec = ((server - prepare - sem_wait) * 1000.0).round() / 1000.0;
        v["stats"]["server_ms"] = json!(server);
        v["stats"]["prepare_ms"] = json!(prepare);
        v["stats"]["sem_wait_ms"] = json!(sem_wait);
        v["stats"]["db_lock_wait_ms"] = json!(self.db_lock_wait_ms());
        v["stats"]["exec_ms"] = json!(exec.max(0.0));
    }
}
