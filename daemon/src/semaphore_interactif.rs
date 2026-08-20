//! semaphore_interactif — CE QUE COÛTE LA RESSOURCE LA PLUS CONTRAINTE, PAR ROUTE.
//!
//! LE TROU QU'IL FERME (P7.8-a). Le sémaphore interactif (`AppState::query_sem`, taille
//! `PLUME_QUERY_CONCURRENCY`, défaut 3) borne les lectures interactives concurrentes — c'est le
//! levier qui tient le budget mémoire de 2 Gio du projet. Le découpage `stats` de `query_timing`
//! rend l'attente d'un permit à l'appelant d'UNE requête, mais il ne laisse aucune trace côté
//! exploitant : rien, dans `/metrics`, ne disait quelle route consommait la borne, ni si une
//! lenteur venait de l'ATTENTE du permit ou du TRAVAIL fait une fois le permit obtenu. Une
//! saturation invisible se diagnostique à tâtons.
//!
//! DEUX GRANDEURS QUE LE TOTAL CONFOND, ET C'EST TOUT L'ENJEU :
//!
//! | série | ce qu'elle mesure | ce qu'elle dit à l'exploitant |
//! |---|---|---|
//! | `plume_query_permit_wait_ms_total` | le temps passé EN FILE, avant d'obtenir le permit | la borne est trop étroite POUR CETTE CHARGE (ou une autre route la monopolise) |
//! | `plume_query_work_ms_total` | le temps passé À TRAVAILLER, permit en main | la route elle-même est lente ; élargir la borne l'aggraverait |
//!
//! Une mesure unique « durée de la route » additionne les deux et désigne donc le mauvais levier —
//! exactement le défaut que `query_timing` a déjà mesuré et fermé côté réponse HTTP (`sem_wait_ms`
//! valait jusqu'à 16,5 s en passe SOLO, là où aucune file n'était possible).
//!
//! LA SATURATION SE PUBLIE, elle ne se déduit pas : `plume_query_permit_waits_total` compte les
//! acquisitions qui ont RÉELLEMENT dû faire la queue, `plume_query_permits_held` dit combien de
//! permis sont pris à l'instant du scrape, `plume_query_permits_limit` rappelle la borne. Un
//! sémaphore dont on ne sait pas s'il est plein ne renseigne sur rien.
//!
//! VOIE UNIQUE, PAS DIX-HUIT MODIFICATIONS. Toutes les routes qui consomment la borne passent par
//! `query_timing::acquire_query_permit` (garde de source :
//! `the_interactive_semaphore_is_only_acquired_through_the_timed_gate`). C'est CE point de passage
//! qui est instrumenté, et lui seul : aucune route n'a de ligne de mesure, et une route ajoutée
//! demain est mesurée sans que personne y pense. L'étiquette `route` n'est pas passée par les
//! appelants — elle est LUE dans une variable de tâche posée par une couche du routeur depuis le
//! GABARIT de route apparié (`axum::extract::MatchedPath`), c'est-à-dire depuis la table matchit
//! elle-même.
//!
//! LA CARDINALITÉ EST BORNÉE, ET C'EST UNE CONTRAINTE DE MÉMOIRE, PAS UN DÉTAIL. L'étiquette est un
//! GABARIT (`/api/v1/label/:name/values`), jamais une URL, jamais un paramètre, jamais un
//! utilisateur : deux requêtes sur des chemins concrets différents partagent la même étiquette. Le
//! registre est en OUTRE plafonné à `ROUTES_CAP` entrées + une entrée de débordement, de sorte que
//! la borne ne dépend PAS du nombre de routes déclarées dans le routeur : au pire
//! `(ROUTES_CAP + 1)` valeurs d'étiquette. Un débordement ne perd pas la mesure (elle tombe dans le
//! seau `(débordement)`), il perd son ATTRIBUTION — et le dit, par
//! `plume_query_permit_routes_tronque=1`, sur le modèle de `plume_netban_store_tronque`.
//!
//! CE QUE CE MODULE NE FAIT PAS : il ne prend aucun permit, ne change aucune taille de sémaphore,
//! n'altère aucune réponse. Des atomiques et un registre de quelques dizaines d'entrées (~4 Kio au
//! plafond) : le mode 0 reste byte-identique du point de vue d'un client.

use crate::*;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::OwnedSemaphorePermit;

/// PLAFOND DU REGISTRE D'ÉTIQUETTES. 21 gabarits de route acquièrent la borne au 2026-08-20 (compte
/// DÉRIVÉ, cf. `routes_qui_consomment_le_semaphore_interactif`) ; le reste est de la marge pour les
/// routes à venir. Ce n'est pas une limite de confort : c'est ce qui rend la cardinalité de
/// `/metrics` indépendante de la taille du routeur.
pub(crate) const ROUTES_CAP: usize = 48;

/// L'étiquette des acquisitions faites au-delà du plafond — la mesure survit, son attribution non.
pub(crate) const ETIQUETTE_DEBORDEMENT: &str = "(débordement)";
/// L'étiquette d'une acquisition faite hors d'une requête HTTP appariée (tâche de fond, test).
/// C'est un SIGNAL, pas un fourre-tout : la borne interactive n'est pas censée être consommée là.
pub(crate) const ETIQUETTE_HORS_REQUETE: &str = "(hors requête)";

/// LES COMPTEURS D'UNE ROUTE. Microsecondes en interne (l'exposition rend des millisecondes à 3
/// décimales, comme les champs `stats`), atomiques relaxés : coût ~1 ns sur un chemin qui vient de
/// faire une acquisition de sémaphore.
#[derive(Debug, Default)]
pub(crate) struct Compteurs {
    acquisitions: AtomicU64,
    attentes: AtomicU64,
    attente_us: AtomicU64,
    attente_max_us: AtomicU64,
    travail_us: AtomicU64,
    travail_max_us: AtomicU64,
}

impl Compteurs {
    /// Permis obtenus par cette route depuis le démarrage.
    pub(crate) fn acquisitions(&self) -> u64 {
        self.acquisitions.load(Ordering::Relaxed)
    }
    /// Acquisitions qui ont RÉELLEMENT fait la queue (saturation observée, jamais déduite).
    pub(crate) fn attentes(&self) -> u64 {
        self.attentes.load(Ordering::Relaxed)
    }
    /// Cumul de l'ATTENTE du permit (µs) — file d'attente, pas travail.
    pub(crate) fn attente_us(&self) -> u64 {
        self.attente_us.load(Ordering::Relaxed)
    }
    /// Plus longue attente observée (µs).
    pub(crate) fn attente_max_us(&self) -> u64 {
        self.attente_max_us.load(Ordering::Relaxed)
    }
    /// Cumul du TRAVAIL permit en main (µs) — de l'acquisition à la libération.
    pub(crate) fn travail_us(&self) -> u64 {
        self.travail_us.load(Ordering::Relaxed)
    }
    /// Plus longue détention observée (µs).
    pub(crate) fn travail_max_us(&self) -> u64 {
        self.travail_max_us.load(Ordering::Relaxed)
    }
}

fn max_atomique(cible: &AtomicU64, v: u64) {
    let mut vu = cible.load(Ordering::Relaxed);
    while v > vu {
        match cible.compare_exchange_weak(vu, v, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actuel) => vu = actuel,
        }
    }
}

/// LE REGISTRE D'ÉTIQUETTES, PLAFONNÉ — et c'est LUI qui borne la cardinalité de `/metrics`.
///
/// Une structure, pas un `static` : le plafond ne se prouve qu'en le FAISANT MORDRE, et un plafond
/// qu'on ne peut faire mordre que sur l'instance globale du processus est un plafond dont l'essai
/// pollue tout le reste. Ici l'essai construit son propre registre.
#[derive(Debug)]
pub(crate) struct Registre {
    entrees: RwLock<Vec<(Box<str>, Arc<Compteurs>)>>,
    plafond: usize,
    tronque: AtomicBool,
}

impl Registre {
    pub(crate) fn neuf(plafond: usize) -> Self {
        Self { entrees: RwLock::new(Vec::with_capacity(8)), plafond, tronque: AtomicBool::new(false) }
    }

    /// Les compteurs d'une étiquette, créés à la première acquisition. Au-delà du plafond, tout
    /// retombe dans le seau de débordement : la MESURE survit, son ATTRIBUTION non — et le registre
    /// le dit (`tronque`), parce qu'une borne muette ne vaut pas mieux qu'aucune borne.
    pub(crate) fn compteurs(&self, nom: &str) -> Arc<Compteurs> {
        if let Some(c) = self.existants(nom) {
            return c;
        }
        let mut g = self.entrees.write();
        if let Some(c) = g.iter().find(|(n, _)| &**n == nom).map(|(_, c)| c.clone()) {
            return c; // course perdue entre la lecture et l'écriture : on prend l'entrée de l'autre
        }
        if g.len() >= self.plafond && nom != ETIQUETTE_DEBORDEMENT {
            self.tronque.store(true, Ordering::Relaxed);
            if let Some(c) = g.iter().find(|(n, _)| &**n == ETIQUETTE_DEBORDEMENT).map(|(_, c)| c.clone()) {
                return c;
            }
            let c = Arc::new(Compteurs::default());
            g.push((ETIQUETTE_DEBORDEMENT.into(), c.clone()));
            return c;
        }
        let c = Arc::new(Compteurs::default());
        g.push((nom.into(), c.clone()));
        c
    }

    /// Les compteurs d'une étiquette SI elle a déjà servi — sans jamais la créer.
    pub(crate) fn existants(&self, nom: &str) -> Option<Arc<Compteurs>> {
        self.entrees.read().iter().find(|(n, _)| &**n == nom).map(|(_, c)| c.clone())
    }

    /// (étiquettes enregistrées, plafond, le plafond a-t-il mordu).
    pub(crate) fn etat(&self) -> (usize, usize, bool) {
        (self.entrees.read().len(), self.plafond, self.tronque.load(Ordering::Relaxed))
    }

    /// Copie des couples (étiquette, compteurs) — le verrou n'est pas tenu pendant le formatage.
    fn instantane(&self) -> Vec<(String, Arc<Compteurs>)> {
        self.entrees.read().iter().map(|(n, c)| (echappe(n), c.clone())).collect()
    }
}

static REGISTRE: std::sync::OnceLock<Registre> = std::sync::OnceLock::new();
pub(crate) fn registre() -> &'static Registre {
    REGISTRE.get_or_init(|| Registre::neuf(ROUTES_CAP))
}

/// Permis DÉTENUS à l'instant présent (acquis, pas encore libérés) — la saturation vue du scrape.
static DETENUS: AtomicU64 = AtomicU64::new(0);
/// Taille du sémaphore interactif, POSÉE au démarrage (`PLUME_QUERY_CONCURRENCY`). 0 = pas encore
/// posée : la jauge est alors ABSENTE de l'exposition plutôt que fausse à zéro.
static BORNE: AtomicU64 = AtomicU64::new(0);
/// ENREGISTRE LA TAILLE DU SÉMAPHORE. Ne la fixe pas et ne la lit pas ailleurs : elle est publiée
/// pour que `plume_query_permits_held` se lise CONTRE quelque chose (« 3 permis pris » ne dit rien
/// sans « sur 3 »).
pub(crate) fn poser_borne(taille: usize) {
    BORNE.store(taille as u64, Ordering::Relaxed);
}

/// Permis détenus à l'instant présent.
pub(crate) fn permis_detenus() -> u64 {
    DETENUS.load(Ordering::Relaxed)
}

/// L'ÉTIQUETTE D'UNE ACQUISITION. `Appariee` porte le GABARIT de route rendu par le routeur (jamais
/// l'URL concrète) ; `Nommee` sert aux appels hors requête HTTP et aux essais.
#[derive(Debug, Clone)]
pub(crate) enum Etiquette {
    Appariee(axum::extract::MatchedPath),
    /// Le constructeur des appels HORS routeur. Aucun chemin de production ne l'emprunte
    /// (d'où l'`allow`) : les essais s'en servent pour mettre le mécanisme en situation
    /// sans monter une pile HTTP, et une tâche de fond qui viendrait un jour prendre un permit
    /// s'étiquetterait par là plutôt que de tomber dans `(hors requête)`.
    #[allow(dead_code)]
    Nommee(&'static str),
}

impl Etiquette {
    fn nom(&self) -> &str {
        match self {
            Etiquette::Appariee(m) => m.as_str(),
            Etiquette::Nommee(n) => n,
        }
    }
}

tokio::task_local! {
    /// La route de la tâche courante. Posée par `sous_route` (couche du routeur), lue par
    /// l'acquisition. Ni la valeur ni sa pose ne traversent un `spawn` : une tâche détachée qui
    /// prendrait un permit compterait — à raison — comme `(hors requête)`.
    static ROUTE_COURANTE: Etiquette;
}

/// EXÉCUTE `f` SOUS UNE ÉTIQUETTE DE ROUTE. Seule façon de poser la variable de tâche.
pub(crate) async fn sous_route<F: std::future::Future>(e: Etiquette, f: F) -> F::Output {
    ROUTE_COURANTE.scope(e, f).await
}

/// LA COUCHE QUI POSE L'ÉTIQUETTE — et la seule modification que le câblage des routes subit.
///
/// Posée en `route_layer` (donc APRÈS l'appariement, et jamais sur le service de fichiers de repli),
/// elle lit le GABARIT apparié par la table matchit — pas l'URL. Une route ajoutée demain est donc
/// étiquetée sans qu'on touche à ce fichier, et aucune valeur d'étiquette ne peut venir du client :
/// c'est de là que vient la borne de cardinalité, avant même le plafond du registre.
///
/// Coût : le clone d'un `MatchedPath` (compteur de référence, aucune allocation) et une portée de
/// variable de tâche. Aucun en-tête, aucun corps, aucun statut n'est touché.
pub(crate) async fn etiqueter_route(req: Request, next: Next) -> Response {
    match req.extensions().get::<axum::extract::MatchedPath>().cloned() {
        // Pas de gabarit apparié (cas impossible sous `route_layer`, mais on ne pose pas d'étiquette
        // fabriquée pour autant) : la requête passe, une acquisition éventuelle comptera
        // `(hors requête)` — un signal, pas un silence.
        None => next.run(req).await,
        Some(m) => sous_route(Etiquette::Appariee(m), next.run(req)).await,
    }
}

/// Les compteurs de la route courante — ou ceux du seau `(hors requête)` hors de toute portée.
///
/// Le nom n'est jamais copié : la résolution se fait DANS la portée de la variable de tâche, sur un
/// `&str` emprunté. Sur un chemin qui vient de faire une acquisition de sémaphore, une allocation de
/// plus ne se verrait pas — mais une mesure qui coûte ce qu'elle mesure finit par se faire éteindre.
fn compteurs_de_la_route_courante() -> Arc<Compteurs> {
    ROUTE_COURANTE
        .try_with(|e| registre().compteurs(e.nom()))
        .unwrap_or_else(|_| registre().compteurs(ETIQUETTE_HORS_REQUETE))
}

/// LE PERMIT MESURÉ — il PORTE le permit du sémaphore et publie, à sa libération, le temps pendant
/// lequel il a occupé la borne.
///
/// Pourquoi un type plutôt qu'un appel en fin de handler : la fin d'un handler a autant de sorties
/// que de `return` et de `?`, et une mesure posée sur une seule d'entre elles serait fausse la
/// moitié du temps. Ici la libération du permit EST la fin du travail — c'est le même instant, par
/// construction, sur tous les chemins de retour.
///
/// Le champ est PRIVÉ : un appelant ne peut ni extraire le permit nu, ni prolonger sa détention
/// au-delà de la valeur, ni fabriquer une détention qui n'a pas eu lieu.
#[derive(Debug)]
pub(crate) struct PermitMesure {
    _permis: OwnedSemaphorePermit,
    compteurs: Arc<Compteurs>,
    depuis: Instant,
}

impl Drop for PermitMesure {
    fn drop(&mut self) {
        let us = self.depuis.elapsed().as_micros() as u64;
        self.compteurs.travail_us.fetch_add(us, Ordering::Relaxed);
        max_atomique(&self.compteurs.travail_max_us, us);
        DETENUS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// COMPTABILISE UNE ACQUISITION et rend le permit mesuré. Appelé UNIQUEMENT par
/// `query_timing::acquire_query_permit` — le point de passage unique.
///
/// `attente` vaut `None` quand un permit était LIBRE (aucune horloge n'a été lue sur ce chemin :
/// c'est le zéro STRUCTUREL de `PermitWait`, cf. `query_timing`) et `Some(d)` quand il a fallu faire
/// la queue. La distinction n'est donc pas « une durée nulle », c'est « il n'y a pas eu de file » —
/// et c'est ce qui rend `plume_query_permit_waits_total` lisible comme une saturation.
pub(crate) fn permis_pris(permis: OwnedSemaphorePermit, attente: Option<Duration>) -> PermitMesure {
    let compteurs = compteurs_de_la_route_courante();
    compteurs.acquisitions.fetch_add(1, Ordering::Relaxed);
    if let Some(d) = attente {
        let us = d.as_micros() as u64;
        compteurs.attentes.fetch_add(1, Ordering::Relaxed);
        compteurs.attente_us.fetch_add(us, Ordering::Relaxed);
        max_atomique(&compteurs.attente_max_us, us);
    }
    DETENUS.fetch_add(1, Ordering::Relaxed);
    PermitMesure { _permis: permis, compteurs, depuis: Instant::now() }
}

/// Échappement d'une valeur d'étiquette Prometheus. Les étiquettes ne viennent QUE de la table de
/// routes et de deux constantes — donc rien à échapper dans l'état actuel du routeur ; il est là pour
/// ça reste vrai si un gabarit exotique apparaît, pas pour réparer une entrée utilisateur.
fn echappe(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn us_en_ms(us: u64) -> String {
    format!("{:.3}", dur_ms(Duration::from_micros(us)))
}

/// EXPOSITION PROMETHEUS de la borne interactive — six séries étiquetées par route, cinq globales.
/// Appelée depuis `metrics::gather_prom` (source de vérité unique, comme `ventilation_serie`).
///
/// Aucune requête SQL, aucun verrou d'écriture : un scrape ne coûte rien à la base.
pub(crate) fn exposition_prom() -> String {
    let instantane = registre().instantane();
    let mut o = String::with_capacity(512 + instantane.len() * 320);
    let bloc = |o: &mut String, nom: &str, typ: &str, aide: &str, valeur: &dyn Fn(&Compteurs) -> String| {
        o.push_str(&format!("# HELP {nom} {aide}\n# TYPE {nom} {typ}\n"));
        for (r, c) in &instantane {
            o.push_str(&format!("{nom}{{route=\"{r}\"}} {}\n", valeur(c)));
        }
    };
    bloc(&mut o, "plume_query_permit_acquisitions_total", "counter",
        "Permis du sémaphore interactif obtenus, par gabarit de route",
        &|c| c.acquisitions().to_string());
    bloc(&mut o, "plume_query_permit_waits_total", "counter",
        "Acquisitions qui ont dû ATTENDRE un permit (saturation de la borne interactive)",
        &|c| c.attentes().to_string());
    bloc(&mut o, "plume_query_permit_wait_ms_total", "counter",
        "Temps cumulé passé EN FILE avant d'obtenir un permit (ms) — jamais du travail",
        &|c| us_en_ms(c.attente_us()));
    bloc(&mut o, "plume_query_permit_wait_ms_max", "gauge",
        "Plus longue attente d'un permit observée depuis le démarrage (ms)",
        &|c| us_en_ms(c.attente_max_us()));
    bloc(&mut o, "plume_query_work_ms_total", "counter",
        "Temps cumulé passé À TRAVAILLER permit en main (ms) — jamais de l'attente",
        &|c| us_en_ms(c.travail_us()));
    bloc(&mut o, "plume_query_work_ms_max", "gauge",
        "Plus longue détention d'un permit observée depuis le démarrage (ms)",
        &|c| us_en_ms(c.travail_max_us()));
    let (n_routes, plafond, tronque) = registre().etat();
    o.push_str("# HELP plume_query_permits_held Permis du sémaphore interactif détenus à l'instant du scrape\n");
    o.push_str("# TYPE plume_query_permits_held gauge\n");
    o.push_str(&format!("plume_query_permits_held {}\n", permis_detenus()));
    let borne = BORNE.load(Ordering::Relaxed);
    if borne > 0 {
        // ABSENTE tant qu'elle n'a pas été posée (outil CLI, essai) : une borne à 0 se lirait comme
        // « sémaphore fermé », ce qui serait un chiffre faux plutôt qu'une absence.
        o.push_str("# HELP plume_query_permits_limit Taille du sémaphore interactif (PLUME_QUERY_CONCURRENCY)\n");
        o.push_str("# TYPE plume_query_permits_limit gauge\n");
        o.push_str(&format!("plume_query_permits_limit {borne}\n"));
    }
    o.push_str("# HELP plume_query_permit_routes Étiquettes de route enregistrées (cardinalité réelle)\n");
    o.push_str("# TYPE plume_query_permit_routes gauge\n");
    o.push_str(&format!("plume_query_permit_routes {n_routes}\n"));
    o.push_str("# HELP plume_query_permit_routes_cap Plafond du registre d'étiquettes (cardinalité au pire)\n");
    o.push_str("# TYPE plume_query_permit_routes_cap gauge\n");
    o.push_str(&format!("plume_query_permit_routes_cap {plafond}\n"));
    o.push_str("# HELP plume_query_permit_routes_tronque 1 si des routes partagent le seau de débordement faute de place\n");
    o.push_str("# TYPE plume_query_permit_routes_tronque gauge\n");
    o.push_str(&format!("plume_query_permit_routes_tronque {}\n", u8::from(tronque)));
    o
}
