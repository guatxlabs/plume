//! DAY-2 OPS (#51) — SELF-MÉTRIQUES & SANTÉ PAR COMPOSANT. Compteurs/jauges PROCESS-GLOBAUX (atomics)
//! incrémentés EN LIGNE sur les chemins déjà chauds (HTTP, ingest, recherche, scheduler) — JAMAIS un scan
//! de `event` par requête (doctrine 2 Go). `gather_prom` produit l'exposition Prometheus texte ; `gather_json`
//! la même donnée pour le panneau UI « Système » ; `component_health` dérive un état R/J/V par sous-système
//! (ingest / détection / rollups / store / forwarder / passes de fond / restauration) depuis la fraîcheur +
//! les horodatages de tick + les compteurs d'erreur. `P10.7-x` : le lien composant -> passes de fond est
//! lu dans `bilan_de_tick::COMPOSANTS`, et TOUT ce qu'aucun composant nommé ne revendique tombe dans le
//! composant « passes de fond » — un aveu publié n'a plus d'endroit où se perdre. Additif : rien de ceci n'altère une réponse HTTP ni une écriture DB -> mode 0
//! byte-identique (les atomics sont invisibles du client).
use crate::*;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// ---------- compteurs / jauges process-globaux (mis à jour EN LIGNE, coût ~1 ns) ----------
/// Requêtes HTTP servies (toutes routes) — bumpé dans `security_headers` (une couche déjà traversée par
/// TOUTES les requêtes) : aucune nouvelle couche, aucune State requise, invisible du client.
pub(crate) static HTTP_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Réponses 5xx (erreurs serveur) — signal d'anomalie côté opérateur.
pub(crate) static HTTP_5XX_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Events ingérés depuis le démarrage (compteur monotone) — bumpé dans `ingest_events_batch_env`.
pub(crate) static INGEST_EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Fichiers spool consommés — bumpé dans `ingest_once`.
pub(crate) static INGEST_FILES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// P-HEC (LOW#2) — batches PUSH (Firehose/Pub-Sub) ACCEPTÉS mais mappés à ZÉRO event (base64/JSON indécodable
/// ou field_map/records_path mal configuré). Rend OBSERVABLE un misconfig de source push qui, sinon, serait
/// silencieusement ACK-droppé (200/204) : un compteur qui grimpe sans `ingest_events_total` correspondant.
pub(crate) static PUSH_ZERO_MAP_TOTAL: AtomicU64 = AtomicU64::new(0);
/// P4.1-p — un compteur PAR RAISON d'ACK-DROP Pub/Sub. Pourquoi pas un seul total : `push_zero_map_total`
/// était incrémenté aussi bien par un `field_map` mal configuré que par une bombe gzip. L'exploitant qui le
/// voyait grimper allait donc inspecter son mapping alors que la cause pouvait être une TAILLE. Un compteur
/// qui NOMME mal ce qu'il compte oriente l'enquête à côté ; il vaut à peine mieux que pas de compteur.
///
/// La longueur est VÉRIFIÉE À LA COMPILATION contre `AckDrop::TOUTES` (assertion sous la déclaration de
/// l'énumération, ingest/pubsub.rs) : une raison ajoutée demain sans sa case NE COMPILE PAS.
pub(crate) static PUBSUB_ACKDROP: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// `S31` — LES BARRIÈRES DE DURABILITÉ DU SPOOL, COMPTÉES. Une publication de spool durable prend DEUX
/// barrières : `fsync` du fichier temporaire AVANT le renommage, `fsync` du répertoire APRÈS. Ces trois
/// compteurs sont le SEUL témoin d'exploitation des QUATRE surfaces dont le corps de réponse appartient
/// à un contrat étranger (Splunk HEC, OTLP, Firehose, Pub/Sub) et ne peut donc pas porter de champ
/// `durable` : sur celles-là, `plume_spool_barriere_echec_total` qui grimpe est la seule façon de voir
/// qu'un 2xx a cessé d'être adossé à une barrière.
///
/// CE QU'ILS NE PROUVENT PAS : la survie à une coupure d'alimentation. Ils comptent des appels rendus
/// sans erreur par le noyau, pas des octets retrouvés après un redémarrage brutal.
pub(crate) static SPOOL_BARRIERE_FICHIER_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Barrières de RÉPERTOIRE prises (rendent durable l'ENTRÉE créée par le renommage).
pub(crate) static SPOOL_BARRIERE_REPERTOIRE_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Barrières REFUSÉES par le noyau. Une barrière de FICHIER refusée fait échouer la publication
/// (l'émetteur garde sa copie). Une barrière de RÉPERTOIRE refusée laisse le lot publié mais NON
/// durable : la réponse reste un succès (l'échouer ferait réémettre, donc DOUBLER le lot) et ce
/// compteur est ce qui le dit.
pub(crate) static SPOOL_BARRIERE_ECHEC_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Recherches interactives (query/search) servies.
pub(crate) static SEARCH_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Ticks du scheduler de règles + horodatage (unix s) du dernier tick — santé « détection ».
pub(crate) static SCHED_RULE_TICKS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCHED_RULE_LAST_TS: AtomicI64 = AtomicI64::new(0);
/// Ticks de rollup + horodatage (unix s) du dernier tick — santé « rollups ».
pub(crate) static SCHED_ROLLUP_TICKS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCHED_ROLLUP_LAST_TS: AtomicI64 = AtomicI64::new(0);
/// Horodatage (unix s) de démarrage du process — posé une fois au boot (process_start_time_seconds).
pub(crate) static START_TS: AtomicI64 = AtomicI64::new(0);
/// READINESS (k8s /readyz) : passe à true APRÈS migrate + bind (port écoute). Lu par le handler readyz.
pub(crate) static READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Réservoir borné des dernières latences de recherche (ms) pour p50/p95. Petit (cap 512) : lock trivial,
/// aucune allocation par point après remplissage. Jamais un vecteur de fuite (que des durées).
static SEARCH_LAT: std::sync::OnceLock<Mutex<std::collections::VecDeque<u32>>> = std::sync::OnceLock::new();
pub(crate) const SEARCH_LAT_CAP: usize = 512;
fn search_lat() -> &'static Mutex<std::collections::VecDeque<u32>> {
    SEARCH_LAT.get_or_init(|| Mutex::new(std::collections::VecDeque::with_capacity(SEARCH_LAT_CAP)))
}

/// Enregistre une latence de recherche (ms) : compteur + réservoir borné (évince le plus ancien).
pub(crate) fn record_search(ms: u32) {
    SEARCH_TOTAL.fetch_add(1, Ordering::Relaxed);
    let mut q = search_lat().lock();
    if q.len() >= SEARCH_LAT_CAP {
        q.pop_front();
    }
    q.push_back(ms);
}

/// GARDE-CHRONO (RAII) : posé en tête des handlers query/search (`let _t = search_timer();`), il enregistre
/// la latence à la SORTIE (Drop) quel que soit le chemin de retour. Coût nul hors ces deux handlers.
pub(crate) struct SearchTimer(Instant);
pub(crate) fn search_timer() -> SearchTimer {
    SearchTimer(Instant::now())
}
impl Drop for SearchTimer {
    fn drop(&mut self) {
        record_search(self.0.elapsed().as_millis().min(u32::MAX as u128) as u32);
    }
}

/// Quantile (nearest-rank) d'un échantillon TRIÉ. Vide -> None.
fn quantile_sorted(sorted: &[u32], q: f64) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    Some(sorted[rank - 1])
}

/// (p50, p95, count) des latences de recherche observées. count=0 -> (0,0,0).
pub(crate) fn search_quantiles() -> (u32, u32, usize) {
    let q = search_lat().lock();
    if q.is_empty() {
        return (0, 0, 0);
    }
    let mut v: Vec<u32> = q.iter().copied().collect();
    v.sort_unstable();
    (quantile_sorted(&v, 0.50).unwrap_or(0), quantile_sorted(&v, 0.95).unwrap_or(0), v.len())
}

// ---------- lectures d'environnement — cheap, sans scan, et JAMAIS un zéro faute de savoir ----------
// S32 — les trois lectures ci-dessous rendaient la valeur la plus RASSURANTE quand elles échouaient :
// `unwrap_or((0.0, 0))` sur `/proc/self`, `Err(_) => 0` sur le répertoire de spool, `unwrap_or(0)` sur
// la taille de la base. Un tableau de bord y voyait « processus au repos », « file vide », « base
// vide » — c'est-à-dire « rien à signaler » — précisément quand la mesure avait disparu. Elles sont
// désormais TYPÉES (`mesure_environnement::Mesure`) et paramétrées sur leurs chemins, donc exerçables
// sans dépendre de l'hôte. Ce module ne fait plus que les APPELER et décider de leur PUBLICATION.

/// (temps processeur cumulé, mémoire résidente) du processus. `Illisible` quand `/proc` ne répond pas
/// ou que sa forme n'est pas comprise — jamais `(0, 0)`.
pub(crate) fn proc_self_cpu_rss() -> mesure_environnement::Mesure<(f64, u64)> {
    mesure_environnement::cpu_rss()
}

/// Nombre de fichiers en attente dans le spool (profondeur de file d'ingest). `Illisible` quand le
/// répertoire est absent ou que son parcours s'interrompt — un répertoire disparu N'EST PAS une file
/// vide.
pub(crate) fn spool_queue_depth(spool: &str) -> mesure_environnement::Mesure<u64> {
    mesure_environnement::profondeur_file_depuis(std::path::Path::new(spool))
}

/// Taille de la base (fichier principal + journal d'écriture) en octets — `stat` seulement, jamais un
/// `COUNT(*)`. Le journal ABSENT vaut zéro (c'est un vrai zéro) ; le fichier principal injoignable
/// rend `Illisible`.
pub(crate) fn db_size_bytes(db_path: &str) -> mesure_environnement::Mesure<u64> {
    mesure_environnement::taille_base_depuis(std::path::Path::new(db_path))
}

// ---------- santé par composant (R/J/V) ----------
/// État santé d'un composant : "green" (V) / "yellow" (J) / "red" (R) / "idle" (inactif = non déployé, sain).
/// `score` = 1.0 / 0.5 / 0.0 / 1.0 -> jauge Prometheus `plume_component_up`.
pub(crate) fn health_score(state: &str) -> f64 {
    match state {
        "green" | "idle" => 1.0,
        "yellow" => 0.5,
        _ => 0.0,
    }
}

/// SNAPSHOT complet des composants (ingest / détection / rollups / store / forwarder / restauration) sous forme de valeurs
/// JSON {component, state, detail, ...}. Lecture SEULE, sur PETITES tables (rollup/alert/destination) +
/// atomics + statvfs : jamais un scan de `event`. Appelé par /metrics, /api/system/health et le diag-bundle.
pub(crate) fn component_health(conn: &Connection, spool: &str, db_path: &str, disk_warn_pct: u8) -> Vec<Value> {
    component_health_avec(conn, spool, db_path, disk_warn_pct, FraicheurDesTicks::du_processus())
}

/// LA FRAÎCHEUR DES DEUX BOUCLES DE FOND, TELLE QU'ELLE ENTRE DANS LA SURFACE D'ÉTAT.
///
/// `P11.24-e` — POURQUOI CE TYPE EXISTE, ET CE QU'IL RETIRE. Les deux horodatages sont des
/// atomiques de PROCESSUS : la boucle de fond les pose, la surface d'état les lit. Sous
/// `cargo test`, les deux vivent dans le MÊME processus que tous les témoins, et un témoin qui
/// voulait un tick ANCIEN devait l'écrire dans l'atomique commune, puis appeler la surface. Entre
/// les deux, n'importe quel autre témoin du binaire pouvait y écrire `maintenant` — et le verdict
/// du premier basculait. MESURÉ le 2026-09-01 : le portail de déploiement a rougi sur
/// « tick règles ancien -> détection non verte (green) » ; rejoué SEUL, il passe.
///
/// LE MÉCANISME N'ÉTAIT PAS UN SEUIL D'ÂGE FRANCHI SOUS LA CHARGE. L'écart posé par le témoin
/// était de MILLE secondes contre un plafond de cent vingt : il aurait fallu que l'ordonnanceur
/// lui vole huit cent quatre-vingts secondes entre l'écriture et la lecture. Ce qui bascule le
/// verdict, c'est une AUTRE écriture, pas un retard.
///
/// CE QUE CE TYPE CHANGE : la surface d'état ne lit plus l'ambiant elle-même. Elle reçoit une
/// fraîcheur, et le seul site qui la dérive du processus est `du_processus`. Un témoin INJECTE
/// donc la sienne et ne partage plus rien avec personne. La production, elle, ne voit aucune
/// différence : `component_health` compose exactement les deux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FraicheurDesTicks {
    /// Horodatage unix du dernier tick du planificateur de règles (0 = jamais tické).
    pub(crate) regles: i64,
    /// Horodatage unix du dernier tick de la boucle de rollup (0 = jamais tické).
    pub(crate) rollups: i64,
}

impl FraicheurDesTicks {
    /// CE QUE LE PROCESSUS A VU — le SEUL site qui lit les deux atomiques pour la surface d'état.
    pub(crate) fn du_processus() -> Self {
        Self {
            regles: SCHED_RULE_LAST_TS.load(Ordering::Relaxed),
            rollups: SCHED_ROLLUP_LAST_TS.load(Ordering::Relaxed),
        }
    }
}

/// LE CORPS DE `component_health`, avec la fraîcheur des ticks EN ENTRÉE plutôt qu'en ambiant.
pub(crate) fn component_health_avec(
    conn: &Connection,
    spool: &str,
    db_path: &str,
    disk_warn_pct: u8,
    fraicheur: FraicheurDesTicks,
) -> Vec<Value> {
    let now_ts = now();
    let mut out = Vec::new();

    // INGEST : santé du pipeline (fraîcheur globale) + backlog spool. Un silence n'est PAS une panne
    // (doctrine fraîcheur) -> stale = jaune (jamais rouge) ; backlog important = jaune (ingest en retard).
    let fresh = pipeline_is_fresh(conn, now_ts);
    let queue = spool_queue_depth(spool);
    let had_data: Option<i64> = conn
        .query_row(
            "SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event UNION ALL SELECT MAX(ts) FROM metric UNION ALL SELECT MAX(ts) FROM snapshot)",
            [], |r| r.get::<_, Option<i64>>(0),
        )
        .ok()
        .flatten();
    // S32 — LE CAS ILLISIBLE EST TRAITÉ EN PREMIER, ET IL NE PEUT PAS ÊTRE VERT. Une file dont le
    // répertoire a disparu se lisait ici comme une file VIDE : le composant retombait sur la fraîcheur
    // et pouvait annoncer « données fraîches » alors que la voie spool était peut-être morte sans que
    // rien ne puisse le dire. Ce n'est pas ROUGE (la voie HTTP d'ingest, elle, continue peut-être de
    // servir) : c'est JAUNE, l'état qui appelle un regard. La cause est nommée dans le détail.
    let (istate, idetail) = match queue.valeur() {
        None => (
            "yellow",
            format!(
                "profondeur de la file d'ingest NON LISIBLE ({}) : ce n'est PAS « file vide », c'est \
                 « pas de mesure » — un retard d'ingest ne serait pas visible ici.",
                queue.detail().unwrap_or("cause non renseignée")
            ),
        ),
        Some(&n) if n > 500 => ("yellow", format!("backlog spool : {n} fichiers en attente")),
        Some(_) if had_data.is_none() => ("idle", "aucune donnée encore ingérée".to_string()),
        Some(_) if fresh => ("green", "données fraîches (< 10 min)".to_string()),
        Some(_) => ("yellow", "aucune donnée récente (source calme ou collecte arrêtée)".to_string()),
    };
    // P4.1-r — CE QUE LE DERNIER PASSAGE SUR LE SPOOL A ABANDONNÉ, ou l'aveu qu'il n'a pas pu l'énumérer.
    // Distinct de la profondeur de file : celle-ci dit combien attendent, ceci dit combien ont été
    // laissés de côté (quarantaine, illisibles) — un fichier abandonné à chaque passage reste dans la
    // file et ne s'ingère jamais, et seul ce compte le fait voir.
    // P10.7-x — LE COMPOSANT NOMME SON NOM, ET C'EST CE MÊME NOM QUI DIT QUELLES PASSES IL PORTE : une
    // seule constante écrit les deux, donc l'entrée de `COMPOSANTS` et l'objet servi ne peuvent pas se
    // désigner différemment.
    let bilan_ingest = crate::bilan_de_tick::bilan_du_composant(crate::bilan_de_tick::COMPOSANT_INGEST);
    let (istate, idetail) = crate::bilan_de_tick::etat_de_surface(istate, idetail, bilan_ingest.as_ref());
    let mut ingest = serde_json::Map::new();
    ingest.insert("component".into(), json!(crate::bilan_de_tick::COMPOSANT_INGEST));
    ingest.insert("state".into(), json!(istate));
    ingest.insert("detail".into(), json!(idetail));
    queue.poser_dans(&mut ingest, "queue_depth");
    crate::bilan_de_tick::poser_bilan(&mut ingest, "abandons_dernier_passage", bilan_ingest.as_ref());
    out.push(Value::Object(ingest));

    // DÉTECTION : le scheduler de règles tick-t-il ? (SCHED_RULE_LAST_TS). 0 = pas encore tické (boot) -> idle.
    // P4.1-r — ET QU'A-T-IL ÉVALUÉ ? Un tick à l'heure qui n'a pas pu lire ses règles était VERT ici :
    // le bilan publié par le planificateur (règles + incidents de risque) le rend ROUGE, et des règles
    // abandonnées (compilation refusée, évaluation en échec) le rendent JAUNE, avec leur compte.
    let rule_last = fraicheur.regles;
    let (dstate, ddetail) = tick_health(rule_last, now_ts, 120, 600, "scheduler de règles");
    let bilan_detection = crate::bilan_de_tick::bilan_du_composant(crate::bilan_de_tick::COMPOSANT_DETECTION);
    let (dstate, ddetail) = crate::bilan_de_tick::etat_de_surface(dstate, ddetail, bilan_detection.as_ref());
    // P10.7-n — ET AVEC QUOI DÉTECTE-T-ON ? Le magasin d'indicateurs savait déjà dire, sur SA route
    // (`/api/threat-intel/coverage`), que son cache tourne sur un jeu PÉRIMÉ — la table `ioc` n'a pas
    // pu être relue, le jeu précédent est CONSERVÉ, la correspondance à l'ingest continue dessus. Ni
    // ce voyant ni `/metrics` ne le portaient : un exploitant qui ne regarde que le vert-orange-rouge
    // voyait « détection : verte » pendant que le jeu vieillissait sans borne. La mesure n'est PAS un
    // bilan de tick (elle vit dans un registre à part, keyé par `db_path`, donc par TENANT) : elle
    // entre par `etat_de_surface_jeu_conserve`, qui est JAUNE là où un tick aveugle est rouge.
    let cache_indicateurs = ioc_reload_dernier(db_path);
    let (dstate, ddetail) = crate::bilan_de_tick::etat_de_surface_jeu_conserve(
        dstate, ddetail, "le cache d'indicateurs (threat-intel)", cache_indicateurs.as_ref(),
    );
    let n_rules: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE enabled=1", [], |r| r.get(0)).unwrap_or(0);
    let mut detection = serde_json::Map::new();
    detection.insert("component".into(), json!(crate::bilan_de_tick::COMPOSANT_DETECTION));
    detection.insert("state".into(), json!(dstate));
    detection.insert("detail".into(), json!(ddetail));
    detection.insert("enabled_rules".into(), json!(n_rules));
    detection.insert("last_tick".into(), json!(rule_last));
    crate::bilan_de_tick::poser_bilan(&mut detection, "abandons_dernier_tick", bilan_detection.as_ref());
    // Convention `S32` : la valeur n'apparaît QUE si elle a été lue. Aucun rechargement encore
    // (démarrage) -> AUCUNE clé posée : l'absence se lit « pas encore », jamais « zéro indicateur ».
    if let Some(m) = &cache_indicateurs {
        m.poser_dans(&mut detection, "cache_indicateurs");
    }
    out.push(Value::Object(detection));

    // ROLLUPS : la boucle de rollup tick-t-elle ? (intervalle défaut 120 s).
    let rollup_last = fraicheur.rollups;
    let (rstate, rdetail) = tick_health(rollup_last, now_ts, 300, 900, "boucle de rollup");
    out.push(json!({ "component": "rollups", "state": rstate, "detail": rdetail, "last_tick": rollup_last }));

    // STORE : disque de données (statvfs). >95% rouge, > seuil jaune, sinon vert. DB ouvrable (on lit ici) = ok.
    let dir = std::path::Path::new(db_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    // S32 — MÊME FIGURE QUE LA FILE D'INGEST, et elle était PIRE ICI : une mesure `statvfs` en échec
    // rendait l'état VERT *et* publiait `disk_used_pct: 0`, c'est-à-dire « disque vide, tout va bien »
    // au moment précis où plus rien n'était mesuré. Le pourcentage est désormais ABSENT quand il n'a
    // pas été mesuré, et l'état est JAUNE : ne pas savoir si le volume de données sature n'est pas un
    // état sain. Ce n'est pas rouge — la base répond, on vient d'y lire.
    let mesure_disque = match fs_total_avail_mb(&dir).and_then(|(t, a)| disk_used_pct(t, a).map(|p| (p, t, a))) {
        Some(x) => mesure_environnement::Mesure::Lue(x),
        None => mesure_environnement::Mesure::Illisible {
            cause: mesure_environnement::CAUSE_SOURCE_ILLISIBLE,
            detail: format!("statvfs({dir}) : usage disque indisponible"),
        },
    };
    let (sstate, sdetail) = match mesure_disque.valeur() {
        Some(&(pct, total, avail)) => {
            let warn = if disk_warn_pct == 0 { 85 } else { disk_warn_pct };
            let st = if pct > 95 { "red" } else if pct > warn { "yellow" } else { "green" };
            (st, format!("disque données {pct}% utilisé ({avail} Mo libres / {total} Mo)"))
        }
        None => (
            "yellow",
            format!(
                "usage disque NON LISIBLE ({}) : impossible de dire si le volume de données sature.",
                mesure_disque.detail().unwrap_or("cause non renseignée")
            ),
        ),
    };
    let mut store = serde_json::Map::new();
    store.insert("component".into(), json!("store"));
    store.insert("state".into(), json!(sstate));
    store.insert("detail".into(), json!(sdetail));
    // Le pourcentage SEUL (pas le triplet) part dans le JSON : c'est lui que le panneau lit. Le
    // verdict et la cause voyagent avec, donc « 0 % » et « pas mesuré » ne se ressemblent plus.
    let pourcentage = match mesure_disque {
        mesure_environnement::Mesure::Lue((pct, _, _)) => mesure_environnement::Mesure::Lue(pct as u64),
        mesure_environnement::Mesure::Illisible { cause, detail } => {
            mesure_environnement::Mesure::Illisible { cause, detail }
        }
    };
    pourcentage.poser_dans(&mut store, "disk_used_pct");
    db_size_bytes(db_path).poser_dans(&mut store, "db_size_bytes");
    out.push(Value::Object(store));

    // FORWARDER (#50 outputs/destinations) : table vide -> idle (mode 0). Une destination ACTIVE en erreur
    // (last_error non vide) -> jaune. Sinon vert. Table absente (schéma < v92) -> idle.
    let (fstate, fdetail) = destination_health(conn);
    // P4.1-r — une liste de destinations qu'on n'a pas pu lire n'était ni « en erreur » ni « OK » : rien.
    let bilan_forwarder = crate::bilan_de_tick::bilan_du_composant(crate::bilan_de_tick::COMPOSANT_FORWARDER);
    let (fstate, fdetail) = crate::bilan_de_tick::etat_de_surface(fstate, fdetail, bilan_forwarder.as_ref());
    let mut forwarder = serde_json::Map::new();
    forwarder.insert("component".into(), json!(crate::bilan_de_tick::COMPOSANT_FORWARDER));
    forwarder.insert("state".into(), json!(fstate));
    forwarder.insert("detail".into(), json!(fdetail));
    crate::bilan_de_tick::poser_bilan(&mut forwarder, "abandons_dernier_tick", bilan_forwarder.as_ref());
    out.push(Value::Object(forwarder));

    // PASSES DE FOND (P10.7-x) — LE COMPLÉMENT : tout ce qu'AUCUN composant ci-dessus ne revendique.
    // Sans lui, une passe de fond qui publie un aveu — la boucle qui ANCRE la chaîne d'intégrité, la
    // passe `config.d` du démarrage — le publiait dans le vide : aucun voyant ne bougeait, et la
    // posture globale restait celle d'un système « qui va bien ». Le composant existe TOUJOURS, même
    // quand rien n'est orphelin : son absence se lirait, elle aussi, « rien à signaler ».
    let orphelins = crate::bilan_de_tick::bilans_orphelins();
    let (bstate, bdetail) = crate::bilan_de_tick::etat_des_passes_orphelines(&orphelins);
    let mut passes = serde_json::Map::new();
    passes.insert("component".into(), json!(crate::bilan_de_tick::COMPOSANT_PASSES_DE_FOND));
    passes.insert("state".into(), json!(bstate));
    passes.insert("detail".into(), json!(bdetail));
    // Les noms BRUTS ici (le JSON n'a pas l'alphabet contraint de Prometheus) : c'est ce qui distingue
    // deux passes que la réduction du nom de série rapprocherait.
    for (nom, m) in &orphelins {
        m.poser_dans(&mut passes, &format!("{nom}_abandons"));
    }
    out.push(Value::Object(passes));

    // RESTAURATION (P8.3-a) : depuis quand une archive n'a-t-elle pas été REMISE EN SERVICE ? Lecture
    // d'UNE ligne `meta`, jamais un scan. Le composant est le seul du lot dont l'état ne décrit pas un
    // sous-système en marche mais une PREUVE MANQUANTE — et c'est précisément ce qui, sans lui, ne se
    // lisait nulle part : une sauvegarde dont aucune ligne n'a jamais été restaurée reste une garantie
    // non éprouvée, et rien ne le disait. Le mode d'escrow est dérivé du réglage qui PRODUIT les
    // archives (`PLUME_BACKUP_AGE_RECIPIENT`), pour qu'un exercice mené sur le chemin symétrique ne
    // puisse pas passer pour un exercice du chemin d'escrow.
    out.push(crate::exercice_de_restauration::composant(conn, crate::backup_age_recipient().is_some(), now_ts));

    out
}

/// Santé d'un tick de fond depuis son dernier horodatage : 0 = jamais tické (boot) -> idle ; frais < warn ->
/// green ; < crit -> yellow ; au-delà -> red (le worker est probablement bloqué).
fn tick_health(last_ts: i64, now_ts: i64, warn_s: i64, crit_s: i64, what: &str) -> (&'static str, String) {
    if last_ts == 0 {
        return ("idle", format!("{what} : pas encore exécuté (démarrage)"));
    }
    let age = now_ts - last_ts;
    if age < warn_s {
        ("green", format!("{what} actif (dernier tick il y a {age}s)"))
    } else if age < crit_s {
        ("yellow", format!("{what} en retard (dernier tick il y a {age}s)"))
    } else {
        ("red", format!("{what} bloqué ? (dernier tick il y a {age}s)"))
    }
}

/// Santé du forwarder depuis la table `destination` (#50). Table absente/vide -> idle. Best-effort.
fn destination_health(conn: &Connection) -> (&'static str, String) {
    let total: i64 = match conn.query_row("SELECT COUNT(*) FROM destination", [], |r| r.get(0)) {
        Ok(n) => n,
        Err(_) => return ("idle", "aucune destination configurée".to_string()),
    };
    if total == 0 {
        return ("idle", "aucune destination configurée".to_string());
    }
    let errored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM destination WHERE enabled=1 AND COALESCE(last_error,'')<>''",
            [], |r| r.get(0),
        )
        .unwrap_or(0);
    if errored > 0 {
        ("yellow", format!("{errored}/{total} destination(s) en erreur"))
    } else {
        ("green", format!("{total} destination(s) OK"))
    }
}

/// Le PIRE de deux états (red > yellow > green > idle) — un seul auteur pour cet ordre, partagé avec
/// `worst_state` et avec le bilan de tick (`bilan_de_tick::etat_de_surface`).
pub(crate) fn pire_des_deux(a: &'static str, b: &'static str) -> &'static str {
    fn rang(e: &str) -> u8 {
        match e {
            "red" => 3,
            "yellow" => 2,
            "green" => 1,
            _ => 0,
        }
    }
    if rang(b) > rang(a) { b } else { a }
}

/// L'état PIRE d'un ensemble de composants -> posture globale (red > yellow > green/idle).
pub(crate) fn worst_state(components: &[Value]) -> &'static str {
    let mut worst = "green";
    for c in components {
        match c.get("state").and_then(|s| s.as_str()) {
            Some("red") => return "red",
            Some("yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

// ---------- exposition ----------
/// Échantillon de self-métriques (valeurs numériques uniquement — jamais un secret/PII), factorisé pour
/// /metrics (texte Prometheus) ET /api/system/metrics (JSON du panneau UI). Lecture SEULE, tables petites.
pub(crate) fn gather_json(conn: &Connection, spool: &str, db_path: &str, schema_version: i64, disk_warn_pct: u8) -> Value {
    let now_ts = now();
    // S32 — LE COUPLE PROCESSEUR/MÉMOIRE N'EST PLUS DÉPLIÉ SUR UN ZÉRO. `unwrap_or((0.0, 0))` publiait
    // « processus au repos, aucune mémoire résidente » quand `/proc` était illisible : les deux valeurs
    // les plus calmes de la série, indiscernables d'un vrai repos. Les deux nombres sont maintenant
    // ABSENTS du JSON quand ils n'ont pas été lus (donc absents de `/metrics`, cf. `g()` plus bas), et
    // l'objet `process` porte le verdict et la cause.
    let processeur_memoire = proc_self_cpu_rss();
    let mut process = serde_json::Map::new();
    if let Some(&(cpu, rss)) = processeur_memoire.valeur() {
        process.insert("cpu_seconds".into(), json!(cpu));
        process.insert("rss_bytes".into(), json!(rss));
    }
    process.insert("verdict".into(), json!(processeur_memoire.verdict()));
    process.insert("cause".into(), json!(processeur_memoire.cause()));
    if let Some(d) = processeur_memoire.detail() {
        process.insert("detail".into(), json!(d));
    }
    let (p50, p95, lat_n) = search_quantiles();
    // ingest « dernière heure » depuis event_rollup (pré-agrégé, ~ms) -> débit sans scanner `event`.
    let events_1h: i64 = conn
        .query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket>=?1", params![now_ts - 3600], |r| r.get(0))
        .unwrap_or(0);
    let alerts_open: i64 = conn.query_row("SELECT COUNT(*) FROM alert WHERE status='new'", [], |r| r.get(0)).unwrap_or(0);
    let components = component_health(conn, spool, db_path, disk_warn_pct);
    let posture = worst_state(&components);
    // ACK-DROP Pub/Sub : la surface est DÉRIVÉE de `AckDrop::TOUTES`, jamais réécrite ici. Une raison ajoutée
    // demain apparaît dans `/metrics` sans qu'on y pense — l'oubli d'exposition n'est pas une option offerte.
    let pubsub_ackdrop_par_raison: serde_json::Map<String, Value> = crate::ingest::pubsub::AckDrop::TOUTES
        .iter()
        .map(|r| (r.libelle().to_string(), json!(PUBSUB_ACKDROP[r.rang()].load(Ordering::Relaxed))))
        .collect();
    let pubsub_ackdrop_total: u64 = PUBSUB_ACKDROP.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    // S32 — les deux objets qui portent une mesure d'environnement sont construits en `Map` plutôt
    // qu'écrits littéralement : c'est `poser_dans` qui décide d'écrire ou non le nombre, et lui seul.
    // Un littéral `"queue_depth": …` obligerait à produire une valeur dans tous les cas — c'est-à-dire
    // à réinventer le zéro que ce lot retire.
    let mut ingest = serde_json::Map::new();
    ingest.insert("events_total".into(), json!(INGEST_EVENTS_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("files_total".into(), json!(INGEST_FILES_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("events_1h".into(), json!(events_1h));
    spool_queue_depth(spool).poser_dans(&mut ingest, "queue_depth");
    ingest.insert("push_zero_map_total".into(), json!(PUSH_ZERO_MAP_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("spool_barriere_fichier_total".into(), json!(SPOOL_BARRIERE_FICHIER_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("spool_barriere_repertoire_total".into(), json!(SPOOL_BARRIERE_REPERTOIRE_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("spool_barriere_echec_total".into(), json!(SPOOL_BARRIERE_ECHEC_TOTAL.load(Ordering::Relaxed)));
    ingest.insert("pubsub_ackdrop_total".into(), json!(pubsub_ackdrop_total));
    ingest.insert("pubsub_ackdrop_par_raison".into(), Value::Object(pubsub_ackdrop_par_raison));
    // S33 — L'IDENTITÉ DE L'HÔTE PORTE SON VERDICT, PAS SA VALEUR. Elle décide quelles actions de
    // réponse s'exécutent localement ; quand elle n'est pas lisible, les actions CIBLÉES ne sont plus
    // réclamées ici, et c'est un fait qu'un exploitant doit pouvoir voir. Le NOM, lui, ne part pas :
    // ce n'est pas un nombre, et le mettre en étiquette ferait de chaque machine une série de plus.
    let mut hote = serde_json::Map::new();
    crate::maintenance::identite_hote().poser_verdict_dans(&mut hote, "identity");
    let mut db = serde_json::Map::new();
    db_size_bytes(db_path).poser_dans(&mut db, "size_bytes");
    // `ventilation` = la DERNIÈRE tentative du tick lent, servie DEPUIS LE CACHE : lire /metrics ou le
    // panneau Système ne déclenche JAMAIS un parcours dbstat. `null` = jamais mesuré ;
    // `{"mesuree":false,…}` = mesure REFUSÉE (jamais un objet de zéros).
    db.insert("ventilation".into(), ventilation_serie::json(&ventilation_serie::derniere(), now_ts));
    // P4.1-r — LE BILAN DU DERNIER TICK DE CHAQUE BOUCLE DE FOND, à côté de ses compteurs de ticks : un
    // tick compté n'est pas un tick qui a évalué. Convention `S32` (`<boucle>_abandons[_verdict|_cause|
    // _detail]`) ; ABSENT avant le premier tick, jamais un zéro inventé.
    let mut scheduler = serde_json::Map::new();
    scheduler.insert("rule_ticks_total".into(), json!(SCHED_RULE_TICKS.load(Ordering::Relaxed)));
    scheduler.insert("rule_last_tick".into(), json!(SCHED_RULE_LAST_TS.load(Ordering::Relaxed)));
    scheduler.insert("rollup_ticks_total".into(), json!(SCHED_ROLLUP_TICKS.load(Ordering::Relaxed)));
    scheduler.insert("rollup_last_tick".into(), json!(SCHED_ROLLUP_LAST_TS.load(Ordering::Relaxed)));
    // P10.7-x — LA TABLE PARCOURUE EST DÉRIVÉE DU REGISTRE (`boucles_publiees`), plus une liste écrite :
    // une passe qui publie est servie le jour où elle publie. Clés BRUTES ici ; c'est l'exposition
    // Prometheus qui les réduit à son alphabet.
    for passe in crate::bilan_de_tick::boucles_publiees() {
        crate::bilan_de_tick::poser_bilan(&mut scheduler, &format!("{passe}_abandons"), crate::bilan_de_tick::dernier(passe).as_ref());
    }
    // P10.7-n — AVEC QUOI LA DÉTECTION PAR INDICATEURS TOURNE, sous la convention `S32` : le nombre
    // n'apparaît QUE s'il a été lu, et l'objet est vide tant qu'aucun rechargement n'a eu lieu (l'axe
    // Prometheus s'en déduit plus bas, et ne s'imprime alors pas du tout — sans quoi il accuserait un
    // démon qui vient de démarrer).
    let mut detection = serde_json::Map::new();
    if let Some(m) = ioc_reload_dernier(db_path) {
        m.poser_dans(&mut detection, "cache_indicateurs");
    }
    json!({
        "ts": now_ts,
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": schema_version,
        "uptime_s": (now_ts - START_TS.load(Ordering::Relaxed)).max(0),
        "process": process,
        "http": {
            "requests_total": HTTP_REQUESTS_TOTAL.load(Ordering::Relaxed),
            "responses_5xx_total": HTTP_5XX_TOTAL.load(Ordering::Relaxed),
        },
        "ingest": ingest,
        "search": { "requests_total": SEARCH_TOTAL.load(Ordering::Relaxed), "p50_ms": p50, "p95_ms": p95, "samples": lat_n },
        "scheduler": scheduler,
        "detection": detection,
        "db": db,
        "host": hote,
        "alerts_open": alerts_open,
        "posture": posture,
        "components": components,
    })
}

fn prom_line(out: &mut String, name: &str, typ: &str, help: &str, value: String) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {typ}\n{name} {value}\n"));
}

/// Exposition Prometheus TEXTE (content-type text/plain; version=0.0.4). Uniquement des compteurs/jauges —
/// aucune étiquette porteuse de PII (les seules étiquettes sont des constantes : version/schema, composant,
/// quantile). Dérivé de `gather_json` pour une source de vérité unique.
pub(crate) fn gather_prom(conn: &Connection, spool: &str, db_path: &str, schema_version: i64, disk_warn_pct: u8) -> String {
    let j = gather_json(conn, spool, db_path, schema_version, disk_warn_pct);
    let mut o = String::with_capacity(2048);
    prom_line(&mut o, "plume_up", "gauge", "1 si le daemon sert des requêtes", "1".into());
    // build info en étiquettes constantes (motif Prometheus build_info).
    o.push_str("# HELP plume_build_info Version applicative et version de schéma (étiquettes constantes)\n");
    o.push_str("# TYPE plume_build_info gauge\n");
    o.push_str(&format!(
        "plume_build_info{{version=\"{}\",schema=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"), schema_version
    ));
    let g = |o: &mut String, name: &str, typ: &str, help: &str, ptr: &str| {
        if let Some(v) = j.pointer(ptr) {
            let s = if v.is_f64() { format!("{:.3}", v.as_f64().unwrap_or(0.0)) } else { v.to_string() };
            prom_line(o, name, typ, help, s);
        }
    };
    // S32 — L'INDICATEUR DE LISIBILITÉ D'UNE MESURE D'ENVIRONNEMENT, à côté d'une série de valeur qui
    // est ABSENTE quand elle n'a pas été lue (c'est `g()` qui l'omet : il n'imprime que ce qu'il
    // trouve). DÉRIVÉ du verdict écrit par `gather_json`, jamais recalculé : la jauge et le champ JSON
    // ne peuvent pas diverger. Les deux ensemble, parce qu'une série absente ne distingue pas « la
    // lecture a échoué » d'un scrape manqué, et qu'un indicateur seul laisserait le zéro en place.
    // CARDINALITÉ : l'étiquette `cause` ne prend ses valeurs que dans `CAUSES` (5 clés fermées), et une
    // seule à la fois puisque les cas sont exclusifs -> au plus 5 séries de sortie par jauge, 1 en régime.
    let lisible = |o: &mut String, nom: &str, quoi: &str, ptr_verdict: &str, ptr_cause: &str| {
        let mot = j.pointer(ptr_verdict).and_then(|v| v.as_str()).unwrap_or(mesure_environnement::VERDICT_ILLISIBLE);
        let cause = j.pointer(ptr_cause).and_then(|v| v.as_str()).unwrap_or(mesure_environnement::CAUSE_SOURCE_ILLISIBLE);
        o.push_str(&mesure_environnement::exposition_prom_lisible(nom, quoi, mot, cause));
    };
    g(&mut o, "plume_process_cpu_seconds_total", "counter", "Temps CPU cumulé du process (s)", "/process/cpu_seconds");
    g(&mut o, "plume_process_resident_memory_bytes", "gauge", "RSS du process (octets)", "/process/rss_bytes");
    lisible(&mut o, "plume_process_mesure_lisible", "la mesure processeur/mémoire du processus", "/process/verdict", "/process/cause");
    prom_line(&mut o, "plume_process_start_time_seconds", "gauge", "Horodatage de démarrage (unix s)", START_TS.load(Ordering::Relaxed).to_string());
    g(&mut o, "plume_http_requests_total", "counter", "Requêtes HTTP servies", "/http/requests_total");
    g(&mut o, "plume_http_responses_5xx_total", "counter", "Réponses 5xx", "/http/responses_5xx_total");
    g(&mut o, "plume_ingest_events_total", "counter", "Events ingérés depuis le démarrage", "/ingest/events_total");
    g(&mut o, "plume_ingest_files_total", "counter", "Fichiers spool consommés", "/ingest/files_total");
    g(&mut o, "plume_ingest_events_1h", "gauge", "Events ingérés sur la dernière heure (rollup)", "/ingest/events_1h");
    g(&mut o, "plume_spool_queue_files", "gauge", "Fichiers en attente dans le spool", "/ingest/queue_depth");
    lisible(&mut o, "plume_spool_queue_lisible", "la profondeur de la file d'ingest", "/ingest/queue_depth_verdict", "/ingest/queue_depth_cause");
    g(&mut o, "plume_push_zero_map_total", "counter", "Batches push acceptés mais mappés à 0 event (misconfig source push)", "/ingest/push_zero_map_total");
    // `S31` — les barrières de durabilité du spool. Les DEUX premières montent ENSEMBLE (une publication
    // durable en prend une de chaque) ; un écart entre elles, ou `echec` qui grimpe, signale un 2xx qui
    // n'est plus adossé à une barrière — le seul signal disponible sur les quatre surfaces à contrat
    // étranger, dont le corps de réponse ne peut pas porter de champ `durable`.
    g(&mut o, "plume_spool_barriere_fichier_total", "counter", "Barrières fsync(fichier) prises avant le renommage du spool", "/ingest/spool_barriere_fichier_total");
    g(&mut o, "plume_spool_barriere_repertoire_total", "counter", "Barrières fsync(répertoire) prises après le renommage du spool", "/ingest/spool_barriere_repertoire_total");
    g(&mut o, "plume_spool_barriere_echec_total", "counter", "Barrières de durabilité du spool REFUSÉES par le noyau", "/ingest/spool_barriere_echec_total");
    g(&mut o, "plume_search_requests_total", "counter", "Recherches interactives servies", "/search/requests_total");
    // quantiles de latence de recherche (résumé pré-calculé côté serveur).
    let (p50, p95, _) = search_quantiles();
    o.push_str("# HELP plume_search_latency_ms Latence des recherches interactives (ms)\n# TYPE plume_search_latency_ms summary\n");
    o.push_str(&format!("plume_search_latency_ms{{quantile=\"0.5\"}} {p50}\n"));
    o.push_str(&format!("plume_search_latency_ms{{quantile=\"0.95\"}} {p95}\n"));
    g(&mut o, "plume_scheduler_rule_ticks_total", "counter", "Ticks du scheduler de règles", "/scheduler/rule_ticks_total");
    g(&mut o, "plume_scheduler_rollup_ticks_total", "counter", "Ticks de la boucle de rollup", "/scheduler/rollup_ticks_total");
    // P4.1-r — PAR BOUCLE DE FOND : les abandons du dernier tick (jauge, ABSENTE tant que la boucle n'a
    // pas tické, ou quand le tick a été AVEUGLE) et la lisibilité du bilan à côté, comme pour toute
    // mesure de `S32`. `g()` n'imprime que ce qu'il trouve : l'absence EST le message, la jauge
    // `…_lisible{cause}` dit pourquoi.
    // P10.7-x — DÉRIVÉ DU REGISTRE, plus d'une liste écrite : `retention` et `overlays` publiaient un
    // bilan que cette boucle-ci ne parcourait pas. Le POINTEUR JSON porte la clé BRUTE (un pointeur
    // n'a pas d'alphabet contraint) ; le NOM DE MÉTRIQUE passe par `nom_de_serie`, parce qu'un nom
    // invalide fait rejeter le relevé ENTIER. Effet de bord voulu : la table ne contient que des clés
    // PUBLIÉES, donc le verdict existe toujours — l'ancienne table nommait les six boucles dès le boot
    // et `lisible()`, ne trouvant pas leur verdict, les accusait toutes d'un tick AVEUGLE.
    for passe in crate::bilan_de_tick::boucles_publiees() {
        let serie = crate::bilan_de_tick::nom_de_serie(passe);
        let jeton = crate::bilan_de_tick::jeton_de_pointeur(passe);
        g(
            &mut o,
            &format!("plume_scheduler_{serie}_abandons"),
            "gauge",
            &format!("Éléments dus ABANDONNÉS (non évalués) au dernier passage de « {passe} »"),
            &format!("/scheduler/{jeton}_abandons"),
        );
        lisible(
            &mut o,
            &format!("plume_scheduler_{serie}_bilan_lisible"),
            &format!("le bilan du dernier passage de « {passe} » (0 = passage AVEUGLE : sa liste d'éléments dus n'a pas pu être lue)"),
            &format!("/scheduler/{jeton}_abandons_verdict"),
            &format!("/scheduler/{jeton}_abandons_cause"),
        );
    }
    // P10.7-n — AVEC QUOI LA DÉTECTION PAR INDICATEURS TOURNE. Les DEUX séries sont conditionnées à
    // l'existence du verdict : `lisible()` retombe sur « illisible » quand il ne trouve pas son
    // pointeur, ce qui accuserait d'un jeu PÉRIMÉ un démon dont le cache n'a simplement jamais été
    // rechargé. « Pas encore » se dit par l'ABSENCE des deux séries, jamais par une accusation.
    if j.pointer("/detection/cache_indicateurs_verdict").is_some() {
        g(&mut o, "plume_ioc_cache_indicateurs", "gauge",
            "Indicateurs RÉELLEMENT en service dans le cache de correspondance à l'ingest (ABSENT si le dernier rechargement a échoué)",
            "/detection/cache_indicateurs");
        lisible(&mut o, "plume_ioc_cache_lisible",
            "le dernier rechargement du cache d'indicateurs (0 = la table `ioc` n'a pas pu être lue ENTIÈREMENT : \
             le jeu précédent est CONSERVÉ et la détection continue dessus, mais il vieillit)",
            "/detection/cache_indicateurs_verdict", "/detection/cache_indicateurs_cause");
    }
    g(&mut o, "plume_db_size_bytes", "gauge", "Taille de la base (db + wal, octets)", "/db/size_bytes");
    lisible(&mut o, "plume_db_size_lisible", "la taille de la base", "/db/size_bytes_verdict", "/db/size_bytes_cause");
    lisible(
        &mut o,
        "plume_host_identity_lisible",
        "l'identité de cet hôte — elle décide quelles actions de réponse CIBLÉES s'exécutent localement ; \
         illisible, les actions ciblées ne sont plus réclamées ici (les non ciblées le restent)",
        "/host/identity_verdict",
        "/host/identity_cause",
    );
    // VENTILATION PAR POSTE — servie depuis le CACHE du tick lent, jamais recalculée ici (un scrape ne
    // peut pas déclencher 35 s de parcours dbstat). Le rendu N'EST PAS passé par `g()` : ce helper
    // n'imprime que ce qu'il trouve, mais il ne sait pas dire « refusé » — or ici l'ABSENCE des jauges
    // d'octets EST le message quand la comptabilité n'a pas fermé. Cf. `ventilation_serie`.
    o.push_str(&ventilation_serie::exposition_prom(&ventilation_serie::derniere(), now()));
    // P7.8-a — LA BORNE INTERACTIVE, PAR ROUTE : attente du permit et travail permit en main SÉPARÉS
    // (un total confond les deux et désigne le mauvais levier), plus la saturation. Rendu par le module
    // qui TIENT les compteurs, jamais réécrit ici : la cardinalité (plafonnée) et le nommage ont un seul
    // auteur. Lecture d'atomiques uniquement — un scrape ne coûte rien à la base.
    o.push_str(&crate::semaphore_interactif::exposition_prom());
    // P10.11-a — LE COÛT COMPOSÉ D'UNE REQUÊTE : l'attente du permit PLUS celle du verrou de la
    // connexion partagée, en SEAUX (une moyenne masque une exposition rare et concentrée, et un p99
    // aussi — mesuré) et en MAXIMUM, plus le temps pendant lequel une passe de vieillissement était
    // en cours. Rendu JUSTE APRÈS la série par route : c'est là que les deux termes de la
    // composition se lisent l'un sous l'autre. Lecture d'atomiques uniquement. Ce que la série NE
    // DIT PAS voyage dans son `# HELP`, pas seulement dans un commentaire de source.
    o.push_str(&crate::attente_serie::exposition_prom());
    // P10.9-a — USAGE DES INDEX, PAR INDEX ET PAR CLASSE DE CONSOMMATEUR. Lecture d'atomiques
    // uniquement (un scrape ne coûte rien à la base) ; cardinalité bornée par le plafond du registre
    // × l'énumération FERMÉE des classes. Rendu par le module qui TIENT les compteurs : le texte de
    // ce que la série NE PROUVE PAS part dans son `# HELP`, donc sous les yeux de qui lit le verdict.
    // Chaîne VIDE tant qu'aucun plan n'a été lu -> observatoire éteint = `/metrics` inchangé.
    o.push_str(&crate::index_usage::observatoire().exposition_prom());
    g(&mut o, "plume_alerts_open", "gauge", "Alertes ouvertes (status=new)", "/alerts_open");
    // BAN NATIF HTTP — la BORNE et son SATURATION. Lu depuis le store live en mémoire (aucune requête SQL :
    // un scrape ne doit rien coûter à la base). `store_tronque=1` dit que des bans posés en base ne sont PAS
    // enforcés faute de place : c'est l'alerte à câbler, une borne muette ne valant pas mieux qu'aucune borne.
    prom_line(&mut o, "plume_netban_entries", "gauge", "IP bloquées par le ban natif HTTP (store live)", netban_cache().read().len().to_string());
    prom_line(&mut o, "plume_netban_cap", "gauge", "Plafond du store live du ban natif (entrées)", NETBAN_CACHE_CAP.to_string());
    prom_line(&mut o, "plume_netban_store_tronque", "gauge", "1 si la base porte plus de bans que le store live n'en charge", u8::from(netban_store_tronque()).to_string());
    // santé par composant : jauge 1/0.5/0 (V/J/R) étiquetée par composant (constantes).
    o.push_str("# HELP plume_component_up Santé par composant (1=vert, 0.5=jaune, 0=rouge)\n# TYPE plume_component_up gauge\n");
    if let Some(cs) = j.get("components").and_then(|c| c.as_array()) {
        for c in cs {
            if let Some(name) = c.get("component").and_then(|s| s.as_str()) {
                let st = c.get("state").and_then(|s| s.as_str()).unwrap_or("red");
                o.push_str(&format!("plume_component_up{{component=\"{name}\"}} {}\n", health_score(st)));
            }
        }
    }
    // EXERCICE DE RESTAURATION (P8.3-a) — DÉRIVÉ de l'entrée de composant ci-dessus, jamais recalculé :
    // deux calculs de la même chose finissent par diverger, et c'est alors la jauge qui ment.
    //
    // `overdue` EST LA JAUGE SUR LAQUELLE UNE ALERTE SE CÂBLE : elle vaut 1 quand aucun exercice n'a
    // JAMAIS eu lieu, quand le dernier a vieilli au-delà de son âge maximal, et quand le seul exercice
    // enregistré portait sur une archive symétrique alors que la reprise réelle passera par l'escrow.
    // Les DEUX autres jauges sont ABSENTES tant qu'aucun exercice n'a eu lieu, et cette absence est le
    // message : publier `age_seconds 0` ferait lire « restauré à l'instant » là où il faut lire « jamais
    // restauré ». C'est la même règle que la ventilation par poste — une jauge qui ne sait pas se taire
    // finit par affirmer.
    if let Some(c) = j.get("components").and_then(|a| a.as_array()).and_then(|a| {
        a.iter().find(|c| c.get("component").and_then(|s| s.as_str()) == Some(crate::exercice_de_restauration::COMPOSANT))
    }) {
        prom_line(&mut o, "plume_restore_drill_overdue", "gauge",
            "1 si un exercice de restauration est dû (jamais fait, périmé, ou mené hors du chemin d'escrow)",
            u8::from(c.get("overdue").and_then(Value::as_bool).unwrap_or(true)).to_string());
        if let Some(ts) = c.get("last_success_ts").and_then(Value::as_i64) {
            prom_line(&mut o, "plume_restore_drill_last_success_timestamp_seconds", "gauge",
                "Horodatage du dernier exercice de restauration réussi (unix s ; absent = jamais)", ts.to_string());
        }
        if let Some(age) = c.get("age_s").and_then(Value::as_i64) {
            prom_line(&mut o, "plume_restore_drill_age_seconds", "gauge",
                "Âge du dernier exercice de restauration réussi (s ; absent = jamais)", age.to_string());
        }
    }
    o
}

