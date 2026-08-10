//! LA SÉRIE DU BUDGET — où partent les octets, **dans le temps** et sans que personne ne relève rien.
//!
//! CE QUI ÉTAIT CASSÉ, ET CE QUE ÇA A COÛTÉ. `db_ventilation` sait dire où partent les octets, mais
//! seulement à l'instant où quelqu'un tape `db-stats --par-objet` — un RELEVÉ PONCTUEL, à la main, qui
//! périme en quelques heures. Trois dégâts MESURÉS, et ils viennent tous de la même absence :
//!   * une carte de leviers (`docs/DESIGN-P10-echelle-2go.md`) bâtie sur une ventilation de BANC
//!     publiée comme « indépendante de l'échelle », que la production a contredite (index 32,8 % ->
//!     25,4 % ; FTS5 8,1 % -> 18,9 %) ;
//!   * une roadmap dont 17 chiffres étaient périmés ou non datés ;
//!   * et une hausse du FTS lue comme de la croissance organique alors que c'était la trace de
//!     l'aging. **Sans série, les deux se ressemblent** : un point ne dit jamais un sens.
//! La compaction FTS livrée en `4ca6339` a exactement le même problème : son gain ne se constate qu'en
//! refaisant un relevé à la main.
//!
//! OÙ LA SÉRIE VIT, ET POURQUOI PAS AILLEURS. Le piège à éviter est la jauge que personne ne collecte.
//! Il a déjà coûté deux fois ici (des timers d'hôte qui écrivaient dans le textfile-collector d'un
//! node-exporter DÉCOMMISSIONNÉ). Ce qui a tranché est une mesure, pas une préférence — relevée sur la
//! production le 2026-08-09 :
//!   * **AUCUN Prometheus ne tourne** dans le cluster. Une jauge `/metrics` de plus, SEULE, ne serait
//!     lue par personne : c'est le piège, pas la sortie.
//!   * En revanche `plume-prom-scrape.timer` est `enabled` + `active`, cadence 30 s — et il a tourné
//!     **9 364 fois depuis le 2026-08-06T06:11:42Z sans jamais joindre UNE SEULE de ses 2 cibles**
//!     (deux ClusterIP morts, absents de `kubectl get svc -A`). Le collecteur existe et tourne ; ce
//!     sont ses cibles qui sont mortes. Le faire pointer sur notre propre `/metrics` ferait transiter
//!     une mesure INTERNE par l'hôte, HTTP, un jeton et le CHEMIN D'INGEST — pour une valeur qui ne
//!     change qu'une fois par heure et qu'il scraperait 120 fois. Et ça dépendrait d'un fichier
//!     (`/etc/plume/prom-targets`) que le dépôt ne contrôle pas.
//!   * Un fichier append-only meurt avec le pod s'il n'est pas sur le PVC, et **aucun consommateur ne
//!     lit de fichier** : ni panneau, ni règle, ni SOQL. Ce serait une troisième sonde dans le vide.
//!   * Une table NEUVE coûterait un schéma, une migration, une rétention — et n'aurait, elle non plus,
//!     aucun lecteur.
//! Donc : **la série est écrite par plume dans sa PROPRE table `metric`**, par un tick lent, sans HTTP,
//! sans jeton, sans hôte. Elle hérite de tout ce qui existe déjà et qui est LU :
//!   * `metric` (brut, `metric_raw_hours` = 48 h) puis `metric_rollup` (bucket HORAIRE,
//!     `metric_days` = 90 j) — la bascule et les deux purges sont déjà écrites (`rollups.rs`) ;
//!   * et le lecteur : la commande SOQL `metric` compile, dans le cœur ÉPINGLÉ (`guatx-core`
//!     `ec6f4bdc`, `src/soql/mod.rs`), un `SELECT … FROM metric … UNION ALL SELECT … FROM
//!     metric_rollup …`. Les 90 jours sont donc interrogeables SANS rien relever :
//!         `metric plume_db_poste_bytes by poste | timechart span=1d avg(value)`
//!     Les mêmes lignes alimentent les panneaux (`handlers/datasource.rs`) et les règles
//!     (`seeds.rs`) — donc `alert` -> ntfy si on veut un seuil.
//!
//! LA CADENCE EST LE COÛT, ET LE COÛT EST MESURÉ. `dbstat` parcourt TOUTES les pages : **35,4 s sur la
//! production (1 586,8 Mio, SQLCipher, pod à 2 cœurs), soit 22,9 s/Gio** (mesuré le 2026-08-09 ; la
//! valeur « ~15 s/Gio » qui traînait dans `db-stats` venait d'un banc NON chiffré et sous-estimait de
//! moitié). Au tick HORAIRE retenu, ça fait **0,98 % d'un cœur**. L'heure n'est pas un chiffre rond :
//! c'est la RÉSOLUTION DE STOCKAGE de la destination — `metric_rollup` agrège par `ts/3600`, donc tout
//! point plus fin est moyenné et perdu au bout de 48 h. Mesurer plus souvent coûterait du CPU pour
//! produire des points que la base jette.
//!
//! ET LA CADENCE SE DÉFEND TOUTE SEULE QUAND LA BASE GROSSIT. `prochain_sommeil` ne rend jamais moins
//! que `PART_MAX_INVERSE` fois la durée du dernier parcours : la mesure ne peut pas dépasser
//! **5 % d'un cœur**, quelle que soit la taille de la base. À 2 Gio le tick reste horaire ; à 10 Gio il
//! s'espacerait tout seul. C'est une borne PAR CONSTRUCTION, pas une intention.
//!
//! CE QUI SE PASSE QUAND LA MESURE N'A PAS PU ÊTRE PRISE. `db_ventilation::mesurer` REFUSE de publier
//! quand sa comptabilité ne ferme pas. Ce refus se PROPAGE : aucune ligne `plume_db_poste_bytes` n'est
//! écrite (la série a un TROU, visible dans un timechart) et une ligne `plume_db_ventilation_ok = 0`
//! NOMME la cause. Un zéro d'octets se lirait « ce poste est vide » ; un trou se lit « je n'ai pas
//! mesuré ». Ce n'est pas la même phrase, et c'est exactement l'erreur que cette campagne ferme
//! ailleurs. Trois états, portés par le TYPE (`Option<Mesure>`) : jamais mesuré / mesuré / refusé.
//!
//! CE QUE ÇA NE COÛTE NI À L'INGEST NI AUX REQUÊTES. Le parcours se fait sur une connexion du POOL DE
//! LECTURE (`read_with`, WAL) : `mesurer_une_fois` ne reçoit qu'un `&str` de chemin — elle n'a
//! STRUCTURELLEMENT pas de quoi prendre le mutex d'écriture. Seule la publication le prend, pour 7
//! `INSERT` d'une ligne, une fois par heure.
//!
//! CE QUE ÇA NE COUVRE PAS, ÉCRIT POUR ÊTRE OPPOSABLE : la boucle porte sur LA BASE DU DÉPLOIEMENT
//! (mode 0), comme `spawn_autovacuum_loop`. En mode multi-tenant (`PLUME_MULTI_TENANT`, défaut off,
//! jamais activé en production) les bases des autres tenants ne sont pas ventilées.
use crate::*;
use std::sync::atomic::Ordering;

/// Le nom de la série des octets par poste. Une seule métrique, une étiquette `poste` : la part d'un
/// poste se calcule depuis la série SEULE (la somme des seaux EST le fichier — c'est ce que la
/// comptabilité fermée garantit), sans avoir besoin d'une seconde mesure pour faire le dénominateur.
pub(crate) const NOM_POSTE: &str = "plume_db_poste_bytes";
/// 1 = la ventilation a été prise à cet horodatage ; 0 = elle a été REFUSÉE (étiquette `cause`).
pub(crate) const NOM_OK: &str = "plume_db_ventilation_ok";
/// Ce que le parcours a coûté. Publié dans les DEUX cas : c'est la donnée qui permettra de rediscuter
/// la cadence sans refaire un relevé à la main — exactement le défaut que ce module ferme.
pub(crate) const NOM_DUREE: &str = "plume_db_ventilation_duree_ms";
/// La cause publiée quand la mesure a réussi. Une étiquette toujours présente (plutôt qu'absente sur
/// succès) garde une forme de série UNIQUE : un `by cause` n'a pas de trou à expliquer.
pub(crate) const CAUSE_AUCUNE: &str = "aucune";

/// Intervalle nominal entre deux parcours. `0` = boucle DÉSACTIVÉE (aucun thread).
pub(crate) const INTERVALLE_DEFAUT_S: u64 = 3600;
/// Le sommeil ne descend jamais sous `PART_MAX_INVERSE` fois la durée du dernier parcours -> la mesure
/// est bornée à 1/20 = **5 % d'un cœur**, quelle que soit la taille de la base.
pub(crate) const PART_MAX_INVERSE: u32 = 20;

/// CE QU'ON SAIT DE LA DERNIÈRE TENTATIVE. Deux variantes, pas trois : « jamais tenté » n'est PAS une
/// variante ici, c'est l'absence de `Mesure` (`Option`). Les trois états sont donc exhaustifs et le
/// compilateur les tient.
#[derive(Clone)]
pub(crate) enum Mesure {
    /// La ventilation a été prise. `octets` suit l'ordre de `db_ventilation::TOUS`, plus les pages
    /// libres en dernier : c'est la liste PUBLIÉE, dérivée de l'énumération.
    Prise { ts: i64, octets: Vec<(&'static str, i64)>, duree_ms: u64 },
    /// Elle a été refusée. La cause est une clé stable, sa phrase est pour le journal et l'exposition.
    NonPrise { ts: i64, cause: &'static str, phrase: String, duree_ms: u64 },
}

impl Mesure {
    pub(crate) fn ts(&self) -> i64 {
        match self {
            Mesure::Prise { ts, .. } | Mesure::NonPrise { ts, .. } => *ts,
        }
    }
    pub(crate) fn duree_ms(&self) -> u64 {
        match self {
            Mesure::Prise { duree_ms, .. } | Mesure::NonPrise { duree_ms, .. } => *duree_ms,
        }
    }
}

/// LA LISTE DES SEAUX PUBLIÉS, DÉRIVÉE de `db_ventilation::TOUS` (jamais réécrite) + les pages libres.
/// Un poste ajouté à l'énumération apparaît dans la série sans que personne ne pense à ce fichier.
pub(crate) fn seaux(v: &db_ventilation::Ventilation) -> Vec<(&'static str, i64)> {
    let mut out: Vec<(&'static str, i64)> =
        db_ventilation::TOUS.iter().map(|p| (p.cle(), v.octets[p.rang()])).collect();
    out.push((db_ventilation::CLE_LIBRES, v.libres_octets));
    out
}

/// Le résultat d'une tentative, quel qu'il soit — PURE (aucune horloge, aucun global) : c'est ce qui
/// rend testable la propriété « un refus ne devient pas un zéro ».
pub(crate) fn depuis_resultat(
    ts: i64,
    duree_ms: u64,
    r: Result<db_ventilation::Ventilation, db_ventilation::Echec>,
) -> Mesure {
    match r {
        Ok(v) => Mesure::Prise { ts, octets: seaux(&v), duree_ms },
        Err(e) => Mesure::NonPrise { ts, cause: e.cause(), phrase: e.phrase(), duree_ms },
    }
}

/// UN POINT DE SÉRIE : le nom, ses étiquettes (JSON, comme la colonne `metric.labels`), sa valeur.
pub(crate) struct Point {
    pub(crate) nom: &'static str,
    pub(crate) etiquettes: Option<String>,
    pub(crate) valeur: f64,
}

/// LES POINTS À ÉCRIRE — PURE, et c'est ici que vit l'invariant ④.
///
/// Sur `Prise` : un point par seau, plus `ok = 1`, plus la durée.
/// Sur `NonPrise` : **aucun point d'octets**. Le trou EST le message ; un `0` se lirait « ce poste est
/// vide », ce qui est une AUTRE affirmation, et fausse. Seuls `ok = 0` (avec sa cause) et la durée
/// sortent.
pub(crate) fn points(m: &Mesure) -> Vec<Point> {
    let etiq = |cle: &str, val: &str| Some(format!("{{\"{cle}\":\"{val}\"}}"));
    let mut out = Vec::new();
    match m {
        Mesure::Prise { octets, duree_ms, .. } => {
            for (cle, o) in octets {
                out.push(Point { nom: NOM_POSTE, etiquettes: etiq("poste", cle), valeur: *o as f64 });
            }
            out.push(Point { nom: NOM_OK, etiquettes: etiq("cause", CAUSE_AUCUNE), valeur: 1.0 });
            out.push(Point { nom: NOM_DUREE, etiquettes: None, valeur: *duree_ms as f64 });
        }
        Mesure::NonPrise { cause, duree_ms, .. } => {
            out.push(Point { nom: NOM_OK, etiquettes: etiq("cause", cause), valeur: 0.0 });
            out.push(Point { nom: NOM_DUREE, etiquettes: None, valeur: *duree_ms as f64 });
        }
    }
    out
}

/// L'EXPOSITION PROMETHEUS de la dernière tentative — PURE (l'instant est un paramètre).
///
/// Trois états, trois sorties DIFFÉRENTES :
///   * `None` (jamais mesuré, p. ex. au démarrage) -> **rien du tout**. Publier `ok 0` dirait « la
///     mesure a échoué », ce qui serait faux ; publier `0` octet dirait « la base est vide », pire.
///   * `Prise` -> les seaux + `ok 1` + l'âge.
///   * `NonPrise` -> `ok 0` étiqueté par la cause + l'âge, et **aucune jauge d'octets** : l'ABSENCE
///     d'une jauge est la façon dont Prometheus dit « pas de valeur », un `0` ne l'est pas.
pub(crate) fn exposition_prom(m: &Option<Mesure>, maintenant: i64) -> String {
    let Some(m) = m else { return String::new() };
    let mut o = String::with_capacity(512);
    if let Mesure::Prise { octets, .. } = m {
        o.push_str("# HELP plume_db_poste_bytes Octets de la base par poste (dbstat ; la somme des postes fait le fichier)\n");
        o.push_str("# TYPE plume_db_poste_bytes gauge\n");
        for (cle, v) in octets {
            o.push_str(&format!("{NOM_POSTE}{{poste=\"{cle}\"}} {v}\n"));
        }
    }
    let (ok, cause) = match m {
        Mesure::Prise { .. } => (1, CAUSE_AUCUNE),
        Mesure::NonPrise { cause, .. } => (0, *cause),
    };
    o.push_str("# HELP plume_db_ventilation_ok 1 si la dernière ventilation a été publiée, 0 si elle a été REFUSÉE (cause en étiquette)\n");
    o.push_str("# TYPE plume_db_ventilation_ok gauge\n");
    o.push_str(&format!("{NOM_OK}{{cause=\"{cause}\"}} {ok}\n"));
    o.push_str("# HELP plume_db_ventilation_duree_ms Durée du parcours dbstat (ms)\n# TYPE plume_db_ventilation_duree_ms gauge\n");
    o.push_str(&format!("{NOM_DUREE} {}\n", m.duree_ms()));
    o.push_str("# HELP plume_db_ventilation_age_seconds Âge de la dernière tentative (s)\n# TYPE plume_db_ventilation_age_seconds gauge\n");
    o.push_str(&format!("plume_db_ventilation_age_seconds {}\n", (maintenant - m.ts()).max(0)));
    o
}

/// La même chose pour le panneau « Système » et le diag-bundle. `None` -> `Value::Null` (le champ est
/// ABSENT du JSON côté appelant) : là encore, jamais un objet de zéros.
pub(crate) fn json(m: &Option<Mesure>, maintenant: i64) -> Value {
    let Some(m) = m else { return Value::Null };
    match m {
        Mesure::Prise { ts, octets, duree_ms } => {
            let postes: serde_json::Map<String, Value> =
                octets.iter().map(|(c, v)| ((*c).to_string(), json!(v))).collect();
            json!({ "mesuree": true, "ts": ts, "age_s": (maintenant - ts).max(0), "duree_ms": duree_ms, "postes": postes })
        }
        Mesure::NonPrise { ts, cause, phrase, duree_ms } => {
            json!({ "mesuree": false, "ts": ts, "age_s": (maintenant - ts).max(0), "duree_ms": duree_ms, "cause": cause, "detail": phrase })
        }
    }
}

/// LE SOMMEIL AVANT LE PROCHAIN PARCOURS — PURE. Jamais moins que `PART_MAX_INVERSE` fois ce que le
/// dernier a coûté : c'est la borne de CPU, et elle ne dépend d'aucun réglage.
pub(crate) fn prochain_sommeil(intervalle: Duration, derniere: Duration) -> Duration {
    intervalle.max(derniere.saturating_mul(PART_MAX_INVERSE))
}

// =================================================================================================
// LE CACHE — la valeur SERVIE, jamais la valeur CALCULÉE
//
// `/metrics` et `/api/system/metrics` lisent ICI et ne déclenchent RIEN : un scrape ne peut pas
// provoquer un parcours de 35 s. Le slot est volontairement bête (aucune logique) : toute la logique
// est dans les fonctions pures ci-dessus, qui sont donc testables sans toucher à un état de processus.
// =================================================================================================
static DERNIERE: std::sync::OnceLock<Mutex<Option<Mesure>>> = std::sync::OnceLock::new();
fn slot() -> &'static Mutex<Option<Mesure>> {
    DERNIERE.get_or_init(|| Mutex::new(None))
}
/// La dernière tentative connue (clone : le verrou n'est jamais tenu pendant un rendu).
pub(crate) fn derniere() -> Option<Mesure> {
    slot().lock().clone()
}
fn poser(m: Mesure) {
    *slot().lock() = Some(m);
}

// =================================================================================================
// LE PARCOURS ET LA PUBLICATION
// =================================================================================================

/// UN parcours, sur une connexion du POOL DE LECTURE. La signature est la garde : cette fonction ne
/// reçoit qu'un CHEMIN, donc elle n'a pas de quoi prendre le mutex d'écriture — l'ingestion ne peut pas
/// attendre après elle. (`read_with` ouvre/reprend une connexion `query_only=ON` en WAL.)
///
/// LES QUATRE LECTURES SONT DANS UNE MÊME TRANSACTION. Sans elle, `PRAGMA page_count` et le parcours
/// `dbstat` liraient DEUX instantanés différents et la comptabilité ne fermerait pas dès qu'une
/// écriture est committée pendant les 35 s du parcours — la mesure serait refusée pour une raison qui
/// n'est pas la sienne. Contrepartie DÉCLARÉE : pendant ces ~35 s le WAL ne peut pas être remis à zéro
/// par un checkpoint (1 % du temps au tick horaire).
pub(crate) fn mesurer_une_fois(db_path: &str, ts: i64) -> Mesure {
    let t0 = Instant::now();
    let m = read_with(db_path, None, |conn| {
        let transaction = conn.execute_batch("BEGIN DEFERRED").is_ok();
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(-1) };
        let page_size = q("PRAGMA page_size");
        let page_count = q("PRAGMA page_count");
        let freelist = q("PRAGMA freelist_count");
        let r = db_ventilation::mesurer(conn, page_size.max(0), page_count.max(0), freelist.max(0));
        if transaction {
            let _ = conn.execute_batch("COMMIT");
        }
        Some(depuis_resultat(ts, t0.elapsed().as_millis().min(u64::MAX as u128) as u64, r))
    });
    // `read_with` rend `None` UNIQUEMENT si la connexion de lecture n'a pas pu être obtenue. C'est un
    // échec de mesure, pas une base vide : il se publie comme tel.
    m.unwrap_or_else(|| Mesure::NonPrise {
        ts,
        cause: "connexion_lecture",
        phrase: format!("aucune connexion de lecture disponible sur {db_path}"),
        duree_ms: t0.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

/// LA VOIE D'ÉCRITURE D'UNE SÉRIE DANS `metric` — partagée par toutes les séries que le démon publie
/// sur lui-même (la ventilation ici, le vieillissement froid dans `vieillissement_serie`). `host` est
/// volontairement `None` : ces séries décrivent LA BASE, pas une machine — leur donner un hôte les
/// inscrirait dans l'inventaire de flotte (`host_rollup`, bâti depuis `metric WHERE host IS NOT NULL`)
/// et inventerait une machine qui n'existe pas. UNE seule copie de cette décision, donc un seul endroit
/// à corriger : une deuxième boucle d'`INSERT` ailleurs finirait par diverger sur ce `None`.
///
/// Prend `&Connection` (donc le mutex d'écriture est tenu par l'APPELANT, et seulement pour ces
/// quelques `INSERT`) : la publication ne peut pas s'étaler sur la durée d'un travail.
pub(crate) fn ecrire_points(conn: &Connection, ts: i64, points: &[Point]) -> usize {
    let mut n = 0;
    for p in points {
        let row =
            MetricRow { ts, name: p.nom.to_string(), labels: p.etiquettes.clone(), value: p.valeur, host: None };
        if store().insert_metric(conn, &row).is_ok() {
            n += 1;
        }
    }
    n
}

/// ÉCRIT les points de la ventilation. L'horodatage est celui de la MESURE (pas de l'écriture) : une
/// publication retardée par le verrou ne doit pas décaler le point dans la série.
pub(crate) fn publier(conn: &Connection, m: &Mesure) -> usize {
    ecrire_points(conn, m.ts(), &points(m))
}

/// Prend le verrou d'écriture — et le rend — POUR LES SEULS `INSERT`. C'est le seul endroit du module
/// qui verrouille : `tour` ne verrouille pas lui-même, et le test `le_tour_ne_verrouille_pas_lui_meme`
/// refuse qu'il se remette à le faire. La « simplification » consistant à ouvrir le verrou en tête du
/// tour tiendrait l'ingestion pendant TOUT le parcours (35,4 s mesurés en production) — c'est
/// exactement la régression que la séparation empêche.
fn publier_sous_verrou(db: &Arc<Mutex<Connection>>, m: &Mesure) -> usize {
    let conn = db.lock();
    publier(&conn, m)
}

/// Le tour complet : parcourir (hors verrou), mémoriser pour `/metrics`, publier dans la série.
pub(crate) fn tour(db: &Arc<Mutex<Connection>>, db_path: &str) -> Duration {
    let t0 = Instant::now();
    let m = mesurer_une_fois(db_path, now());
    poser(m.clone());
    let ecrits = publier_sous_verrou(db, &m);
    match &m {
        Mesure::Prise { octets, duree_ms, .. } => {
            let total: i64 = octets.iter().map(|(_, v)| *v).sum();
            eprintln!(
                "[ventilation] {} points écrits — {} Mio ventilés en {duree_ms} ms ({})",
                ecrits,
                total / (1024 * 1024),
                octets.iter().map(|(c, v)| format!("{c}={} Mio", v / (1024 * 1024))).collect::<Vec<_>>().join(" ")
            );
        }
        Mesure::NonPrise { cause, phrase, .. } => {
            // NON mesuré, DIT comme tel : ni silence, ni zéro publié.
            eprintln!("[ventilation] NON MESURÉE ({cause}) : {phrase} — aucun octet publié, la série porte un trou");
        }
    }
    t0.elapsed()
}

/// LA BOUCLE. Gatée sur `PLUME_VENTILATION_INTERVAL_S` (0 = aucun thread). Défaut : horaire — la
/// résolution de `metric_rollup`, pour 0,98 % d'un cœur sur la production mesurée.
pub(crate) fn spawn_boucle(
    conf: HashMap<String, String>,
    db_path: String,
    db: Arc<Mutex<Connection>>,
    bound: Arc<std::sync::atomic::AtomicBool>,
) {
    let intervalle: u64 = cfg(&conf, "PLUME_VENTILATION_INTERVAL_S", &INTERVALLE_DEFAUT_S.to_string())
        .parse()
        .unwrap_or(INTERVALLE_DEFAUT_S);
    if intervalle == 0 {
        eprintln!("[ventilation] PLUME_VENTILATION_INTERVAL_S=0 -> série DÉSACTIVÉE (aucun thread, aucun parcours dbstat)");
        return;
    }
    let intervalle = Duration::from_secs(intervalle);
    std::thread::spawn(move || {
        // Gate STRUCTUREL, calqué sur `spawn_analyze_full` : on ne consomme pas de CPU avant que le
        // port n'écoute (la sonde de vivacité passe d'abord).
        while !bound.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_secs(90)); // grâce : après le bind, le 1er rollup, l'ANALYZE
        loop {
            let coute = tour(&db, &db_path);
            std::thread::sleep(prochain_sommeil(intervalle, coute));
        }
    });
}
