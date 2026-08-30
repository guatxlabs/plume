//! Fraîcheur & heartbeats (P4) : santé pipeline `pipeline_is_fresh`, handler `integrations`, cache
//! SWR `FRESHNESS_CACHE`/handler `freshness`, extraction de sources `extract_query_sources`, calcul
//! par-source `compute_freshness`, et alerte capteur muet `check_heartbeats`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Santé du pipeline d'ingestion : la donnée la PLUS récente, TOUTES sources confondues, est-elle fraîche
/// (< 10 min) ? Sert à la logique ÉVÉNEMENTIELLE des capteurs (un hôte calme n'est pas « muet » tant que
/// QUELQUE CHOSE arrive). Même seuil/requête que compute_freshness (cohérence statut UI <-> alerte muet).
/// COÛT : `MAX(ts)` par table = un simple max INDEXÉ (O(1), dernière entrée d'index) dès lors qu'un index
/// ts-leading existe : idx_event_ts (event) + idx_metric_ts / idx_snapshot_ts (ensure_host_rollup_scan_indexes_
/// background). Sans eux (fenêtre transitoire du 1er boot), metric/snapshot retombent en full-scan -> c'est
/// justement ce que ces index suppriment (MAX(ts) non borné par-requête = risque watchdog).
// ====================================================================================================
// LE VERDICT SUR UN CAPTEUR — UNE SEULE DÉRIVATION, DEUX SURFACES.
//
// CE QUI ÉTAIT CASSÉ. Le statut AFFICHÉ (`compute_integrations`) et le déclenchement de l'ALERTE
// (`check_heartbeats`) étaient deux `match` écrits séparément sur les mêmes entrées. Ils divergeaient
// sur le cas le plus fréquent d'une PME : un capteur JAMAIS BRANCHÉ (`last_seen = None` — YARA,
// CrowdSec, k8s… absents d'un Linux nu). Le panneau disait « inconnu » (en attente) ; l'alerte, elle,
// levait « Capteur muet : YARA (scan) — pipeline d'ingestion muet » dès que le pipeline global
// décrochait. MESURÉ le 2026-08-02 par le vrai chemin (`check_heartbeats` sur une base où seul
// `sshd` a déjà émis, silence de 11 min) : 8 alertes « capteur muet » nommaient des capteurs qui
// n'ont JAMAIS RIEN ÉMIS sur cette machine. C'est la famille qu'on ferme : une surface qui SAIT
// qu'elle n'a jamais rien observé et qui affirme quand même une panne.
//
// LA FORME DÉRIVÉE. `None` n'est pas « en retard depuis longtemps » : c'est « aucune observation ».
// Un capteur sans aucune observation n'a pas de silence à constater — il ne peut donc pas être
// « muet », quel que soit l'état du pipeline. Le verdict est désormais UNE fonction ; les deux
// surfaces l'appellent, et `StatutCapteur::alerte()` dit lequel des trois verdicts réveille
// quelqu'un. Une 24ᵉ entrée de `COLLECTORS`, ou une 3ᵉ surface, hérite de la règle sans la réécrire.
//
// L'ÉCART DE SEUIL EST GARDÉ, MAIS DÉCLARÉ. Le panneau montrait « muet » à 3 cycles manqués,
// l'alerte à 5 — écart réel, jamais écrit nulle part, qu'on aurait effacé par mégarde en unifiant.
// Il devient un PARAMÈTRE NOMMÉ (`CYCLES_TOLERES_*`) : l'humain qui REGARDE voit l'écart tout de
// suite, celui qu'on RÉVEILLE mérite deux cycles de plus. Aucune valeur ne change.
// ====================================================================================================

/// Cycles manqués tolérés AVANT de déclarer un capteur continu muet. Deux valeurs, deux usages.
pub(crate) const CYCLES_TOLERES_AFFICHAGE: i64 = 3;
pub(crate) const CYCLES_TOLERES_ALERTE: i64 = 5;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum StatutCapteur {
    /// AUCUNE observation, jamais. « en attente » côté UI. N'alerte JAMAIS : il n'y a pas de silence
    /// à constater sur un capteur qui n'a jamais parlé.
    Inconnu,
    /// Il parle (ou son silence est normal : capteur événementiel + pipeline frais).
    Actif,
    /// Il a DÉJÀ parlé et s'est tu au-delà du tolérable — le seul verdict qui alerte.
    Muet,
}

impl StatutCapteur {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            StatutCapteur::Inconnu => "inconnu",
            StatutCapteur::Actif => "actif",
            StatutCapteur::Muet => "muet",
        }
    }
    /// LE SEUL verdict qui lève une alerte. Écrit ici plutôt qu'au site d'appel pour qu'une 3ᵉ
    /// surface ne puisse pas inventer sa propre règle de déclenchement.
    pub(crate) fn alerte(&self) -> bool {
        matches!(self, StatutCapteur::Muet)
    }
}

/// LE verdict. `ls` = dernière collecte OBSERVÉE (`None` = jamais rien vu, cf. `Sonde`).
/// `event_based` = capteur dont le débit dépend d'une activité externe : son silence propre n'est PAS
/// un symptôme (hôte calme), seul l'effondrement du pipeline GLOBAL en est un.
pub(crate) fn statut_capteur(
    ls: Option<i64>,
    interval: i64,
    event_based: bool,
    pipe_fresh: bool,
    cycles_toleres: i64,
    now_ts: i64,
) -> StatutCapteur {
    match ls {
        None => StatutCapteur::Inconnu,
        Some(_) if event_based => {
            if pipe_fresh {
                StatutCapteur::Actif
            } else {
                StatutCapteur::Muet
            }
        }
        Some(t) if now_ts - t <= interval * cycles_toleres => StatutCapteur::Actif,
        Some(_) => StatutCapteur::Muet,
    }
}

pub(crate) fn pipeline_is_fresh(conn: &Connection, now_ts: i64) -> bool {
    let global_last: Option<i64> = conn.query_row(
        "SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event UNION ALL SELECT MAX(ts) FROM metric UNION ALL SELECT MAX(ts) FROM snapshot)",
        [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
    global_last.map(|m| now_ts - m < 600).unwrap_or(false)
}

// ====================================================================================================
// LE STATUT D'UNE SOURCE — UNE SEULE DÉRIVATION, DEUX SURFACES (Fraîcheur, Inventaire). P11.3-b.
//
// CE QUI ÉTAIT CASSÉ. Le démon rendait `frais` / `calme` / `muet`, et la surface web fabriquait seule un
// quatrième mot, « dégradé / en retard », à partir de DEUX choses sans rapport : des alertes actives sur la
// source, ou un âge supérieur à quatre fois un intervalle `expected_s` qui n'était pas une cadence attendue
// mais la MOYENNE OBSERVÉE sur vingt-quatre heures (86400 / n_24h). Une source périodique dont le débit
// dépend de l'activité (le courrier) se retrouvait « en retard » à quatre fois sa moyenne ; une source
// événementielle à fort débit (les sondes de ports) était classée « continu » par sa moyenne puis
// « en retard » après une heure de calme ; et la page expliquait en pied que l'âge « n'est pas un retard »
// pendant que l'en-tête disait le contraire.
//
// LA FORME DÉRIVÉE. La seule CADENCE ATTENDUE qui existe est celle que `COLLECTORS` DÉCLARE (intervalle et
// nature continue ou événementielle de chaque sonde). Une source qu'une sonde observe en CONTINU est
// « en retard » au-delà de `interval × CYCLES_TOLERES_AFFICHAGE` — le même seuil qui rend le capteur « muet »
// dans Intégrations, et deux cycles avant l'alerte. Une source ÉVÉNEMENTIELLE, ou qu'aucune sonde ne
// déclare, n'est jamais « en retard » : son âge ne dit que son activité (« frais » / « calme »). Le mot
// « dégradé » disparaît ; les alertes actives restent un COMPTE à côté du statut, pas un statut.
// ====================================================================================================

/// Seuil du mot « frais » : la dernière donnée date de moins de quinze minutes.
pub(crate) const FRAIS_S: i64 = 900;

/// FENÊTRE des deux surfaces : un feed vu il y a plus longtemps n'est PLUS listé. Écrite une fois, lue par
/// la fraîcheur, par l'inventaire, et par le plafond d'un intervalle de cadence déclaré à la main (déclarer
/// une cadence plus longue que cette fenêtre reviendrait à déclarer un rythme que la console ne pourra
/// jamais juger : la source aura disparu de la liste avant l'échéance).
pub(crate) const FENETRE_INVENTAIRE_S: i64 = 7 * 86400;

// `CadenceDeclaree` / `cadence_declaree` vivent dans `sondes.rs` : la cadence attendue est une propriété
// DÉCLARÉE de la table des sondes, pas une dérivation de cette surface.

/// LE statut. Quatre mots, chacun avec UN sens : `muet` (plus rien n'arrive, toutes sources confondues),
/// `en_retard` (cadence déclarée continue dépassée), `frais` (donnée < FRAIS_S), `calme` (collecte saine,
/// source peu active). `None` pour la cadence = même verdict que `NonDeclaree`.
pub(crate) fn statut_de_source(age_s: i64, pipeline_fresh: bool, cadence: Option<&CadenceDeclaree>) -> &'static str {
    if !pipeline_fresh {
        return "muet";
    }
    if let Some(CadenceDeclaree::Continue { interval_s, .. }) = cadence {
        if age_s > interval_s * CYCLES_TOLERES_AFFICHAGE {
            return "en_retard";
        }
    }
    if age_s <= FRAIS_S {
        "frais"
    } else {
        "calme"
    }
}

/// Les champs de cadence d'un feed, tels que les deux surfaces les rendent : la déclaration (et la sonde
/// qui la porte), et le rythme OBSERVÉ sur vingt-quatre heures — nommé pour ce qu'il est, jamais plus
/// « attendu ».
pub(crate) fn cadence_json(cadence: &CadenceDeclaree, n_24h: i64) -> Value {
    let observed_interval_s = if n_24h > 0 { Some(86400 / n_24h) } else { None };
    json!({
        "cadence_declaree": cadence.etiquette(),
        "cadence_interval_s": cadence.interval_s(),
        "cadence_capteur": cadence.capteur(),
        // QUI la déclare (P11.3-c) : une sonde du démon, ou un humain de cette installation — avec son nom
        // et la date de SON geste. Le lecteur n'a plus à supposer qu'une cadence vient du code.
        "cadence_declarant": cadence.declarant().map(|d| d.libelle()),
        "cadence_par": cadence.declarant().and_then(|d| d.humain()),
        "cadence_le": cadence.declarant().and_then(|d| d.le()),
        "observed_interval_s": observed_interval_s,
    })
}

// SWR pour /api/integrations (#23) — même motif que /api/freshness ci-dessus. ROOT CAUSE du ~6 s À CHAUD :
// le handler exécute les 23 requêtes de COLLECTORS, chacune `SELECT MAX(ts) FROM event WHERE source=?[ AND
// category='health']`. `event` (~4,7 M lignes CHIFFRÉES) n'a qu'un idx_event_src MONOCOLONNE — AUCUN composite
// (source,ts) ni (source,category,ts) — donc chaque MAX(ts) doit balayer TOUTES les lignes de la source (avec
// lookup table pour lire `ts`, absent de l'index) => ~6 s CUMULÉS, à chaud comme à froid (contrairement à
// /api/overview désormais servi par les rollups). La liste des collecteurs + l'inventaire host_rollup évoluent
// LENTEMENT (last_seen) et l'UI re-poll (auto-refresh) -> on sert le JSON en STALE-WHILE-REVALIDATE (TTL 30 s,
// comme /api/freshness) : HIT frais instantané ; PÉRIMÉ servi tout de suite + revalidation ASYNC bornée
// (refresh_sem, anti-stampede) ; FROID = calcul SYNCHRONE une seule fois (même latence qu'avant sur le 1er
// appel, et le pré-chauffage boot le remplit d'ordinaire AVANT le 1er clic). Données IDENTIQUES à un calcul
// frais, à ≤TTL près. Clé = db_path (l'inventaire n'est PAS filtré par environnement). NB : la vue reste
// hors du lock writer (read pool + watchdog 5 s) — inchangé. Fix alternatif plus profond NON retenu (risque) :
// un composite (source,category,ts) rendrait chaque MAX(ts) O(1) mais impose un build sur 4,7 M lignes +
// amplification d'écriture sur le chemin d'ingest chaud ; le SWR est byte-identique et sans risque ingest.
//
// ── 2026-08-03 (P3.7-a) — CE PARAGRAPHE EST EN PARTIE PÉRIMÉ, ET CE QU'IL A LAISSÉ PASSER COMPTE.
// (a) « n'a qu'un idx_event_src MONOCOLONNE » : FAUX depuis v108, idx_event_src_ts(source, ts) existe —
//     les 12 sondes SANS `category` sont donc DÉJÀ des sauts en fin de plage d'index (15 VM steps,
//     constants sous x4 volume). L'attribution « toutes les 23 requêtes balayent » ne tenait plus.
// (b) L'objection sur le composite (source, category, ts) était JUSTE — mais elle ne visait QUE le
//     composite PLEIN. Un index PARTIEL `(source, ts) WHERE category='health'` ferme les mêmes 8 sondes
//     en n'indexant QUE les battements : mesuré 21,8 o/battement (~1,5 Mio) contre 25,5 o/ligne INGÉRÉE
//     (~250 Mio) pour le composite plein, et un insert btree toutes les ~37 s au lieu d'un par event.
//     C'est ce qui a été livré (cf. daemon/src/sondes.rs, migration v114).
// (c) LE COÛT QUE CE SWR N'A JAMAIS COUVERT : le cache ci-dessous protège /api/integrations. Il ne
//     protège PAS `check_heartbeats`, qui exécute LES MÊMES sondes toutes les 20 s SOUS LE VERROU
//     D'ÉCRITURE. Mettre un cache devant la surface de LECTURE a rendu le symptôme invisible côté UI
//     pendant que le coût continuait d'être payé sur le chemin d'ÉCRITURE — c'est là que le O(N)
//     mesuré en P3.7-a se cachait. Un cache déplace un coût ; il n'en supprime aucun.
pub(crate) const INTEGRATIONS_TTL: Duration = Duration::from_secs(30);
pub(crate) static INTEGRATIONS_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = std::sync::OnceLock::new();
pub(crate) static INTEGRATIONS_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn integrations_map() -> &'static Mutex<HashMap<String, (Instant, Value)>> {
    INTEGRATIONS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) async fn integrations(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    use std::sync::atomic::Ordering;
    let db_path = req_db_path(&st, &au);
    let ckey = db_path.clone();
    // HIT frais -> instantané.
    if let Some((t, v)) = integrations_map().lock().get(&ckey) {
        if t.elapsed() < INTEGRATIONS_TTL {
            return Json(v.clone());
        }
    }
    // PÉRIMÉ présent -> SWR : sert le périmé immédiatement + revalidation async bornée (anti-stampede).
    let stale = integrations_map().lock().get(&ckey).cloned();
    if let Some((_, v)) = stale {
        if !INTEGRATIONS_REFRESHING.swap(true, Ordering::AcqRel) {
            let db = db_path.clone();
            let ck = ckey.clone();
            let sem = st.refresh_sem.clone();
            tokio::spawn(async move {
                // try_acquire (PAS await) : lane refresh saturée -> on renonce (le périmé reste servi).
                if let Ok(_permit) = sem.try_acquire_owned() {
                    let db2 = db.clone();
                    if let Ok(nv) = tokio::task::spawn_blocking(move || compute_integrations(&db2)).await {
                        integrations_map().lock().insert(ck, (Instant::now(), nv));
                    }
                }
                INTEGRATIONS_REFRESHING.store(false, Ordering::Release);
            });
        }
        return Json(v);
    }
    // FROID : calcul SYNCHRONE une seule fois (même latence qu'avant sur le 1er appel) PUIS mise en cache.
    // On NE renvoie PAS de placeholder « warming » (contrairement à freshness) -> aucune régression de forme :
    // le 1er appel voit exactement les mêmes données qu'aujourd'hui, juste mises en cache pour la suite.
    let dbp = db_path.clone();
    let nv = tokio::task::spawn_blocking(move || compute_integrations(&dbp))
        .await
        .unwrap_or_else(|_| json!({ "collectors": [], "hosts": [], "flotte": null }));
    integrations_map().lock().insert(ckey, (Instant::now(), nv.clone()));
    Json(nv)
}

/// Calcul (LOURD — cf. ROOT CAUSE ci-dessus) du panneau intégrations. Mis en cache SWR par le handler
/// `integrations` ; NE PAS appeler directement depuis le chemin requête (passer par le handler / le cache).
/// Lecture seule (read pool + watchdog 5 s), JAMAIS le lock writer (st.db). L'INVENTAIRE D'HÔTES est lu du
/// rollup pré-agrégé `host_rollup` (v77, cf. rollup_hosts) : AUCUN scan de event∪metric∪snapshot.
pub(crate) fn compute_integrations(db_path: &str) -> Value {
    let now_ts = now();
    read_with_watchdog(db_path, json!({ "collectors": [], "hosts": [], "flotte": null }), move |conn| {
        // FIX #2 — capteurs ÉVÉNEMENTIELS : leur statut suit la SANTÉ DU PIPELINE global, pas leur propre
        // intervalle (sinon hôte calme = faux MUET permanent). Calculé une fois pour tous les collecteurs.
        let pipe_fresh = pipeline_is_fresh(conn, now_ts);
        let collectors: Vec<Value> = COLLECTORS
            .iter()
            .map(|(id, label, interval, sonde, event_based)| {
                // SONDE TYPÉE (cf. bandeau `Sonde` de main.rs) : le SQL est DÉRIVÉ de ce que la sonde
                // observe. Pour un capteur d'INSTANTANÉ, `ls` est la machine la PLUS EN RETARD du parc —
                // une seule machine encore vivante ne peut plus faire passer tout le parc pour frais.
                let ls: Option<i64> = sonde.derniere_collecte(conn);
                // VERDICT PARTAGÉ avec l'alerte (`statut_capteur`) : ces deux surfaces ne peuvent plus
                // dire deux choses différentes de la même observation. Seul le nombre de cycles
                // tolérés diffère, et il est nommé.
                let status = statut_capteur(
                    ls,
                    *interval,
                    *event_based,
                    pipe_fresh,
                    CYCLES_TOLERES_AFFICHAGE,
                    now_ts,
                )
                .label();
                // P3.2-a — LA PORTÉE EST RENDUE, PAS DEVINÉE. `status: "actif"` ne veut pas dire la même
                // chose selon que la sonde juge la machine la plus EN RETARD ou la plus FRAÎCHE du parc,
                // et cet écart n'était lisible que dans le SQL dérivé. Champ ADDITIF : dérivé du même
                // descripteur typé que la requête, donc affichage et exécution ne peuvent pas diverger.
                json!({ "id": id, "label": label, "interval_s": interval, "last_seen": ls, "status": status, "event_based": event_based, "portee": sonde.portee().etiquette() })
            })
            .collect();
        // INVENTAIRE d'hôtes = host_rollup pré-agrégé (cf. rollup_hosts) : AUCUN scan de event∪metric∪snapshot.
        let hosts = host_inventory_simple(conn);
        // P3.2-a — LE VERDICT DE FLOTTE, en COMPTE et non en série par hôte (cf. `sonde_de_flotte.rs`).
        // C'est le seul chiffre de ce panneau qui parle des machines MUETTES ; les 21 sondes à portée
        // « tous hôtes confondus » ci-dessus ne peuvent pas le dire, par construction. `None` (lecture
        // impossible) rend `null` — jamais un zéro rassurant fabriqué à la place d'une observation.
        let flotte = match flotte_muette(conn, now_ts) {
            // `muets_declares_attendus` accompagne le compte : sans lui, la carte dirait « aucun muet »
            // là où des machines muettes ont simplement été déclarées telles, ce qui est une autre
            // phrase (`P11.10-a`).
            Some(f) => json!({
                "attendus": f.attendus,
                "muets": f.muets,
                "muets_declares_attendus": f.muets_declares_attendus,
                "seuil_s": FLEET_STALE_S,
            }),
            None => Value::Null,
        };
        json!({ "collectors": collectors, "hosts": hosts, "flotte": flotte })
    })
}
/// Fraîcheur PAR SOURCE (data-driven, pas la liste figée des collecteurs) : pour chaque feed —
/// source d'event, kind de snapshot, et les métriques (agrégées) — l'âge du dernier point + un statut
/// (`statut_de_source`). La cadence ATTENDUE est celle que `COLLECTORS` DÉCLARE (`cadence_declaree`) ; le
/// rythme observé sur 24 h (86400/n_24h) est rendu à part et ne juge rien. Lecture seule (read pool + watchdog).
// SWR pour /api/freshness : la requête de fraîcheur agrège 7 JOURS d'events par source (GROUP BY + SUM
// conditionnel) -> scan LOURD sur la base chiffrée qui TOUCHE le watchdog 5 s à CHAQUE appel (mesuré ~5,1 s).
// Or la fraîcheur évolue lentement (last_seen / cadence) ET l'UI la rappelle à chaque tick d'auto-refresh
// (30 s) + au chargement (dans le Promise.all de refresh()). On la sert donc en stale-while-revalidate :
//   - HIT frais (< TTL) -> instantané ;
//   - périmé -> on sert le périmé TOUT DE SUITE + refresh ASYNC borné (refresh_sem, JAMAIS query_sem ;
//     anti-stampede : un seul refresh en vol) ;
//   - froid (1re fois / après redémarrage) -> calcul synchrone hors runtime (spawn_blocking).
// N'affecte PAS l'alerte « capteur muet » (check_heartbeats, séparé, sur son propre timer).
pub(crate) const FRESHNESS_TTL: Duration = Duration::from_secs(30);
// MT-KEY: par db_path (R3). Chaque base (tenant) a sa propre valeur SWR de fraîcheur (feeds/last_seen) ;
// jamais de partage inter-tenant. TTL/SWR inchangés. En mono-tenant : une seule entrée -> identique.
pub(crate) static FRESHNESS_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = std::sync::OnceLock::new();
// Gate anti-stampede GLOBAL (booléen, AUCUNE donnée tenant -> pas un vecteur de fuite) : borne à UN refresh
// en vol. En multi-tenant il sérialise les refresh entre tenants (staleness bornée, pas de fuite) ;
// #2a-2 pourra le clé par db_path si la contention devient sensible. En mono-tenant : comportement identique.
pub(crate) static FRESHNESS_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn freshness_map() -> &'static Mutex<HashMap<String, (Instant, Value)>> {
    FRESHNESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) async fn freshness(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    use std::sync::atomic::Ordering;
    let dbp_owned = req_db_path(&st, &au); // #2a-2b : fraîcheur de la base du tenant courant (cache keyé db_path)
    // FILTRE ENVIRONNEMENT (#2d) : la clé de cache inclut l'env (env_range_key) -> une fraîcheur env=staging
    // n'écrase pas env=prod. Mode 0 (env None) -> clé = db_path (byte-identique) -> cache inchangé.
    let env_owned = au.env_filter().map(|e| e.to_string());
    let ckey_owned = env_range_key(env_owned.as_deref(), dbp_owned.as_str());
    let ckey = ckey_owned.as_str();
    // HIT frais -> instantané.
    if let Some((t, v)) = freshness_map().lock().get(ckey) {
        if t.elapsed() < FRESHNESS_TTL {
            return Json(v.clone());
        }
    }
    // STALE présent -> SWR : sert le périmé immédiatement + déclenche un refresh async borné.
    let stale = freshness_map().lock().get(ckey).cloned();
    if let Some((_, v)) = stale {
        if !FRESHNESS_REFRESHING.swap(true, Ordering::AcqRel) {
            let db = dbp_owned.clone();
            let ck = ckey_owned.clone();
            let envc = env_owned.clone();
            let sem = st.refresh_sem.clone();
            tokio::spawn(async move {
                // try_acquire (PAS await) : lane refresh saturée -> on renonce (le périmé reste servi).
                if let Ok(_permit) = sem.try_acquire_owned() {
                    let db2 = db.clone();
                    let env2 = envc.clone();
                    if let Ok(nv) = tokio::task::spawn_blocking(move || compute_freshness(&db2, env2.as_deref())).await {
                        freshness_map().lock().insert(ck, (Instant::now(), nv)); // MT-KEY : entrée de CE (db_path, env)
                    }
                }
                FRESHNESS_REFRESHING.store(false, Ordering::Release);
            });
        }
        return Json(v);
    }
    // FROID : aucune valeur en cache (1re fois / après redémarrage du pod). On NE bloque PLUS la requête
    // ~5 s (scan 7 j chiffré) : sous une rafale de F5 cela faisait attendre TOUTES les requêtes jusqu'à 10 s.
    // À la place — exactement comme le SWR des panneaux sert « warming » à froid — on déclenche le calcul
    // en ASYNC sur la lane refresh (anti-stampede via FRESHNESS_REFRESHING : UN seul calcul en vol même
    // sous 40 appels parallèles) et on renvoie TOUT DE SUITE un payload « warming ». Les appels suivants
    // (tick 30 s du front, ou re-poll rapproché) récupèrent la valeur dès qu'elle est calculée, via le
    // chemin HIT/STALE ci-dessus. (N'affecte PAS check_heartbeats, alerte « capteur muet » séparée.)
    if !FRESHNESS_REFRESHING.swap(true, Ordering::AcqRel) {
        let db = dbp_owned.clone();
        let ck = ckey_owned.clone();
        let envc = env_owned.clone();
        let sem = st.refresh_sem.clone();
        tokio::spawn(async move {
            // try_acquire (PAS await) : lane refresh saturée -> on renonce ; un prochain appel relancera.
            if let Ok(_permit) = sem.try_acquire_owned() {
                let db2 = db.clone();
                let env2 = envc.clone();
                if let Ok(nv) = tokio::task::spawn_blocking(move || compute_freshness(&db2, env2.as_deref())).await {
                    freshness_map().lock().insert(ck, (Instant::now(), nv)); // MT-KEY : entrée de CE (db_path, env)
                }
            }
            FRESHNESS_REFRESHING.store(false, Ordering::Release);
        });
    }
    // payload « warming » non bloquant : feeds vides + flag -> l'UI affiche un placeholder « … » et re-poll.
    Json(json!({ "warming": true, "feeds": [], "ts": now() }))
}

/// Extrait les valeurs `source=<x>` d'une requête de règle (stockée dans alert.detail par
/// run_due_rules). Gère la forme GXQL `source=foo` ET la forme SQL `source='foo'` / `source="foo"`.
/// Tolérant : token lu jusqu'au prochain séparateur (espace/tab/newline/pipe ou guillemet fermant).
///
/// S7 — CE N'EST PLUS LA VOIE PRINCIPALE, ET IL EST IMPORTANT DE SAVOIR POURQUOI ELLE RESTE. Cette
/// fonction lit de la PROSE : elle ne peut nommer que ce que l'auteur de la règle a bien voulu écrire,
/// donc elle est aveugle à toute règle volontairement générique — c'est le défaut S7. L'imputation
/// principale vient désormais de la DONNÉE (`daemon/src/imputation.rs`, colonne `alert.sources`).
/// Cette voie-ci garde DEUX emplois, tous deux réels : (1) les alertes levées AVANT la migration v115,
/// dont la colonne est vide — les effacer d'un revers ferait disparaître des pastilles aujourd'hui
/// justes ; (2) les règles en SQL BRUT, opaques au compilateur GXQL, où `source='cloudflare'` reste la
/// seule chose de lisible. C'est aussi le repli en dernier ressort de l'imputation elle-même.
pub(crate) fn extract_query_sources(detail: &str) -> Vec<String> {
    let bytes = detail.as_bytes();
    let needle = b"source=";
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            let quote = if j < bytes.len() && (bytes[j] == b'\'' || bytes[j] == b'"') {
                let q = bytes[j]; j += 1; Some(q)
            } else { None };
            let start = j;
            while j < bytes.len() {
                let c = bytes[j];
                let stop = match quote { Some(qc) => c == qc, None => matches!(c, b' ' | b'\t' | b'\n' | b'|') };
                if stop { break; }
                j += 1;
            }
            if j > start {
                // from_utf8_lossy : ne panique jamais sur une frontière non-UTF8 (sources = ASCII en pratique).
                out.push(String::from_utf8_lossy(&bytes[start..j]).into_owned());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

// ====================================================================================================
// `P10.7-f` — CE QUI, DANS UN RELEVÉ DE FRAÎCHEUR, N'EST PAS ALLÉ AU BOUT.
//
// POURQUOI CETTE ROUTE-CI EST LA PIRE DE LA FAMILLE. Sa closure porte QUINZE énoncés et balaie les
// DEUX grandes tables : `MAX(ts) FROM event` pour la santé du pipeline, et `alert WHERE status='new'`
// en entier pour l'imputation. C'est aussi la seule dont un même corps servi est alimenté par
// PLUSIEURS énoncés indépendants.
//
// ET C'EST EXACTEMENT LÀ QUE LA MESURE DU 2026-08-30 MORD : une interruption ne porte que sur
// l'énoncé EN VOL. Dans cette closure, la coupe peut donc tronquer les flux d'événements pendant que
// les instantanés et les métriques sont COMPLETS — la forme la plus indiscernable qui soit. D'où la
// forme de l'aveu : il NOMME ce qui est incomplet au lieu de condamner la réponse entière, et il
// n'existe pas du tout quand tous les parcours sont allés au bout. « La garde a tiré » n'est pas
// « une liste a été tronquée » : rien ici ne regarde l'armement de la garde, seulement l'erreur que
// le parcours VOIT.
//
// DEUX SURFACES SÉPARÉES, DEUX AVEUX. `feeds` est une LISTE (des flux manquent) ; `imputation_des_alertes`
// est un jeu de COMPTES qui doivent se retrouver entre eux (`actives = avec_cloche + sans_source_nommee
// + sans_imputation`). Un compte tronqué ne raccourcit rien : il rend une somme qui a l'air juste et
// qui porte sur moins d'alertes qu'il n'y en a. Son aveu vit DANS l'objet concerné, pour qu'un
// consommateur qui ne lit que ce sous-objet ne soit pas trompé — et il est REPRIS à la racine, parce
// que c'est `error` à la racine que la console teste.
// ====================================================================================================

/// La phrase servie quand un ou plusieurs parcours de ce corps se sont arrêtés en route.
pub(crate) const CAUSE_FRAICHEUR_INCOMPLETE: &str = "RELEVÉ DE FRAÎCHEUR INCOMPLET : un ou plusieurs \
     parcours de lignes ne sont pas allés au bout. Ce qui est nommé ci-dessous est un PRÉFIXE ou un \
     SOUS-COMPTE, pas la mesure — un flux absent de `feeds` n'est PAS un flux qui ne remonte plus, et \
     un compte pris ici ne porte pas sur tout. Combien il en manque n'est pas connu. Incomplet : ";

/// La phrase servie DANS `imputation_des_alertes` quand c'est ce parcours-là qui a été coupé.
pub(crate) const CAUSE_IMPUTATION_NON_ETABLIE: &str = "PARTAGE DES ALERTES NON ÉTABLI : le parcours \
     des alertes actives ne s'est pas achevé. Les quatre nombres se retrouvent encore entre eux, mais \
     ils portent sur MOINS d'alertes qu'il n'y en a d'actives — et les cloches par source qui en \
     dérivent sont des sous-comptes. Cause : ";

/// Le nom sous lequel le parcours des alertes actives est noté (et retrouvé pour l'aveu imbriqué).
const PARCOURS_IMPUTATION: &str = "le partage des alertes actives";

/// `P10.7-f` — LE RELEVÉ DES PARCOURS DE CE CORPS QUI NE SONT PAS ALLÉS AU BOUT.
///
/// Rien n'y entre sur un parcours complet : `FinDeParcours::cause()` est la seule porte, et c'est ce
/// qui empêche un aveu INCONDITIONNEL — un corps qui avoue toujours n'avoue rien.
#[derive(Default)]
pub(crate) struct ParcoursDeFraicheur {
    manquants: Vec<(&'static str, String)>,
}
impl ParcoursDeFraicheur {
    /// Note ce qu'un parcours alimentait, et la cause du moteur telle qu'il l'a dite. Ne note RIEN
    /// quand le parcours est allé au bout.
    pub(crate) fn noter(&mut self, quoi: &'static str, fin: &FinDeParcours) {
        if let Some(cause) = fin.cause() {
            self.manquants.push((quoi, cause.to_string()));
        }
    }
    /// La phrase de racine, ou `None` si tout est allé au bout.
    pub(crate) fn aveu(&self) -> Option<String> {
        if self.manquants.is_empty() {
            return None;
        }
        let liste: Vec<String> = self.manquants.iter().map(|(quoi, cause)| format!("{quoi} ({cause})")).collect();
        Some(format!("{CAUSE_FRAICHEUR_INCOMPLETE}{}", liste.join(" ; ")))
    }
    /// La cause du seul parcours de l'imputation, s'il a été coupé.
    pub(crate) fn cause_de_l_imputation(&self) -> Option<&str> {
        self.manquants.iter().find(|(quoi, _)| *quoi == PARCOURS_IMPUTATION).map(|(_, c)| c.as_str())
    }
}

/// LE PARTAGE DES ALERTES ACTIVES PAR SOURCE — les quatre familles de `P11.3-d` et les cloches par
/// feed, lues en UN parcours de `alert WHERE status='new'`.
///
/// EXTRAITE DU CORPS DE `compute_freshness` PAR `P10.7-f`, et pour une raison qui n'est pas
/// esthétique : c'est LE parcours de cette route que la charge peut couper (la table `alert` en
/// entier, sans borne de fenêtre), et tant qu'il vivait au milieu d'une closure passée à
/// `read_with_watchdog` AUCUN témoin ne pouvait lui présenter une interruption. Isolée sur
/// `&Connection`, elle se joue — coupe comprise — sans monter le routeur.
pub(crate) struct ImputationDesAlertes {
    /// source -> nb d'alertes actives qui lui sont imputées (la cloche d'un feed).
    pub(crate) par_source: std::collections::HashMap<String, i64>,
    pub(crate) actives: i64,
    pub(crate) avec_cloche: i64,
    pub(crate) sans_source_nommee: i64,
    pub(crate) sans_imputation: i64,
}

/// Lit le partage, et DIT si le parcours est allé au bout.
///
/// PARCOURS EN FLUX, ET C'EST UNE CONTRAINTE MESURÉE, PAS UN GOÛT : `parcourir` matérialiserait le
/// `detail` COMPLET de toutes les alertes actives avant la première itération, sur une base qui doit
/// tenir dans 2 Go. `parcourir_chaque` garde le flux ligne à ligne de l'idiome précédent et n'ajoute
/// en mémoire qu'une cause. Les quatre familles se retrouvent toujours entre elles
/// (`actives = avec_cloche + sans_source_nommee + sans_imputation`) — sur un parcours COUPÉ aussi,
/// mais alors elles portent sur moins d'alertes qu'il n'y en a, et c'est la fin de parcours qui le dit.
pub(crate) fn lire_l_imputation_des_alertes(conn: &Connection, envp: &str) -> (ImputationDesAlertes, FinDeParcours) {
    let mut out = ImputationDesAlertes {
        par_source: std::collections::HashMap::new(),
        actives: 0,
        avec_cloche: 0,
        sans_source_nommee: 0,
        sans_imputation: 0,
    };
    let avec_colonne = format!("SELECT COALESCE(sources,''), COALESCE(detail,'') FROM alert WHERE status='new'{envp}");
    let sans_colonne = format!("SELECT '', COALESCE(detail,'') FROM alert WHERE status='new'{envp}");
    let fin = match conn.prepare(&avec_colonne).or_else(|_| conn.prepare(&sans_colonne)) {
        Ok(mut s) => match s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            Ok(rows) => parcourir_chaque(rows, |(srcs, d): (String, String)| {
                out.actives += 1;
                let imputees = if srcs.is_empty() { extract_query_sources(&d) } else { imputation_decoder(&srcs) };
                let (mut portee, mut nomme_l_inconnu) = (false, false);
                for src in imputees {
                    if src == SOURCE_INDETERMINABLE {
                        nomme_l_inconnu = true;
                    } else {
                        *out.par_source.entry(src).or_insert(0) += 1;
                        portee = true;
                    }
                }
                if portee {
                    out.avec_cloche += 1;
                } else if nomme_l_inconnu {
                    out.sans_source_nommee += 1;
                } else {
                    out.sans_imputation += 1;
                }
            }),
            Err(e) => FinDeParcours::NonCommence { cause: e.to_string() },
        },
        // LES DEUX ÉNONCÉS ONT ÉTÉ REFUSÉS : ce n'est pas « aucune alerte active », c'est une lecture
        // qui n'a pas eu lieu (`P10.7-e`). Les quatre nombres restent à zéro et la fin le DIT.
        Err(e) => FinDeParcours::NonCommence { cause: e.to_string() },
    };
    (out, fin)
}

/// Calcul (LOURD, borné par read_with_watchdog 5 s) de la fraîcheur des sources. Mis en cache SWR par
/// le handler `freshness` ci-dessus — ne PAS appeler directement depuis le chemin requête.
pub(crate) fn compute_freshness(db_path: &str, env: Option<&str>) -> Value {
    let now_ts = now();
    // FILTRE ENVIRONNEMENT (#2d) : None (mode 0 / all) -> prédicats VIDES -> SQL byte-identique (cache
    // tous-env inchangé). Some("<env>") -> chaque feed est filtré `env_id='<env>'` (event_rollup/snapshot/
    // metric portent env_id v66/v67). Valeur validée (env_slug_ok) + échappée (soql_esc) -> anti-injection.
    let envp = env_and_pred(env);
    let wenv = env_where_pred(env);
    read_with_watchdog(db_path, json!({ "feeds": [], "ts": now_ts }), move |conn| {
        let d1 = now_ts - 86400;        // fenêtre 24h -> estimation de cadence
        let cut7 = now_ts - FENETRE_INVENTAIRE_S; // ne liste que les feeds vus dans la fenêtre de l'inventaire
        let mut feeds: Vec<Value> = Vec::new();
        // `P10.7-f` — CE QUI, DANS CE CORPS, NE SERA PAS ALLÉ AU BOUT. Vide sur le chemin nominal.
        let mut releve = ParcoursDeFraicheur::default();
        // SANTÉ DU PIPELINE : la donnée la PLUS récente, TOUTES sources confondues. Tant qu'au moins une
        // source arrive (<10 min), l'ingestion fonctionne. Si même la plus fraîche est vieille -> ingestion
        // en panne (réseau / corruption / collecte arrêtée) = le SEUL cas où on alerte ("muet"). Sinon l'âge
        // d'une source ne reflète QUE son activité (normal qu'une source rare soit "vieille") -> jamais "retard".
        let global_last: Option<i64> = conn.query_row(
            &format!("SELECT MAX(m) FROM (SELECT MAX(ts) m FROM event{wenv} UNION ALL SELECT MAX(ts) FROM metric{wenv} UNION ALL SELECT MAX(ts) FROM snapshot{wenv})"),
            [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
        let pipeline_fresh = global_last.map(|m| now_ts - m < 600).unwrap_or(false);
        // ALERTES ACTIVES (status='new') imputées à chaque SOURCE, pour que le front surligne les feeds
        // « chauds » — et, surtout, pour que la pastille de la source FAUTIVE bascule.
        //
        // S7 — D'OÙ VIENT LE NOM DE LA SOURCE. De `alert.sources` (migration v115), ÉCRIT au moment où
        // l'alerte a été levée et DÉRIVÉ DE LA DONNÉE (colonne `source` des événements appariés ;
        // descripteur typé de la sonde pour un capteur muet). Le lecteur ne devine plus rien : c'est le
        // producteur, qui a la donnée sous la main, qui a répondu — cf. daemon/src/imputation.rs.
        //
        // REPLI TEXTUEL, CONSERVÉ ET BORNÉ : `sources` VIDE signifie « alerte antérieure à la migration ».
        // Pour celles-là, on relit les jetons `source=<x>` du texte de la règle recopié dans `detail`
        // (`extract_query_sources`) — comportement byte-identique à l'historique. Aucune alerte NEUVE ne
        // passe par là : le producteur écrit toujours au moins l'inconnu NOMMÉ.
        //
        // L'INCONNU NOMMÉ NE VOTE POUR PERSONNE. `SOURCE_INDETERMINABLE` ne correspond au nom d'aucun feed :
        // il est compté à part et RESSORT dans la charge utile (`imputation_des_alertes`), au lieu d'être un
        // zéro muet réparti sur tout le monde ou une imputation prise au hasard.
        //
        // BASE NON MIGRÉE : la colonne n'existe pas -> le `prepare` échoue. On NE tombe PAS à zéro (ce
        // serait perdre en silence un surlignage qui marchait avant) : on rejoue l'énoncé HISTORIQUE,
        // qui ne lit que `detail`. Un seul décodeur pour les deux chemins -> aucune sémantique en double.
        //
        // P11.3-d — LES TROIS FAMILLES, ET LE TOTAL QUI SE RETROUVE. La charge utile n'en nommait que
        // deux (la cloche d'un feed, le compte d'orphelines) ; MESURÉ le 2026-08-23 sur trois alertes
        // actives, UNE n'était comptée nulle part — colonne `sources` vide (huit producteurs sur douze la
        // laissent ainsi) ET aucun jeton `source=` dans son texte. Un lecteur ne pouvait donc pas vérifier
        // que la somme fait le tout, et la phrase de la console laissait croire à un trou de collecte là
        // où il n'y a qu'une alerte qui ne parle pas d'un flux. Les familles sont comptées PAR ALERTE
        // (une alerte imputée à trois feeds compte une fois ici, et trois fois dans les cloches) :
        //   - `avec_cloche`          : au moins un feed la porte ;
        //   - `sans_source_nommee`   : elle DIT qu'elle ne sait pas nommer sa source (inconnu NOMMÉ) —
        //                              une alerte d'hôte, de règle ou de seuil n'a pas de flux, c'est
        //                              normal et ce n'est pas un défaut de collecte ;
        //   - `sans_imputation`      : rien d'enregistré et rien de lisible dans son texte (alerte levée
        //                              avant l'imputation, ou producteur qui ne l'écrit pas). Le compte
        //                              par source l'ignore — et il faut le DIRE, pas la faire disparaître.
        let (imputation, fin_imputation) = lire_l_imputation_des_alertes(conn, &envp);
        let alert_counts = imputation.par_source;
        let (actives, avec_cloche, sans_source_nommee, sans_imputation) =
            (imputation.actives, imputation.avec_cloche, imputation.sans_source_nommee, imputation.sans_imputation);
        releve.noter(PARCOURS_IMPUTATION, &fin_imputation);
        // CE QUE L'EXPLOITANT A DÉCLARÉ, lu UNE fois (P11.3-c). N'est appliqué qu'aux feeds `event` : la
        // clé de `source_settings` est un nom de SOURCE, et un `kind` d'instantané qui porterait le même
        // nom n'est pas la même chose — appliquer la déclaration aux deux ferait mentir l'une des deux.
        let declarations = crate::handlers::sources::marquages_de_sources(conn);
        let mk = |kind: &str, name: String, last: i64, n24: i64| -> Value {
            let age = now_ts - last;
            // CADENCE DÉCLARÉE — par la sonde de COLLECTORS, sinon par l'exploitant -> STATUT (cf. bandeau
            // `statut_de_source`). Le rythme observé (86400 / n_24h) est rendu à part, sous son vrai nom :
            // il n'est pas une attente.
            let cadence = if kind == "event" {
                cadence_du_feed(kind, &name, declarations.get(&name).and_then(|m| m.cadence.as_ref()))
            } else {
                cadence_declaree(kind, &name)
            };
            let status = statut_de_source(age, pipeline_fresh, Some(&cadence));
            // active_alerts : nb d'alertes 'new' imputées à `name` (0 si aucune / feed non corrélable comme les
            // snapshots/métriques). Un COMPTE à côté du statut, jamais un statut. Calculé avant le move de `name`.
            let active_alerts = alert_counts.get(&name).copied().unwrap_or(0);
            let mut f = json!({ "kind": kind, "name": name, "last_seen": last, "age_s": age, "n_24h": n24, "status": status, "active_alerts": active_alerts });
            if let (Some(o), Value::Object(c)) = (f.as_object_mut(), cadence_json(&cadence, n24)) {
                o.extend(c);
            }
            f
        };
        // SOURCE = event_rollup pré-agrégé (~ms ; mêmes colonnes que les panneaux : source, bucket horaire, n)
        // au lieu d'un scan 7 j de `event` chiffré (~14,6 s -> tué par le watchdog 5 s, qui faisait disparaître
        // TOUS les feeds event de /api/freshness). n24 = somme des n sur les buckets < 24 h. HAVING SUM(n)>=3 :
        // écarte les artefacts one-shot (selftest, mtls-test… 1 event) -> pas de faux muet permanent.
        // ?1 = cut 24 h (d1), ?2 = cut 7 j (cut7).
        // FRAÎCHEUR RÉELLE — last = MAX(last_ts) : le VRAI horodatage du dernier event, matérialisé PAR LE
        // ROLLUP lui-même (rollup_events écrit MAX(ts) AS last_ts à chaque ré-agrégation de la fenêtre chaude
        // = heure courante+précédente, toutes les ~120 s ; migration v64). Une source CONTINUE a donc un âge
        // de quelques SECONDES (le vrai dernier event), PAS le plancher horaire MAX(bucket) qui dérivait
        // 0->59 min puis « rajeunissait » au changement d'heure. COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)) :
        // fallback sur le plancher horaire pour une source dont les buckets sont TOUS encore à 0 (anciens, pas
        // ré-agrégés depuis la migration) — jamais reforcée à « frais ». Lecture sur la PETITE table rollup
        // (qq ms, bien dans le budget 5 s) : AUCUN scan de `event`. (L'ancien correctif `SELECT source,MAX(ts)
        // FROM event WHERE ts>=now-3600 GROUP BY source` full-scannait les 3,9 M lignes chiffrées en ~21 s
        // faute d'index (source,ts) -> tué par le watchdog -> map vide -> retombait sur le plancher : RETIRÉ.)
        if let Ok(mut s) = conn.prepare(&format!("SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) FROM event_rollup WHERE bucket>=?2 AND source<>''{envp} GROUP BY source HAVING SUM(n)>=3")) {
            let fin = match s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                Ok(rows) => parcourir_chaque(rows, |(src, last, n): (String, i64, i64)| {
                    feeds.push(mk("event", src, last, n));
                }),
                Err(e) => FinDeParcours::NonCommence { cause: e.to_string() },
            };
            releve.noter("les flux d'événements", &fin);
        }
        // INSTANTANÉS — un feed par `kind`, mais dont la FRAÎCHEUR est celle de la machine la PLUS EN
        // RETARD (`MIN` sur les `MAX(ts)` par hôte), même dérivation que `Sonde::Instantane`. Avant :
        // `MAX(ts) … GROUP BY kind` = la machine la plus FRAÎCHE -> mesuré le 2026-08-02, un parc de 50
        // dont 49 muettes depuis 2 h affichait UN feed « frais ». Le volume (`n_24h`) est INCHANGÉ (somme
        // sur les hôtes) et `n_hosts` donne le dénominateur. Mono-hôte : un seul groupe -> valeurs
        // STRICTEMENT identiques à l'ancienne requête.
        if let Ok(mut s) = conn.prepare(&format!(
            "SELECT kind, MIN(l), SUM(nn), COUNT(*) FROM (\
               SELECT kind, host, MAX(ts) AS l, SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) AS nn \
               FROM snapshot WHERE ts>?2{envp} GROUP BY kind, host) GROUP BY kind"
        )) {
            let fin = match s.query_map(params![d1, cut7], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
            }) {
                Ok(rows) => parcourir_chaque(rows, |(k, m, n, nh): (String, i64, i64, i64)| {
                    let mut f = mk("snapshot", k, m, n);
                    if let Some(o) = f.as_object_mut() { o.insert("n_hosts".into(), json!(nh)); }
                    feeds.push(f);
                }),
                Err(e) => FinDeParcours::NonCommence { cause: e.to_string() },
            };
            releve.noter("les flux d'instantanés", &fin);
        }
        // métriques : un feed agrégé (remote-write) + DÉTAIL par série (déplié dans l'UI sur clic)
        let mlast: Option<i64> = conn.query_row(&format!("SELECT MAX(ts) FROM metric WHERE ts>?1{envp}"), params![cut7], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
        if let Some(m) = mlast {
            let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM metric WHERE ts>?1{envp}"), params![d1], |r| r.get(0)).unwrap_or(0);
            let series: i64 = conn.query_row(&format!("SELECT COUNT(DISTINCT name) FROM metric WHERE ts>?1{envp}"), params![d1], |r| r.get(0)).unwrap_or(0);
            // liste des séries (nom + dernière donnée + statut) -> l'UI les déplie sous le feed agrégé.
            let mut series_list: Vec<Value> = Vec::new();
            if let Ok(mut s) = conn.prepare(&format!("SELECT name, MAX(ts), SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) FROM metric WHERE ts>?2{envp} GROUP BY name ORDER BY name")) {
                let fin = match s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                    Ok(rows) => parcourir_chaque(rows, |(nm, ls, n24): (String, i64, i64)| {
                        let age = now_ts - ls;
                        let st = statut_de_source(age, pipeline_fresh, None);
                        series_list.push(json!({ "name": nm, "last_seen": ls, "age_s": age, "n_24h": n24, "status": st }));
                    }),
                    Err(e) => FinDeParcours::NonCommence { cause: e.to_string() },
                };
                releve.noter("les séries de métriques", &fin);
            }
            let mut mf = mk("metric", format!("métriques · {series} séries"), m, n);
            if let Some(o) = mf.as_object_mut() { o.insert("series".into(), json!(series_list)); }
            feeds.push(mf);
        }
        // S7 + P11.3-d — LE PARTAGE DES ALERTES ACTIVES, publié MÊME À ZÉRO : une surface qui n'affiche un
        // compteur que lorsqu'il est non nul ne permet pas de distinguer « rien à signaler » de « ce
        // compteur n'existe pas ». Les quatre nombres se retrouvent (`actives = avec_cloche +
        // sans_source_nommee + sans_imputation`), et c'est ce qui permet au lecteur de vérifier qu'aucune
        // alerte ne s'est perdue en route. `jeton_sans_source` publie le nom EXACT de l'inconnu nommé pour
        // que la console puisse pivoter dessus sans le réécrire en dur.
        let mut corps = json!({
            "feeds": feeds,
            "ts": now_ts,
            "pipeline_fresh": pipeline_fresh,
            "imputation_des_alertes": {
                "actives": actives,
                "avec_cloche": avec_cloche,
                "sans_source_nommee": sans_source_nommee,
                "sans_imputation": sans_imputation,
                "jeton_sans_source": SOURCE_INDETERMINABLE,
            },
        });
        // `P10.7-f` — L'AVEU EST PORTÉ PAR CE QUI EST INCOMPLET. Celui de l'imputation vit DANS son
        // objet (un consommateur qui ne lit que ce sous-objet n'est pas trompé) ; celui de la racine
        // les NOMME tous, parce que c'est `error` à la racine que la console teste. Les deux sont
        // strictement conditionnels : sur un parcours complet, ce corps est byte-identique à celui
        // d'avant cette clé.
        if let Some(cause) = releve.cause_de_l_imputation() {
            corps["imputation_des_alertes"]["error"] = json!(format!("{CAUSE_IMPUTATION_NON_ETABLIE}{cause}"));
        }
        if let Some(phrase) = releve.aveu() {
            corps["error"] = json!(phrase);
        }
        corps
    })
}

/// Alerte si un capteur ayant DÉJÀ remonté devient muet (> 5x son intervalle) = angle mort.
/// REND SON BILAN (`P4.1-r`) : les sondes de capteurs lisent chacune un horodatage et rendent un verdict
/// (`Inconnu` compris) — elles n'abandonnent rien ; c'est le dead-man's-switch du PARC qui peut se
/// retrouver aveugle, et son bilan est celui de cette fonction.
pub(crate) fn check_heartbeats(db: &Arc<Mutex<Connection>>) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let conn = db.lock();
    // FIX #2 — pour un capteur ÉVÉNEMENTIEL (auth), le « muet » NE se juge PAS sur son propre intervalle
    // (un hôte sans login serait un faux MUET permanent) mais sur la SANTÉ DU PIPELINE global : tant que la
    // donnée la plus récente, toutes sources confondues, est fraîche, l'auth n'est PAS muette (silence
    // normal). Les capteurs CONTINUS gardent leur logique 5x-intervalle (vraies alertes muet préservées).
    let pipe_fresh = pipeline_is_fresh(&conn, now_ts);
    for (id, label, interval, sonde, event_based) in COLLECTORS.iter() {
        let ls: Option<i64> = sonde.derniere_collecte(&conn);
        let dedup = format!("hb-{id}"); // clé STABLE -> une seule alerte par épisode (zéro répétition horaire)
        // MUET ? Le MÊME verdict que celui affiché par le panneau (cf. `statut_capteur`), à ceci près
        // qu'on réveille quelqu'un deux cycles plus tard. `Inconnu` (jamais rien vu) n'alerte JAMAIS :
        // c'était le défaut mesuré le 2026-08-02 (8 alertes « capteur muet » sur des capteurs jamais
        // installés, pendant que le panneau les affichait « en attente »).
        let mute = statut_capteur(ls, *interval, *event_based, pipe_fresh, CYCLES_TOLERES_ALERTE, now_ts)
            .alerte();
        if mute {
            // détail : ancienneté de CE capteur si connue, sinon état du pipeline (cas événementiel sans
            // historique). Sévérité 2 inchangée.
            // `None` est désormais INATTEIGNABLE ici : `Inconnu` n'alerte plus (un capteur jamais vu
            // n'a pas de silence à constater), donc `mute` implique `ls.is_some()`. On garde le bras
            // comme filet — il ne doit plus jamais s'imprimer, et s'il s'imprime c'est que la règle
            // a été réécrite ailleurs.
            let mut detail = match ls {
                Some(t) => format!("aucune donnée depuis {} min", (now_ts - t) / 60),
                None => "pipeline d'ingestion muet (cas devenu inatteignable)".to_string(),
            };
            // QUELLES MACHINES. Sur un parc, « Capteur muet : firewall » sans nom n'est pas actionnable :
            // l'opérateur ne sait pas s'il s'agit d'une machine ou de quarante-neuf. Les sondes d'INSTANTANÉ
            // savent le dire (la série est (kind, hôte)) -> on nomme les 5 plus en retard + le reste compté.
            // Vide pour les sondes à portée flotte confondue -> détail INCHANGÉ (mode 0 byte-identique).
            // MÊME seuil que le verdict (`CYCLES_TOLERES_ALERTE`) : un littéral ici se serait mis à
            // diverger en silence du jour où quelqu'un touche la constante — la liste des machines
            // « en retard » ne correspondrait plus à ce qui a déclenché l'alerte.
            let retard = sonde.hotes_en_retard(&conn, now_ts - interval * CYCLES_TOLERES_ALERTE, 6);
            if !retard.is_empty() {
                let noms: Vec<String> = retard.iter().take(5)
                    .map(|(h, t)| format!("{} ({} min)", if h.is_empty() { "(sans hôte)" } else { h }, (now_ts - t) / 60))
                    .collect();
                detail.push_str(&format!(
                    " — machines en retard : {}{}",
                    noms.join(", "),
                    if retard.len() > 5 { ", …" } else { "" }
                ));
            }
            // S7 — QUELLE SOURCE, ET PAS « UNE » SOURCE. L'imputation vient du DESCRIPTEUR DE LA SONDE
            // (`Sonde::EventFlux { sources }`, `Sonde::Instantane { kind }`…), c'est-à-dire de la même
            // donnée typée dont la requête de fraîcheur est dérivée — jamais du libellé `label`, qui est
            // de la prose (« journald (auth) »). C'est ce qui fait basculer la pastille de CETTE source
            // dans /api/freshness : le `detail` de cette alerte ne porte aucun jeton `source=`, donc
            // l'extraction textuelle historique n'imputait RIEN pour AUCUN des 23 capteurs.
            let sources = imputation_encoder(&imputer_alerte_de_capteur(sonde));
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,sources) VALUES(?1,?2,2,?3,?4,?5,?6)",
                params![now_ts, format!("heartbeat.{id}"), format!("Capteur muet : {label}"), detail, dedup, sources],
            );
            // Épisode DÉJÀ ouvert (l'INSERT ci-dessus est un no-op) : l'imputation est tout de même
            // rafraîchie, pour la même raison que côté règles — la liste des sources d'un capteur peut
            // changer entre deux versions du binaire, et une pastille ne doit pas rester accrochée à
            // une imputation périmée pour toute la durée de l'épisode.
            let _ = conn.execute(
                "UPDATE alert SET sources=?1 WHERE dedup=?2 AND status IN ('new','ack')",
                params![sources, dedup],
            );
        } else {
            // capteur de nouveau actif (ou jamais vu / pipeline frais) -> résout l'alerte ouverte et libère la clé
            let _ = conn.execute(
                "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                params![dedup],
            );
        }
    }
    // P9.8-a — LE MAGASIN DE SECRETS rejoint le MÊME tick, la MÊME famille d'alertes et le MÊME
    // verrou que les deux dead-man's-switches ci-dessus, parce qu'il est le même genre de fait : un
    // approvisionnement arrêté est un angle mort qui se présente comme un état normal. Les deux
    // bilans sont ABSORBÉS plutôt que l'un rendu à la place de l'autre — sans quoi une famille
    // aveugle serait masquée par une famille lisible, et le tick passerait pour calme.
    let mut b = crate::bilan_de_tick::BilanDuPlanificateur::default();
    b.absorber(verifier_flotte_muette(&conn, now_ts));
    b.absorber(crate::sonde_du_magasin_de_secrets::verifier_le_magasin_de_secrets(&conn, now_ts));
    b.bilan_de_tick()
}

/// P3.2-a — LE DEAD-MAN'S-SWITCH DU PARC : un hôte qui se tait ENTIÈREMENT lève un signal.
///
/// POURQUOI ICI ET PAS DANS LA BOUCLE CI-DESSUS. Les 23 entrées de `COLLECTORS` répondent « ce CAPTEUR
/// parle-t-il ? » ; aucune ne peut répondre « ce PARC parle-t-il ? », parce que 21 d'entre elles ont une
/// portée « tous hôtes confondus » et que les 2 autres ne voient que `snapshot`. Une 24ᵉ entrée aurait
/// donc menti sur ce qu'elle est. C'est une sonde à part, de portée `ParHote`, et elle le DIT.
///
/// UN ÉPISODE PAR ENSEMBLE MUET, ET UN SEUL OUVERT. La clé de déduplication porte l'EMPREINTE de
/// l'ensemble : tant qu'il ne bouge pas, rien ne se répète ; dès qu'une machine s'y ajoute, l'épisode
/// précédent est RÉSOLU et un neuf s'ouvre. Sans ça, la première machine décommissionnée — que
/// `host_rollup` garde muette pour toujours, cette table n'étant jamais prunée — laisserait une alerte
/// ouverte qui avalerait en silence la mort de toutes les suivantes.
fn verifier_flotte_muette(conn: &Connection, now_ts: i64) -> crate::bilan_de_tick::BilanDeTick {
    // `None` = la lecture a ÉCHOUÉ. On ne lève rien ET on ne résout rien : résoudre serait affirmer un
    // parc sain qu'on n'a pas observé, ce qui est exactement le défaut que ce chantier ferme. Et on le
    // DIT (`P4.1-r`) : un dead-man's-switch qui ne sait plus lire le parc est lui-même un signal — sans
    // cet aveu, il s'éteignait en silence et la santé « détection » restait verte.
    let Some(f) = flotte_muette(conn, now_ts) else {
        return crate::mesure_environnement::Mesure::Illisible {
            cause: crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE,
            detail: "flotte muette : `host_rollup` illisible (ou une ligne indécodable) — le parc n'a pas été observé ce tick".to_string(),
        };
    };
    let ouverte = f.cle_dedup();
    // RÉSOLUTION de tout épisode de la famille qui n'est PAS l'ensemble courant. Couvre les deux cas
    // d'un seul geste : plus aucun hôte muet (`ouverte` = None -> tout est résolu), et ensemble CHANGÉ.
    let _ = conn.execute(
        "UPDATE alert SET status='resolved', dedup=NULL \
         WHERE dedup LIKE ?1 || '%' AND dedup IS NOT ?2 AND status IN ('new','ack')",
        params![DEDUP_FLOTTE_MUETTE, ouverte],
    );
    // Aucun hôte muet : rien à ouvrir, et c'est un VRAI zéro — le parc a été LU. C'est un fait du parc
    // (`muets == 0`), testé comme tel ; `cle_dedup` n'est `None` que dans ce cas-là.
    if f.muets == 0 {
        return crate::mesure_environnement::Mesure::Lue(0);
    }
    // `Some` par construction dès que `muets > 0` ; un invariant rompu PANIQUE ici, et le planificateur
    // compte la panique comme un tick aveugle — jamais une clé vide posée en silence.
    let dedup = ouverte.expect("cle_dedup rend Some dès que muets > 0");
    // Le TITRE ne porte que des NOMBRES (il remonte dans le bulletin de support, cf. `system.rs`, qui
    // sélectionne `rule LIKE 'heartbeat.%'`) ; les NOMS de machines vivent dans le détail, qui n'y va pas.
    // `sources` = l'INCONNU NOMMÉ : cette alerte se rapporte à des HÔTES, pas à un feed — lui imputer une
    // source ferait basculer la pastille d'une source qui n'a rien fait, et la colonne VIDE la ferait
    // retomber en silence sur l'extraction textuelle (cf. `imputation.rs`).
    let sources = imputation_encoder(&[SOURCE_INDETERMINABLE.to_string()]);
    let _ = conn.execute(
        "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,sources) VALUES(?1,?2,2,?3,?4,?5,?6)",
        params![
            now_ts,
            "heartbeat.flotte-hotes-muets",
            format!("Hôtes muets : {} sur {}", f.muets, f.attendus),
            detail_flotte_muette(&f, now_ts),
            dedup,
            sources
        ],
    );
    crate::mesure_environnement::Mesure::Lue(0)
}
