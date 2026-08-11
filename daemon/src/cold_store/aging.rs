//! cold_store::aging — la MACHINE À ÉTATS DEUX PHASES de l'aging (hot -> cold) + la MATH de rétention + les
//! dead-man's-switches. C'est le pilote de `cold_age_run` (appelé depuis `retention_run`).
//!
//! TAIL GUARD (H1 — anti-réutilisation de rowid) : `event.id` est un `INTEGER PRIMARY KEY` SANS AUTOINCREMENT ->
//! le compteur de rowid = `MAX(id)` de la table et peut REDESCENDRE quand la ligne détenant ce max est supprimée
//! (un insert ultérieur réutilise alors un id <= ancien max). Comme le DELETE d'aging borne `id<=max_id`, ager le
//! jour qui DÉTIENT le tail global ferait chuter le compteur pendant SA propre suppression (verrou relâché entre
//! lots, FIX #3) -> un insert backdaté concurrent pourrait réutiliser un id<=max_id, tomber dans ce jour et être
//! supprimé SANS archive. On capture donc AUSSI `table_max=MAX(id)` (toute la table) au snapshot et on DIFFÈRE
//! l'aging d'un (env_id, day) tant que `max_id==table_max` ; on ne l'âge que quand `table_max>max_id` (une ligne
//! d'id supérieur subsiste AILLEURS — jour plus récent ou event de contrôle NONPURGE — et épingle le compteur
//! au-dessus de max_id pendant tout le DELETE). Différer est SANS PERTE (même philosophie que les stragglers) : le
//! jour reste HOT/interrogeable, agé dès qu'une donnée plus récente tiendra le tail. Cas « ingest arrêté
//! DÉFINITIVEMENT » : le dernier jour ne verra jamais de successeur -> jamais columnarisé, reste hot jusqu'au
//! hard-purge -> AUCUNE perte, seulement pas de tier froid pour ce résidu (compromis P1 accepté ; l'alternative
//! = `event.id` AUTOINCREMENT, migration lourde du schéma cœur touchant TOUS les déploiements, HORS périmètre).
//!
//! IMMUTABILITÉ COLD vs REPARSE (H2) : une donnée agée est IMMUABLE (columnarisée). Le reparse/backfill admin
//! (handlers::detection::parser_reparse) CLAMPE donc sa borne basse à `hot_cutoff` quand le tier cold est ON
//! (via `reparse_lower_bound`) -> il ne mute QUE des lignes encore hot ; reparser une donnée agée exigerait une
//! réécriture cold, HORS périmètre P1. `hot_cutoff` = MÊME formule que l'aging (`cold_hot_cutoff`, source unique).
//!
//! CRASH-SAFETY MULTI-FICHIERS (#18 P2b — re-dérivée intégralement, cf. `age_one_day`) : l'aging d'un jour est
//! DEUX PHASES. PHASE 1 (ÉCRITURE, module `writer`) : depuis le hot INTACT, on STREAME les N fichiers séquencés,
//! chacun scellé DURABLEMENT AVANT qu'AUCUN hot ne soit supprimé ; la fin de Phase 1 est COMMITÉE par `last_file=1`.
//! PHASE 2 (SUPPRESSION) : pour chaque fichier scellé, VERIFY (identité (env,day,seq) + borne ts DU FICHIER +
//! décodage) PUIS DELETE borné à la FENÊTRE KEYSET de CE fichier (`id<=max_id` FIX #1 + `(lo_cursor, hi_cursor]`)
//! PUIS `purged=1`. Un crash à tout point est IDEMPOTENT : Phase 2 ne démarre JAMAIS avant que `last_file=1` soit
//! commité -> un crash en Phase 1 laisse le hot 100% intact et un re-run REBÂTIT seulement les fichiers manquants ;
//! un crash en Phase 2 REPREND les deletes par-fichier idempotents (max_id RELU du seal, jamais re-dérivé du hot).

use super::*;
use std::path::Path;
// `P10.5-a` — l'instrumentation de la passe. Importée EXPLICITEMENT (pas par le glob) : c'est une
// dépendance vers un module NON gaté, et la nommer ici dit d'où viennent `Compte`, `Issue` et la fenêtre.
use crate::vieillissement_serie::{self, Compte, Fenetre, Issue};

/// Lit UNE page (au plus `limit` lignes) du jour (env_id, day) STRICTEMENT après le curseur keyset `(lo_ts, lo_id)`,
/// bornée `id <= max_id` (FIX #1) + NONPURGE, ordonnée `(ts, id)`. Verrou writer COURT (relâché après la lecture).
/// Renvoie `(id, ColdRow)` — l'`id` sert au curseur keyset et à la borne DELETE. Partagée par tous les fichiers.
pub(super) fn read_cold_page(
    db: &Arc<Mutex<Connection>>,
    env_id: &str,
    day_start: i64,
    day_end: i64,
    max_id: i64,
    lo_ts: i64,
    lo_id: i64,
    limit: usize,
) -> Result<Vec<(i64, ColdRow)>, String> {
    // `P10.13-a` — TEXTE UNIQUE dans `enonces` : la sonde de lecture seule rejoue CET énoncé, elle n'en
    // recopie pas une variante qui divergerait au premier changement de colonne ou de borne.
    let sql = sql_page_froide();
    let conn = db.lock();
    let mut st = conn.prepare(&sql).map_err(pe)?;
    let it = st
        .query_map(
            params![env_id, day_start, day_end, max_id, lo_ts, lo_id, limit as i64],
            |r| {
                let id: i64 = r.get(0)?;
                Ok((
                    id,
                    ColdRow {
                        row: EventRow {
                            ts: r.get(1)?,
                            severity: r.get(2)?,
                            source: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                            category: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                            host: r.get(5)?,
                            src_ip: r.get(6)?,
                            dst_ip: r.get(7)?,
                            url: r.get(8)?,
                            dedup: r.get(10)?,
                            engagement_id: r.get::<_, Option<String>>(11)?.unwrap_or_default(),
                            origin: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                            env_id: r.get(13)?,
                            message: r.get::<_, Option<String>>(14)?.unwrap_or_default(),
                            fields: r.get(15)?,
                        },
                        xff: r.get(9)?,
                    },
                ))
            },
        )
        .map_err(pe)?;
    let mut v = Vec::new();
    for row in it {
        v.push(row.map_err(pe)?);
    }
    Ok(v)
}

/// Rétention la PLUS LONGUE applicable (policies per-index #49 à retention_days>0 ∪ globale). Borne basse LARGE
/// de découverte (aucun jour éligible d'un index long ne doit être manqué) ET base du clamp de fenêtre chaude.
pub(super) fn max_retention(policies: &[IndexPolicy], retention_days: i64) -> i64 {
    policies
        .iter()
        .filter(|p| p.retention_days > 0)
        .map(|p| p.retention_days)
        .chain(std::iter::once(retention_days))
        .max()
        .unwrap_or(retention_days)
}

/// Fenêtre chaude (jours) — SOURCE UNIQUE du clamp (partagée par l'aging ET le clamp reparse H2, jamais
/// dupliquée). Défaut 7 ; clampée [1, max_ret-1] (le hot ne peut couvrir toute la rétention la plus longue ;
/// max_ret>=retention_days>1 côté aging -> borne haute >=1, clamp valide).
pub(super) fn clamp_hot_window(conf: &HashMap<String, String>, max_ret: i64) -> i64 {
    cfg(conf, "PLUME_COLD_HOT_WINDOW_DAYS", "7")
        .parse()
        .unwrap_or(7)
        .clamp(1, (max_ret - 1).max(1))
}

/// #18 P1.5 — RÉTENTION COLD (`cold_ret`) : la rétention TOTALE visée quand le tier cold est ON. C'est
/// l'horizon jusqu'auquel les jour-files cold survivent (et jusqu'auquel le hard-purge hot de `event` est
/// REPOUSSÉ pour la bande GLOBALE, cf. rollups::retention_run_tenant) -> le cold ÉTEND la rétention totale
/// au-delà de l'horizon hot au lieu de seulement rétrécir le hot. `PLUME_COLD_RETENTION_DAYS` :
///   - NON POSÉ / vide (DÉFAUT) -> `cold_ret = retention_days` -> comportement EXACTEMENT historique
///     (byte-identique : toutes les formules d'aging/expiry/purge se réduisent au code d'avant P1.5).
///   - POSÉ -> CLAMP SANS PERTE dans `[retention_days, 3650]`. Une valeur < `retention_days` est REMONTÉE à
///     `retention_days` (choix NO-LOSS : raccourcir le cold sous la rétention globale ferait expirer un
///     cold-file AVANT que le hot de la même donnée soit hard-purgé -> perte de rétention ; interdit). La
///     borne haute réutilise le plafond dur `event` (3650 j). `max(retention_days, ..)` sur le plafond
///     garantit `min <= max` même si `retention_days` était (défensivement) au-dessus du plafond.
/// PARAMÈTRE `retention_days` = rétention GLOBALE effective (déjà résolue/clampée par l'appelant). Fonction
/// PURE (aucun état) : partagée par l'aging/expiry (cold_store) ET le hard-purge hot (rollups) -> horizon
/// UNIQUE, jamais divergent entre les deux consommateurs.
pub(crate) fn cold_retention_days(conf: &HashMap<String, String>, retention_days: i64) -> i64 {
    let raw = cfg(conf, "PLUME_COLD_RETENTION_DAYS", "");
    if raw.trim().is_empty() {
        return retention_days; // NON POSÉ -> exactement retention_days (byte-identique, backward-compat).
    }
    let ceil = COLD_RETENTION_CEIL_DAYS.max(retention_days); // garantit min<=max (clamp panic-safe).
    raw.trim().parse::<i64>().unwrap_or(retention_days).clamp(retention_days, ceil)
}

/// Cutoff `ts` (epoch s) de la fenêtre chaude pour ce tenant : une ligne `ts < hot_cutoff` est COLD-ÉLIGIBLE
/// (aged -> columnarisée -> IMMUABLE) ; `ts >= hot_cutoff` = encore HOT (mutable). SOURCE UNIQUE partagée par
/// l'aging (via `clamp_hot_window`/`max_retention`) et le clamp reparse (H2) -> les deux voient EXACTEMENT la
/// même frontière hot/cold. `conn` sert à charger les policies per-index (#49).
pub(crate) fn cold_hot_cutoff(conn: &Connection, conf: &HashMap<String, String>, n: i64, retention_days: i64) -> i64 {
    n - cold_hot_window_days(conn, conf, retention_days) * SECS_PER_DAY
}

/// LA FENÊTRE CHAUDE EFFECTIVE (jours) — la valeur RÉELLEMENT appliquée, CLAMP COMPRIS. Extraite de
/// `cold_hot_cutoff` (qui en dérive désormais son cutoff, donc aucune divergence possible) parce que la
/// bannière de démarrage doit publier ce que le processus APPLIQUE : annoncer `PLUME_COLD_HOT_WINDOW_DAYS`
/// brut annoncerait une fenêtre que le clamp peut contredire.
pub(crate) fn cold_hot_window_days(conn: &Connection, conf: &HashMap<String, String>, retention_days: i64) -> i64 {
    clamp_hot_window(conf, max_retention(&load_index_policies(conn), retention_days))
}

/// H2 — BORNE BASSE EFFECTIVE d'un reparse/backfill admin quand le tier cold est ON. Dans le modèle cold, une
/// donnée agée est IMMUABLE (columnarisée : elle ne peut plus être mutée en place sans réécriture cold, HORS
/// périmètre P1). Un reparse dont la fenêtre `days` atteint un jour agé pourrait, pendant la columnarisation
/// (verrou relâché entre pages, FIX #3), muter une ligne DÉJÀ flushée en Parquet puis supprimée du hot ->
/// perte silencieuse de fidélité de contenu. On CLAMP donc la borne basse à `max(requested_cut, hot_cutoff)` :
/// le reparse ne mute QUE des lignes encore hot. GATE RUNTIME `PLUME_COLD_TIER` ICI : cold OFF -> `requested_cut`
/// renvoyé INCHANGÉ (comportement byte-identique). Le GATE COMPILE est chez l'appelant (feature `cold_tier`).
pub(crate) fn reparse_lower_bound(conn: &Connection, conf: &HashMap<String, String>, n: i64, requested_cut: i64) -> i64 {
    if cfg(conf, "PLUME_COLD_TIER", "") != "1" {
        return requested_cut; // cold runtime OFF -> reparse inchangé (mute toute la fenêtre demandée).
    }
    let retention_days = retention_effective(conn, conf, "retention_days");
    requested_cut.max(cold_hot_cutoff(conn, conf, n, retention_days))
}

/// Supprime (chunké, verrou relâché entre lots) les lignes hot d'UN FICHIER scellé (#18 P2b) — prédicat IDENTITÉ
/// borné à EXACTEMENT la tranche que CE fichier a archivée : `id <= max_id` (FIX #1, borne globale du jour) +
/// RETENTION_NONPURGE + FENÊTRE KEYSET du fichier `(lo_cursor, hi_cursor]` — c.-à-d. `(ts,id) > (lo_ts, lo_id)` ET
/// `(ts,id) <= (ts_max, hi_id)`. Cette fenêtre est CELLE que la page d'écriture a lue (même ordre `ts,id`, même
/// borne `id<=max_id`) -> le DELETE cible ligne-pour-ligne le contenu du fichier, JAMAIS celui d'un autre fichier
/// du jour (les fenêtres keyset sont DISJOINTES même quand deux fichiers partagent un `ts` frontière — l'`id`
/// départage). Une ligne backdatée ingérée APRÈS le seal porte `id > max_id` -> exclue (survit en hot = straggler).
/// Idempotent, converge (un re-run supprime le reliquat, jamais 2×). `ts_max` = `hi_ts` (curseur keyset haut).
///
/// PRÉCONDITION (aujourd'hui garantie SEULEMENT par le flot de contrôle de `age_one_day`/`phase2_delete`, PAS par
/// le compilateur — l'écrire ICI pour qu'un futur découpage en modules ne perde pas le contrat cross-lignes) : le
/// fichier cold de ce `(env_id, day, seq)` A ÉTÉ écrit, fsync'd, VÉRIFIÉ (décodage INTÉGRAL via `verify_parquet_rows`)
/// ET scellé durablement AVANT que ce delete ne s'exécute. Le delete est borné `id<=max_id` (FIX #1) + la fenêtre
/// keyset DU fichier. Le compilateur n'imposera JAMAIS verify-avant-delete par-delà une frontière de module : la
/// précondition doit rester écrite. NE JAMAIS appeler cette fonction sur un fichier non vérifié = perte de hot.
///
/// REND LE NOMBRE DE LIGNES RÉELLEMENT SUPPRIMÉES (`P10.5-a`). Ce n'est PAS `expected_rows` du seal : un
/// re-run idempotent en supprime zéro alors que le seal en annonce des milliers. Publier l'espéré ferait
/// croire à un drainage à chaque tick — exactement le genre de chiffre faux qu'un trou vaut mieux que.
#[allow(clippy::too_many_arguments)]
pub(super) fn delete_file_rows(db: &Arc<Mutex<Connection>>, env_id: &str, day: i64, max_id: i64, lo_ts: i64, lo_id: i64, ts_max: i64, hi_id: i64) -> i64 {
    let day_start = day * SECS_PER_DAY;
    let day_end = day_start + SECS_PER_DAY;
    let batch = retention_purge_batch();
    let env = env_id.to_string();
    chunked_purge(
        db,
        "event",
        &format!(
            "env_id=?1 AND ts>=?2 AND ts<?3 AND id<=?4 AND {RETENTION_NONPURGE} \
               AND (ts>?5 OR (ts=?5 AND id>?6)) AND (ts<?7 OR (ts=?7 AND id<=?8))"
        ),
        &[&env, &day_start, &day_end, &max_id, &lo_ts, &lo_id, &ts_max, &hi_id],
        batch,
    )
}

/// AGING vers le tier COLD Parquet (#18 Phase 1). Appelée depuis `retention_run` DERRIÈRE le gate compile
/// `cold_tier` ; ce corps applique le gate RUNTIME `PLUME_COLD_TIER` (retour immédiat si absent). Quand
/// elle retourne tôt, `retention_run` reste byte-identique à l'historique.
///
/// FENÊTRE : âge les JOURS COMPLETS dont l'intervalle [début,fin) est ENTIÈREMENT plus vieux que la fenêtre
/// chaude `PLUME_COLD_HOT_WINDOW_DAYS` ET entièrement DANS la rétention (`retention_days`). Un jour n'est
/// éligible que lorsqu'il est totalement passé -> son ensemble de lignes hot est STABLE (l'ingest écrit à
/// ts≈maintenant, jamais dans un jour passé) -> le compte est déterministe (discovery == select == footer
/// == delete). La bande agée [now-retention .. now-hot_window] est DISJOINTE de la bande hard-purgée par
/// `retention_run` (ts < now-retention) -> aucune interférence.
///
/// SÉQUENCE PAR (env_id, day) — #18 P2b, DEUX PHASES, jour splitté en N FICHIERS bornés (`age_one_day`) :
///   PHASE 1 (ÉCRITURE, hot INTACT) — snapshot(N,max_id,table_max) [1 verrou court, FIX #1 + H1] -> pour chaque
///   seq=0..N-1 : `write_one_file` (≤`file_cap` lignes, streamé 1 row-group RAM, keyset `(ts,id)`) -> fsync ->
///   VERIFY(identité (env,day,seq)+fenêtre ts+decode) -> rename tmp->final -> fsync dir -> INSERT seal(seq,
///   purged=0, ts_min/ts_max, lo/hi keyset, max_id, last_file=0) ; le curseur keyset du fichier k borne le début
///   du fichier k+1. FIN DE PHASE 1 COMMITÉE atomiquement : `UPDATE last_file=1` sur le dernier seq.
///   PHASE 2 (SUPPRESSION) — pour chaque fichier scellé non purgé : VERIFY(identité+ts+decode) -> DELETE chunké
///   borné à la FENÊTRE KEYSET du fichier (`id<=max_id` FIX #1 + `(lo_cursor, hi_cursor]`) -> UPDATE purged=1.
///
/// CRASH-SAFETY MULTI-FICHIERS (idempotence à CHAQUE point — RE-DÉRIVÉE intégralement pour N fichiers). INVARIANT
/// PIVOT : la PHASE 2 (le PREMIER delete) ne démarre JAMAIS avant que `last_file=1` soit durable -> tant que la
/// Phase 1 n'est pas COMMITÉE, le hot du jour est 100% INTACT. Toutes les fenêtres de crash :
///   • crash EN PHASE 1 (0..k fichiers scellés purged=0, AUCUN last_file, hot intact) -> re-run : aucun last_file
///     -> on REPREND l'écriture depuis le curseur keyset `(ts_max, hi_id)` du plus HAUT seq scellé (max_id RELU
///     des seals, JAMAIS re-dérivé), on écrit k+1..N-1 depuis le hot INTACT, puis last_file=1. On NE ré-écrit ni
///     ne re-vérifie les fichiers 0..k déjà scellés (préfixe durable) ; les fenêtres keyset restant DISJOINTES et
///     CONTIGUËS -> PAS DE TROU, PAS DE DUP. Un `.tmp` à demi-écrit (fichier k+1 avant rename) est simplement
///     ÉCRASÉ. PAS DE PERTE (hot intact), PAS DE DUP.
///   • crash APRÈS rename d'un fichier mais AVANT son seal -> re-run : ce seq n'a pas de seal -> il est RE-vu comme
///     « à écrire » depuis le curseur du seq précédent -> le final est ÉCRASÉ par une reconstruction cohérente
///     (même fenêtre keyset, même contenu). Le delete n'a pas eu lieu -> hot intact.
///   • crash APRÈS last_file, EN PHASE 2 (fichiers 0..j purged=1, j+1..N-1 purged=0) -> re-run : last_file présent
///     -> on NE ré-écrit RIEN (write done) ; on REPREND la Phase 2 sur les fichiers non purgés : VERIFY puis DELETE
///     borné à LEUR fenêtre keyset (max_id RELU du seal — FIX #1) puis purged=1. Fichiers déjà purged=1 SAUTÉS
///     (idempotent). Fichiers scellés immuables+complets -> PAS DE PERTE ; deletes keyset-disjoints+convergents
///     -> PAS DE DUP, aucun double-delete.
///   • si le VERIFY d'un fichier scellé ÉCHOUE au re-run (corrompu/absent/page cassée/identité étrangère) -> ce
///     fichier n'est PAS supprimé (et le tick s'arrête là pour ce jour) + signal stderr : fail-safe (jamais de
///     suppression sur preuve non prouvée LISIBLE ; les fichiers déjà purgés avant l'échec le restent, le reste
///     reste hot et sera retenté au tick suivant).
///
/// STRAGGLERS (choix P1 conservé) : une ligne backdatée qui atterrit dans un jour DÉJÀ entièrement drainé (tous
/// fichiers purged=1) porte `id > max_id` (ingest monotone) -> aucune fenêtre keyset scellée ne la couvre -> elle
/// reste EN HOT jusqu'au hard-purge (PAS de perte — visible/interrogeable), simplement jamais columnarisée. Le
/// split multi-fichiers N'AGE PAS les stragglers d'un jour clos (la re-columnarisation d'un jour scellé reste
/// HORS périmètre) : NO-LOSS absolu, même compromis qu'en P1.
///
/// RÉTENTION PAR-INDEX (#49, FIX #4) : la rétention EFFECTIVE d'un (env_id, day) est la policy per-index de son
/// env_id si définie (retention_days>0), sinon la globale. TOUS les fichiers d'un jour partagent le MÊME (env_id,
/// day) -> UN index -> résolution nette. L'aging columnarise les jours dans la rétention de LEUR index (borne
/// basse par-env), et l'EXPIRY ne supprime les cold-files d'un jour que quand la rétention de SON index est
/// dépassée (jamais de suppression prématurée d'un index à rétention plus LONGUE que la globale).
///
/// HOLDS/CONTRÔLE : si un legal-hold est actif (enforcement != NoHolds) -> aging SUSPENDU ce tick (les
/// preuves restent hot, fail-safe). Les events de contrôle (RETENTION_NONPURGE) ne sont JAMAIS agés/supprimés.
///
/// CE QUE LA PASSE RACONTE (`P10.5-a`) — mesuré en production le 2026-08-10 : un vieillissement libérait
/// 120 Mio de base chaude et écrivait 3,70 Mio de Parquet SANS ÉMETTRE UNE LIGNE. Le corps de la passe est
/// donc désormais `balayer`, encadré ICI par une fenêtre de mesure (durée, CPU du fil, crête RSS ramenée à la
/// fenêtre) : à chaque exécution, UNE ligne de journal ET une série dans `metric`
/// (`vieillissement_serie`). L'encadrement est TOTAL — tous les retours de `balayer` passent par le même
/// point de publication, donc aucune sortie ne peut redevenir muette sans qu'on le voie. Seul le gate
/// RUNTIME reste AVANT la fenêtre : tier froid éteint = pas de passe, donc pas de point (l'absence de série
/// dit « ça ne tourne pas », un `0` dirait « ça tourne et ça ne fait rien »).
pub(crate) fn cold_age_run(db: &Arc<Mutex<Connection>>, db_path: &str, conf: &HashMap<String, String>, n: i64, retention_days: i64) {
    // --- GATE RUNTIME : sans PLUME_COLD_TIER=1, retour immédiat (retention_run byte-identique). ---
    if cfg(conf, "PLUME_COLD_TIER", "") != "1" {
        return;
    }
    let fenetre = Fenetre::ouvrir();
    let mut compte = Compte::default();
    let issue = balayer(db, db_path, conf, n, retention_days, &mut compte);
    let bilan = fenetre.clore(issue, compte);
    // Les DEUX sorties : la phrase (lisible dans `kubectl logs`, sans requête à écrire) ET la série (lisible
    // 90 jours plus tard, en SOQL). L'une ne remplace pas l'autre — c'est le défaut mesuré qui l'a montré.
    eprintln!("{}", vieillissement_serie::phrase(&bilan));
    vieillissement_serie::publier(db, n, &bilan);
}

/// LE CORPS DE LA PASSE — tout ce que faisait `cold_age_run` avant l'instrumentation, à l'identique, plus
/// l'accumulation du `compte`. Rend l'ISSUE (balayée / suspendue-et-pourquoi) au lieu de `()` : c'est ce
/// typage qui interdit qu'une sortie redevienne silencieuse (le compilateur exige une issue sur CHAQUE
/// chemin, et l'appelant en fait toujours une ligne + un point de série).
fn balayer(
    db: &Arc<Mutex<Connection>>,
    db_path: &str,
    conf: &HashMap<String, String>,
    n: i64,
    retention_days: i64,
    compte: &mut Compte,
) -> Issue {
    if retention_days <= 1 {
        // Rétention globale trop courte pour distinguer une fenêtre chaude ; rien à ager. C'ÉTAIT un retour
        // muet : le tier froid déclaré actif ne columnarisait rien et rien ne le disait.
        return Issue::Suspendu(vieillissement_serie::CAUSE_RETENTION_COURTE);
    }

    // Legal-hold : suspension DÉLIBÉRÉE -> on s'abstient d'ager ce tick ET on NE déclenche PAS le signal de
    // retard (ce n'est PAS un stall silencieux : le hold est lui-même visible/audité). Preuves conservées hot.
    match { let conn = db.lock(); legal_hold_enforcement(&conn) } {
        HoldEnforce::NoHolds => {}
        _ => {
            eprintln!("[cold] legal-hold actif/indéterminé -> aging cold SUSPENDU ce tick (fail-safe)");
            return Issue::Suspendu(vieillissement_serie::CAUSE_LEGAL_HOLD);
        }
    }

    // `P10.13-a` — LA BANDE DE CE TICK, calculée UNE FOIS et PARTAGÉE avec la sonde de lecture seule
    // (`cold-aging-plan`). Elle porte tout ce qui était dérivé en ligne ici : rétention cold étendue
    // (#18 P1.5, défaut = `retention_days` -> byte-identique), policies per-index (#49, FIX #4 ; table
    // absente -> Vec vide -> tout retombe sur la globale), rétention la plus LONGUE applicable (borne
    // basse LARGE : aucun jour d'un index long ni de la bande étendue ne doit être manqué), fenêtre
    // chaude clampée (MÊME clamp que le reparse H2, source unique), bornes de découverte, et les deux
    // plafonds de split. La partager plutôt que la recalculer est ce qui interdit à l'instrument de
    // mesurer d'AUTRES bornes que celles de la passe. `ensure_cold_seal_table` (idempotent, ÉCRITURE)
    // reste ICI, hors de `Bande::calculer` : c'est ce qui rend la même fonction appelable depuis une
    // connexion ouverte en LECTURE SEULE. GATE COLD OFF n'atteint JAMAIS ici -> base inchangée (mode 0).
    let bande = { let conn = db.lock(); ensure_cold_seal_table(&conn); Bande::calculer(&conn, conf, n, retention_days) };
    let cold_ret = bande.cold_ret;
    let hot_window = bande.hot_window;

    // CLÉ COLD (chiffrement at-rest, #18) — dérivée (HKDF domaine séparé `plume-cold-aead-v1`) de la clé
    // SQLCipher DU TENANT. FAIL-CLOSED : sans clé (PLUME_DB_KEY indisponible), on N'ÂGE RIEN ce tick — aucun
    // Parquet, aucune suppression hot, aucun plaintext écrit. Le cold ON EXIGE le chiffrement : il n'existe
    // AUCUN chemin cold-en-clair (un repli en clair recréerait EXACTEMENT la régression de confidentialité
    // qu'on ferme). Le tick suivant réessaiera dès que la clé revient (hot INTACT entre-temps). DEAD-MAN'S-
    // SWITCH : une clé absente à CHAQUE tick empêche l'aging de drainer -> AVEC l'extension (cold_ret>retention_days)
    // le hot grossit vers cold_ret ; on rend ce retard VISIBLE ici aussi. SANS extension (cold_ret==retention_days,
    // défaut), le hot reste plafonné à retention_days comme avant -> aucun bloat NOUVEAU -> signal NON émis
    // (et byte-identique : tous les tests existants, knob non posé, ne l'atteignent jamais).
    let pass = match cold_aead_passphrase(conf, db_path) {
        Some(p) => p,
        None => {
            eprintln!("[cold] PLUME_DB_KEY indisponible -> chiffrement at-rest impossible : aging cold SUSPENDU ce tick (fail-closed ; hot intact, aucun fichier écrit)");
            if cold_ret > retention_days {
                detect_aging_stall(db, n, hot_window, cold_ret);
            }
            return Issue::Suspendu(vieillissement_serie::CAUSE_CLE_ABSENTE);
        }
    };

    // Racine cold PAR-TENANT (FIX #2) — dérivée du db_path du tenant, jamais du PLUME_COLD_DIR global partagé.
    let cold_dir = cold_root(conf, db_path);

    // `P10.5-a` — LA DÉCOUVERTE PEUT ÉCHOUER, ET SON ÉCHEC RESSEMBLAIT À « RIEN À FAIRE ». Les `if let
    // Ok(..)`/`flatten()` d'origine avalaient une erreur de `prepare`, de `query_map` ou de ligne : la liste
    // sortait VIDE et la passe se comportait exactement comme un tick sans travail. Une fois la passe
    // instrumentée ce serait PIRE qu'avant — la série publierait « 0 jour candidat », un ZÉRO MESURÉ, là où
    // la vérité est « je n'ai pas pu regarder ». On garde le comportement (aucune interruption : l'expiry et
    // les détecteurs de fin de passe doivent tourner) mais on RETIENT l'échec, et l'issue le portera.
    let mut decouverte_ok = true;

    if bande.ouverte() {
        // Découverte des (env_id, day) candidats sur la bande LARGE (STABLE : jours passés). EXCLUT les events
        // de contrôle (RETENTION_NONPURGE) -> jamais agés. `P10.13-a` : texte ET bornes viennent de `enonces`,
        // donc la sonde de lecture seule mesure CETTE requête-ci, sur CES bornes-ci.
        let groups: Vec<(String, i64)> = {
            let conn = db.lock();
            let sql = sql_decouverte_des_jours();
            let (lo, hi) = bande.bornes_de_decouverte();
            let mut out = Vec::new();
            match conn.prepare(&sql) {
                Ok(mut st) => match st.query_map(params![lo, hi], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                }) {
                    Ok(rows) => {
                        for ligne in rows {
                            match ligne {
                                Ok(g) => out.push(g),
                                // Une ligne illisible SOUS-COMPTERAIT les candidats sans le dire.
                                Err(e) => {
                                    decouverte_ok = false;
                                    eprintln!("[cold] découverte des jours agéables : ligne illisible ({e})");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        decouverte_ok = false;
                        eprintln!("[cold] découverte des jours agéables IMPOSSIBLE ({e}) -> aucun jour examiné ce tick");
                    }
                },
                Err(e) => {
                    decouverte_ok = false;
                    eprintln!("[cold] découverte des jours agéables IMPOSSIBLE ({e}) -> aucun jour examiné ce tick");
                }
            }
            out
        };

        // Chaque candidat suit EXACTEMENT une des CINQ suites (écarté / différé / échoué / columnarisé /
        // sans travail) — c'est la comptabilité que `Compte::comptabilite_jours_fermee` exige, et qui refuse
        // de publier si un chemin ajouté plus tard oubliait de se compter.
        compte.jours_candidats += groups.len() as i64;
        for (env_id, day) in groups {
            // ÉCARTÉ : `env_id` non conforme (fail-safe, pas de composant de chemin) OU jour au-delà de la
            // rétention de SON index (FIX #4 : laissé au hard-purge / à l'expiry, jamais columnarisé pour
            // être supprimé aussitôt). Le prédicat vit dans `Bande` -> la sonde retient les MÊMES jours.
            if !bande.retenu(&env_id, day, n) {
                compte.jours_ecartes += 1;
                continue;
            }
            match age_one_day(db, db_path, &cold_dir, &env_id, day, bande.file_cap, bande.rg_rows, &pass, compte) {
                Ok(Journee::Columnarisee) => compte.jours_columnarises += 1,
                Ok(Journee::SansTravail) => compte.jours_sans_travail += 1,
                Ok(Journee::Differee) => compte.jours_differes += 1,
                Err(e) => {
                    compte.jours_echoues += 1;
                    eprintln!("[cold] aging {env_id}/{} échoué (lignes conservées hot): {e}", ymd_from_day(day));
                }
            }
        }
    }

    // NETTOYAGE des jours-Parquet au-delà de la rétention de LEUR index (FIX #4). day_end <= now - eff_ret,
    // fallback GLOBAL = `cold_ret` (#18 P1.5 : un cold-file d'un env sans policy survit jusqu'à cold_ret) —
    // MÊME `Bande::eff_ret` que la découverte, donc jamais deux définitions de la rétention par-env.
    expire_cold_days(db, &cold_dir, n, &bande);

    // #18 — SIGNAL « seal cold BLOQUÉ » (phase-2 délete-side stall). Complémentaire de detect_aging_stall :
    // celui-ci attrape un jour DÉJÀ scellé mais dont le fichier reste perpétuellement CORROMPU
    // (cold_seal.purged=0, VERIFY échoue à chaque tick de phase2) -> le hot n'est jamais purgé, invisible en UI
    // (seulement stderr). detect_aging_stall EXCLUT les jours qui ONT un seal, donc ne peut PAS le voir. Placé
    // APRÈS expire_cold_days pour que les seals hors-rétention (retirés par l'expiry) ne soient PAS faux-flaggés.
    // NON gaté sur `cold_ret > retention_days` (un fichier scellé corrompu bloque phase2 indépendamment de
    // l'extension) — mais DANS cold_age_run qui retourne tôt si PLUME_COLD_TIER != "1" -> gate cold-on.
    detect_cold_seal_stuck(db, n);

    // #18 P1.5 — DEAD-MAN'S-SWITCH « aging cold en RETARD ». Repousser le hard-purge hot à `cold_ret` fait que,
    // SI l'aging cesse silencieusement de drainer le hot (clé absente chaque tick, verify en échec, ingest
    // arrêté...), le hot grossit vers `cold_ret` au lieu d'être plafonné à la fenêtre chaude -> BLOAT (RAM/disque)
    // et PAS de perte. On rend ce retard VISIBLE via le canal de santé standard (emit_cold_aging_stall :
    // event source='plume-config'/origin='daemon'/category='health', NON-PURGEABLE, hourly-dedup, NON-FATAL).
    // DÉTECTION précise : lignes non-NONPURGE en HOT dont le JOUR est plus vieux que la fenêtre chaude d'une
    // marge CLAIRE (hot_window + COLD_STALL_GRACE_DAYS) ET dont le (env_id, jour) n'a AUCUN seal -> un jour
    // DRAINÉ normalement (agé) est supprimé du hot, et un jour columnarisé (même straggler-porteur) a un seal
    // -> EXCLUS. Ne restent que les jours qui AURAIENT dû être columnarisés et ne l'ont pas été (vrai stall,
    // ou defer H1 permanent sur ingest mort = bloat réel à signaler). Zéro faux positif en régime drainé.
    // GATE `cold_ret > retention_days` : le risque de bloat est INTRODUIT par l'extension (le hard-purge hot
    // passe à cold_ret). Sans extension (défaut), le hot reste plafonné à retention_days comme avant -> aucun
    // signal (et donc byte-identique : les tests existants, knob non posé, ne l'activent JAMAIS).
    if cold_ret > retention_days {
        detect_aging_stall(db, n, hot_window, cold_ret);
    }

    // L'ISSUE EN DERNIER, et elle porte l'échec de découverte : « 0 candidat » n'est publiable que si on a
    // VRAIMENT regardé. Sinon la passe est suspendue avec sa cause, et la série a un trou NOMMÉ.
    if decouverte_ok {
        Issue::Balaye
    } else {
        Issue::Suspendu(vieillissement_serie::CAUSE_DECOUVERTE)
    }
}

/// #18 P1.5 — grâce (jours) au-delà de la fenêtre chaude avant de crier au retard d'aging. Une valeur > 0
/// absorbe le jour-frontière tout juste sorti de la fenêtre chaude (que l'aging va columnariser au tick même)
/// -> le signal ne se déclenche que sur un retard NET, jamais sur le régime drainé normal.
pub(super) const COLD_STALL_GRACE_DAYS: i64 = 2;

/// #18 — grâce (secondes) avant de crier au « seal cold BLOQUÉ ». Un tick sain scelle purged=0 PUIS purge
/// (purged=1) DANS le même tick ~horaire ; un purged=0 qui SURVIT des heures = phase2 coincée (VERIFY échoue
/// en boucle sur un fichier corrompu). 6 h couvre plusieurs ticks -> aucun faux positif sur le tick frontière.
pub(super) const COLD_SEAL_STUCK_GRACE_S: i64 = 6 * 3600;

/// #18 P1.5 — DÉTECTE un aging cold EN RETARD et émet (si besoin) le signal de santé. Non-fatal ; best-effort.
/// Compte les lignes non-NONPURGE HOT dont le jour est plus vieux que `hot_window + COLD_STALL_GRACE_DAYS` et
/// dont le (env_id, jour) N'A PAS de seal (ni écrit, ni en cours) — c.-à-d. des lignes qui auraient dû être
/// columnarisées mais ne l'ont pas été. > 0 -> signal (dédupé à l'heure). Aucune écriture si compte == 0.
///
/// LA PHRASE QUI ÉTAIT ICI DISAIT « requête bornée par idx_event_ts (range sur `ts`) » : c'était FAUX, et
/// mesuré faux le 2026-08-11 sur la production — `SCAN e`, 1 720 594 lignes balayées, 27 705 ms, pour une
/// bande qui contient au plus ~500 lignes. Elle est retirée plutôt que corrigée : le plan ne se DÉCLARE
/// pas dans un commentaire, il se LIT avec `cold-aging-plan`. Ce que cet énoncé coûte est écrit là où il
/// vit, avec les chiffres qui le disent (`enonces::sql_retard_de_vieillissement`).
pub(super) fn detect_aging_stall(db: &Arc<Mutex<Connection>>, n: i64, hot_window: i64, cold_ret: i64) {
    // `P10.13-a` — BORNES DÉRIVÉES de `enonces` (source unique, cf. `bornes_du_retard`) : la sonde doit
    // planifier CET énoncé sur CETTE fenêtre, et un `None` veut dire « rien à surveiller » (la fenêtre
    // chaude + grâce couvre déjà toute la rétention).
    let Some((stall_lo, stall_hi)) = bornes_du_retard(hot_window, cold_ret, n) else {
        return;
    };
    let conn = db.lock();
    // ANTI-JOINTURE sur le seal du (env_id, jour) : exclut tout jour columnarisé/en-cours (drainé OU
    // straggler-porteur). `P10.13-a` — texte UNIQUE dans `enonces` : c'est le SECOND énoncé qui peut balayer
    // `event`, et la sonde doit pouvoir le lire avec le MÊME texte.
    let sql = sql_retard_de_vieillissement();
    let lingering: i64 = match conn.query_row(&sql, params![stall_lo, stall_hi], |r| r.get(0)) {
        Ok(v) => v,
        // FAIL-LOUD. Le `unwrap_or(0)` qui était ici rendait « 0 » — c.-à-d. « aucun retard » — quand la
        // REQUÊTE avait échoué. Un dead-man's-switch qui répond « tout va bien » parce qu'il n'a rien pu
        // lire est précisément le mode de panne qu'il existe pour fermer, et il le faisait EN SILENCE.
        // On ne peut pas émettre le signal (on ne sait pas s'il y a retard) : on refuse le verdict, et on
        // le dit sur le canal où les autres échecs de la passe sont déjà écrits.
        Err(e) => {
            eprintln!(
                "[cold] dead-man's-switch de RETARD inopérant ce tick — la requête a échoué ({e}). AUCUN \
                 verdict rendu (ni « en retard », ni « à jour »). Le prochain tick réessaie ; si cela dure, \
                 lire le plan avec `plume-daemon cold-aging-plan`."
            );
            return;
        }
    };
    if lingering > 0 {
        emit_cold_aging_stall(&conn, n, lingering, hot_window, cold_ret);
    }
}

/// #18 P1.5 — SIGNAL DE SANTÉ « aging cold en RETARD » (dead-man's-switch). RÉUTILISE le canal existant de
/// emit_ledger_health / emit_disk_health / emit_backup_symmetric_signal : event `source='plume-config'` +
/// `origin='daemon'` + `category='health'` -> NON-PURGEABLE (RETENTION_NONPURGE), SOC-visible/alertable, et
/// NON-FATAL (c'est un signal, jamais un arrêt). DÉDUP HORAIRE (dedup UNIQUE `plume-cold-aging-stall-<bucket>`)
/// -> au plus 1 signal/heure malgré des ticks retention_run plus fréquents (anti-tempête, miroir exact des
/// autres emit_*). Sévérité 3. Renvoie true si une ligne a été écrite.
fn emit_cold_aging_stall(conn: &Connection, now_ts: i64, lingering: i64, hot_window: i64, cold_ret: i64) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE -> 1 signal/heure max
    let dedup = format!("plume-cold-aging-stall-{bucket}");
    let msg = format!(
        "TIER COLD EN RETARD : {lingering} event(s) non-contrôle stagnent en HOT bien au-delà de la fenêtre \
         chaude ({hot_window} j) sans avoir été columnarisés. L'aging cold ne draine plus le hot (PLUME_DB_KEY \
         absente ? verify en échec ? ingest arrêté ?) -> le hot grossit vers la rétention étendue ({cold_ret} j) \
         au lieu d'être plafonné à la fenêtre chaude (bloat RAM/disque, PAS de perte). Vérifier PLUME_DB_KEY et \
         les journaux [cold]."
    );
    let fields = json!({
        "subsystem": "cold-tier",
        "signal": "aging-stall",
        "lingering_rows": lingering,
        "hot_window_days": hot_window,
        "cold_retention_days": cold_ret
    })
    .to_string();
    store()
        .insert_event(conn, &EventRow {
            ts: now_ts,
            source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
            category: "health".into(),
            severity: 3,
            message: msg,
            host: Some("plume-daemon".into()),
            src_ip: None,
            dst_ip: None,
            url: None,
            dedup: Some(dedup),
            fields: Some(fields),
            engagement_id: String::new(),
            origin: "daemon".into(), // marqueur DAEMON -> exclut de la purge (un forgeur porte origin='')
            env_id: None,
        })
        .unwrap_or(0)
        > 0
}

/// #18 — DÉTECTE un seal cold BLOQUÉ (delete-side stall) et émet (si besoin) le signal de santé. Non-fatal ;
/// best-effort. Un jour scellé mais JAMAIS purgé (purged=0) dont le sealed_ts est plus vieux que la grâce =
/// phase2 coincée (VERIFY échoue en boucle sur un fichier corrompu -> la slice cold est illisible ET le hot
/// n'est jamais purgé). LIT UNIQUEMENT la petite table `cold_seal` -> AUCUNE clé de déchiffrement requise.
pub(super) fn detect_cold_seal_stuck(db: &Arc<Mutex<Connection>>, n: i64) {
    let conn = db.lock();
    let cutoff = n - COLD_SEAL_STUCK_GRACE_S;
    // COUNT(*) = fichiers-seals bloqués ; COUNT(DISTINCT env/day) = jours distincts ; MIN(sealed_ts) = le plus
    // ancien seal coincé. Requête sur la PETITE table cold_seal, bornée par purged=0 (rare en régime sain).
    let row: Option<(i64, i64, i64)> = conn
        .query_row(SQL_SEAL_BLOQUE, params![cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok();
    if let Some((files, days, oldest_ts)) = row {
        if files > 0 {
            emit_cold_seal_stuck(&conn, n, files, days, oldest_ts);
        }
    }
}

/// #18 — SIGNAL DE SANTÉ « seal cold BLOQUÉ » (delete-side stall). MIROIR EXACT de emit_cold_aging_stall :
/// même canal (event `source='plume-config'` + `origin='daemon'` + `category='health'`) -> NON-PURGEABLE
/// (RETENTION_NONPURGE), SOC-visible/alertable, NON-FATAL. DÉDUP HORAIRE (dedup UNIQUE
/// `plume-cold-seal-stuck-<bucket>`) -> au plus 1 signal/heure via INSERT-OR-IGNORE. Sévérité 4. Renvoie true
/// si une ligne a été écrite.
fn emit_cold_seal_stuck(conn: &Connection, now_ts: i64, files: i64, days: i64, oldest_ts: i64) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE -> 1 signal/heure max
    let dedup = format!("plume-cold-seal-stuck-{bucket}");
    let msg = format!(
        "SEAL COLD BLOQUÉ : {files} fichier(s) scellé(s) sur {days} jour(s) restent NON PURGÉS (phase-2 \
         bloquée) — VERIFY échoue en boucle -> la slice cold est ILLISIBLE et le hot n'est jamais purgé. \
         Vérifier les journaux [cold] et l'intégrité disque."
    );
    let fields = json!({
        "subsystem": "cold-tier",
        "signal": "seal-stuck",
        "stuck_files": files,
        "stuck_days": days,
        "oldest_sealed_ts": oldest_ts
    })
    .to_string();
    store()
        .insert_event(conn, &EventRow {
            ts: now_ts,
            source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
            category: "health".into(),
            severity: 4,
            message: msg,
            host: Some("plume-daemon".into()),
            src_ip: None,
            dst_ip: None,
            url: None,
            dedup: Some(dedup),
            fields: Some(fields),
            engagement_id: String::new(),
            origin: "daemon".into(), // marqueur DAEMON -> exclut de la purge (un forgeur porte origin='')
            env_id: None,
        })
        .unwrap_or(0)
        > 0
}

/// CE QU'UN JOUR EST DEVENU — TROIS issues SANS erreur, qui ne doivent pas se confondre dans la série.
///
/// `P10.12-a` (résiduel) — POURQUOI IL Y EN A TROIS ET PLUS DEUX. `Ok(Journee::Agee) => jours_ages += 1`
/// était atteint par DEUX situations SANS AUCUN TRAVAIL : le retour défensif « rien d'agéable » (aucune ligne
/// non-contrôle dans le jour) et le no-op « déjà scellé, phase 2 déjà drainée ». La série publiait donc
/// `plume_cold_aging_jours{issue="age"} = 10` pour **10 jours no-op** — mesuré en production le 2026-08-10,
/// un chiffre faux dans la série même qui existe pour supprimer les chiffres faux. Le COMPORTEMENT (compromis
/// « stragglers » assumé et verrouillé par `fix1_straggler_in_sealed_day_stays_hot_no_loss`) est INCHANGÉ ;
/// seul ce que la série en DIT change.
///
/// LA DISTINCTION EST DÉRIVÉE, JAMAIS ÉNUMÉRÉE (cf. `Journee::selon_le_travail`) : elle se lit dans le DELTA
/// des compteurs de travail du `Compte`, pas dans le chemin de retour emprunté. Une troisième situation
/// no-op ajoutée demain tombera du bon côté sans que personne n'y pense.
enum Journee {
    /// Le jour a réellement columnarisé : au moins un fichier écrit et/ou une tranche chaude retirée.
    Columnarisee,
    /// Le jour a été TRAITÉ SANS ERREUR mais SANS TRAVAIL : rien d'agéable, ou déjà scellé et déjà drainé.
    SansTravail,
    /// Différé par la garde H1 (le jour détient le tail du compteur de rowid) — sans perte, reviendra.
    Differee,
}

impl Journee {
    /// LE VERDICT, DÉRIVÉ DU TRAVAIL RÉELLEMENT COMPTABILISÉ entre l'entrée et la sortie de `age_one_day`.
    /// `Compte::a_travaille_depuis` compare la PROJECTION « tout sauf la comptabilité des jours » : un
    /// compteur de travail ajouté demain (octets, fichiers, lignes…) est donc pris en compte le jour où il
    /// est ajouté, sans qu'aucune liste ne soit tenue ici.
    fn selon_le_travail(avant: &Compte, apres: &Compte) -> Journee {
        if apres.a_travaille_depuis(avant) {
            Journee::Columnarisee
        } else {
            Journee::SansTravail
        }
    }
}

/// Traite UN (env_id, day) selon la machine à états seal DEUX PHASES multi-fichiers (cf. doc de `cold_age_run`).
/// `file_cap` = plafond de lignes par fichier (split) ; `rg_rows` = taille de row-group intra-fichier. Renvoie
/// Err si l'aging n'a pas pu se compléter proprement (l'appelant journalise ; les lignes restent hot -> pas de perte).
/// `compte` (`P10.5-a`) est incrémenté PAR FICHIER au fil de l'eau (jamais à la fin) -> un échec au milieu du jour
/// conserve la trace de ce qui a réellement été écrit et supprimé.
///
/// `P10.12-a` (résiduel) — L'ISSUE « SANS ERREUR » EST DÉRIVÉE, PAS DÉCLARÉE. Le `Compte` est photographié à
/// l'entrée ; chaque sortie `Ok` passe par `Journee::selon_le_travail`, qui compare la photo à l'état final.
/// Un chemin qui rendrait `Ok` sans avoir rien columnarisé est donc compté SANS TRAVAIL même si son auteur ne
/// l'avait pas prévu — c'est ce qui a manqué aux deux chemins no-op que la production a exhibés le 2026-08-10.
#[allow(clippy::too_many_arguments)]
fn age_one_day(db: &Arc<Mutex<Connection>>, db_path: &str, cold_dir: &Path, env_id: &str, day: i64, file_cap: usize, rg_rows: usize, pass: &str, compte: &mut Compte) -> Result<Journee, String> {
    let avant = *compte; // la PHOTO d'entrée : tout le verdict « columnarisé ou non » en dérive.
    let seals = { let conn = db.lock(); file_seals(&conn, env_id, day) };
    let write_done = seals.iter().any(|s| s.last_file);

    if !write_done {
        // ---- PHASE 1 (ÉCRITURE) : hot INTACT (aucun delete tant que `last_file` n'est pas commité). ----
        if seals.is_empty() {
            // FRAIS : snapshot (max_id GLOBAL du jour + table_max pour H1) sous UN verrou court, AVANT écriture.
            let (n_rows, max_id, table_max) = {
                let conn = db.lock();
                let (n_rows, max_id) = count_and_max_id(&conn, env_id, day)?;
                (n_rows, max_id, event_table_max_id(&conn)?)
            };
            if n_rows == 0 {
                // Défensif : rien d'agéable (aucune ligne non-contrôle) -> pas de fichier, pas de seal. Jour
                // TRAITÉ, mais SANS AUCUN TRAVAIL — et c'est le verdict dérivé qui le dit, pas cette ligne :
                // elle rend le MÊME appel que la sortie normale, le delta de compteurs tranche.
                return Ok(Journee::selon_le_travail(&avant, compte));
            }
            // H1 — TAIL GUARD (anti-réutilisation de rowid), inchangé et appliqué au NIVEAU JOUR (la Phase 2 supprime
            // TOUT le jour `id<=max_id`). Le DELETE borne `id <= max_id` ; il n'est dangereux que si SQLite peut
            // ré-allouer un rowid <= max_id, ce qui exige que le compteur global (= MAX(id)) tombe <= max_id —
            // impossible tant qu'une ligne d'id > max_id SUBSISTE hors de l'ensemble supprimé. Si ce jour DÉTIENT le
            // tail (`max_id == table_max`), sa suppression ferait chuter le compteur -> un insert backdaté concurrent
            // (verrou relâché entre lots) réutiliserait un id <= max_id, atterrirait dans ce jour, et serait supprimé
            // SANS archive. On DIFFÈRE donc ce jour ce tick ; on ne l'âge QUE lorsque `table_max > max_id` (une ligne
            // d'id > max_id survit AILLEURS et épingle le compteur). DIFFÉRER = SANS PERTE (reste hot). Comme aucun
            // fichier n'est écrit tant que la garde n'est pas passée, un jour AVEC des seals a forcément passé la garde
            // (au premier tick) -> le resume-écriture NE re-teste PAS H1 (identique au resume single-file historique).
            if max_id >= table_max {
                eprintln!(
                    "[cold] {env_id}/{} détient le tail du compteur rowid (max_id={max_id}) -> aging DIFFÉRÉ ce tick (anti-réutilisation, reste hot sans perte)",
                    ymd_from_day(day)
                );
                return Ok(Journee::Differee);
            }
            let dir = day_dir(cold_dir, env_id);
            std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            write_day_files(db, db_path, cold_dir, env_id, day, max_id, 0, i64::MIN, i64::MIN, file_cap, rg_rows, pass, compte)?;
        } else {
            // RESUME ÉCRITURE (crash EN Phase 1 : préfixe 0..k scellé, AUCUN last_file). Hot INTACT. On REPREND
            // depuis le curseur keyset du plus HAUT seq scellé, avec le max_id RELU des seals (JAMAIS re-dérivé du
            // hot — FIX #1). Les fichiers 0..k ne sont ni ré-écrits ni re-vérifiés (préfixe durable). H1 déjà passé.
            let last = seals.last().expect("seals non vide");
            let max_id = last.max_id;
            write_day_files(db, db_path, cold_dir, env_id, day, max_id, last.seq + 1, last.ts_max, last.hi_id, file_cap, rg_rows, pass, compte)?;
        }
    }

    // ---- PHASE 2 (SUPPRESSION) : write done (fresh/resume ci-dessus ont posé last_file, ou il l'était déjà). ----
    phase2_delete(db, cold_dir, env_id, day, pass, compte)?;
    // Un jour dont TOUS les fichiers étaient déjà `purged=1` traverse la phase 2 sans rien faire (les
    // stragglers `id > max_id` restent hot, compromis assumé) : le delta de compteurs est nul -> SANS TRAVAIL.
    Ok(Journee::selon_le_travail(&avant, compte))
}

/// PHASE 2 (suppression) d'un jour : pour chaque FICHIER scellé non purgé, VERIFY (identité (env,day,seq) +
/// fenêtre ts + décodage) PUIS DELETE chunké borné à la FENÊTRE KEYSET du fichier (`id<=max_id` + `(lo,hi]`)
/// PUIS `purged=1`. Fichiers déjà purgés SAUTÉS (idempotent). Un VERIFY en échec sur un fichier ARRÊTE la Phase 2
/// pour ce jour (fail-safe : ce fichier — et les suivants — restent hot, retentés au tick suivant) sans toucher
/// aux fichiers déjà purgés. max_id/lo/hi RELUS du seal (jamais re-dérivés du hot rétréci — FIX #1).
///
/// PRÉCONDITION (contrat d'ORDONNANCEMENT crash-safety, aujourd'hui imposé SEULEMENT par le flot de contrôle de
/// `age_one_day` : Phase 2 ne démarre qu'après le COMMIT `last_file=1` de Phase 1 — PAS par le compilateur) : pour
/// CHAQUE fichier scellé, le cold `(env_id, day, seq)` a été écrit, fsync'd, VÉRIFIÉ (décodage intégral via
/// `verify_parquet_rows`) et scellé durablement AVANT tout delete. Cette fonction RE-VÉRIFIE au delete (défense en
/// profondeur), puis borne le delete `id<=max_id` (FIX #1) + fenêtre keyset. Après un futur découpage en modules,
/// le compilateur n'imposera plus verify-avant-delete par-delà les frontières : ce contrat doit rester écrit.
fn phase2_delete(db: &Arc<Mutex<Connection>>, cold_dir: &Path, env_id: &str, day: i64, pass: &str, compte: &mut Compte) -> Result<(), String> {
    let seals = { let conn = db.lock(); file_seals(&conn, env_id, day) };
    for f in seals {
        if f.purged {
            continue; // déjà supprimé du hot (idempotent ; les stragglers id>max_id restent hot).
        }
        let path = file_path(cold_dir, env_id, day, f.seq);
        let ident = FileIdent { env_id, day, seq: f.seq, ts_min: f.ts_min, ts_max: f.ts_max };
        verify_parquet_rows(&path, f.expected as usize, Some(ident), pass)
            .map_err(|e| format!("fichier scellé seq {} invalide au delete (SUSPENDU): {e}", f.seq))?;
        // COMPTE (`P10.5-a`) : le chiffre publié est celui que le DELETE a RENDU, jamais `f.expected` — un
        // re-run idempotent supprime zéro ligne pour un seal qui en annonce des milliers.
        compte.lignes_retirees += delete_file_rows(db, env_id, day, f.max_id, f.lo_ts, f.lo_id, f.ts_max, f.hi_id);
        compte.fichiers_purges += 1;
        let conn = db.lock();
        let _ = conn.execute(
            "UPDATE cold_seal SET purged=1 WHERE env_id=?1 AND day=?2 AND seq=?3",
            params![env_id, day, f.seq],
        );
    }
    Ok(())
}

/// Supprime les jours-Parquet (TOUS leurs fichiers séquencés + leurs marqueurs seal) au-delà de la rétention de
/// LEUR index (FIX #4 : day_end <= now - eff_ret(env_id), jamais au seul cutoff GLOBAL). Tous les fichiers d'un
/// jour partagent le MÊME (env_id, day) -> UN index -> rétention effective NETTE. Un index à rétention plus LONGUE
/// que la globale n'est donc JAMAIS expiré prématurément (pas de perte) ; un index plus COURT n'est pas sur-retenu.
/// Bon marché (unlink par fichier). Best-effort ; une erreur d'unlink est journalisée, pas fatale.
fn expire_cold_days(db: &Arc<Mutex<Connection>>, cold_dir: &Path, n: i64, bande: &Bande) {
    // On lit TOUS les seals par-FICHIER (petite table) : (env_id, day, seq). Un jour = plusieurs lignes (une/seq).
    let all: Vec<(String, i64, i64)> = { let conn = db.lock(); all_sealed_files(&conn) };
    for (env_id, day, seq) in all {
        let r = bande.eff_ret(&env_id);
        // Expire seulement quand le jour est ENTIÈREMENT au-delà de la rétention de son index :
        // (day+1)*SECS_PER_DAY <= n - r*SECS_PER_DAY  <=>  day <= (n - r*SECS_PER_DAY)/SECS_PER_DAY - 1.
        let max_expire_day = (n - r * SECS_PER_DAY).div_euclid(SECS_PER_DAY) - 1;
        if day > max_expire_day {
            continue; // encore dans la rétention de son index -> on GARDE (jamais de suppression prématurée).
        }
        if env_id_ok(&env_id) {
            let p = file_path(cold_dir, &env_id, day, seq);
            if let Err(e) = std::fs::remove_file(&p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("[cold] unlink {} échoué: {e}", p.display());
                }
            }
        }
        // Supprime la ligne seal DE CE FICHIER (par-seq) -> quand tous les seq d'un jour expiré sont traités, le
        // jour n'a plus aucun seal (detect_aging_stall/lecteur ne le voient plus). Idempotent (un seq déjà retiré).
        let conn = db.lock();
        let _ = conn.execute("DELETE FROM cold_seal WHERE env_id=?1 AND day=?2 AND seq=?3", params![env_id, day, seq]);
    }
}
