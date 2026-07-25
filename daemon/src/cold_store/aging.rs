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
    let sql = format!(
        "SELECT id,ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields \
         FROM event WHERE env_id=?1 AND ts>=?2 AND ts<?3 AND id<=?4 AND {RETENTION_NONPURGE} \
           AND (ts>?5 OR (ts=?5 AND id>?6)) ORDER BY ts, id LIMIT ?7",
    );
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
fn max_retention(policies: &[IndexPolicy], retention_days: i64) -> i64 {
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
fn clamp_hot_window(conf: &HashMap<String, String>, max_ret: i64) -> i64 {
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
    let policies = load_index_policies(conn);
    let max_ret = max_retention(&policies, retention_days);
    n - clamp_hot_window(conf, max_ret) * SECS_PER_DAY
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
#[allow(clippy::too_many_arguments)]
pub(super) fn delete_file_rows(db: &Arc<Mutex<Connection>>, env_id: &str, day: i64, max_id: i64, lo_ts: i64, lo_id: i64, ts_max: i64, hi_id: i64) {
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
    );
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
pub(crate) fn cold_age_run(db: &Arc<Mutex<Connection>>, db_path: &str, conf: &HashMap<String, String>, n: i64, retention_days: i64) {
    // --- GATE RUNTIME : sans PLUME_COLD_TIER=1, retour immédiat (retention_run byte-identique). ---
    if cfg(conf, "PLUME_COLD_TIER", "") != "1" {
        return;
    }
    if retention_days <= 1 {
        return; // rétention globale trop courte pour distinguer une fenêtre chaude ; rien à ager.
    }

    // #18 P1.5 — RÉTENTION COLD ÉTENDUE. `cold_ret` = rétention TOTALE (défaut = retention_days -> byte-
    // identique). C'est la rétention GLOBALE effective consommée ci-dessous : eff_ret d'un env SANS policy
    // per-index retombe sur `cold_ret` (au lieu de retention_days), la découverte d'aging s'étend jusqu'à
    // `cold_ret`, et l'expiry cold retient les jour-files jusqu'à `cold_ret`. Le hard-purge hot de `event`
    // est repoussé au MÊME `cold_ret` par rollups (source unique `cold_retention_days`) -> aucune ligne
    // non-NONPURGE n'est supprimée (hot OU cold) avant SA rétention effective. Calculée TÔT : gouverne aussi
    // le seuil du dead-man's-switch (detect_aging_stall) qui doit rester joignable même si la clé manque.
    let cold_ret = cold_retention_days(conf, retention_days);

    // Legal-hold : suspension DÉLIBÉRÉE -> on s'abstient d'ager ce tick ET on NE déclenche PAS le signal de
    // retard (ce n'est PAS un stall silencieux : le hold est lui-même visible/audité). Preuves conservées hot.
    match { let conn = db.lock(); legal_hold_enforcement(&conn) } {
        HoldEnforce::NoHolds => {}
        _ => {
            eprintln!("[cold] legal-hold actif/indéterminé -> aging cold SUSPENDU ce tick (fail-safe)");
            return;
        }
    }

    // Policies per-index (#49, FIX #4) + fenêtre chaude, calculées AVANT la dérivation de clé : elles doivent
    // rester disponibles pour le dead-man's-switch même sur le chemin fail-closed (clé absente). Table absente
    // -> Vec vide -> tout retombe sur la rétention globale. ensure_cold_seal_table (idempotent) crée la table
    // de seals interrogée par detect_aging_stall. GATE COLD OFF n'atteint JAMAIS ici -> base inchangée (mode 0).
    let policies = { let conn = db.lock(); ensure_cold_seal_table(&conn); load_index_policies(&conn) };
    // Rétention EFFECTIVE d'un env_id : sa policy per-index (>0) si définie, sinon la GLOBALE ÉTENDUE (cold_ret).
    // Un index à policy propre garde EXACTEMENT sa fenêtre (jamais élargie par cold_ret ni raccourcie) ; seul
    // l'env SANS policy bénéficie de l'extension -> per-index SHORTER expire à sa policy, LONGER est honoré.
    let eff_ret = |env: &str| -> i64 {
        policies.iter().find(|p| p.retention_days > 0 && p.name == env).map(|p| p.retention_days).unwrap_or(cold_ret)
    };
    // Rétention la PLUS LONGUE applicable (GLOBALE ÉTENDUE ∪ policies) -> borne basse LARGE de découverte
    // (aucun jour éligible d'un index long NI de la bande globale étendue [retention_days..cold_ret] ne doit
    // être manqué : sans cette extension, les jours globaux entre retention_days et cold_ret ne seraient
    // jamais columnarisés et resteraient hot jusqu'au filet de sécurité à cold_ret).
    let max_ret = max_retention(&policies, cold_ret);
    // Fenêtre chaude (jours) — MÊME clamp que le reparse (H2) via `clamp_hot_window` (source unique).
    let hot_window: i64 = clamp_hot_window(conf, max_ret);

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
            return;
        }
    };

    // Racine cold PAR-TENANT (FIX #2) — dérivée du db_path du tenant, jamais du PLUME_COLD_DIR global partagé.
    let cold_dir = cold_root(conf, db_path);

    // Taille de row-group (STREAM, FIX #3). Réglable ops/tests ; défaut ROW_GROUP_ROWS ; borné.
    let rg_rows: usize = cfg(conf, "PLUME_COLD_ROWGROUP_ROWS", &ROW_GROUP_ROWS.to_string())
        .parse::<usize>()
        .unwrap_or(ROW_GROUP_ROWS)
        .clamp(1, ROW_GROUP_ROWS);
    // #18 P2b — PLAFOND de lignes PAR FICHIER (split du jour). Réglable ops/tests ; défaut COLD_FILE_MAX_ROWS ;
    // borné [1, COLD_FILE_MAX_ROWS]. Un jour de > file_cap lignes produit plusieurs fichiers séquencés bornés.
    let file_cap: usize = cfg(conf, "PLUME_COLD_FILE_MAX_ROWS", &COLD_FILE_MAX_ROWS.to_string())
        .parse::<usize>()
        .unwrap_or(COLD_FILE_MAX_ROWS)
        .clamp(1, COLD_FILE_MAX_ROWS);

    let hot_cutoff = n - hot_window * SECS_PER_DAY;
    let hi_day_excl = hot_cutoff.div_euclid(SECS_PER_DAY); // floor : jours >= celui-ci sont dans la fenêtre chaude.
    // Borne basse LARGE : rétention la plus longue (ceil). La borne PAR-ENV (plus stricte) filtre ensuite.
    let broad_lo_day = (n - max_ret * SECS_PER_DAY + SECS_PER_DAY - 1).div_euclid(SECS_PER_DAY);

    if hi_day_excl > broad_lo_day {
        // Découverte des (env_id, day) candidats sur la bande LARGE (STABLE : jours passés). EXCLUT les events
        // de contrôle (RETENTION_NONPURGE) -> jamais agés.
        let groups: Vec<(String, i64)> = {
            let conn = db.lock();
            let sql = format!(
                "SELECT env_id, ts/{SECS_PER_DAY} AS day FROM event \
                 WHERE ts>=?1 AND ts<?2 AND {RETENTION_NONPURGE} \
                 GROUP BY env_id, ts/{SECS_PER_DAY} ORDER BY env_id, day",
            );
            let lo = broad_lo_day * SECS_PER_DAY;
            let hi = hi_day_excl * SECS_PER_DAY;
            let mut out = Vec::new();
            if let Ok(mut st) = conn.prepare(&sql) {
                if let Ok(rows) = st.query_map(params![lo, hi], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                }) {
                    out = rows.flatten().collect();
                }
            }
            out
        };

        for (env_id, day) in groups {
            if !env_id_ok(&env_id) {
                continue; // fail-safe : env_id non conforme -> pas de composant de chemin, on n'âge pas.
            }
            // Borne basse PAR-ENV (FIX #4) : n'âge un jour que s'il est ENCORE dans la rétention de SON index.
            // Un jour au-delà (day < env_lo_day) est hors rétention -> laissé au hard-purge / à l'expiry (jamais
            // columnarisé pour être supprimé aussitôt).
            let r = eff_ret(&env_id);
            let env_lo_day = (n - r * SECS_PER_DAY + SECS_PER_DAY - 1).div_euclid(SECS_PER_DAY); // ceil
            if day < env_lo_day {
                continue;
            }
            if let Err(e) = age_one_day(db, db_path, &cold_dir, &env_id, day, file_cap, rg_rows, &pass) {
                eprintln!("[cold] aging {env_id}/{} échoué (lignes conservées hot): {e}", ymd_from_day(day));
            }
        }
    }

    // NETTOYAGE des jours-Parquet au-delà de la rétention de LEUR index (FIX #4). day_end <= now - eff_ret,
    // fallback GLOBAL = `cold_ret` (#18 P1.5 : un cold-file d'un env sans policy survit jusqu'à cold_ret).
    expire_cold_days(db, &cold_dir, n, cold_ret, &policies);

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
}

/// #18 P1.5 — grâce (jours) au-delà de la fenêtre chaude avant de crier au retard d'aging. Une valeur > 0
/// absorbe le jour-frontière tout juste sorti de la fenêtre chaude (que l'aging va columnariser au tick même)
/// -> le signal ne se déclenche que sur un retard NET, jamais sur le régime drainé normal.
const COLD_STALL_GRACE_DAYS: i64 = 2;

/// #18 — grâce (secondes) avant de crier au « seal cold BLOQUÉ ». Un tick sain scelle purged=0 PUIS purge
/// (purged=1) DANS le même tick ~horaire ; un purged=0 qui SURVIT des heures = phase2 coincée (VERIFY échoue
/// en boucle sur un fichier corrompu). 6 h couvre plusieurs ticks -> aucun faux positif sur le tick frontière.
pub(super) const COLD_SEAL_STUCK_GRACE_S: i64 = 6 * 3600;

/// #18 P1.5 — DÉTECTE un aging cold EN RETARD et émet (si besoin) le signal de santé. Non-fatal ; best-effort.
/// Compte les lignes non-NONPURGE HOT dont le jour est plus vieux que `hot_window + COLD_STALL_GRACE_DAYS` et
/// dont le (env_id, jour) N'A PAS de seal (ni écrit, ni en cours) — c.-à-d. des lignes qui auraient dû être
/// columnarisées mais ne l'ont pas été. > 0 -> signal (dédupé à l'heure). Requête bornée par idx_event_ts
/// (range sur `ts`) ; la sous-requête `cold_seal` est sur une PETITE table. Aucune écriture si compte == 0.
pub(super) fn detect_aging_stall(db: &Arc<Mutex<Connection>>, n: i64, hot_window: i64, cold_ret: i64) {
    let stall_hi = n - (hot_window + COLD_STALL_GRACE_DAYS) * SECS_PER_DAY; // plus vieux que la fenêtre chaude + grâce
    // BORNE BASSE = now - cold_ret : au-delà de cold_ret la donnée est HORS rétention (filet de sécurité du
    // hard-purge hot, PAS le rôle de l'aging) -> on ne la compte PAS comme « aurait dû être columnarisée »
    // (sinon un straggler résiduel près/au-delà de cold_ret, dont le seal a été expiré, ferait un faux positif).
    // La bande [now-cold_ret, now-(hot_window+grâce)) est EXACTEMENT la zone où la donnée DEVRAIT être en cold.
    let stall_lo = n - cold_ret * SECS_PER_DAY;
    if stall_hi <= stall_lo {
        return; // fenêtre chaude+grâce couvre déjà toute la rétention (cold_ret trop court) -> rien à surveiller.
    }
    let conn = db.lock();
    // NOT EXISTS (seal du (env_id, jour)) : exclut tout jour columnarisé/en-cours (drainé OU straggler-porteur).
    let sql = format!(
        "SELECT COUNT(*) FROM event e \
         WHERE e.ts >= ?1 AND e.ts < ?2 AND {RETENTION_NONPURGE} \
           AND NOT EXISTS (SELECT 1 FROM cold_seal s WHERE s.env_id=e.env_id AND s.day=e.ts/{SECS_PER_DAY})"
    );
    let lingering: i64 = conn.query_row(&sql, params![stall_lo, stall_hi], |r| r.get(0)).unwrap_or(0);
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
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT env_id||'/'||day), COALESCE(MIN(sealed_ts),0) \
             FROM cold_seal WHERE purged=0 AND sealed_ts < ?1",
            params![cutoff],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
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

/// Traite UN (env_id, day) selon la machine à états seal DEUX PHASES multi-fichiers (cf. doc de `cold_age_run`).
/// `file_cap` = plafond de lignes par fichier (split) ; `rg_rows` = taille de row-group intra-fichier. Renvoie
/// Err si l'aging n'a pas pu se compléter proprement (l'appelant journalise ; les lignes restent hot -> pas de perte).
#[allow(clippy::too_many_arguments)]
fn age_one_day(db: &Arc<Mutex<Connection>>, db_path: &str, cold_dir: &Path, env_id: &str, day: i64, file_cap: usize, rg_rows: usize, pass: &str) -> Result<(), String> {
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
                return Ok(()); // défensif : rien d'agéable (aucune ligne non-contrôle) -> pas de fichier, pas de seal.
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
                return Ok(());
            }
            let dir = day_dir(cold_dir, env_id);
            std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            write_day_files(db, db_path, cold_dir, env_id, day, max_id, 0, i64::MIN, i64::MIN, file_cap, rg_rows, pass)?;
        } else {
            // RESUME ÉCRITURE (crash EN Phase 1 : préfixe 0..k scellé, AUCUN last_file). Hot INTACT. On REPREND
            // depuis le curseur keyset du plus HAUT seq scellé, avec le max_id RELU des seals (JAMAIS re-dérivé du
            // hot — FIX #1). Les fichiers 0..k ne sont ni ré-écrits ni re-vérifiés (préfixe durable). H1 déjà passé.
            let last = seals.last().expect("seals non vide");
            let max_id = last.max_id;
            write_day_files(db, db_path, cold_dir, env_id, day, max_id, last.seq + 1, last.ts_max, last.hi_id, file_cap, rg_rows, pass)?;
        }
    }

    // ---- PHASE 2 (SUPPRESSION) : write done (fresh/resume ci-dessus ont posé last_file, ou il l'était déjà). ----
    phase2_delete(db, cold_dir, env_id, day, pass)
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
fn phase2_delete(db: &Arc<Mutex<Connection>>, cold_dir: &Path, env_id: &str, day: i64, pass: &str) -> Result<(), String> {
    let seals = { let conn = db.lock(); file_seals(&conn, env_id, day) };
    for f in seals {
        if f.purged {
            continue; // déjà supprimé du hot (idempotent ; les stragglers id>max_id restent hot).
        }
        let path = file_path(cold_dir, env_id, day, f.seq);
        let ident = FileIdent { env_id, day, seq: f.seq, ts_min: f.ts_min, ts_max: f.ts_max };
        verify_parquet_rows(&path, f.expected as usize, Some(ident), pass)
            .map_err(|e| format!("fichier scellé seq {} invalide au delete (SUSPENDU): {e}", f.seq))?;
        delete_file_rows(db, env_id, day, f.max_id, f.lo_ts, f.lo_id, f.ts_max, f.hi_id);
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
fn expire_cold_days(db: &Arc<Mutex<Connection>>, cold_dir: &Path, n: i64, global_ret: i64, policies: &[IndexPolicy]) {
    let eff_ret = |env: &str| -> i64 {
        policies.iter().find(|p| p.retention_days > 0 && p.name == env).map(|p| p.retention_days).unwrap_or(global_ret)
    };
    // On lit TOUS les seals par-FICHIER (petite table) : (env_id, day, seq). Un jour = plusieurs lignes (une/seq).
    let all: Vec<(String, i64, i64)> = { let conn = db.lock(); all_sealed_files(&conn) };
    for (env_id, day, seq) in all {
        let r = eff_ret(&env_id);
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
