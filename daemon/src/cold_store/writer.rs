//! cold_store::writer — WRITER STREAMÉ par-fichier + PHASE 1 (écriture) de l'aging : split d'un jour en fichiers
//! bornés en taille, chacun scellé DURABLEMENT (fsync+VERIFY+rename+seal) AVANT tout DELETE hot.
//!
//! LAYOUT FICHIER (#18 P2b — FICHIERS BORNÉS EN TAILLE) : un jour (env_id, jour UTC) est SPLITTÉ en N fichiers
//! BORNÉS en taille (au plus `COLD_FILE_MAX_ROWS` lignes chacun ~= 1 row-group), séquencés `NNNN` (0000, 0001, …)
//! DANS L'ORDRE `ts` croissant. MOTIVATION : le lecteur cold (P2b) DÉCHIFFRE un fichier ENTIER en RAM (le reader
//! Parquet exige un accès aléatoire au footer alors que le déchiffrement age est séquentiel) -> borner la TAILLE
//! d'un fichier borne la RAM de déchiffrement à VOLUME QUELCONQUE (un « gros jour » ne fait plus exploser la RAM :
//! il fait plus de fichiers, pas des fichiers plus gros). Le budget 2 Gio est ainsi tenu indépendamment du volume
//! quotidien. Les lignes restent GLOBALEMENT triées par `ts` sur l'ensemble du jour (partition SÉQUENTIELLE par le
//! plafond de lignes). La RAM d'ÉCRITURE est bornée à UN row-group (`rg_rows`) ; par défaut `file_cap == rg_rows`
//! -> 1 fichier = 1 row-group.
//!
//! CRASH-SAFETY — CÔTÉ ÉCRITURE (PHASE 1) : depuis le hot INTACT (aucun delete), on STREAME les N fichiers séquencés
//! par pagination keyset `(ts,id)`, chacun scellé DURABLEMENT (fsync+VERIFY+rename+seal `purged=0`) AVANT qu'AUCUN
//! hot ne soit supprimé ; la fin de Phase 1 est COMMITÉE atomiquement par le marqueur `last_file=1` sur le dernier
//! seq. Un seal N'EST écrit qu'APRÈS fsync(tmp) + `verify_parquet_rows` (décodage intégral + identité + fenêtre ts)
//! + rename + fsync(dir) -> un seal EXISTANT ⟹ le fichier est durable, complet, déchiffrable et décodable.

use super::*;
use std::fs::File;
use std::path::Path;

use parquet::file::writer::SerializedFileWriter;

/// WRITER IN-RAM (TESTS / fixtures UNIQUEMENT) : écrit `rows` comme UN SEUL fichier `seq=0` en Parquet ZSTD à
/// `path`, lignes TRIÉES PAR `ts` (tri STABLE), en row-groups de `ROW_GROUP_ROWS`. Le chemin de PRODUCTION n'utilise
/// PAS cette fonction (il STREAME + SPLITTE en fichiers bornés, cf. `write_one_file`/`write_day_files`) : elle
/// matérialise tout `rows` en RAM -> réservée aux PETITES fixtures single-file (d'où `#[cfg(test)]`).
#[cfg(test)]
pub(crate) fn write_day_parquet(path: &Path, rows: &[ColdRow], pass: &str) -> Result<usize, String> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&i| rows[i].row.ts);
    let file = File::create(path).map_err(|e| format!("création {}: {e}", path.display()))?;
    // CHIFFRÉ at-rest comme le chemin de PRODUCTION (Parquet -> writer age STREAM -> fichier) : les fixtures
    // de test produisent des jour-files chiffrés, identiques au format réel (grep-plaintext impossible).
    let out = std::io::BufWriter::new(file);
    let age_w = cold_encryptor(pass)?.wrap_output(out).map_err(|e| format!("age wrap_output {}: {e}", path.display()))?;
    let mut writer = SerializedFileWriter::new(age_w, cold_schema(), cold_writer_props()).map_err(pe)?;
    // FIX B (fixtures) — stampe la LIAISON D'IDENTITÉ (env_id, jour) DÉRIVÉE des lignes : un jour-file (même de
    // test) est par construction UN (env_id, jour) homogène -> `rows[0]` suffit. Les fixtures portent ainsi la
    // MÊME liaison que le chemin de PRODUCTION (streaming), qui, lui, la passe EXPLICITEMENT.
    // Fixture = fichier UNIQUE d'un jour -> seq=0 (single-file, `last_file`) : même liaison d'identité
    // (env,day,seq=0) que le chemin de production pour un jour tenant en un seul fichier.
    if let Some(first) = rows.first() {
        stamp_identity(&mut writer, first.row.env_id.as_deref().unwrap_or(""), first.row.ts.div_euclid(SECS_PER_DAY), 0);
    }
    for chunk in order.chunks(ROW_GROUP_ROWS) {
        let group: Vec<ColdRow> = chunk.iter().map(|&i| rows[i].clone()).collect();
        write_row_group(&mut writer, &group)?;
    }
    let age_w = writer.into_inner().map_err(pe)?; // footer Parquet écrit DANS le flux age
    let mut out = age_w.finish().map_err(|e| format!("age finish {}: {e}", path.display()))?; // dernier chunk + tag
    std::io::Write::flush(&mut out).map_err(|e| format!("flush {}: {e}", path.display()))?;
    Ok(rows.len())
}

/// WRITER IN-RAM MULTI-ROW-GROUPS (TESTS UNIQUEMENT, #18 P3) : comme `write_day_parquet` mais chunke en
/// row-groups de `rg_rows` lignes (au lieu de `ROW_GROUP_ROWS`) -> fabrique des fichiers MULTI-ROW-GROUPS avec
/// PEU de lignes, sur des plages `ts`/dims contrôlées par groupe. Sert à exercer l'ÉLAGAGE ROW-GROUP (pushdown
/// P3) : les lignes restent TRIÉES par `ts` (invariant writer), donc des `ts` monotones donnent des row-groups à
/// plages `ts` DISJOINTES (une requête sélective en saute la plupart). Mêmes props writer que la production
/// (`cold_writer_props` -> stats CHUNK min/max par groupe) -> le pushdown lit les MÊMES statistiques qu'en prod.
#[cfg(test)]
pub(crate) fn write_day_parquet_rg(path: &Path, rows: &[ColdRow], pass: &str, rg_rows: usize) -> Result<usize, String> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&i| rows[i].row.ts);
    let file = File::create(path).map_err(|e| format!("création {}: {e}", path.display()))?;
    let out = std::io::BufWriter::new(file);
    let age_w = cold_encryptor(pass)?.wrap_output(out).map_err(|e| format!("age wrap_output {}: {e}", path.display()))?;
    let mut writer = SerializedFileWriter::new(age_w, cold_schema(), cold_writer_props()).map_err(pe)?;
    if let Some(first) = rows.first() {
        stamp_identity(&mut writer, first.row.env_id.as_deref().unwrap_or(""), first.row.ts.div_euclid(SECS_PER_DAY), 0);
    }
    for chunk in order.chunks(rg_rows.max(1)) {
        let group: Vec<ColdRow> = chunk.iter().map(|&i| rows[i].clone()).collect();
        write_row_group(&mut writer, &group)?;
    }
    let age_w = writer.into_inner().map_err(pe)?;
    let mut out = age_w.finish().map_err(|e| format!("age finish {}: {e}", path.display()))?;
    std::io::Write::flush(&mut out).map_err(|e| format!("flush {}: {e}", path.display()))?;
    Ok(rows.len())
}

/// MÉTADONNÉES d'UN fichier cold écrit (renvoyées par `write_one_file`) : compte + bornes utilisées par le seal
/// par-fichier (index d'élagage `ts_min/ts_max` + curseur keyset HAUT `(ts_max, hi_id)` qui borne le DELETE de
/// CE fichier et sert de curseur BAS au fichier suivant). `ts_min`/`ts_max` = 1re/dernière ligne (fichier trié
/// par `ts`) ; `hi_id` = id de la DERNIÈRE ligne au sens keyset `(ts,id)` (PAS le max id du fichier : un backdaté
/// d'id haut mais ts bas est trié AVANT -> l'ordre keyset borne exactement la tranche, cf. `delete_file_rows`).
pub(super) struct FileMeta {
    pub(super) row_count: usize,
    pub(super) ts_min: i64,
    pub(super) ts_max: i64,
    pub(super) hi_id: i64,
    /// #28 PHASE B — stats/bloom d'élagage dimensionnel calculées SUR LES LIGNES DE CE FICHIER (à l'écriture,
    /// depuis les colonnes typées de l'EventRow -> générique). Scellées dans `cold_seal.dim_stats`.
    pub(super) dim_stats: DimStats,
}

/// WRITER STREAMÉ D'UN SEUL FICHIER (#18 P2b, FIX #3) — UNITÉ PER-FICHIER, sans état mutable partagé avec les
/// autres fichiers du jour (seams propres pour le lecteur PARALLÈLE-READY P2b : une future unité de LECTURE
/// prendra symétriquement une ligne de seal `{seq, ts_min, ts_max, lo/hi, max_id}` + la clé et décodera CE
/// fichier INDÉPENDAMMENT). Écrit à `path` AU PLUS `file_cap` lignes du jour (env_id, day), STRICTEMENT après
/// le curseur keyset `(lo_ts, lo_id)`, en NE MATÉRIALISANT JAMAIS plus d'UN row-group (`rg_rows` lignes) en RAM.
/// Borne `id <= max_id` (FIX #1) + NONPURGE (verrou writer relâché ENTRE les pages -> l'ingest s'intercale).
/// STAMPE la liaison d'identité (env_id, jour, `seq`) DANS le flux age (footer chiffré) -> VERIFY récuse tout
/// swap jour/env/seq. Renvoie `Ok(None)` si AUCUNE ligne au-delà du curseur (jour épuisé -> pas de fichier créé,
/// aucun octet écrit) ; sinon `Ok(Some(FileMeta))`. L'ensemble `{env/day/NONPURGE, id<=max_id, keyset>curseur}`
/// est IMMUABLE pendant la Phase 1 (aucun delete avant `last_file`) -> lecture déterministe, Σ = compte du footer.
#[allow(clippy::too_many_arguments)]
pub(super) fn write_one_file(
    path: &Path,
    db: &Arc<Mutex<Connection>>,
    env_id: &str,
    day: i64,
    seq: i64,
    max_id: i64,
    lo_ts: i64,
    lo_id: i64,
    file_cap: usize,
    rg_rows: usize,
    pass: &str,
) -> Result<Option<FileMeta>, String> {
    let day_start = day * SECS_PER_DAY;
    let day_end = day_start + SECS_PER_DAY;
    // 1re page AVANT toute création de fichier : si le jour est épuisé au-delà du curseur -> Ok(None) (jamais de
    // fichier vide sur disque, jamais de seal orphelin). LIMIT = min(rg_rows, file_cap) (borne double : RAM + taille).
    let first_lim = rg_rows.min(file_cap).max(1);
    let mut page = read_cold_page(db, env_id, day_start, day_end, max_id, lo_ts, lo_id, first_lim)?;
    if page.is_empty() {
        return Ok(None);
    }
    // CHIFFREMENT AT-REST (#18) : Parquet -> writer age STREAM (AEAD) -> fichier. Le fichier ne contient QUE
    // l'en-tête age (SANS données) puis du CHIFFRÉ : AUCUN octet Parquet EN CLAIR n'atteint le disque. Nonce
    // par-fichier ALÉATOIRE + compteur de chunk d'age -> nonces AEAD uniques.
    let file = File::create(path).map_err(|e| format!("création {}: {e}", path.display()))?;
    let out = std::io::BufWriter::new(file);
    let age_w = cold_encryptor(pass)?.wrap_output(out).map_err(|e| format!("age wrap_output {}: {e}", path.display()))?;
    let mut writer = SerializedFileWriter::new(age_w, cold_schema(), cold_writer_props()).map_err(pe)?;
    stamp_identity(&mut writer, env_id, day, seq);

    let ts_min = page[0].1.row.ts; // 1re ligne (ordre ts,id) -> min ts du fichier (index d'élagage bas).
    // #28 PHASE B — accumulateur des stats/bloom d'élagage dimensionnel sur TOUTES les lignes du fichier (mis à
    // jour ligne-à-ligne avant que la page ne soit consommée en row-group). GÉNÉRIQUE (dims universelles typées).
    let mut dim_builder = DimStatsBuilder::new();
    // Curseur keyset HAUT du fichier — DÉFINITIVEMENT assigné dans la boucle (qui s'exécute >=1 fois, page
    // non-vide) avant tout `break` -> pas d'initialiseur mort (`lo_ts`/`lo_id` ne servent qu'à la 1re lecture).
    let mut last_ts;
    let mut last_id;
    let mut written = 0usize;
    loop {
        // Avance le curseur au dernier (ts,id) de la page (rows ordonnées ts,id -> le dernier est le max keyset).
        let last = page.last().unwrap();
        last_ts = last.1.row.ts;
        last_id = last.0;
        let group: Vec<ColdRow> = page.into_iter().map(|(_, r)| r).collect();
        for r in &group {
            dim_builder.add_row(r); // stats/bloom AVANT l'écriture du groupe (mêmes lignes, même fichier).
        }
        write_row_group(&mut writer, &group)?;
        written += group.len();
        if written >= file_cap {
            break; // FICHIER PLEIN (plafond de taille atteint) -> on scelle et le fichier suivant reprend le curseur.
        }
        // Page suivante, LIMIT bornée par le RESTE du plafond de fichier ET la taille de row-group.
        let lim = rg_rows.min(file_cap - written).max(1);
        page = read_cold_page(db, env_id, day_start, day_end, max_id, last_ts, last_id, lim)?;
        if page.is_empty() {
            break; // fin du jour -> ce fichier est le dernier (le driver posera `last_file`).
        }
    }
    // FINALISATION : footer Parquet écrit DANS le flux age (`into_inner`), clôture du flux age (dernier chunk +
    // tag AEAD via `finish`), flush du BufWriter. (L'appelant fsync + VERIFY avant tout DELETE hot.)
    let age_w = writer.into_inner().map_err(pe)?;
    let mut out = age_w.finish().map_err(|e| format!("age finish {}: {e}", path.display()))?;
    std::io::Write::flush(&mut out).map_err(|e| format!("flush {}: {e}", path.display()))?;
    Ok(Some(FileMeta { row_count: written, ts_min, ts_max: last_ts, hi_id: last_id, dim_stats: dim_builder.finish() }))
}

/// fsync durable d'un fichier déjà écrit (ré-ouvre + `sync_all` : force le flush des pages sales sur disque).
pub(super) fn fsync_file(path: &Path) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("fsync open {}: {e}", path.display()))?;
    f.sync_all().map_err(|e| format!("fsync {}: {e}", path.display()))
}

/// fsync du RÉPERTOIRE (rend le rename/create d'entrée durable après un crash).
pub(super) fn fsync_dir(dir: &Path) -> Result<(), String> {
    let f = File::open(dir).map_err(|e| format!("fsync dir open {}: {e}", dir.display()))?;
    f.sync_all().map_err(|e| format!("fsync dir {}: {e}", dir.display()))
}

/// PHASE 1 (écriture) d'un jour : écrit+scelle les fichiers séquencés DEPUIS `start_seq`/curseur `(lo_ts, lo_id)`
/// jusqu'à épuisement du hot BORNÉ `id<=max_id`, chacun DURABLE (fsync+VERIFY+rename+seal `purged=0`) AVANT tout
/// delete, puis COMMIT la fin de Phase 1 via `last_file=1` sur le plus HAUT seq. Aucun delete ici (hot intact).
/// Idempotent au resume : appelée avec le curseur du dernier fichier scellé -> reprend proprement sans trou/dup.
///
/// PRÉCONDITION (côté ÉCRITURE du contrat d'ordonnancement — le pendant de la précondition de `phase2_delete`) : un
/// seal N'EST écrit (`INSERT ... cold_seal ... purged=0`) qu'APRÈS fsync(tmp) + `verify_parquet_rows` (décodage
/// intégral + identité (env,day,seq) + fenêtre ts) + rename + fsync(dir). Autrement dit : un seal EXISTANT ⟹ le
/// fichier est durable, complet, déchiffrable et décodable. Ne JAMAIS déplacer l'écriture du seal AVANT le VERIFY :
/// c'est l'ancre qui autorise plus tard `delete_file_rows`/`phase2_delete` à supprimer le hot. À préserver au refactor.
#[allow(clippy::too_many_arguments)]
pub(super) fn write_day_files(
    db: &Arc<Mutex<Connection>>,
    db_path: &str,
    cold_dir: &Path,
    env_id: &str,
    day: i64,
    max_id: i64,
    start_seq: i64,
    mut lo_ts: i64,
    mut lo_id: i64,
    file_cap: usize,
    rg_rows: usize,
    pass: &str,
) -> Result<(), String> {
    let dir = day_dir(cold_dir, env_id);
    let mut seq = start_seq;
    loop {
        let final_path = file_path(cold_dir, env_id, day, seq);
        let tmp = final_path.with_extension("parquet.tmp");
        // Écrit UN fichier (≤ file_cap lignes) depuis le curseur keyset. None -> jour épuisé (aucun fichier créé).
        let meta = match write_one_file(&tmp, db, env_id, day, seq, max_id, lo_ts, lo_id, file_cap, rg_rows, pass)? {
            Some(m) => m,
            None => break,
        };
        fsync_file(&tmp)?;
        // VERIFY-DÉCHIFFRE+DÉCODE + IDENTITÉ (env,day,seq)+fenêtre ts AVANT rename (FIX #5 + FIX B/P2b) : on ne
        // publie/scelle un fichier que prouvé complet, déchiffrable ET décodable. Sinon rien n'est renommé/scellé.
        let ident = FileIdent { env_id, day, seq, ts_min: meta.ts_min, ts_max: meta.ts_max };
        if let Err(e) = verify_parquet_rows(&tmp, meta.row_count, Some(ident), pass) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("verify tmp seq {seq} échoué (rien supprimé): {e}"));
        }
        std::fs::rename(&tmp, &final_path)
            .map_err(|e| format!("rename {}->{}: {e}", tmp.display(), final_path.display()))?;
        fsync_dir(&dir)?;
        // SEAL DURABLE du fichier (purged=0, last_file=0) AVANT tout DELETE — porte l'index d'élagage (ts_min/ts_max),
        // la fenêtre keyset (lo/hi) qui bornera son delete, et le max_id GLOBAL (FIX #1). REPLACE : idempotent si un
        // seq est ré-écrit au resume (crash post-rename pré-seal) — même contenu, même seal.
        {
            let conn = db.lock();
            // #28 PHASE B — scelle AUSSI les stats/bloom d'élagage dimensionnel (BLOB `dim_stats`) DANS la MÊME
            // ligne de seal, écrites APRÈS le VERIFY (donc un seal EXISTANT ⟹ fichier durable+stats cohérentes).
            // INSERT OR REPLACE reste idempotent au resume (même contenu -> même stats -> même blob).
            conn.execute(
                "INSERT OR REPLACE INTO cold_seal(env_id,day,seq,expected_rows,sealed_ts,purged,max_id,ts_min,ts_max,lo_ts,lo_id,hi_id,last_file,dim_stats) \
                 VALUES(?1,?2,?3,?4,?5,0,?6,?7,?8,?9,?10,?11,0,?12)",
                params![env_id, day, seq, meta.row_count as i64, now(), max_id, meta.ts_min, meta.ts_max, lo_ts, lo_id, meta.hi_id, meta.dim_stats.encode()],
            )
            .map_err(pe)?;
        }
        // Curseur keyset HAUT de ce fichier -> curseur BAS (exclusif) du suivant. Fenêtres DISJOINTES + CONTIGUËS.
        lo_ts = meta.ts_max;
        lo_id = meta.hi_id;
        seq += 1;
        if meta.row_count < file_cap {
            break; // dernier fichier (page finale non pleine == fin du jour) -> pas de fichier suivant à tenter.
        }
    }
    // COMMIT DE FIN DE PHASE 1 (atomique) : `last_file=1` sur le plus HAUT seq du jour. Couvre AUSSI le resume où
    // AUCUN nouveau fichier n'a été écrit (crash juste avant ce marqueur) : on pose alors le marqueur sur le seq
    // existant. Sans aucun fichier du tout (jour vide) -> UPDATE no-op (0 ligne) -> Phase 2 ne trouvera rien.
    //
    // #28 PHASE A — SIDECAR ROLLUP COLD, COMMITÉ DANS LA MÊME TRANSACTION que `last_file=1` (crash-atomique) :
    // soit les deux sont durables, soit AUCUN. Le hot est INTACT ici (PHASE 2/delete ne démarre qu'après
    // `last_file=1`).
    //
    // PERF (#28 Phase A, MED) : le SCAN d'agrégation LOURD tourne HORS du verrou writer, via une connexion
    // READ-ONLY séparée sur le hot INTACT (`compute_cold_rollup`) -> l'ingest CONTINUE sous WAL pendant le scan.
    // L'ensemble agé est FROZEN par `id<=max_id` (l'ingest concurrent porte `id>max_id`, exclu) -> le scan est
    // STABLE sans le verrou d'écriture. Puis SEULE une ÉCRITURE COURTE (delete-jour + insert du résultat
    // matérialisé, top-N-borné) reste DANS la tx `BEGIN IMMEDIATE` : le verrou writer n'est tenu que le temps du
    // bulk-insert, plus du scan. REPLI : si le scan lock-free échoue (clé/chemin indisponible), on RETOMBE sur
    // `seal_cold_rollup` (calcul sous verrou, INSERT...SELECT) DANS la même tx -> le scellement a TOUJOURS un
    // chemin correct, jamais un seal cassé. Les DEUX chemins produisent le MÊME résultat (même corps SQL) et sont
    // idempotents (delete-jour-puis-insert) -> re-run (resume Phase 1) recalcule à l'identique. Une fois
    // `last_file=1` durable, `age_one_day` court-circuite la Phase 1 -> ce rollup n'est JAMAIS recalculé sur un
    // hot rétréci. Échec de la tx -> ROLLBACK (ni rollup ni last_file) -> hot intact, retenté au tick suivant.
    let materialized = match crate::rollups::compute_cold_rollup(db, db_path, env_id, day, max_id) {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!("[cold] scan rollup lock-free indisponible ({e}) -> repli calcul sous verrou (correct, plus lent)");
            None
        }
    };
    let conn = db.lock();
    let committed = (|| -> Result<(), String> {
        conn.execute_batch("BEGIN IMMEDIATE").map_err(pe)?;
        match &materialized {
            Some(m) => crate::rollups::apply_cold_rollup(&conn, env_id, day, m)?,
            None => crate::rollups::seal_cold_rollup(&conn, env_id, day, max_id)?,
        }
        conn.execute(
            "UPDATE cold_seal SET last_file=1 WHERE env_id=?1 AND day=?2 AND seq=(SELECT MAX(seq) FROM cold_seal WHERE env_id=?1 AND day=?2)",
            params![env_id, day],
        )
        .map_err(pe)?;
        conn.execute_batch("COMMIT").map_err(pe)?;
        Ok(())
    })();
    if let Err(e) = committed {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(format!("commit fin de Phase 1 + sidecar rollup cold échoué (hot intact, retry au prochain tick): {e}"));
    }
    Ok(())
}
