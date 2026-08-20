//! cold_store::reader — LE CÔTÉ LECTURE : P2b hydrate (primitive INTERNE, lignes cold BRUTES) + P3 union hot∪cold
//! MASQUÉE (câblage du lecteur DANS le chemin de requête, DERRIÈRE le masquage + l'authorizer).
//!
//! SÉCURITÉ (invariant NON NÉGOCIABLE — MASQUAGE DIFFÉRÉ À P3) : `hydrate_cold` produit des lignes cold BRUTES,
//! NON MASQUÉES, dans une table SQLite ÉPHÉMÈRE EN MÉMOIRE. Le masquage de champs (#45) ET l'authorizer DENY sont
//! appliqués PLUS TARD (P3) quand le GXQL s'exécute sur l'UNION hot∪cold. `hydrate_cold` N'EST DONC JAMAIS câblée
//! dans un chemin de requête utilisateur (query_exec / /api/query / un handler / une route) : exposer ces lignes
//! brutes = fuite de données non masquées. Cette fonction est une PRIMITIVE ; c'est P3 (`open_cold_union`) qui la
//! consommera DERRIÈRE le masquage.
//!
//! CRUX SÉCURITÉ P3 (invariant NON NÉGOCIABLE) : les lignes cold ne deviennent joignables par un utilisateur QU'À
//! travers le MASQUAGE de champs (#45) + l'AUTHORIZER DENY EXISTANTS, appliqués aux lignes cold EXACTEMENT comme
//! aux lignes hot. On n'y arrive PAS en ré-implémentant le masquage : on fait passer les lignes cold par le MÊME
//! SQL compilé (une seule fois, via le MÊME `SqliteDialect` + la MÊME `FieldMaskSet`) et le MÊME authorizer que le
//! hot (une VUE TEMP `event` = union masquée-parité qui SHADOWE `main.event`).
//!
//! ISOLATION PAR-TENANT : le lecteur dérive la clé AEAD (`cold_aead_passphrase`) ET la racine cold (`cold_root`) du
//! MÊME `db_path` que le writer -> tenant T lit avec la clé de T sous la racine cold de T. FAIL-CLOSED sur
//! corruption : si UN fichier sélectionné est corrompu/illisible/à mauvaise clé/à identité étrangère, `hydrate_cold`
//! ÉCHOUE (Err) — JAMAIS de résultat cold partiel silencieux.

use super::*;
use std::path::Path;

use parquet::column::reader::{ColumnReader, ColumnReaderImpl};
use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::metadata::RowGroupMetaData;
use parquet::file::reader::{FileReader, RowGroupReader};

// ====================================================================================================
// LECTEUR MINIMAL (TESTS UNIQUEMENT) — round-trip du writer. Ce N'EST PAS le reader de requête (P2/P3) :
// il itère les lignes via l'API `record` et reconstruit `ColdRow` par nom de colonne pour prouver la
// fidélité (toutes colonnes + JSON `fields` intacts). Compilé seulement en test.
// ====================================================================================================
#[cfg(test)]
pub(crate) fn read_day_parquet(path: &Path, pass: &str) -> Result<Vec<ColdRow>, String> {
    use parquet::record::Field;
    let reader = open_cold_reader(path, pass)?; // déchiffre -> Bytes -> décode (round-trip du format chiffré)
    let mut out = Vec::new();
    for rec in reader.get_row_iter(None).map_err(pe)? {
        let row = rec.map_err(pe)?;
        let mut cr = ColdRow::default();
        for (name, field) in row.get_column_iter() {
            let as_str = |f: &Field| -> Option<String> {
                match f {
                    Field::Str(s) => Some(s.clone()),
                    Field::Null => None,
                    _ => None,
                }
            };
            let as_long = |f: &Field| -> Option<i64> {
                match f {
                    Field::Long(v) => Some(*v),
                    _ => None,
                }
            };
            match name.as_str() {
                "ts" => cr.row.ts = as_long(field).unwrap_or(0),
                "severity" => cr.row.severity = as_long(field).unwrap_or(0),
                "source" => cr.row.source = as_str(field).unwrap_or_default(),
                "category" => cr.row.category = as_str(field).unwrap_or_default(),
                "host" => cr.row.host = as_str(field),
                "src_ip" => cr.row.src_ip = as_str(field),
                "dst_ip" => cr.row.dst_ip = as_str(field),
                "url" => cr.row.url = as_str(field),
                "xff" => cr.xff = as_str(field),
                "dedup" => cr.row.dedup = as_str(field),
                "engagement_id" => cr.row.engagement_id = as_str(field).unwrap_or_default(),
                "origin" => cr.row.origin = as_str(field).unwrap_or_default(),
                "env_id" => cr.row.env_id = as_str(field),
                "message" => cr.row.message = as_str(field).unwrap_or_default(),
                "fields" => cr.row.fields = as_str(field),
                _ => {}
            }
        }
        out.push(cr);
    }
    Ok(out)
}

// ====================================================================================================
// #18 P2b — READER / HYDRATE (primitive INTERNE, hot∪cold : hydratation des lignes cold en fenêtre).
// ----------------------------------------------------------------------------------------------------
// POLITIQUE CORRUPTION / COUVERTURE INCOMPLÈTE (choix : FAIL-CLOSED) : si UN fichier de l'ensemble SÉLECTIONNÉ
// est corrompu / illisible / à mauvaise clé / à identité (env,day,seq) ou fenêtre ts étrangère, `hydrate_cold`
// ÉCHOUE (Err) — JAMAIS de résultat cold partiel silencieux. Un SOC qui reçoit une réponse INCOMPLÈTE sans le
// savoir prend de mauvaises décisions ; échouer bruyamment (l'appelant P3 fait échouer la requête) est le seul
// comportement sûr. (Alternative « loud-skip + flag incomplet » rejetée : un flag est trop facile à ignorer en
// aval ; l'échec dur force le traitement de l'anomalie.)
//
// PARALLÉLISME (borné, frugal, pur-std — AUCUNE dép lourde ; rayon N'EST PAS au projet) : décodage+déchiffrement
// = CPU-lourd et INDÉPENDANT par fichier -> N workers `std::thread::scope` tirent les fichiers sélectionnés via un
// compteur atomique (ordre d'index croissant), déchiffrent+décodent+filtrent leur fichier en un lot de lignes, et
// POUSSENT `(index, lot)` dans un `sync_channel` BORNÉ (back-pressure = borne RAM). Un UNIQUE inséreur (thread
// principal du scope) draine le canal, RÉORDONNE par index (buffer de réordonnancement borné par le degré, car le
// compteur atomique garantit une avance d'index <= degré) et insère SÉRIELLEMENT dans `cold_event` (SQLite
// n'aime pas les écrivains concurrents). DÉTERMINISME : le contenu de `cold_event` est IDENTIQUE quel que soit le
// degré — l'ordre d'insertion CANONIQUE = (day, seq, position-dans-fichier), reconstruit par le réordonnancement,
// jamais l'ordre d'achèvement des workers (aucune horloge/aléa ne fuit dans le résultat). Prouvé par test (degré
// 1 vs 4 -> dumps identiques, rowid inclus).
//
// BORNE RAM (budget 2 Gio) : ≈ degré × (UN fichier déchiffré ~32 Mio + ses lignes en-fenêtre matérialisées, <=
// COLD_FILE_MAX_ROWS) + buffer de réordonnancement (<= degré fichiers) + le plafond hydraté (`cold_hydrate_row_cap`,
// = PLUME_QUERY_MAX). Degré défaut CONSERVATEUR (`min(available_parallelism-2, 4)` clampé >= 1) -> le plancher
// 2 Gio tient. Un « gros jour » ne fait PAS exploser la RAM : il fait PLUS de fichiers bornés, pas de fichiers
// plus gros (invariant writer P2b), donc chaque unité par-fichier reste bornée.

/// Colonnes cold PROJETABLES = les 15 colonnes RÉELLEMENT stockées en Parquet (ORDRE CANONIQUE == `cold_schema`,
/// fin -> gros). `id` (rowid hot) N'EST PAS stocké en cold -> non projetable (dans `cold_event` il redevient un
/// rowid auto). `needed_cols` DOIT être un sous-ensemble de cette liste (sinon Err fail-closed).
pub(super) const PARQUET_COLS: [&str; 15] = [
    "ts", "severity", "source", "category", "host", "src_ip", "dst_ip", "url", "xff", "dedup",
    "engagement_id", "origin", "env_id", "message", "fields",
];

/// Schéma de `cold_event` — MÊMES colonnes/ORDRE que la table `event` LIVE (base `db/schema.sql` + ALTER v2
/// src_ip/dst_ip/url/xff) -> P3 peut ATTACH + UNION hot∪cold sans réconciliation de colonnes. Contraintes
/// RELÂCHÉES (pas de NOT NULL / UNIQUE / DEFAULT) : la table est ÉPHÉMÈRE et la PROJECTION laisse les colonnes
/// NON demandées à NULL (une NOT NULL les ferait échouer). `id INTEGER PRIMARY KEY` = rowid auto (les lignes
/// cold ne portent pas d'id) -> assigné dans l'ordre d'insertion CANONIQUE -> déterministe.
const COLD_EVENT_DDL: &str = "CREATE TABLE cold_event(\
     id INTEGER PRIMARY KEY, ts INTEGER, source TEXT, category TEXT, severity INTEGER, host TEXT, \
     message TEXT, fields TEXT, dedup TEXT, env_id TEXT, origin TEXT, engagement_id TEXT, \
     src_ip TEXT, dst_ip TEXT, url TEXT, xff TEXT)";

/// PLAFOND de lignes HYDRATÉES (fail-safe) = MÊME budget que le row-cap des requêtes HOT interactives
/// (`PLUME_QUERY_MAX` dans query_exec : défaut 5000, borné ]0, 100000]). Au-delà -> TRONCATURE + signal
/// (`ColdHydrate.truncated=true`), JAMAIS une réponse incomplète silencieuse. SOURCE unique dupliquée VOLONTAI-
/// REMENT (query_exec n'expose pas d'accesseur) ; garder les deux synchronisés.
pub(super) fn cold_hydrate_row_cap() -> usize {
    std::env::var("PLUME_QUERY_MAX").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0 && n <= 100_000).unwrap_or(5000)
}

/// Degré de parallélisme du LECTEUR cold (#18 P2b, PARTAGÉ avec le décode vectorisé P6) — knob
/// `PLUME_COLD_READ_PARALLELISM`. Défaut CONSERVATEUR (plancher 2 Gio sûr) : `min(available_parallelism-2, 4)`
/// clampé >= 1. Une valeur explicite est clampée [1, 64] (garde-fou). Le degré effectif est ensuite re-clampé au
/// nombre de fichiers sélectionnés par l'appelant. RÉUTILISÉ VERBATIM par le chemin vectorisé (planner P6) -> même
/// borne RAM 2Go-safe (`degree` fichiers déchiffrés EN VOL au plus) sur les DEUX chemins alternatifs (jamais
/// simultanés pour une même requête). Ops n'a qu'UN seul knob à régler.
pub(super) fn cold_read_parallelism() -> usize {
    if let Some(v) = std::env::var("PLUME_COLD_READ_PARALLELISM").ok().and_then(|s| s.trim().parse::<usize>().ok()) {
        return v.clamp(1, 64);
    }
    let avail = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    avail.saturating_sub(2).min(4).max(1)
}

// ====================================================================================================
// #18 P1 — DÉCODE COLONNAIRE BAS-NIVEAU (remplace la Row API dans le chemin CHAUD `decode_one_file`).
// ----------------------------------------------------------------------------------------------------
// La Row API (`get_row_iter` -> un `Row` boxé + un `Field` par LIGNE×COLONNE, puis `get_column_iter`) matérialise
// des millions de petits objets : sur 800k lignes c'était ~84% du temps de requête (POC). ICI on lit chaque
// ROW-GROUP colonne par colonne via `ColumnReader::read_records` (batch = TOUT le groupe d'un coup) dans des
// buffers TYPÉS (`Vec<i64>` / `Vec<ByteArray>`), puis on transpose en lignes. RAM BORNÉE : on ne matérialise
// jamais plus d'UN row-group (writer P2b : fichier <= COLD_FILE_MAX_ROWS, groupe <= ROW_GROUP_ROWS). Les
// DEF-LEVELS pilotent la reconstruction `Option<..>` des colonnes OPTIONAL (def==0 -> NULL, def==1 -> valeur
// suivante) — une absence n'est JAMAIS une chaîne vide. Encodages (dictionary/plain/RLE) gérés par le décodeur
// bas-niveau ; on ne réassemble que les valeurs dans l'ordre. PARITÉ BYTE-À-BYTE avec la Row API prouvée par
// `columnar_decode_parity` (oracle = `read_day_parquet`, qui garde `get_row_iter`).

/// Colonnes REQUIRED du schéma cold (`cold_schema` : max def level 0 -> AUCUN def-level, valeurs contiguës ==
/// lignes). Le COMPLÉMENT est OPTIONAL (def-levels 0/1). DOIT rester synchro avec `cold_schema` (writer).
fn cold_col_required(name: &str) -> bool {
    matches!(name, "ts" | "severity" | "source" | "category" | "engagement_id" | "origin" | "message")
}

/// `ByteArray` -> `String` en UTF-8 STRICT — MÊME conversion que la Row API (`convert_byte_array` :
/// `String::from_utf8(data)`) -> parité exacte (mêmes octets -> même String, même échec sur non-UTF8).
fn ba_to_string(ba: &ByteArray) -> Result<String, String> {
    String::from_utf8(ba.data().to_vec()).map_err(|e| format!("cold colonnaire: BYTE_ARRAY non-UTF8: {e}"))
}

// ====================================================================================================
// #18 P2 — ColumnBatch : les BUFFERS COLONNES TYPÉS d'UN row-group (la représentation NATIVE que le moteur
// vectorisé balaye SANS jamais matérialiser de lignes ni passer par SQLite). STREAMING : un ColumnBatch par
// row-group, jamais tout le fichier en RAM (writer P2b : fichier <= COLD_FILE_MAX_ROWS, groupe <= ROW_GROUP_ROWS).
// La transpose column-major -> row-major (`ColdRow`/`Value`, chemin P1/hydrate) devient UN CONSOMMATEUR de
// ColumnBatch (`into_value_rows`) -> le décodeur P1 est INCHANGÉ dans son RÉSULTAT (parité prouvée par les tests
// P1 existants qui passent tous par ce décode) et le fallback hydrate-SQLite reste intact.
// ----------------------------------------------------------------------------------------------------

/// Buffer typé d'UNE colonne d'un row-group. `I64` = colonne INT64 REQUIRED (`ts`/`severity` : le schéma cold
/// n'a AUCUN INT64 optionnel -> jamais de NULL ici). `Str` = colonne BYTE_ARRAY/UTF8 : `Option` -> le NULL est
/// PRÉSERVÉ via les def-levels (REQUIRED -> jamais `None` ; OPTIONAL -> `None` == absence, pas chaîne vide).
pub(super) enum ColData {
    I64(Vec<i64>),
    Str(Vec<Option<String>>),
}

impl ColData {
    pub(super) fn len(&self) -> usize {
        match self {
            ColData::I64(v) => v.len(),
            ColData::Str(v) => v.len(),
        }
    }
}

/// Buffers colonnes d'UN row-group (unité de streaming vectorisé). `names` == colonnes décodées (ordre canonique
/// de `PARQUET_COLS`) ; `cols` aligné positionnellement sur `names`. Toutes les colonnes portent `nrows` valeurs.
pub(super) struct ColumnBatch {
    pub(super) nrows: usize,
    pub(super) names: Vec<&'static str>,
    pub(super) cols: Vec<ColData>,
}

impl ColumnBatch {
    /// Référence typée d'une colonne décodée (par nom). `None` si la colonne n'a pas été décodée dans ce batch.
    pub(super) fn col(&self, name: &str) -> Option<&ColData> {
        self.names.iter().position(|n| *n == name).map(|i| &self.cols[i])
    }

    /// CONSOMMATEUR P1/hydrate : TRANSPOSE column-major -> row-major en `Value`, APPENDANT à `out`. Reproduit
    /// EXACTEMENT l'ancienne transpose de `decode_columnar` (déplacement des `String`, aucune copie ; ordre
    /// positionnel == `names`) -> parité P1 byte-à-byte conservée.
    pub(super) fn into_value_rows(self, out: &mut Vec<Vec<rusqlite::types::Value>>) {
        use rusqlite::types::Value;
        let ncol = self.names.len();
        let base = out.len();
        for _ in 0..self.nrows {
            out.push(Vec::with_capacity(ncol));
        }
        for col in self.cols.into_iter() {
            match col {
                ColData::I64(v) => {
                    for (r, x) in v.into_iter().enumerate() {
                        out[base + r].push(Value::Integer(x));
                    }
                }
                ColData::Str(v) => {
                    for (r, x) in v.into_iter().enumerate() {
                        out[base + r].push(match x {
                            Some(s) => Value::Text(s),
                            None => Value::Null,
                        });
                    }
                }
            }
        }
    }
}

/// Lit INTÉGRALEMENT un chunk INT64 (le row-group courant) en `nrows` `i64` typés, EN UN SEUL passage. Cold n'a
/// que des INT64 REQUIRED (`ts`/`severity`) -> valeurs contiguës == lignes, AUCUN def-level. Un INT64 OPTIONAL
/// serait une désynchro schéma/décodeur -> Err fail-closed (ColData::I64 ne porte pas de NULL, par construction).
fn read_i64_col_typed(r: &mut ColumnReaderImpl<Int64Type>, nrows: usize, required: bool) -> Result<ColData, String> {
    if !required {
        return Err("cold colonnaire: colonne INT64 OPTIONAL inattendue (schéma cold: ts/severity REQUIRED)".into());
    }
    let mut vals: Vec<i64> = Vec::with_capacity(nrows);
    let mut records = 0usize;
    while records < nrows {
        let (rec, _v, _l) = r.read_records(nrows - records, None, None, &mut vals).map_err(pe)?;
        if rec == 0 {
            break; // plus de page (défensif : ne devrait pas arriver avant nrows sur un groupe complet).
        }
        records += rec;
    }
    if records != nrows {
        return Err(format!("cold colonnaire: INT64 {records} lignes lues != {nrows} attendues"));
    }
    if vals.len() != nrows {
        return Err(format!("cold colonnaire: INT64 requis {} valeurs != {nrows}", vals.len()));
    }
    Ok(ColData::I64(vals))
}

/// Lit INTÉGRALEMENT un chunk BYTE_ARRAY (UTF8) du row-group courant en `nrows` `Option<String>` typés, EN UN
/// SEUL passage. Conversion UTF-8 STRICTE identique à la Row API (`ba_to_string`) ; def-levels pour l'optionalité
/// (`None` vs valeur). L'allocation d'UNE `String` par valeur non-null est INHÉRENTE (les kernels et `Value::Text`
/// possèdent leurs chaînes).
fn read_str_col_typed(r: &mut ColumnReaderImpl<ByteArrayType>, nrows: usize, required: bool) -> Result<ColData, String> {
    let mut vals: Vec<ByteArray> = Vec::with_capacity(nrows);
    let mut defs: Vec<i16> = Vec::new();
    let mut records = 0usize;
    while records < nrows {
        let (rec, _v, _l) = r
            .read_records(nrows - records, if required { None } else { Some(&mut defs) }, None, &mut vals)
            .map_err(pe)?;
        if rec == 0 {
            break;
        }
        records += rec;
    }
    if records != nrows {
        return Err(format!("cold colonnaire: BYTE_ARRAY {records} lignes lues != {nrows} attendues"));
    }
    let mut out: Vec<Option<String>> = Vec::with_capacity(nrows);
    if required {
        if vals.len() != nrows {
            return Err(format!("cold colonnaire: BYTE_ARRAY requis {} valeurs != {nrows}", vals.len()));
        }
        for ba in &vals {
            out.push(Some(ba_to_string(ba)?));
        }
    } else {
        let mut vi = 0usize;
        for d in &defs {
            if *d >= 1 {
                out.push(Some(ba_to_string(&vals[vi])?));
                vi += 1;
            } else {
                out.push(None);
            }
        }
    }
    Ok(ColData::Str(out))
}

/// Index de fichier de chaque colonne projetée : le schéma cold est PLAT -> leaf index == position dans
/// `PARQUET_COLS` (ordre canonique == `cold_schema`). Colonne hors `PARQUET_COLS` -> Err fail-closed.
fn resolve_proj_idx(proj_cols: &[&str]) -> Result<Vec<usize>, String> {
    let mut idx_of: Vec<usize> = Vec::with_capacity(proj_cols.len());
    for c in proj_cols {
        let i = PARQUET_COLS
            .iter()
            .position(|x| x == c)
            .ok_or_else(|| format!("cold colonnaire: colonne projetée inconnue/non-cold '{c}'"))?;
        idx_of.push(i);
    }
    Ok(idx_of)
}

/// DÉCODE UN row-group en `ColumnBatch` (buffers colonnes typés) restreint aux colonnes de `idx_of` (indices
/// dans `PARQUET_COLS`). RAM bornée à UN groupe. Toute divergence de compte/type REMONTE (Err) -> fail-closed.
pub(super) fn decode_batch(rg: &dyn RowGroupReader, idx_of: &[usize]) -> Result<ColumnBatch, String> {
    let nrows = rg.metadata().num_rows().max(0) as usize;
    let mut names: Vec<&'static str> = Vec::with_capacity(idx_of.len());
    let mut cols: Vec<ColData> = Vec::with_capacity(idx_of.len());
    for &fidx in idx_of {
        let name = PARQUET_COLS[fidx];
        let required = cold_col_required(name);
        let col = match rg.get_column_reader(fidx).map_err(pe)? {
            ColumnReader::Int64ColumnReader(mut r) => read_i64_col_typed(&mut r, nrows, required)?,
            ColumnReader::ByteArrayColumnReader(mut r) => read_str_col_typed(&mut r, nrows, required)?,
            _ => return Err(format!("cold colonnaire: type physique inattendu pour la colonne '{name}'")),
        };
        if col.len() != nrows {
            return Err(format!("cold colonnaire: colonne '{name}' a {} lignes != {nrows}", col.len()));
        }
        names.push(name);
        cols.push(col);
    }
    Ok(ColumnBatch { nrows, names, cols })
}

/// #18 P3 — COMPTEURS d'ÉLAGAGE ROW-GROUP (pushdown). PREUVE mesurable que le pushdown saute réellement des
/// row-groups : `scanned` = groupes DÉCODÉS, `skipped` = groupes SAUTÉS (décode évité car les statistiques
/// natives prouvent 0 match). Cumulés cross-fichier par l'appelant (P4) -> un facteur de gain observable.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RgPruneStats {
    pub(super) scanned: u64,
    pub(super) skipped: u64,
}

/// STREAMING vectorisé AVEC ÉLAGAGE ROW-GROUP (#18 P3) : décode `decode_cols` (sous-ensemble de `PARQUET_COLS`)
/// row-group par row-group et appelle `f` sur CHAQUE `ColumnBatch` retenu (jamais tout le fichier en RAM). AVANT
/// de décoder un row-group, consulte `can_match(&row_group_meta)` : si `false` (statistiques natives min/max
/// PROUVENT qu'aucune ligne ne peut matcher), le row-group est SAUTÉ — AUCUNE colonne n'est lue/décodée — et
/// `skipped` est incrémenté ; sinon il est décodé (`scanned++`). `prune=false` force le décode de TOUS les
/// groupes (chemin de PARITÉ on/off : `can_match` n'est jamais consulté). `f` renvoie `false` pour un arrêt
/// anticipé (ex. plafond de matérialisation). Toute erreur de décode REMONTE (fail-closed).
///
/// INVARIANT ABSOLU (identique au `seal` : « jamais rater une ligne ») : l'élagage n'agit QUE sur la décision
/// de décoder, JAMAIS sur le résultat que `f` accumule. Un skip à tort = lignes manquantes = fausse détection
/// SOC -> `can_match` DOIT être conservateur (skip UNIQUEMENT si prouvé vide, cf. `rg_can_match`). Résultat avec
/// `prune=true` == résultat avec `prune=false` : les groupes sautés ne contenaient prouvablement aucun match.
pub(super) fn for_each_batch_pruned(
    reader: &dyn FileReader,
    decode_cols: &[&str],
    prune: bool,
    stats: &mut RgPruneStats,
    mut can_match: impl FnMut(&RowGroupMetaData) -> bool,
    mut f: impl FnMut(&ColumnBatch) -> Result<bool, String>,
) -> Result<(), String> {
    let idx_of = resolve_proj_idx(decode_cols)?;
    let md = reader.metadata();
    for g in 0..reader.num_row_groups() {
        if prune && !can_match(md.row_group(g)) {
            stats.skipped += 1;
            continue; // décode ÉVITÉ : aucune colonne de ce row-group n'est lue (le gain P3).
        }
        stats.scanned += 1;
        let rg = reader.get_row_group(g).map_err(pe)?;
        let batch = decode_batch(&*rg, &idx_of)?;
        if !f(&batch)? {
            break;
        }
    }
    Ok(())
}

/// DÉCODE COLONNAIRE d'un fichier cold DÉCHIFFRÉ (déjà en RAM) restreint à `proj_cols` (sous-ensemble de
/// `PARQUET_COLS`, ORDRE quelconque). Renvoie les lignes en `Vec<Vec<Value>>` (positionnel == `proj_cols`),
/// EXACTEMENT ce que produisait le chemin Row-API projeté. STREAMING par row-group (RAM bornée à UN groupe) :
/// chaque groupe est décodé en `ColumnBatch` typé PUIS transposé column-major -> row-major (`into_value_rows`).
/// La transpose est désormais un CONSOMMATEUR de `ColumnBatch` -> parité P1 inchangée. Toute divergence -> Err.
fn decode_columnar(reader: &dyn FileReader, proj_cols: &[&str]) -> Result<Vec<Vec<rusqlite::types::Value>>, String> {
    use rusqlite::types::Value;
    let idx_of = resolve_proj_idx(proj_cols)?;
    let total = reader.metadata().file_metadata().num_rows().max(0) as usize;
    let mut out: Vec<Vec<Value>> = Vec::with_capacity(total);
    for g in 0..reader.num_row_groups() {
        let rg = reader.get_row_group(g).map_err(pe)?;
        let batch = decode_batch(&*rg, &idx_of)?;
        batch.into_value_rows(&mut out);
    }
    Ok(out)
}

/// SONDE BENCH (test-only) : décode TOUTES les colonnes en buffers TYPÉS bruts (`Vec<i64>`/`Vec<ByteArray>`)
/// SANS conversion String ni transposition en lignes -> isole le coût du DÉCODE PARQUET pur (le plancher que
/// P1 attaque) de la MATÉRIALISATION de lignes/String (inhérente au contrat `ColdRow`). Renvoie (nb valeurs
/// i64, nb valeurs ByteArray) lues, juste pour empêcher l'élision du décodage.
#[cfg(test)]
pub(crate) fn decode_columnar_raw_counts(path: &Path, pass: &str) -> Result<(usize, usize), String> {
    let reader = open_cold_reader(path, pass)?;
    let mut n_i64 = 0usize;
    let mut n_ba = 0usize;
    for g in 0..reader.num_row_groups() {
        let rg = reader.get_row_group(g).map_err(pe)?;
        let nrows = rg.metadata().num_rows().max(0) as usize;
        for fidx in 0..PARQUET_COLS.len() {
            let required = cold_col_required(PARQUET_COLS[fidx]);
            let mut defs: Vec<i16> = Vec::new();
            match rg.get_column_reader(fidx).map_err(pe)? {
                ColumnReader::Int64ColumnReader(mut r) => {
                    let mut vals: Vec<i64> = Vec::with_capacity(nrows);
                    let mut rd = 0usize;
                    while rd < nrows {
                        let (rec, _v, _l) = r.read_records(nrows - rd, if required { None } else { Some(&mut defs) }, None, &mut vals).map_err(pe)?;
                        if rec == 0 { break; }
                        rd += rec;
                    }
                    n_i64 += vals.len();
                }
                ColumnReader::ByteArrayColumnReader(mut r) => {
                    let mut vals: Vec<ByteArray> = Vec::with_capacity(nrows);
                    let mut rd = 0usize;
                    while rd < nrows {
                        let (rec, _v, _l) = r.read_records(nrows - rd, if required { None } else { Some(&mut defs) }, None, &mut vals).map_err(pe)?;
                        if rec == 0 { break; }
                        rd += rec;
                    }
                    n_ba += vals.len();
                }
                _ => return Err("sonde: type inattendu".into()),
            }
        }
    }
    Ok((n_i64, n_ba))
}

/// LECTEUR COLONNAIRE de fichier cold vers `Vec<ColdRow>` (toutes colonnes) — équivalent P1 de l'oracle
/// Row-API `read_day_parquet`, employé par le HARNAIS DE PARITÉ/BENCH pour prouver l'identité champ-à-champ.
/// Reconstruit `ColdRow` à partir des `Value` colonnaires (MÊME mapping par nom que `read_day_parquet`).
#[cfg(test)]
pub(crate) fn read_day_parquet_columnar(path: &Path, pass: &str) -> Result<Vec<ColdRow>, String> {
    use rusqlite::types::Value;
    let reader = open_cold_reader(path, pass)?;
    let cols: Vec<&str> = PARQUET_COLS.to_vec();
    let rows = decode_columnar(&reader, &cols)?;
    let as_str = |v: &Value| -> Option<String> {
        match v {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        }
    };
    let as_long = |v: &Value| -> i64 {
        match v {
            Value::Integer(n) => *n,
            _ => 0,
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for vals in rows {
        let mut cr = ColdRow::default();
        for (i, name) in PARQUET_COLS.iter().enumerate() {
            let v = &vals[i];
            match *name {
                "ts" => cr.row.ts = as_long(v),
                "severity" => cr.row.severity = as_long(v),
                "source" => cr.row.source = as_str(v).unwrap_or_default(),
                "category" => cr.row.category = as_str(v).unwrap_or_default(),
                "host" => cr.row.host = as_str(v),
                "src_ip" => cr.row.src_ip = as_str(v),
                "dst_ip" => cr.row.dst_ip = as_str(v),
                "url" => cr.row.url = as_str(v),
                "xff" => cr.xff = as_str(v),
                "dedup" => cr.row.dedup = as_str(v),
                "engagement_id" => cr.row.engagement_id = as_str(v).unwrap_or_default(),
                "origin" => cr.row.origin = as_str(v).unwrap_or_default(),
                "env_id" => cr.row.env_id = as_str(v),
                "message" => cr.row.message = as_str(v).unwrap_or_default(),
                "fields" => cr.row.fields = as_str(v),
                _ => {}
            }
        }
        out.push(cr);
    }
    Ok(out)
}

/// UN fichier cold SÉLECTIONNÉ pour l'hydratation (unité de travail PARALLÈLE-READY) : sa place `(day, seq)` +
/// l'identité/borne du seal nécessaires à `verify_parquet_rows`. `order_index` = rang CANONIQUE (day, seq
/// croissants) -> l'ordre d'insertion déterministe.
struct SelFile {
    day: i64,
    seq: i64,
    expected: usize,
    ts_min: i64,
    ts_max: i64,
}

/// Résultat de l'hydratation cold (#18 P2b) : la connexion ÉPHÉMÈRE EN MÉMOIRE portant `cold_event` (lignes
/// cold BRUTES/NON MASQUÉES — masquage/DENY = P3) + métadonnées de couverture. `files_pruned` = fichiers du
/// range de jours dont `[ts_min,ts_max]` NE chevauche PAS la fenêtre (JAMAIS ouverts/déchiffrés) ; `files_read`
/// = fichiers sélectionnés effectivement lus ; `rows_hydrated` = lignes insérées ; `truncated` = plafond atteint.
pub(crate) struct ColdHydrate {
    pub(crate) conn: Connection,
    pub(crate) files_pruned: usize,
    pub(crate) files_read: usize,
    pub(crate) rows_hydrated: usize,
    pub(crate) truncated: bool,
}

/// DÉCODE UN fichier cold (unité PER-FICHIER, appelée par un worker — AUCUN accès à la connexion tenant). Chaîne :
/// `file_path` -> `verify_parquet_rows` (déchiffre UN fichier borné <= COLD_FILE_MAX_ROWS +
/// décode INTÉGRALEMENT + IDENTITÉ (env,day,seq) + fenêtre ts DU FICHIER — la garantie crash-safety RÉUTILISÉE
/// verbatim) -> ré-ouvre (2e déchiffrement, coût borné accepté hors chemin chaud) et décode avec PROJECTION ->
/// garde les lignes `ts ∈ [q_start, q_end]`. Chaque ligne = `Vec<Value>` aligné sur `proj_cols` (ordre canonique).
/// Toute erreur (déchiffrement/identité/décodage/absence) REMONTE -> fail-closed chez l'appelant (aucune donnée
/// cold partielle). `ts_idx` = position de "ts" dans `proj_cols` (toujours présent, forcé par l'appelant).
fn decode_one_file(
    cold_dir: &Path,
    env_id: &str,
    f: &SelFile,
    proj_cols: &[&str],
    ts_idx: usize,
    q_start: i64,
    q_end: i64,
    pass: &str,
) -> Result<Vec<Vec<rusqlite::types::Value>>, String> {
    use rusqlite::types::Value;
    let path = file_path(cold_dir, env_id, f.day, f.seq);
    // GATE crash-safety RÉUTILISÉ : déchiffre+décode INTÉGRALEMENT + lie l'identité (env,day,seq) et la fenêtre
    // ts du fichier. Un fichier corrompu / mauvaise clé / identité étrangère -> Err ICI -> hydratation fail-closed.
    let ident = FileIdent { env_id, day: f.day, seq: f.seq, ts_min: f.ts_min, ts_max: f.ts_max };
    verify_parquet_rows(&path, f.expected, Some(ident), pass)?;
    // Extraction PROJETÉE via le DÉCODE COLONNAIRE (P1) : 2e ouverture (le reader parquet exige un accès random
    // au footer ; verify a déjà prouvé la lisibilité), puis lecture bas-niveau par colonne/row-group — ne
    // MATÉRIALISE que les colonnes demandées, sans un objet `Row`/`Field` par ligne (le coût dominant en Row-API).
    let reader = open_cold_reader(&path, pass)?;
    let ncol = proj_cols.len();
    let rows = decode_columnar(&reader, proj_cols)
        .map_err(|e| format!("hydrate {}: décodage colonnaire projeté échoué: {e}", path.display()))?;
    let mut out = Vec::with_capacity(rows.len());
    for vals in rows {
        if vals.len() != ncol {
            return Err(format!("hydrate {}: {} colonnes projetées != {ncol} attendues", path.display(), vals.len()));
        }
        // FILTRE FENÊTRE DE REQUÊTE (inclusif). `ts` toujours projeté (forcé) -> présent à `ts_idx`.
        let ts = match &vals[ts_idx] {
            Value::Integer(t) => *t,
            other => return Err(format!("hydrate {}: ts projeté non-entier ({other:?})", path.display())),
        };
        if ts >= q_start && ts <= q_end {
            out.push(vals);
        }
    }
    Ok(out)
}

/// #18 P2b — HYDRATE les lignes cold de la fenêtre `[q_start_ts, q_end_ts]` (INCLUSIVE) du tenant `db_path`/`env_id`
/// dans une table `cold_event` ÉPHÉMÈRE EN MÉMOIRE (schéma == `event` live -> P3 ATTACH+UNION). PRIMITIVE INTERNE :
/// lignes BRUTES/NON MASQUÉES (masquage/DENY = P3) -> NE JAMAIS câbler dans un chemin de requête utilisateur.
///
/// `conn` = connexion du TENANT (lit l'index `cold_seal`, base SQLCipher). `db_path` = clé PAR-TENANT dérivant la
/// racine cold + la clé AEAD (isolation FIX #2). `needed_cols` = colonnes à PROJETER (sous-ensemble de
/// `PARQUET_COLS` ; "ts" est TOUJOURS forcé, requis par le filtre de fenêtre ET l'union P3). Colonne inconnue ->
/// Err fail-closed. Étapes : (1) ÉLAGAGE SANS DÉCHIFFREMENT (seuls les seals dont `[ts_min,ts_max]` chevauche la
/// fenêtre, sur les jours SPANNÉS par la fenêtre ; jamais un Parquet ouvert pour décider) ; (2) unité par-fichier
/// PARALLÈLE (verify+projection+filtre) ; (3) insertion SÉRIALISÉE déterministe bornée par `cold_hydrate_row_cap`
/// (troncature signalée). GATE RUNTIME `PLUME_COLD_TIER` : si absent -> `cold_event` VIDE (le lecteur ne sert que
/// derrière le même gate que le writer). Corruption d'un fichier sélectionné -> Err (fail-closed, jamais partiel).
pub(crate) fn hydrate_cold(
    conn: &Connection,
    conf: &HashMap<String, String>,
    db_path: &str,
    env_id: &str,
    q_start_ts: i64,
    q_end_ts: i64,
    needed_cols: &[&str],
    dim_preds: &[DimEq],
) -> Result<ColdHydrate, String> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // Connexion ÉPHÉMÈRE EN MÉMOIRE + table cold_event (toujours créée -> l'appelant a un handle utilisable même
    // si 0 ligne / gate off).
    let mem = Connection::open_in_memory().map_err(pe)?;
    mem.execute_batch(COLD_EVENT_DDL).map_err(pe)?;

    let empty = |mem: Connection, pruned: usize| ColdHydrate {
        conn: mem, files_pruned: pruned, files_read: 0, rows_hydrated: 0, truncated: false,
    };

    // GATE RUNTIME (miroir du writer) : sans PLUME_COLD_TIER=1, aucun tier cold -> table vide.
    if cfg(conf, "PLUME_COLD_TIER", "") != "1" {
        return Ok(empty(mem, 0));
    }
    // Anti-traversée : env_id validé AVANT toute construction de chemin (comme le writer).
    if !env_id_ok(env_id) {
        return Err(format!("hydrate_cold: env_id non conforme '{env_id}'"));
    }
    if q_end_ts < q_start_ts {
        return Ok(empty(mem, 0)); // fenêtre vide -> rien (défensif).
    }

    // Colonnes projetées CANONIQUES = "ts" forcé ∪ (needed_cols ∩ PARQUET_COLS), dans l'ordre de PARQUET_COLS ->
    // liste d'insertion déterministe. Toute colonne demandée hors PARQUET_COLS (ex. "id") -> Err fail-closed.
    for c in needed_cols {
        if !PARQUET_COLS.contains(c) {
            return Err(format!("hydrate_cold: colonne demandée inconnue/non-cold '{c}' (attendu sous-ensemble de {PARQUET_COLS:?})"));
        }
    }
    let want = |c: &str| c == "ts" || needed_cols.contains(&c);
    let proj_cols: Vec<&str> = PARQUET_COLS.iter().copied().filter(|c| want(c)).collect();
    let ts_idx = proj_cols.iter().position(|&c| c == "ts").expect("ts toujours projeté");

    // Clé AEAD + racine cold PAR-TENANT (dérivées du MÊME db_path que le writer). Sans clé -> pas de tier cold
    // lisible : cold ON EXIGE le chiffrement (comme le writer fail-closed). On renvoie une table VIDE plutôt
    // qu'une Err : l'absence de clé n'est pas une corruption de fichier, et le writer n'a rien pu écrire non plus.
    let pass = match cold_aead_passphrase(conf, db_path) {
        Some(p) => p,
        None => return Ok(empty(mem, 0)),
    };
    let cold_dir = cold_root(conf, db_path);

    // ---- (1) ÉLAGAGE SANS DÉCHIFFREMENT : jours SPANNÉS par la fenêtre × seals chevauchants. -----------------
    // `div_euclid` (floor) coïncide avec le `ts/86400` (trunc) de l'écriture des seals pour tout `ts >= 0` — les ts
    // SOC sont des epoch-seconds TOUJOURS positifs -> lo_day/hi_day couvrent exactement les jours de la fenêtre.
    let lo_day = q_start_ts.div_euclid(SECS_PER_DAY);
    let hi_day = q_end_ts.div_euclid(SECS_PER_DAY);
    let mut selected: Vec<SelFile> = Vec::new();
    let mut pruned = 0usize;
    for day in lo_day..=hi_day {
        for s in file_seals(conn, env_id, day) {
            // CHEVAUCHEMENT d'intervalles [ts_min,ts_max] vs [q_start,q_end] (inclusif) — décidé UNIQUEMENT sur
            // l'index seal (dans la base chiffrée), JAMAIS en ouvrant un Parquet.
            if s.ts_min <= q_end_ts && s.ts_max >= q_start_ts {
                // #28 PHASE B — ÉLAGAGE DIMENSIONNEL (encore SANS déchiffrer) : si la requête porte des égalités
                // sur des dims universelles ET que ce fichier a des stats scellées QUI PROUVENT l'absence de la
                // valeur (min/max hors bornes OU bloom certain-absent), on le SAUTE. `dim_stats == None` (seal
                // pré-Phase-B / blob illisible) -> pas d'élagage -> on GARDE (fallback correct). Correction : un
                // faux positif de bloom ne fait que garder (déchiffrement de plus), jamais rater une ligne.
                if !dim_preds.is_empty() {
                    if let Some(stats) = &s.dim_stats {
                        if stats.excluded_by(dim_preds) {
                            pruned += 1;
                            continue;
                        }
                    }
                }
                selected.push(SelFile { day, seq: s.seq, expected: s.expected as usize, ts_min: s.ts_min, ts_max: s.ts_max });
            } else {
                pruned += 1;
            }
        }
    }
    // ORDRE CANONIQUE (day, seq) -> order_index = position dans `selected` (l'insertion déterministe en dépend).
    selected.sort_by(|a, b| a.day.cmp(&b.day).then(a.seq.cmp(&b.seq)));
    if selected.is_empty() {
        return Ok(empty(mem, pruned));
    }

    // ---- (2)+(3) POOL borné de décodeurs -> canal borné -> inséreur unique déterministe. --------------------
    let cap = cold_hydrate_row_cap();
    let n_sel = selected.len();
    let degree = cold_read_parallelism().min(n_sel).max(1);
    let insert_sql = format!("INSERT INTO cold_event({}) VALUES({})", proj_cols.join(","), vec!["?"; proj_cols.len()].join(","));

    let next = AtomicUsize::new(0);
    let abort = AtomicBool::new(false);
    // Canal BORNÉ = back-pressure (borne RAM). Capacité = degré (assez pour ne pas affamer l'inséreur).
    let (tx, rx) = std::sync::mpsc::sync_channel::<(usize, Result<Vec<Vec<rusqlite::types::Value>>, String>)>(degree);

    let mut first_err: Option<String> = None;
    let mut rows_hydrated = 0usize;
    let mut truncated = false;

    std::thread::scope(|scope| -> Result<(), String> {
        // --- N WORKERS décodeurs (déchiffrement/décodage CPU, indépendants ; AUCUN accès à `mem`). ---
        for _ in 0..degree {
            let tx = tx.clone();
            let next = &next;
            let abort = &abort;
            let selected = &selected;
            let proj_cols = &proj_cols;
            let cold_dir = &cold_dir;
            let pass = pass.as_str();
            scope.spawn(move || {
                loop {
                    if abort.load(Ordering::Relaxed) {
                        break; // arrêt anticipé (Err ailleurs OU troncature atteinte) -> ne tire plus de fichier.
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= selected.len() {
                        break;
                    }
                    let res = decode_one_file(cold_dir, env_id, &selected[i], proj_cols, ts_idx, q_start_ts, q_end_ts, pass);
                    let is_err = res.is_err();
                    if tx.send((i, res)).is_err() {
                        break; // récepteur parti
                    }
                    if is_err {
                        abort.store(true, Ordering::Relaxed); // fail-closed : signale les autres workers.
                        break;
                    }
                }
            });
        }
        drop(tx); // seuls les clones-workers gardent un tx -> rx se ferme quand tous ont fini.

        // --- INSÉREUR UNIQUE (thread principal du scope) : réordonne par index, insère, borne, tronque. ---
        // INVARIANT DRAIN-ON-ERROR : toute défaillance CÔTÉ INSÉREUR (prepare/execute en mémoire, ex. SQLITE_NOMEM)
        // NE DOIT PAS ?-retourner ici. `rx` est créé HORS du scope (simple borrow) -> un retour anticipé le laisserait
        // NON vidé, et `thread::scope` joindrait ensuite des workers potentiellement BLOQUÉS sur `tx.send` (canal
        // plein) -> DEADLOCK (le join pend à jamais). On enregistre donc `first_err`, on `abort`, et on DRAINE `rx`
        // jusqu'à fermeture (chaque `tx.send` bloqué débloque, tous les clones `tx` finissent droppés) -> le join
        // joint proprement. L'erreur est surfacée APRÈS le scope via `first_err` (fail-closed, aucun cold partiel).
        let mut stmt = match mem.prepare(&insert_sql) {
            Ok(s) => s,
            Err(e) => {
                first_err = Some(pe(e));
                abort.store(true, Ordering::Relaxed);
                while rx.recv().is_ok() {} // draine jusqu'à ce que TOUS les tx workers soient débloqués+droppés
                return Ok(()); // erreur surfacée par `first_err` après le scope (jamais un join pendu)
            }
        };
        let mut buf: HashMap<usize, Vec<Vec<rusqlite::types::Value>>> = HashMap::new();
        let mut next_expected = 0usize;
        while let Ok((idx, res)) = rx.recv() {
            match res {
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    abort.store(true, Ordering::Relaxed);
                    continue; // CONTINUER à drainer (débloque les workers en send) -> pas de deadlock/join qui pend.
                }
                Ok(rows) => {
                    if first_err.is_some() || truncated {
                        continue; // on draine sans insérer (arrêt décidé) ; les batches restants sont jetés.
                    }
                    buf.insert(idx, rows);
                    // Vide le buffer dans l'ORDRE CANONIQUE contigu (index attendu) -> insertion déterministe.
                    while let Some(rows) = buf.remove(&next_expected) {
                        for row in rows {
                            if rows_hydrated >= cap {
                                truncated = true;
                                abort.store(true, Ordering::Relaxed); // plafond -> stoppe les workers, continue de drainer.
                                break;
                            }
                            // MÊME traitement DRAIN-ON-ERROR que l'arm Err(worker) plus haut : un INSERT en mémoire qui
                            // échoue (ex. SQLITE_NOMEM) enregistre first_err + abort et STOPPE l'insertion, mais NE
                            // ?-retourne PAS -> la boucle `while let ... rx.recv()` continue de DRAINER (débloque les
                            // workers en send) -> le join ne pend jamais. first_err est surfacé après le scope (fail-closed).
                            if let Err(e) = stmt.execute(rusqlite::params_from_iter(row.iter())) {
                                if first_err.is_none() {
                                    first_err = Some(pe(e));
                                }
                                abort.store(true, Ordering::Relaxed);
                                break;
                            }
                            rows_hydrated += 1;
                        }
                        next_expected += 1;
                        if truncated || first_err.is_some() {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    })?;

    if let Some(e) = first_err {
        // FAIL-CLOSED : un fichier sélectionné était corrompu/illisible -> JAMAIS de cold partiel silencieux.
        return Err(format!("hydrate_cold: fichier cold sélectionné invalide -> requête ÉCHOUÉE (aucun résultat partiel): {e}"));
    }

    Ok(ColdHydrate { conn: mem, files_pruned: pruned, files_read: n_sel, rows_hydrated, truncated })
}

// ====================================================================================================
// #18 P3 — UNION hot∪cold MASQUÉE (câblage du lecteur cold DANS le chemin de requête, DERRIÈRE la sécurité).
// ----------------------------------------------------------------------------------------------------
// Mécanisme (cf. header de module pour le crux sécurité) :
//   • Le SQL compilé référence la table `event`. On l'exécute sur une connexion où `main` = la base HOT (RO,
//     clé DU TENANT via `apply_key_for`) et où une VUE TEMP `event` (schéma temp, PRIORITAIRE sur `main.event`
//     pour tout nom non qualifié) EXPOSE `SELECT … FROM main.event WHERE ts>=B  UNION ALL  SELECT … FROM
//     cold_event WHERE ts<B`. TOUTE référence `event` du SQL compilé (leaf + append/join, à toute profondeur)
//     tape donc l'UNION -> le masquage (émis DANS la projection compilée : `plume_fmask_hash(src_ip)` / CASE /
//     `NULL`) et l'authorizer DENY s'appliquent aux colonnes de l'union -> aux lignes cold AUTOMATIQUEMENT.
//   • WIRING RÉUTILISÉ VERBATIM : `install_query_udfs` + `install_fmask_udf` (sel lu sur `main`=hot, identique)
//     + `install_field_authorizer` (query_exec.rs) — le MÊME authorizer que le pool HOT, `cold_event` déclarée
//     miroir de `event` (déni de colonne déniée aussi en cold). Exécution via `run_on_conn` (query_exec.rs) —
//     MÊME watchdog/budget/annulation/plafond/garde `stmt.readonly()`.
//   • PARITÉ MASQUAGE de la VUE : la projection de base HOT (`base_proj_col`, cœur) émet `NULL` pour une colonne
//     sous DENY. La vue fait DE MÊME (colonnes déniées -> `NULL AS c`) -> une requête bénigne qui n'accède PAS à
//     la colonne déniée NE déclenche PAS l'authorizer (aucune lecture de la colonne), EXACTEMENT comme en hot ;
//     et une colonne HASH/MASK reste BRUTE dans la vue (l'expression de masque du SQL compilé s'applique dessus).
//
// FRONTIÈRE hot/cold (anti-double-comptage ET sans-perte) : `B` = `hot_cutoff` ALIGNÉ AU JOUR (l'aging
// columnarise des JOURS ENTIERS < `hi_day_excl` = `floor(hot_cutoff/86400)` ; rien de columnarisé n'a `ts>=B`).
// L'union prend hot `ts>=B` ∪ cold `ts<B` : une ligne scellée-non-encore-purgée (dans les DEUX, `ts<B`) n'est
// comptée QU'UNE FOIS (côté cold ; le côté hot l'exclut). L'union est une union de LIGNES ; le SQL compilé
// agrège UNE SEULE FOIS au-dessus (jamais une fusion d'agrégats partiels -> dc/avg/top corrects). En régime
// drainé, tout `ts<B` est en cold -> aucune perte ; l'aging en RETARD (rare, signalé par le dead-man's-switch)
// et les stragglers (compromis P1 documenté, jamais columnarisés) sont les seules zones grises connues.
//
// COMPLÉTUDE ROLLUP-GAP (P1.5) : une agrégation sur `[retention_days, cold_ret]` ne trouve PLUS de rollups
// (purgés à retention_days) mais les events VIVENT jusqu'à cold_ret en cold. Le déclencheur (query.rs) DÉSACTIVE
// le rollup-route dès que la fenêtre atteint sous `B` -> l'agrégat est calculé sur le BRUT hot∪cold (cold_event)
// = COMPLET, jamais un résultat tronqué à la seule fenêtre couverte par les rollups.
//
// BORNE RAM (budget 2 Gio) : l'ensemble cold hydraté est PLAFONNÉ (`cold_hydrate_row_cap` = PLUME_QUERY_MAX) et
// copié dans une TABLE TEMP -> l'union tourne sur (event HOT indexé par ts) ∪ (table temp bornée) sous le budget
// interactif existant. Le support des objets TEMP et du trieur est celui décidé par `sqlite_plafond` — et ce
// support est la RAM AU DÉFAUT (`temp_store=MEMORY`, cf. `mot_temp_store`) : ce n'est donc PAS lui qui borne
// l'ensemble ici, c'est `cold_hydrate_row_cap`. Ne pas s'appuyer sur un déversement qui n'existe qu'en opt-in.
// `truncated` REMONTE au caller (jamais un cold∪hot tronqué présenté comme complet).

/// Colonnes de `event`/`cold_event` (ORDRE FIXE) exposées par la VUE d'union — sur-ensemble de tout ce que le
/// SQL compilé peut référencer (projection de base + WHERE + json_extract(fields)). Miroir EXACT du schéma live.
pub(super) const UNION_COLS: [&str; 16] = [
    "id", "ts", "source", "category", "severity", "host", "message", "fields", "dedup", "env_id",
    "origin", "engagement_id", "src_ip", "dst_ip", "url", "xff",
];

/// GATE RUNTIME du tier cold (miroir de l'aging/reader). `PLUME_COLD_TIER=1` requis.
pub(crate) fn cold_tier_runtime_on(conf: &HashMap<String, String>) -> bool {
    cfg(conf, "PLUME_COLD_TIER", "") == "1"
}

/// FRONTIÈRE hot/cold de REQUÊTE (epoch s), ALIGNÉE AU JOUR : `floor(hot_cutoff/86400)*86400`. Dérivée de la
/// MÊME `cold_hot_cutoff` que l'aging -> aucune divergence de frontière. Rows `ts < B` = territoire COLD (jours
/// entièrement columnarisés) ; `ts >= B` = HOT. `retention_days` = rétention globale effective (résolue par
/// l'appelant, comme l'aging) -> `conn` sert à charger les policies per-index (#49) via `cold_hot_cutoff`.
pub(crate) fn cold_query_boundary(conn: &Connection, conf: &HashMap<String, String>, n: i64, retention_days: i64) -> i64 {
    let cutoff = cold_hot_cutoff(conn, conf, n, retention_days);
    cutoff.div_euclid(SECS_PER_DAY) * SECS_PER_DAY
}

/// Métadonnées de COUVERTURE de l'union cold (transparence + incomplétude). `truncated=true` -> l'ensemble cold
/// a atteint le plafond -> résultat INCOMPLET (à surfacer au caller, JAMAIS présenté comme complet).
pub(crate) struct ColdUnionMeta {
    pub(crate) truncated: bool,
    pub(crate) rows_hydrated: usize,
    pub(crate) files_read: usize,
    pub(crate) files_pruned: usize,
}

/// Connexion d'UNION hot∪cold prête à exécuter le SQL compilé (masquage/DENY câblés). `conn` : base HOT (RO,
/// clé tenant) portant une TABLE TEMP `cold_event` (lignes hydratées, bornées) + une VUE TEMP `event` (union
/// masquée-parité) qui SHADOWE `main.event`. NON poolée : détruite au Drop (jamais rendue au read-pool HOT).
pub(crate) struct ColdUnionConn {
    pub(crate) conn: Connection,
    pub(crate) meta: ColdUnionMeta,
}

/// Expression de projection d'une colonne dans la VUE d'union : `NULL AS c` si `c` est sous DENY (#45) —
/// PARITÉ EXACTE avec la projection de base HOT (`base_proj_col` émet `NULL` pour une colonne déniée) -> une
/// requête bénigne ne LIT jamais la colonne déniée (pas de déclenchement authorizer, comme en hot) ; sinon la
/// colonne BRUTE (une éventuelle action HASH/MASK est appliquée PAR-DESSUS par le SQL compilé).
pub(super) fn union_proj(deny: &std::collections::HashSet<String>) -> String {
    UNION_COLS
        .iter()
        .map(|c| {
            if deny.iter().any(|d| d.eq_ignore_ascii_case(c)) {
                format!("NULL AS {c}")
            } else {
                (*c).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// env_id DISTINCTS ayant AU MOINS un seal dans la plage de jours `[lo_ts, hi_ts]`. Sert quand la requête ne
/// filtre PAS l'environnement (mode 0 -> `{prod}` ; super-admin cross-env mode 1 -> tous) : on hydrate CHAQUE
/// env présent en cold. Table absente / aucune -> vide. Lu sur la base du TENANT (cold_seal chiffré at-rest).
pub(super) fn distinct_seal_envs(conn: &Connection, lo_ts: i64, hi_ts: i64) -> Vec<String> {
    let lo_day = lo_ts.div_euclid(SECS_PER_DAY);
    let hi_day = hi_ts.div_euclid(SECS_PER_DAY);
    let mut out = Vec::new();
    if let Ok(mut st) = conn.prepare("SELECT DISTINCT env_id FROM cold_seal WHERE day>=?1 AND day<=?2 ORDER BY env_id") {
        if let Ok(rows) = st.query_map(params![lo_day, hi_day], |r| r.get::<_, String>(0)) {
            out = rows.flatten().collect();
        }
    }
    out
}

/// #18 P3 — CONSTRUIT la connexion d'UNION hot∪cold masquée (cf. doc de section). Ouvre la base HOT en RO+clé
/// tenant, HYDRATE la sous-fenêtre cold `[from, min(to,B-1)]` (bornée), copie les lignes (≤ cap) dans une TABLE
/// TEMP `cold_event`, monte la VUE TEMP `event` = union masquée-parité SHADOWANT `main.event`, puis installe le
/// wiring sécu VERBATIM (UDF + HASH #45 + authorizer DENY). `env_filter` : `Some(e)` -> ce seul env ; `None` ->
/// tous les env présents en cold (mode 0 = prod). Erreur d'hydratation (fichier cold corrompu) -> Err fail-closed
/// (jamais un cold partiel silencieux). L'appelant exécute le SQL compilé via `run_on_conn` sur `conn`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_cold_union(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    dim_preds: &[DimEq],
) -> Result<ColdUnionConn, String> {
    use rusqlite::types::Value as SqlVal;

    // (1) HOT conn RO + clé DU TENANT. Budget mémoire par `sqlite_plafond` : la table TEMP d'hydratation
    // est bornée par `cold_hydrate_row_cap`, mais les AGRÉGATS exécutés sur la vue d'union ont le même
    // trieur que partout ailleurs — donc le même besoin de plafond. PAS de `query_only=ON` : les objets
    // TEMP doivent pouvoir être créés ; `main` ouvert READ_ONLY -> le HOT reste PHYSIQUEMENT immuable.
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(pe)?;
    apply_key_for(&conn, db_path);
    let _ = conn.execute_batch("PRAGMA busy_timeout=3000;");
    let _ = sqlite_plafond::armer(&conn);

    // (2) Colonnes sous DENY (#45) de CE tenant -> NULLifiées dans la vue (parité HOT).
    let deny: std::collections::HashSet<String> =
        crate::field_deny_cols_cell().read().get(db_path).cloned().unwrap_or_default();
    // Colonnes à PROJETER en hydratation = PARQUET_COLS \ {ts (forcé)} \ deny (inutile de déchiffrer une colonne
    // qui sera NULL dans la vue). Sous-ensemble VALIDE de PARQUET_COLS -> hydrate_cold ne fail-close pas.
    let needed: Vec<&str> = PARQUET_COLS
        .iter()
        .copied()
        .filter(|c| *c != "ts" && !deny.iter().any(|d| d.eq_ignore_ascii_case(c)))
        .collect();

    // (3) Fenêtre COLD : cold = `ts < B` ; borne haute = min(to, B-1) (to<=0 = non borné -> B-1). Borne basse =
    // `from` si borné, sinon le plus VIEUX jour scellé (évite d'itérer les jours depuis l'epoch pour from=0).
    let hi = if q_to > 0 { q_to.min(boundary - 1) } else { boundary - 1 };
    let lo = if q_from > 0 {
        q_from
    } else {
        conn.query_row("SELECT MIN(day) FROM cold_seal", [], |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten()
            .map(|d| d * SECS_PER_DAY)
            .unwrap_or(hi)
    };

    // (4) TABLE TEMP cold_event (schéma == event live).
    let temp_ddl = COLD_EVENT_DDL.replacen("CREATE TABLE", "CREATE TEMP TABLE", 1);
    conn.execute_batch(&temp_ddl).map_err(pe)?;

    // (5) HYDRATE chaque env (bornée) + copie dans la table temp, plafonnée globalement.
    let envs: Vec<String> = match env_filter {
        Some(e) if !e.trim().is_empty() => vec![e.to_string()],
        _ => distinct_seal_envs(&conn, lo, hi),
    };
    let cap = cold_hydrate_row_cap();
    let cols_csv = UNION_COLS.join(",");
    let placeholders = vec!["?"; UNION_COLS.len()].join(",");
    let mut truncated = false;
    let mut rows_hydrated = 0usize;
    let mut files_read = 0usize;
    let mut files_pruned = 0usize;
    if hi >= lo {
        for env in &envs {
            if !env_id_ok(env) {
                continue; // fail-safe (anti-traversée) — jamais de chemin arbitraire.
            }
            let hy = hydrate_cold(&conn, conf, db_path, env, lo, hi, &needed, dim_preds)?;
            files_read += hy.files_read;
            files_pruned += hy.files_pruned;
            truncated |= hy.truncated;
            // Copie hy.conn.cold_event -> conn.cold_event (temp), plafond GLOBAL (multi-env borné au même cap).
            let mut sel = hy.conn.prepare(&format!("SELECT {cols_csv} FROM cold_event ORDER BY id")).map_err(pe)?;
            let mut ins = conn.prepare(&format!("INSERT INTO cold_event({cols_csv}) VALUES({placeholders})")).map_err(pe)?;
            let mut rows = sel.query([]).map_err(pe)?;
            while let Some(r) = rows.next().map_err(pe)? {
                if rows_hydrated >= cap {
                    truncated = true;
                    break;
                }
                let mut vals: Vec<SqlVal> = Vec::with_capacity(UNION_COLS.len());
                for i in 0..UNION_COLS.len() {
                    vals.push(r.get::<_, SqlVal>(i).map_err(pe)?);
                }
                ins.execute(rusqlite::params_from_iter(vals.iter())).map_err(pe)?;
                rows_hydrated += 1;
            }
        }
    }

    // (6) VUE TEMP `event` = union masquée-parité, SHADOWANT `main.event`. `boundary` est un i64 interne
    // (jamais d'entrée utilisateur) -> inliné sans risque d'injection.
    let proj = union_proj(&deny);
    let view_sql = format!(
        "CREATE TEMP VIEW event AS \
           SELECT {proj} FROM main.event WHERE ts >= {boundary} \
           UNION ALL \
           SELECT {proj} FROM cold_event WHERE ts < {boundary}"
    );
    conn.execute_batch(&view_sql).map_err(pe)?;

    // (7) WIRING SÉCU VERBATIM (query_exec.rs) — installé APRÈS le montage (la vue NULL les colonnes déniées ->
    // aucune lecture de colonne déniée pendant le montage). Le SQL compilé exécuté ensuite hérite du masquage
    // (déjà dans le SQL) + de l'authorizer DENY, appliqués à l'union hot∪cold.
    install_query_udfs(&conn);
    install_fmask_udf(&conn);
    install_field_authorizer(&conn, db_path);

    Ok(ColdUnionConn { conn, meta: ColdUnionMeta { truncated, rows_hydrated, files_read, files_pruned } })
}

/// #18 P3 — EXÉCUTE une requête (page + COUNT optionnel) sur l'union hot∪cold. Construit la connexion d'union
/// UNE FOIS (une seule hydratation) puis exécute `page_sql` (et `count_sql` si paginé) via `run_on_conn` (MÊME
/// budget/watchdog/annulation/masquage/authorizer que le hot). Une erreur d'hydratation (cold corrompu) -> Err
/// (fail-closed). À appeler depuis `spawn_blocking` (I/O + déchiffrement).
///
/// RENVOIE UNE `ColdAnswer`, PAS UN `Value`. Quand l'hydratation froide a PLAFONNÉ, le `Value` calculé sur
/// l'échantillon est SÉQUESTRÉ : le seul chemin vers la sérialisation est `ColdAnswer::render(shape)`, qui
/// REFUSE toute valeur dérivée d'un ensemble tronqué (cf. `cold_store::exactness`). Avant ce type, cette
/// fonction rendait un `Value` que trois sites d'appel affichaient tel quel, avec un drapeau à côté —
/// c'est-à-dire un `stats count` faux d'un facteur mesuré ×203.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cold_union_query(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    page_sql: &str,
    count_sql: Option<&str>,
    budget_ms: u64,
    qid: Option<&str>,
    dim_preds: &[DimEq],
) -> Result<(ColdAnswer, ColdUnionMeta), String> {
    let u = open_cold_union(db_path, conf, env_filter, q_from, q_to, boundary, dim_preds)?;
    let page = run_on_conn(&u.conn, db_path, page_sql, budget_ms, qid)?;
    let total = match count_sql {
        Some(cs) => run_on_conn(&u.conn, db_path, cs, budget_ms, qid)
            .ok()
            .and_then(|v| v.get("rows").and_then(|r| r.get(0)).and_then(|r0| r0.get(0)).and_then(|x| x.as_i64())),
        None => None,
    };
    let answer = ColdAnswer::new(page, total, u.meta.truncated, cold_hydrate_row_cap(), u.meta.rows_hydrated);
    Ok((answer, u.meta))
}
