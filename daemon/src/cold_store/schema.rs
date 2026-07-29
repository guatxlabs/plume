//! cold_store::schema — MODÈLE COLONNAIRE Parquet du tier froid : `ColdRow`, schéma, helpers d'écriture de colonnes.
//!
//! ORDRE DES COLONNES : colonnes fines d'abord, les GROSSES (`message`, `fields`) EN DERNIER -> projection bon
//! marché en P2 (on saute les colonnes fat). Un fichier contient un ou plusieurs row-groups de `rg_rows` lignes
//! (~256K par défaut) : la RAM d'ÉCRITURE est bornée à UN row-group. Compression ZSTD ; fichier déclaré TRIÉ sur
//! la colonne 0 (`ts`, ascendant) -> les lecteurs exploitent la monotonie + stats min/max par groupe.

use super::*;

use parquet::basic::{Compression, LogicalType, Repetition, Type as PhysicalType, ZstdLevel};
use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::metadata::SortingColumn;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::{SerializedFileWriter, SerializedRowGroupWriter};
use parquet::schema::types::Type;

/// Ligne du tier froid = `EventRow` (contrat neutre du cœur) + `xff`. La colonne live `event.xff` (ajoutée
/// par la migration, présente dans `EVENT_COLS`/le vocabulaire GXQL) n'existe PAS dans `EventRow` : pour ne
/// JAMAIS perdre de donnée interrogeable en agant (l'aging SUPPRIME les lignes hot), le writer la porte
/// EXPLICITEMENT ici. (`id` = rowid interne non exposé au GXQL -> non conservé ; `dedup` l'est.)
#[derive(Debug, Clone, Default)]
pub(crate) struct ColdRow {
    pub(crate) row: EventRow,
    pub(crate) xff: Option<String>,
}

impl From<EventRow> for ColdRow {
    fn from(row: EventRow) -> Self {
        ColdRow { row, xff: None }
    }
}

// `EventRow` (cœur) ne dérive PAS `PartialEq` (et l'y ajouter sort du périmètre core « variante Parquet
// seule ») -> égalité champ-à-champ implémentée ICI (exercée par le test de round-trip du writer).
impl PartialEq for ColdRow {
    fn eq(&self, o: &Self) -> bool {
        let a = &self.row;
        let b = &o.row;
        a.ts == b.ts
            && a.severity == b.severity
            && a.source == b.source
            && a.category == b.category
            && a.host == b.host
            && a.src_ip == b.src_ip
            && a.dst_ip == b.dst_ip
            && a.url == b.url
            && a.dedup == b.dedup
            && a.fields == b.fields
            && a.engagement_id == b.engagement_id
            && a.origin == b.origin
            && a.env_id == b.env_id
            && self.xff == o.xff
    }
}

/// Schéma Parquet (message type) : une colonne par colonne `event`, ordre FIN -> GROS (message/fields en
/// dernier). Colonne 0 = `ts` (clé de tri + stats d'élagage). Chaînes = BYTE_ARRAY/UTF8 ; entiers = INT64.
/// Colonnes NOT NULL de `event` (ts/severity/source/category/message/engagement_id/origin) = REQUIRED ;
/// les nullables (host/src_ip/dst_ip/url/xff/dedup/env_id/fields) = OPTIONAL (round-trip fidèle du NULL).
pub(super) fn cold_schema() -> std::sync::Arc<Type> {
    let req_i64 = |name: &str| {
        Type::primitive_type_builder(name, PhysicalType::INT64)
            .with_repetition(Repetition::REQUIRED)
            .build()
            .expect("schéma cold: INT64 requis")
    };
    let req_str = |name: &str| {
        Type::primitive_type_builder(name, PhysicalType::BYTE_ARRAY)
            .with_repetition(Repetition::REQUIRED)
            .with_logical_type(Some(LogicalType::String))
            .build()
            .expect("schéma cold: UTF8 requis")
    };
    let opt_str = |name: &str| {
        Type::primitive_type_builder(name, PhysicalType::BYTE_ARRAY)
            .with_repetition(Repetition::OPTIONAL)
            .with_logical_type(Some(LogicalType::String))
            .build()
            .expect("schéma cold: UTF8 optionnel")
    };
    // ORDRE CANONIQUE (doit rester synchro avec l'ordre d'écriture des colonnes ET le lecteur par nom).
    let fields = vec![
        std::sync::Arc::new(req_i64("ts")),        // 0  clé de tri / élagage
        std::sync::Arc::new(req_i64("severity")),  // 1
        std::sync::Arc::new(req_str("source")),    // 2
        std::sync::Arc::new(req_str("category")),  // 3
        std::sync::Arc::new(opt_str("host")),      // 4
        std::sync::Arc::new(opt_str("src_ip")),    // 5
        std::sync::Arc::new(opt_str("dst_ip")),    // 6
        std::sync::Arc::new(opt_str("url")),       // 7
        std::sync::Arc::new(opt_str("xff")),       // 8
        std::sync::Arc::new(opt_str("dedup")),     // 9
        std::sync::Arc::new(req_str("engagement_id")), // 10
        std::sync::Arc::new(req_str("origin")),    // 11
        std::sync::Arc::new(opt_str("env_id")),    // 12
        std::sync::Arc::new(req_str("message")),   // 13  FAT
        std::sync::Arc::new(opt_str("fields")),    // 14  FAT (JSON)
    ];
    std::sync::Arc::new(
        Type::group_type_builder("plume_event")
            .with_fields(fields)
            .build()
            .expect("schéma cold: groupe racine"),
    )
}

pub(super) fn wr_i64<W: std::io::Write + Send>(rg: &mut SerializedRowGroupWriter<'_, W>, vals: &[i64]) -> Result<(), String> {
    let mut c = rg.next_column().map_err(pe)?.ok_or("cold: colonne INT64 manquante")?;
    c.typed::<Int64Type>().write_batch(vals, None, None).map_err(pe)?;
    c.close().map_err(pe)?;
    Ok(())
}

pub(super) fn wr_req_str<W: std::io::Write + Send>(rg: &mut SerializedRowGroupWriter<'_, W>, vals: &[ByteArray]) -> Result<(), String> {
    let mut c = rg.next_column().map_err(pe)?.ok_or("cold: colonne UTF8 requise manquante")?;
    c.typed::<ByteArrayType>().write_batch(vals, None, None).map_err(pe)?;
    c.close().map_err(pe)?;
    Ok(())
}

pub(super) fn wr_opt_str<W: std::io::Write + Send>(
    rg: &mut SerializedRowGroupWriter<'_, W>,
    vals: &[ByteArray],
    defs: &[i16],
) -> Result<(), String> {
    let mut c = rg.next_column().map_err(pe)?.ok_or("cold: colonne UTF8 optionnelle manquante")?;
    c.typed::<ByteArrayType>().write_batch(vals, Some(defs), None).map_err(pe)?;
    c.close().map_err(pe)?;
    Ok(())
}

/// Propriétés du writer (partagées par le writer in-RAM et le writer STREAMÉ) : ZSTD + fichier déclaré TRIÉ
/// sur la colonne 0 (`ts`, ascendant) -> les lecteurs P2 exploitent la monotonie + stats min/max par groupe.
pub(super) fn cold_writer_props() -> std::sync::Arc<WriterProperties> {
    std::sync::Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .set_sorting_columns(Some(vec![SortingColumn {
                column_idx: 0,
                descending: false,
                nulls_first: false,
            }]))
            .set_created_by("plume-cold/#18-p1".to_string())
            .build(),
    )
}

/// Écrit UN row-group (colonnes 0..14, ORDRE == `cold_schema`) depuis un slice de lignes DÉJÀ ordonnées par
/// `ts`. Ne matérialise QUE ce groupe -> borne mémoire (un seul row-group en RAM à la fois). Partagé par le
/// writer in-RAM (tests) ET le writer STREAMÉ de production. Toute divergence d'ordre casse l'écriture.
pub(super) fn write_row_group<W: std::io::Write + Send>(writer: &mut SerializedFileWriter<W>, group: &[ColdRow]) -> Result<(), String> {
    let mut rg = writer.next_row_group().map_err(pe)?;
    // Constructeur (vals, def_levels) pour une colonne OPTIONAL depuis un extracteur Option<&str>.
    let build_opt = |f: &dyn Fn(&ColdRow) -> Option<&str>| -> (Vec<ByteArray>, Vec<i16>) {
        let mut vals = Vec::new();
        let mut defs = Vec::with_capacity(group.len());
        for r in group {
            match f(r) {
                Some(s) => {
                    vals.push(ByteArray::from(s));
                    defs.push(1);
                }
                None => defs.push(0),
            }
        }
        (vals, defs)
    };
    let req_str_vals = |f: &dyn Fn(&ColdRow) -> &str| -> Vec<ByteArray> {
        group.iter().map(|r| ByteArray::from(f(r))).collect()
    };

    // 0 ts
    let ts: Vec<i64> = group.iter().map(|r| r.row.ts).collect();
    wr_i64(&mut rg, &ts)?;
    // 1 severity
    let sev: Vec<i64> = group.iter().map(|r| r.row.severity).collect();
    wr_i64(&mut rg, &sev)?;
    // 2 source (req)
    wr_req_str(&mut rg, &req_str_vals(&|r| r.row.source.as_str()))?;
    // 3 category (req)
    wr_req_str(&mut rg, &req_str_vals(&|r| r.row.category.as_str()))?;
    // 4 host (opt)
    let (v, d) = build_opt(&|r| r.row.host.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 5 src_ip
    let (v, d) = build_opt(&|r| r.row.src_ip.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 6 dst_ip
    let (v, d) = build_opt(&|r| r.row.dst_ip.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 7 url
    let (v, d) = build_opt(&|r| r.row.url.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 8 xff (porté par ColdRow, hors EventRow)
    let (v, d) = build_opt(&|r| r.xff.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 9 dedup
    let (v, d) = build_opt(&|r| r.row.dedup.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 10 engagement_id (req)
    wr_req_str(&mut rg, &req_str_vals(&|r| r.row.engagement_id.as_str()))?;
    // 11 origin (req)
    wr_req_str(&mut rg, &req_str_vals(&|r| r.row.origin.as_str()))?;
    // 12 env_id (opt : round-trip fidèle du None)
    let (v, d) = build_opt(&|r| r.row.env_id.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;
    // 13 message (req) — FAT
    wr_req_str(&mut rg, &req_str_vals(&|r| r.row.message.as_str()))?;
    // 14 fields (opt) — FAT (JSON)
    let (v, d) = build_opt(&|r| r.row.fields.as_deref());
    wr_opt_str(&mut rg, &v, &d)?;

    rg.close().map_err(pe)?;
    Ok(())
}
