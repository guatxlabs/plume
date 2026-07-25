//! cold_store::identity — LIAISON D'IDENTITÉ FICHIER (#18 FIX B / P2b) : stamp (env_id, jour, seq) dans le
//! footer AEAD + VERIFY décodage-intégral avant tout DELETE hot.
//!
//! LIAISON D'IDENTITÉ FICHIER (#18 FIX B) — clés de métadonnées FILE-LEVEL Parquet stampées DANS le flux age.
//! age (scrypt) donne confidentialité + intégrité PAR-FICHIER mais AUCUN associated-data : la clé d'un tenant est
//! la MÊME pour tous ses jours/env_id -> un attaquant à accès disque cold pouvait, DANS un tenant, échanger
//! `2026-01-01.parquet` <-> `2026-06-01.parquet` (ou deux env_id sous la même clé) ; le déchiffrement réussissait
//! et VERIFY (compte + décodabilité) passait -> service de données du MAUVAIS jour/env ET, au resume, DELETE des
//! lignes hot de CE jour contre un cold mal-mappé = perte. On LIE donc chaque jour-file à son (env_id, jour) en
//! stampant ces valeurs dans les KV metadata du FOOTER Parquet. Le footer est ENTIÈREMENT dans le flux age (AEAD)
//! -> ces métadonnées sont CONFIDENTIELLES *et* INFORGEABLES sans la clé du tenant. VERIFY (fresh-seal ET resume)
//! RÉCUSE tout fichier dont l'identité liée != (env_id, jour) attendus -> `Err` -> fail-safe (aucun DELETE hot),
//! au même titre qu'un échec de déchiffrement. (L'isolement inter-TENANT est déjà couvert par la clé par-tenant ;
//! ceci ferme le swap INTRA-tenant jour<->jour / env<->env, et — via `seq` — le swap intra-jour de SÉQUENCE.)
//!
//! VERIFY (crux crash-safety, FIX #5) : prouve que le Parquet est RÉELLEMENT DÉCODABLE avant d'autoriser tout
//! DELETE du hot. Un footer valide NE SUFFIT PAS : une page de DONNÉES corrompue passe le simple `num_rows` du
//! footer mais rend le cold ILLISIBLE. On DÉCODE donc TOUTES les lignes (défense en profondeur) : toute erreur
//! de décodage / divergence de compte / identité étrangère -> Err -> l'aging NE SUPPRIME ALORS RIEN du hot.

use super::*;
use std::path::Path;

use parquet::file::metadata::KeyValue;
use parquet::file::reader::FileReader;
use parquet::file::writer::SerializedFileWriter;

const COLD_META_ENV_ID: &str = "plume.cold.env_id";
const COLD_META_DAY: &str = "plume.cold.day";
/// #18 P2b — SÉQUENCE stampée : lie un fichier à SA place `seq` DANS le jour (env_id, day). Sans cela, un
/// attaquant à accès disque cold pouvait, DANS un même (env_id, jour), échanger `…-0000.parquet` <->
/// `…-0001.parquet` (même clé, même jour) ; le déchiffrement réussissait et l'ancien VERIFY (env_id+jour)
/// passait -> service/delete de la MAUVAISE tranche. On stampe donc AUSSI le `seq` : VERIFY récuse tout fichier
/// dont le seq lié != seq attendu -> ferme le swap intra-jour de SÉQUENCE (au même titre que le swap jour/env).
const COLD_META_SEQ: &str = "plume.cold.seq";
const COLD_META_FORMAT: &str = "plume.cold.format";
/// Version de FORMAT stampée (défense en profondeur / évolutivité : un lecteur futur peut refuser un format inconnu).
/// Bumpée à `#18-p2` pour le format MULTI-FICHIERS (jour splitté en fichiers séquencés + liaison `seq`).
const COLD_FORMAT_VERSION: &str = "plume-cold/#18-p2";

/// Stampe la LIAISON D'IDENTITÉ (env_id, jour UTC, SÉQUENCE, version de format) dans les KV metadata du footer
/// Parquet. APPELÉ APRÈS `SerializedFileWriter::new` et AVANT `into_inner` -> les valeurs partent dans le footer,
/// DONC À L'INTÉRIEUR du flux age (chiffrées + authentifiées). Le jour est stampé comme sa CHAÎNE `YYYY-MM-DD`
/// (UTC), identique au nom de fichier -> comparaison directe au VERIFY. AUCUN canal plaintext latéral (jamais
/// écrit hors du flux age) -> la propriété « pas de plaintext sur disque » (#18) reste intacte.
pub(super) fn stamp_identity<W: std::io::Write + Send>(writer: &mut SerializedFileWriter<W>, env_id: &str, day: i64, seq: i64) {
    writer.append_key_value_metadata(KeyValue::new(COLD_META_ENV_ID.to_string(), env_id.to_string()));
    writer.append_key_value_metadata(KeyValue::new(COLD_META_DAY.to_string(), ymd_from_day(day)));
    writer.append_key_value_metadata(KeyValue::new(COLD_META_SEQ.to_string(), seq.to_string()));
    writer.append_key_value_metadata(KeyValue::new(COLD_META_FORMAT.to_string(), COLD_FORMAT_VERSION.to_string()));
}

/// Lecture SEULE du footer (num_rows) — l'ANCIENNE vérif (métadonnées pures). N'existe QUE pour le TEST qui
/// prouve qu'un footer valide NE SUFFIT PAS (une page corrompue passe le footer mais échoue au décodage).
/// N'AUTORISE JAMAIS à elle seule une suppression du hot (cf. `verify_parquet_rows` qui, lui, DÉCODE).
#[cfg(test)]
pub(super) fn footer_num_rows(path: &Path, pass: &str) -> Result<i64, String> {
    let reader = open_cold_reader(path, pass)?; // déchiffre AVANT de lire le footer (fichier chiffré at-rest)
    Ok(reader.metadata().file_metadata().num_rows())
}

/// IDENTITÉ ATTENDUE d'UN fichier cold (#18 P2b) : (env_id, jour, `seq`) liés dans le footer AEAD + la fenêtre
/// `[ts_min, ts_max]` DÉCLARÉE de CE fichier (dans le seal). Passée à `verify_parquet_rows` par les chemins qui
/// la connaissent (aging fresh + resume). Le lecteur PARALLÈLE P2b construira le MÊME `FileIdent` depuis une ligne
/// de seal pour vérifier chaque fichier avant de le servir. `ts_min`/`ts_max` sont INCLUSIFS (bornes réelles).
pub(crate) struct FileIdent<'a> {
    pub(crate) env_id: &'a str,
    pub(crate) day: i64,
    pub(crate) seq: i64,
    pub(crate) ts_min: i64,
    pub(crate) ts_max: i64,
}

/// VERIFY (crux crash-safety, FIX #5) : prouve que le Parquet est RÉELLEMENT DÉCODABLE avant d'autoriser tout
/// DELETE du hot. Un footer valide NE SUFFIT PAS : une page de DONNÉES corrompue (checksum ZSTD cassé, page
/// tronquée) passe le simple `num_rows` du footer mais rend le cold ILLISIBLE -> perte silencieuse au moment
/// du hard-purge du hot. On DÉCODE donc TOUTES les lignes (toutes colonnes matérialisées via l'itérateur
/// `record`) : toute erreur de décodage -> Err. On confronte AUSSI le compte décodé à `expected` ET au footer.
/// Toute divergence / fichier illisible / page corrompue -> Err : l'aging NE SUPPRIME ALORS RIEN du hot
/// (fail-safe : jamais de perte sur un Parquet non prouvé lisible). Coût : une passe de lecture par fichier
/// au seal (ou au re-run après crash) — acceptable (hors chemin chaud).
/// `expect_ident` = `Some(FileIdent)` LIE la vérification à une identité attendue (FIX B, #18 P2b) : les chemins
/// qui la CONNAISSENT (aging fresh-seal ET resume, avant tout DELETE) la passent -> le fichier est RÉCUSÉ si sa
/// liaison (env_id, jour, `seq` — KV metadata DANS l'AEAD) ou ses `ts` (hors `[ts_min, ts_max]` déclaré) ne
/// correspondent pas. `None` = vérif de compte+décodabilité SEULE (fixtures génériques). Un mismatch -> `Err`,
/// exactement comme un échec de déchiffrement -> même fail-safe : l'aging NE SUPPRIME RIEN du hot.
pub(crate) fn verify_parquet_rows(path: &Path, expected: usize, expect_ident: Option<FileIdent<'_>>, pass: &str) -> Result<(), String> {
    // DÉCHIFFRE d'abord (fichier chiffré at-rest #18) : une clé fausse / un tag AEAD invalide / une troncature
    // échoue ICI -> `Err` -> l'aging ne supprime RIEN du hot (fail-safe, jamais de perte sur un cold non
    // prouvé LISIBLE). Le déchiffrement AEAD authentifie déjà l'INTÉGRALITÉ des octets ; le décodage intégral
    // ci-dessous (FIX #5) reste une défense EN PROFONDEUR (compte + matérialisation de chaque ligne).
    let reader = open_cold_reader(path, pass)?;
    let fmeta = reader.metadata().file_metadata();
    let footer = fmeta.num_rows();
    if footer < 0 || footer as usize != expected {
        return Err(format!("verify {}: footer={footer} != attendu {expected}", path.display()));
    }
    // FIX B / P2b — LIAISON D'IDENTITÉ (env_id, jour, seq). Les KV metadata sont DANS le flux age (déjà
    // déchiffré+authentifié ci-dessus) -> confidentielles ET inforgeables sans la clé du tenant. On RÉCUSE tout
    // fichier dont l'identité liée != attendue : bloque le swap INTRA-tenant vers un AUTRE (env_id, jour) ET vers
    // une AUTRE séquence du même jour (même clé) — un tel fichier déchiffre/décode parfaitement mais sert la
    // MAUVAISE tranche / provoque un DELETE mal-mappé. Mismatch -> `Err` (fail-safe, aucun DELETE).
    let ts_bounds = if let Some(id) = expect_ident.as_ref() {
        let kv = fmeta.key_value_metadata();
        let get = |key: &str| -> Option<&str> {
            kv.and_then(|v| v.iter().find(|k| k.key == key)).and_then(|k| k.value.as_deref())
        };
        let file_env = get(COLD_META_ENV_ID)
            .ok_or_else(|| format!("verify {}: liaison d'identité {COLD_META_ENV_ID} ABSENTE (fichier non lié -> refus)", path.display()))?;
        let file_day = get(COLD_META_DAY)
            .ok_or_else(|| format!("verify {}: liaison d'identité {COLD_META_DAY} ABSENTE (fichier non lié -> refus)", path.display()))?;
        let file_seq = get(COLD_META_SEQ)
            .ok_or_else(|| format!("verify {}: liaison d'identité {COLD_META_SEQ} ABSENTE (fichier non lié -> refus)", path.display()))?;
        let exp_day_str = ymd_from_day(id.day);
        let exp_seq_str = id.seq.to_string();
        if file_env != id.env_id || file_day != exp_day_str || file_seq != exp_seq_str {
            return Err(format!(
                "verify {}: identité liée ({file_env},{file_day},{file_seq}) != attendue ({},{exp_day_str},{exp_seq_str}) -> REFUS (swap intra-tenant jour/env/seq ?)",
                path.display(), id.env_id
            ));
        }
        Some((id.ts_min, id.ts_max))
    } else {
        None
    };
    // DÉCODAGE INTÉGRAL : matérialise chaque ligne (force le décodage de CHAQUE page de données de CHAQUE
    // colonne). Une page corrompue lève ici. On compte pour re-confronter à `expected` (défense en profondeur).
    // DÉFENSE EN PROFONDEUR (FIX B / P2b) : si l'identité est connue, chaque `ts` DOIT tomber dans la fenêtre
    // DÉCLARÉE `[ts_min, ts_max]` DU FICHIER (inclusive) -> attrape INDÉPENDAMMENT un swap de fichier même si les
    // KV metadata étaient contournées (un fichier d'un autre seq/jour a des ts hors de cette fenêtre serrée).
    let mut decoded = 0usize;
    for rec in reader.get_row_iter(None).map_err(pe)? {
        let row = rec.map_err(|e| format!("verify {}: décodage ligne échoué (page corrompue?): {e}", path.display()))?;
        if let Some((lo, hi)) = ts_bounds {
            let mut ts: Option<i64> = None;
            for (name, field) in row.get_column_iter() {
                if name.as_str() == "ts" {
                    if let parquet::record::Field::Long(v) = field {
                        ts = Some(*v);
                    }
                    break;
                }
            }
            match ts {
                Some(t) if t >= lo && t <= hi => {}
                other => {
                    return Err(format!(
                        "verify {}: ts={other:?} hors de la fenêtre déclarée du fichier [{lo},{hi}] -> REFUS (swap de fichier ?)",
                        path.display()
                    ));
                }
            }
        }
        decoded += 1;
    }
    if decoded != expected {
        return Err(format!("verify {}: {decoded} lignes décodées != attendu {expected}", path.display()));
    }
    Ok(())
}
