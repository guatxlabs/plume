//! backup::dump_restauration — LA CHARGE de l'enveloppe `age(zstd(charge))` : le DUMP TYPÉ STREAMING B1
//! (`PLUMEDUMP1\n`, format auto-descriptif little-endian à longueur préfixée, plan dérivé de `sqlite_master`,
//! AUCUN clair sur disque), le dispatch `backup_compressed` (B1 par défaut, repli legacy `sqlcipher_export` sur
//! un schéma que le dump ne représente pas) et la RESTAURATION `restore_compressed`, qui reconnaît la charge à
//! son marqueur de tête (dump B1 ou fichier SQLite historique), jamais au nom du fichier.
//! Sous-module de `backup` (cf. `backup/mod.rs`), qui ré-exporte sa surface `pub(crate)` sous les chemins d'origine.
use super::*;

// ============================================================================
// B1 — BACKUP STREAMING (élimine le PLAINTEXT TRANSITOIRE sur disque)
// ----------------------------------------------------------------------------
// PROBLÈME résiduel du legacy (backup_compressed_legacy) : sqlcipher_export matérialise
// la DB ENTIÈRE EN CLAIR dans un fichier temporaire (~2,4 Gio) avant compress+chiffre ->
// fenêtre d'exposition + pic disque.
//
// B1 : on ne matérialise JAMAIS le clair. On PARCOURT le schéma + les données ligne-à-ligne
// depuis la DB SQLCipher OUVERTE (déchiffrée EN MÉMOIRE par SQLCipher, jamais sur disque
// clair), on SÉRIALISE un DUMP typé binaire, pipe DIRECT -> zstd -> age -> `.age` final.
// AUCUN fichier clair intermédiaire.
//
// FORMAT de sortie : age( zstd( <DUMP B1> ) ). Les couches age+zstd sont IDENTIQUES au legacy
// -- SEULE la charge utile change. Le restore DISTINGUE les deux par le MARQUEUR de tête de la
// charge décompressée : `SQLite format 3\0` = ancien backup (age(zstd(fichier SQLite clair)))
// -> legacy ; `DUMP_MAGIC` = backup B1 -> streaming. -> rétrocompat TOTALE des backups EXISTANTS.
//
// FIDÉLITÉ (DATA-LOSS-CRITICAL) : chaque cellule est lue via ValueRef (classe de stockage EXACTE
// Null/Integer/Real/Text/Blob) et sérialisée SANS PERTE :
//   - Real -> f64::to_bits (8 o) : bit-exact, PAS de formatage décimal (0 perte de précision ;
//     -0.0, sous-normaux, NaN/Inf inclus).
//   - Blob -> octets BRUTS (longueur-préfixée) : octets nuls / 0xFF préservés.
//   - Text -> octets UTF-8 BRUTS (plume garantit l'UTF-8). Un TEXT non-UTF8 (valeur légale en SQLite
//     mais non représentable en dump typé) -> classé `PlanErr::Unsupported` (comme un schéma non-B1) :
//     l'appelant REPLIE AUTOMATIQUEMENT sur le legacy (sqlcipher_export copie les octets VERBATIM) ->
//     jamais de perte silencieuse, jamais un backup qui plante. NB : distinct d'une vraie panne
//     IO/chiffrement (Fatal) qui, elle, ne doit PAS être masquée par un fallback (risque de boucle).
//   - Integer/Null -> exacts.
// Au restore on RE-LIE (bind) ces Value dans un INSERT préparé : l'AFFINITÉ de colonne est
// ré-appliquée à l'IDENTIQUE (même schéma) -> IDEMPOTENTE -> classe de stockage reproduite
// exactement. rowid préservé (colonne alias INTEGER PRIMARY KEY, ou `rowid` explicite pour les
// tables rowid sans alias). sqlite_sequence (compteurs AUTOINCREMENT) préservé -> pas de
// réutilisation de rowid après restore.
//
// SCHÉMA : capturé depuis sqlite_master (tables/index/triggers/vues + colonnes ALTERées). Les FTS5
// à CONTENU EXTERNE (content='<table réelle>', ex: event_fts) sont RECONSTRUITES par `rebuild`
// depuis leur table de contenu (index DÉRIVÉ -> fidélité FONCTIONNELLE, correcte car le contenu
// source EST préservé bit-à-bit). Toute forme de schéma que B1 NE PEUT représenter fidèlement
// (FTS contentless `content=''` ex: event_fields_fts, FTS régulière, autre vtable) est DÉTECTÉE
// AVANT toute écriture -> REPLI AUTOMATIQUE sur le legacy (sqlcipher_export copie les shadow tables
// bit-à-bit). -> jamais de perte ; au pire pas d'élimination du clair pour ces schémas opt-in.
//
// 2 Gio-SAFE : lecture ligne-à-ligne via le pager SQLite (cache borné) + sérialisation immédiate
// dans le flux zstd -> au plus 1 ligne + buffers en RAM, JAMAIS toute la DB, JAMAIS de clair sur
// disque. Snapshot cohérent : lecture sous transaction ouverte (BEGIN) -> vue figée même si la DB
// de prod est écrite en parallèle.
// Le PLANCHER est structurel, pas espéré : `write_value_ref` sérialise la cellule EMPRUNTÉE au pager
// (`ValueRef`) sans la recopier, rien n'est retenu d'une ligne à l'autre, et aucun tampon ne grandit
// avec le nombre de lignes. Une LIGNE énorme coûte donc sa propre taille, pas celle de sa table, et ce
// n'est pas un seuil mais une INVARIANCE, mesurée au banc par le test
// `backup_streaming_peak_live_heap_follows_row_width_not_row_count` (2026-08-08, au banc) : à largeur de cellule
// CONSTANTE (4 Mio), 2 lignes puis 16 -> pic de tas vivant 1 147 968 o puis 1 147 600 o, soit 368 o
// d'écart pour 56 Mio de charge ajoutée. Le test porte ses deux mutations : faire accumuler le dump
// entier écarte les pics de 58 722 184 o (ROUGE), recopier chaque cellule avant écriture déplace les
// DEUX pics à ~5,34 Mio sans les écarter (VERT — c'est la borne connue, pas un défaut).
// La borne restante est le champ unique : `rd_bytes` alloue la valeur entière à la relecture, donc une
// cellule de 1 Gio coûterait 1 Gio (pire cas, par construction).
//
// LE TERME QUI DOMINE RÉELLEMENT LE PIC N'EST PAS LE DUMP, C'EST LE KDF (mesuré 2026-08-08). Sur le
// chemin par PASSPHRASE — le DÉFAUT quand `PLUME_BACKUP_AGE_RECIPIENT` n'est pas configuré — `age`
// choisit son facteur de travail scrypt par un ÉTALONNAGE AU CHRONO à chaque sauvegarde (age 0.11
// `target_scrypt_work_factor` : viser ~1 s de CPU), et scrypt alloue 128·r·2^log_n = 2^(10+log_n)
// octets. Six sauvegardes consécutives de la MÊME base ont donné log_n = 13 puis 14, soit 8 Mio puis
// 16 Mio de tampon — le pic de la sauvegarde passe de 9,4 Mio à 17,8 Mio sans qu'aucune ligne ne
// change. Le reste est DÉDUIT, pas mesuré : le seuil de l'ancienne version de ce test valait 32 Mio,
// donc toute machine assez rapide pour choisir log_n >= 16 le faisait rougir à coup sûr ; age donne
// lui-même 18 comme « ~1 s sur une machine moderne », soit 256 Mio — l'ordre de grandeur des
// « +247 Mio » mesurés en CI qui ont fait refuser le build de 8618753 en accusant le streaming à tort.
//
// CE QUI ÉTAIT « DÉDUIT » CI-DESSUS EST MAINTENANT MESURÉ, ET C'ÉTAIT PIRE (2026-08-09) : le facteur
// dépend aussi du PROFIL DE COMPILATION. Le même appel, sur la même machine, choisit log_n = 13/14/14
// en `debug` (ce que compile `cargo test`) mais **19/19/20 en `release` — 512 Mio puis 1 Gio**, la
// moitié du budget de 2 Gio, tirée au sort à chaque sauvegarde. Les mesures 13/14 de la veille
// venaient donc d'un binaire de test, pas du profil de production.
// CE TERME EST DÉSORMAIS BORNÉ : le chemin par passphrase écrit un facteur FIXE
// (`BACKUP_SCRYPT_LOG_N_DEFAUT`, 4 194 304 octets) et la lecture plafonne à `BACKUP_SCRYPT_MAX_LOG_N`
// — voir la section « FACTEUR DE TRAVAIL SCRYPT » en tête de fichier pour pourquoi cette borne ne
// coûte AUCUNE résistance au brute-force. Le destinataire ASYMÉTRIQUE (x25519), recommandé pour
// l'escrow, n'a de toute façon pas ce terme du tout.
//
// ----------------------------------------------------------------------------
// CE QUE LE DUMP N'EMPORTE PAS — l'échange, nommé et mesuré.
// ----------------------------------------------------------------------------
// L'ancien format était une DB SQLite COMPLÈTE : il emportait donc AUSSI les index B-tree, les tables
// shadow FTS5 (`*_data`/`*_idx`/`*_docsize`/`*_config`), les `sqlite_stat*` et les pages libres de la
// fragmentation. Le dump typé n'emporte QUE le DDL et les LIGNES ; tout le reste est DÉRIVÉ et se
// reconstruit à la restauration (`CREATE INDEX` rejoués, `INSERT INTO <fts>(<fts>) VALUES('rebuild')`).
// Ce n'est pas une perte de données — c'est un déplacement de coût de la sauvegarde vers la restauration.
//
// MESURE (`backup_streaming_is_smaller_than_the_plaintext_export_on_the_same_db`, 2026-08-08), MÊME base
// de test au schéma RÉEL de plume : 20 000 événements, `event_fts` peuplée, base SQLCipher de 7 221 248 o.
//     chemin        charge sérialisée   `.age` produit
//     streaming        3 714 129 o         321 017 o
//     historique       6 758 400 o         780 941 o
// Soit un `.age` 2,4x PLUS PETIT. La TAILLE est stable d'une exécution à l'autre ; le TEMPS de
// restauration, lui, ne l'est pas, et il faut le dire ainsi plutôt que de citer un chiffre unique :
//     suite en série (machine au repos)   : streaming 2 640 ms  vs historique 2 366 ms   (+12 %)
//     suite complète en parallèle         : streaming 4 614 ms  vs historique 1 936 ms   (+138 %)
// La reconstruction des index et de la FTS est du CPU pur : sous contention elle se dégrade bien plus
// vite que la simple recopie de pages du chemin historique. L'ORDRE est constant (le streaming restaure
// toujours plus lentement), l'AMPLEUR dépend de la charge de la machine — à provisionner dans le RTO
// comme un facteur pouvant approcher 2,5x, pas comme un surcoût de 20 %.
// Sur une base RÉELLE l'écart de TAILLE est structurellement plus grand encore : index + FTS y
// pesaient plus de 40 % du fichier (relevé du 2026-08-08) — exactement la part que le
// dump n'emporte pas. La contrepartie grandit dans le même sens : plus il y a d'index à ne pas
// transporter, plus il y en a à reconstruire au restore.
//
// ----------------------------------------------------------------------------
// DÉFAUT, PAS OPT-IN — et pourquoi ce sens-là.
// ----------------------------------------------------------------------------
// Le streaming est le chemin par DÉFAUT ; l'ancien reste joignable par
// `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1` (`backup_force_plaintext_export`). Trois raisons de ne pas
// avoir laissé le défaut sur l'ancien : (1) la propriété achetée — pas de clair sur disque — ne vaut
// que si elle est prise par le chemin réellement emprunté en production, et un opt-in ne l'est jamais ;
// (2) le seul risque du streaming est une infidélité de représentation, et il est FERMÉ AVANT ÉCRITURE
// par le repli automatique (`PlanErr::Unsupported`) : un schéma ou une valeur qu'il ne sait pas rendre
// bit-à-bit ne produit pas un backup dégradé, il produit un backup de l'ANCIEN format ; (3) la
// restauration lit les DEUX formats au marqueur, donc basculer le défaut ne périme aucune sauvegarde
// déjà en séquestre. Le sens inverse — laisser l'ancien par défaut — aurait gardé la fenêtre de clair
// ouverte en échange d'aucune sécurité supplémentaire.
// ============================================================================

/// Marqueur de tête du DUMP B1 (11 octets). NE COLLISIONNE PAS avec `SQLite format 3\0` (les octets
/// diffèrent dès le 1er) -> le restore distingue B1 (streaming) de l'ancien format (fichier SQLite).
pub(crate) const DUMP_MAGIC: &[u8; 11] = b"PLUMEDUMP1\n";

/// Borne anti-OOM d'une valeur/chaîne lue depuis le dump (post-AEAD, donc déjà intègre : l'age
/// authentifie ; une altération -> échec de déchiffrement). Plancher > SQLITE_MAX_LENGTH (1 Gio).
const DUMP_MAX_FIELD: usize = 2 << 30; // 2 Gio

// -- primitives d'encodage little-endian, longueur-préfixée (format auto-descriptif, parse en flux) --
fn wr_u8<W: std::io::Write>(w: &mut W, v: u8) -> std::io::Result<()> { w.write_all(&[v]) }
fn wr_u16<W: std::io::Write>(w: &mut W, v: u16) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_u32<W: std::io::Write>(w: &mut W, v: u32) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_u64<W: std::io::Write>(w: &mut W, v: u64) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_i64<W: std::io::Write>(w: &mut W, v: i64) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_bytes<W: std::io::Write>(w: &mut W, b: &[u8]) -> std::io::Result<()> { wr_u32(w, b.len() as u32)?; w.write_all(b) }
fn wr_str<W: std::io::Write>(w: &mut W, s: &str) -> std::io::Result<()> { wr_bytes(w, s.as_bytes()) }

fn rd_u8<R: std::io::Read>(r: &mut R) -> std::io::Result<u8> { let mut b = [0u8; 1]; r.read_exact(&mut b)?; Ok(b[0]) }
fn rd_u16<R: std::io::Read>(r: &mut R) -> std::io::Result<u16> { let mut b = [0u8; 2]; r.read_exact(&mut b)?; Ok(u16::from_le_bytes(b)) }
fn rd_u32<R: std::io::Read>(r: &mut R) -> std::io::Result<u32> { let mut b = [0u8; 4]; r.read_exact(&mut b)?; Ok(u32::from_le_bytes(b)) }
fn rd_u64<R: std::io::Read>(r: &mut R) -> std::io::Result<u64> { let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(u64::from_le_bytes(b)) }
fn rd_i64<R: std::io::Read>(r: &mut R) -> std::io::Result<i64> { let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(i64::from_le_bytes(b)) }
fn rd_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let n = rd_u32(r)? as usize;
    if n > DUMP_MAX_FIELD { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("champ dump surdimensionné ({n} o) — corrompu"))); }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}
fn rd_str<R: std::io::Read>(r: &mut R) -> std::io::Result<String> {
    let b = rd_bytes(r)?;
    String::from_utf8(b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Writer transparent qui COMPTE les octets écrits (mesure la taille du DUMP EN CLAIR, pour le log/stat
/// de ratio) sans jamais matérialiser le clair.
struct CountWriter<'a, W: std::io::Write + 'a> { inner: &'a mut W, count: u64 }
impl<'a, W: std::io::Write + 'a> std::io::Write for CountWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { let n = self.inner.write(buf)?; self.count += n as u64; Ok(n) }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}

/// Cite un identifiant SQL (table/colonne) — double-quote + échappe les `"` internes.
pub(super) fn quote_ident(name: &str) -> String { format!("\"{}\"", name.replace('"', "\"\"")) }

/// Sérialise UNE cellule (ValueRef -> flux typé). Text validé UTF-8 (invariant plume ; sinon la VALEUR
/// n'est pas représentable en dump typé -> `PlanErr::Unsupported` qui DÉCLENCHE le repli legacy, PAS une
/// erreur Fatale qui planterait tout le backup). Real via to_bits (bit-exact). Blob/octets bruts.
/// DISTINCTION CRITIQUE : une VALEUR non-représentable (TEXT non-UTF8) est RÉCUPÉRABLE via le legacy
/// (sqlcipher_export copie les octets verbatim) -> `Unsupported` ; une vraie erreur d'écriture flux
/// (IO/zstd/age) est une PANNE -> `Fatal` (jamais masquée par un fallback qui pourrait boucler). `table`
/// pour le message.
fn write_value_ref<W: std::io::Write>(w: &mut W, v: rusqlite::types::ValueRef, table: &str) -> Result<(), PlanErr> {
    use rusqlite::types::ValueRef as VR;
    let r = match v {
        VR::Null => wr_u8(w, 0),
        VR::Integer(i) => wr_u8(w, 1).and_then(|_| wr_i64(w, i)),
        VR::Real(f) => wr_u8(w, 2).and_then(|_| wr_u64(w, f.to_bits())),
        VR::Text(bytes) => {
            if std::str::from_utf8(bytes).is_err() {
                // VALEUR non fidèlement représentable en dump typé -> repli legacy (byte-verbatim), PAS Fatal.
                return Err(PlanErr::Unsupported(format!(
                    "TEXT non-UTF8 dans la table {table} — valeur non représentable en dump typé B1 (repli legacy octet-à-octet)")));
            }
            wr_u8(w, 3).and_then(|_| wr_bytes(w, bytes))
        }
        VR::Blob(bytes) => wr_u8(w, 4).and_then(|_| wr_bytes(w, bytes)),
    };
    r.map_err(|e| PlanErr::Fatal(format!("écriture valeur ({table}) : {e}")))
}

/// Désérialise UNE cellule (flux typé -> Value liable par bind). Reproduit exactement la classe de
/// stockage source.
fn read_value<R: std::io::Read>(r: &mut R) -> Result<rusqlite::types::Value, String> {
    use rusqlite::types::Value as V;
    let tag = rd_u8(r).map_err(|e| format!("lecture tag valeur : {e}"))?;
    let v = match tag {
        0 => V::Null,
        1 => V::Integer(rd_i64(r).map_err(|e| format!("lecture INTEGER : {e}"))?),
        2 => V::Real(f64::from_bits(rd_u64(r).map_err(|e| format!("lecture REAL : {e}"))?)),
        3 => V::Text(rd_str(r).map_err(|e| format!("lecture TEXT : {e}"))?),
        4 => V::Blob(rd_bytes(r).map_err(|e| format!("lecture BLOB : {e}"))?),
        other => return Err(format!("B1: tag de valeur inconnu {other} (dump corrompu)")),
    };
    Ok(v)
}

/// Erreur de collecte du plan : `Unsupported` -> l'appelant REPLIE sur le legacy (schéma non
/// représentable en dump typé) ; `Fatal` -> vraie erreur (DB illisible, IO...).
enum PlanErr { Unsupported(String), Fatal(String) }

struct TableDump { name: String, select_sql: String, insert_sql: String, ncols: usize }
enum PostStep { Sql(String), FtsRebuild(String) }
struct DumpPlan {
    pre_ddl: Vec<String>,      // CREATE TABLE des tables ordinaires
    tables: Vec<TableDump>,    // données à streamer (dans l'ordre pre_ddl)
    seqs: Vec<(String, i64)>,  // sqlite_sequence (compteurs AUTOINCREMENT)
    post: Vec<PostStep>,       // vtables + rebuild + index + triggers + vues, dans l'ordre d'application
}

/// `CREATE VIRTUAL TABLE ...` ?
fn is_virtual_table(sql: &str) -> bool { sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE") }

/// Table de contenu d'une FTS (3/4/5) à CONTENU EXTERNE (`content='X'`, X non vide) -> Some(X).
/// contentless (`content=''`), FTS régulière (pas de content=) ou pas FTS -> None (= NON B1-safe).
fn fts_external_content(sql: &str) -> Option<String> {
    let up = sql.to_ascii_uppercase();
    if !(up.contains("USING FTS5") || up.contains("USING FTS4") || up.contains("USING FTS3")) { return None; }
    let low = sql.to_ascii_lowercase();
    let mut idx = 0usize;
    while let Some(pos) = low[idx..].find("content") {
        let after = idx + pos + "content".len();
        idx = after;
        let rest = sql[after..].trim_start();
        if rest.starts_with('_') { continue; }       // content_rowid -> pas la clé content
        if !rest.starts_with('=') { continue; }
        let after_eq = rest[1..].trim_start();
        let q = match after_eq.chars().next() { Some(c) if c == '\'' || c == '"' => c, _ => continue };
        let body = &after_eq[1..];
        if let Some(endq) = body.find(q) {
            let val = &body[..endq];
            if val.is_empty() { return None; }        // content='' -> contentless
            return Some(val.to_string());
        }
    }
    None
}

/// Construit le plan de dump d'UNE table ordinaire : liste de colonnes + SELECT/INSERT.
/// Préserve le rowid : via l'alias INTEGER PRIMARY KEY quand il existe, sinon en préfixant `rowid`
/// explicitement (tables rowid sans alias) — sauf WITHOUT ROWID (pas de rowid).
fn build_table_dump(conn: &Connection, name: &str, create_sql: &str) -> Result<TableDump, String> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_ident(name)))
        .map_err(|e| format!("table_info {name} : {e}"))?;
    let cols: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(5)?))) // name, type, pk
        .map_err(|e| format!("table_info map {name} : {e}"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| format!("table_info collect {name} : {e}"))?;
    if cols.is_empty() { return Err(format!("table {name} sans colonnes")); }

    let without_rowid = create_sql.to_ascii_uppercase().replace([' ', '\t', '\n', '\r'], "").contains("WITHOUTROWID");
    let pk_cols: Vec<&(String, String, i64)> = cols.iter().filter(|c| c.2 > 0).collect();
    let has_int_pk_alias = pk_cols.len() == 1 && pk_cols[0].1.eq_ignore_ascii_case("INTEGER");
    let prepend_rowid = !without_rowid && !has_int_pk_alias;

    let mut sel_cols: Vec<String> = Vec::new();
    let mut ins_cols: Vec<String> = Vec::new();
    if prepend_rowid { sel_cols.push("rowid".into()); ins_cols.push("rowid".into()); }
    for (cn, _, _) in &cols { sel_cols.push(quote_ident(cn)); ins_cols.push(quote_ident(cn)); }
    let ncols = sel_cols.len();
    let select_sql = format!("SELECT {} FROM {}", sel_cols.join(", "), quote_ident(name));
    let placeholders = std::iter::repeat("?").take(ncols).collect::<Vec<_>>().join(", ");
    let insert_sql = format!("INSERT INTO {} ({}) VALUES ({})", quote_ident(name), ins_cols.join(", "), placeholders);
    Ok(TableDump { name: name.to_string(), select_sql, insert_sql, ncols })
}

/// Collecte le PLAN de dump depuis sqlite_master. Renvoie `Unsupported` (AVANT toute écriture) si le
/// schéma contient une table virtuelle non représentable en dump typé -> repli legacy propre.
fn collect_dump_plan(conn: &Connection) -> Result<DumpPlan, PlanErr> {
    let mut stmt = conn.prepare("SELECT type, name, COALESCE(sql,'') FROM sqlite_master ORDER BY rowid")
        .map_err(|e| PlanErr::Fatal(format!("prepare sqlite_master : {e}")))?;
    let master: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        .map_err(|e| PlanErr::Fatal(format!("query sqlite_master : {e}")))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| PlanErr::Fatal(format!("collect sqlite_master : {e}")))?;

    // tables virtuelles + set des shadow tables (<vt>_<suffixe>).
    // RISQUE LATENT (collision de nom) : ce set est HEURISTIQUE — il matche par NOM (<vtable>_<suffixe>),
    // pas par rattachement réel. Une vraie table UTILISATEUR nommée `<vt>_data`/`_idx`/... alors qu'une
    // vtable `<vt>` existe serait skippée du dump SANS erreur (perte silencieuse). AUJOURD'HUI INOFFENSIF :
    //   (1) le seul suffixe n'est ajouté que pour des vtables RÉELLEMENT présentes (`for vt in &vtables`) ;
    //   (2) le schéma plume actuel n'a AUCUNE table utilisateur de cette forme ;
    //   (3) en pratique SQLite REFUSE la coexistence — créer la vtable `<vt>` échoue si `<vt>_data` existe
    //       déjà (nom de shadow pris), et inversement -> les deux ne cohabitent pas dans une DB vivante.
    // Un durcissement exact (n'exclure que les shadow tables réellement rattachées) exige une détection
    // fiable non triviale (pas de flag propre en sqlite_master) -> laissé en l'état, risque documenté.
    let vtables: Vec<&String> = master.iter().filter(|(ty, _, sql)| ty == "table" && is_virtual_table(sql)).map(|(_, n, _)| n).collect();
    let shadow_suffixes = ["data", "idx", "docsize", "config", "content", "row", "segments", "segdir", "stat"];
    let mut shadow: std::collections::HashSet<String> = std::collections::HashSet::new();
    for vt in &vtables { for s in shadow_suffixes { shadow.insert(format!("{vt}_{s}")); } }

    let ordinary_names: std::collections::HashSet<String> = master.iter()
        .filter(|(ty, name, sql)| ty == "table" && !is_virtual_table(sql) && !name.starts_with("sqlite_") && !shadow.contains(name.as_str()))
        .map(|(_, name, _)| name.clone())
        .collect();

    let mut plan = DumpPlan { pre_ddl: vec![], tables: vec![], seqs: vec![], post: vec![] };
    let (mut virt_creates, mut rebuilds, mut indexes, mut triggers, mut views) =
        (Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new());

    for (ty, name, sql) in &master {
        match ty.as_str() {
            "table" => {
                if is_virtual_table(sql) {
                    match fts_external_content(sql) {
                        Some(content_table) if ordinary_names.contains(&content_table) => {
                            virt_creates.push(sql.clone());
                            rebuilds.push(name.clone());
                        }
                        _ => return Err(PlanErr::Unsupported(format!(
                            "table virtuelle {name} non représentable en dump typé (FTS contentless/régulière ou vtable non-FTS)"))),
                    }
                } else if name.starts_with("sqlite_") {
                    // sqlite_sequence : compteurs AUTOINCREMENT (données capturées plus bas, CREATE auto).
                    // sqlite_stat* / sqlite_autoindex_* : advisory/auto -> ignorés (régénérés par ANALYZE / à la création d'index).
                } else if shadow.contains(name.as_str()) {
                    // shadow d'une vtable -> recréée+repeuplée par le rebuild.
                } else {
                    plan.pre_ddl.push(sql.clone());
                    let td = build_table_dump(conn, name, sql).map_err(PlanErr::Fatal)?;
                    plan.tables.push(td);
                }
            }
            "index" => { if !sql.is_empty() { indexes.push(sql.clone()); } } // sqlite_autoindex_* -> sql vide -> skip
            "trigger" => { if !sql.is_empty() { triggers.push(sql.clone()); } }
            "view" => { if !sql.is_empty() { views.push(sql.clone()); } }
            _ => {}
        }
    }

    // sqlite_sequence : capture les compteurs (préserve la fenêtre AUTOINCREMENT -> anti-réutilisation rowid).
    if master.iter().any(|(ty, name, _)| ty == "table" && name == "sqlite_sequence") {
        let mut s = conn.prepare("SELECT name, seq FROM sqlite_sequence")
            .map_err(|e| PlanErr::Fatal(format!("prepare sqlite_sequence : {e}")))?;
        plan.seqs = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| PlanErr::Fatal(format!("query sqlite_sequence : {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| PlanErr::Fatal(format!("collect sqlite_sequence : {e}")))?;
    }

    // ordre d'application post : vtables -> rebuilds -> index -> triggers -> vues.
    for s in virt_creates { plan.post.push(PostStep::Sql(s)); }
    for n in rebuilds { plan.post.push(PostStep::FtsRebuild(n)); }
    for s in indexes { plan.post.push(PostStep::Sql(s)); }
    for s in triggers { plan.post.push(PostStep::Sql(s)); }
    for s in views { plan.post.push(PostStep::Sql(s)); }
    Ok(plan)
}

/// Sérialise le DUMP B1 (magic + schéma + données + sqlite_sequence + post-DDL) dans `w` (le flux
/// zstd->age). Lit les lignes en flux via le pager SQLite -> RAM bornée.
fn dump_stream<W: std::io::Write>(conn: &Connection, plan: &DumpPlan, w: &mut W) -> Result<(), PlanErr> {
    // Erreurs d'ÉCRITURE FLUX (IO/zstd/age) et de LECTURE DB (prepare/query) = vraies PANNES -> Fatal.
    // SEULE une valeur non représentable (write_value_ref -> Unsupported) déclenche le repli legacy.
    let we = |r: std::io::Result<()>| r.map_err(|e| PlanErr::Fatal(format!("dump : écriture flux : {e}")));
    we(w.write_all(DUMP_MAGIC))?;
    // section 1 : pre-DDL (CREATE TABLE).
    we(wr_u32(w, plan.pre_ddl.len() as u32))?;
    for s in &plan.pre_ddl { we(wr_str(w, s))?; }
    // section 2 : données.
    we(wr_u32(w, plan.tables.len() as u32))?;
    for t in &plan.tables {
        we(wr_str(w, &t.name))?;
        we(wr_u16(w, t.ncols as u16))?;
        we(wr_str(w, &t.insert_sql))?;
        let mut stmt = conn.prepare(&t.select_sql).map_err(|e| PlanErr::Fatal(format!("prepare select {} : {e}", t.name)))?;
        let mut rows = stmt.query([]).map_err(|e| PlanErr::Fatal(format!("query {} : {e}", t.name)))?;
        loop {
            match rows.next().map_err(|e| PlanErr::Fatal(format!("next {} : {e}", t.name)))? {
                Some(row) => {
                    we(wr_u8(w, 1))?; // ligne présente
                    for i in 0..t.ncols {
                        let vr = row.get_ref(i).map_err(|e| PlanErr::Fatal(format!("get_ref {} col {i} : {e}", t.name)))?;
                        write_value_ref(w, vr, &t.name)?;
                    }
                }
                None => { we(wr_u8(w, 0))?; break; } // fin de table
            }
        }
    }
    // section 3 : sqlite_sequence.
    we(wr_u32(w, plan.seqs.len() as u32))?;
    for (n, s) in &plan.seqs { we(wr_str(w, n))?; we(wr_i64(w, *s))?; }
    // section 4 : post-DDL.
    we(wr_u32(w, plan.post.len() as u32))?;
    for p in &plan.post {
        match p {
            PostStep::Sql(s) => { we(wr_u8(w, 1))?; we(wr_str(w, s))?; }
            PostStep::FtsRebuild(n) => { we(wr_u8(w, 2))?; we(wr_str(w, n))?; }
        }
    }
    we(wr_u8(w, 0xFF))?; // sentinelle de fin (détecte une troncature)
    Ok(())
}

/// B1 — SAUVEGARDE STREAMING (zéro clair transitoire). Ouvre la DB SQLCipher, fige un snapshot lecture
/// (BEGIN), collecte le plan (repli `Unsupported` AVANT toute écriture si schéma non-B1) puis dump ->
/// zstd -> age -> dest. Renvoie {plaintext_bytes(=taille du dump), dest_bytes, wrote_plaintext_to_disk=false}.
fn backup_compressed_stream(db_path: &str, dest: &str, pass: &str, recipient: Option<&str>) -> Result<BackupStats, PlanErr> {
    let conn = open_db_keyed_without_schema_contract(db_path, Some(pass)).map_err(|e| PlanErr::Fatal(format!("ouverture DB source : {e}")))?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| PlanErr::Fatal(format!("DB source illisible (clé PLUME_DB_KEY incorrecte ?) : {e}")))?;
    // BEGIN -> snapshot lecture figé pour toute la durée du dump (cohérence multi-tables, même sous écritures concurrentes).
    conn.execute_batch("BEGIN").map_err(|e| PlanErr::Fatal(format!("begin snapshot : {e}")))?;

    let plan = collect_dump_plan(&conn)?; // Unsupported -> repli AVANT toute écriture (rien créé).

    let _ = std::fs::remove_file(dest);
    let out = std::fs::File::create(dest).map_err(|e| PlanErr::Fatal(format!("création dest : {e}")))?;
    let out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
    // Chiffrement : ASYMÉTRIQUE (destinataire public age1..., escrow hors-cluster) si posé, sinon SYMÉTRIQUE
    // par passphrase (= clé SQLCipher) à facteur scrypt FIXÉ — MÊME fonction que le legacy (`backup_encryptor`),
    // pour qu'aucun des deux chemins ne puisse diverger de l'autre sur la borne.
    let encryptor = backup_encryptor(pass, recipient).map_err(PlanErr::Fatal)?;
    let age_w = encryptor.wrap_output(out).map_err(|e| PlanErr::Fatal(format!("age wrap_output : {e}")))?;
    let mut z = zstd::Encoder::new(age_w, BACKUP_ZSTD_LEVEL).map_err(|e| PlanErr::Fatal(format!("init zstd : {e}")))?;
    let plaintext_bytes = {
        let mut cw = CountWriter { inner: &mut z, count: 0 };
        // dump_stream renvoie déjà un PlanErr TYPÉ : Unsupported (valeur non représentable, ex. TEXT
        // non-UTF8) -> repli legacy propre par l'appelant ; Fatal (IO/DB) -> vraie panne. On propage tel quel.
        dump_stream(&conn, &plan, &mut cw)?;
        cw.count
    };
    let age_w = z.finish().map_err(|e| PlanErr::Fatal(format!("finalisation zstd : {e}")))?;
    age_w.finish().map_err(|e| PlanErr::Fatal(format!("finalisation age : {e}")))?;
    let _ = conn.execute_batch("COMMIT"); // fin du snapshot (lecture seule).

    let dest_bytes = taille_sur_disque(std::path::Path::new(dest));
    Ok(BackupStats { plaintext_bytes: crate::mesure_environnement::Mesure::Lue(plaintext_bytes), dest_bytes, wrote_plaintext_to_disk: false })
}

/// SAUVEGARDE COMPRESSÉE+CHIFFRÉE — B1 par défaut (dump STREAMING, ZÉRO clair transitoire) avec REPLI
/// automatique sur le legacy (sqlcipher_export -> plaintext temporaire éphémère) pour les schémas non
/// représentables en dump typé (FTS contentless/régulière...). Format de sortie IDENTIQUE dans les
/// deux cas : age(zstd(<charge>)) ; le restore distingue via le marqueur de tête. Requiert une clé non
/// vide. Renvoie {plaintext_bytes, dest_bytes, wrote_plaintext_to_disk}.
pub(crate) fn backup_compressed(db_path: &str, dest: &str, key: Option<&str>, recipient: Option<&str>) -> Result<BackupStats, String> {
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
    };
    // GATE FAIL-CLOSED escrow (identique legacy) — AVANT toute écriture : refuse un backup symétrique si
    // l'asymétrique est EXIGÉ mais qu'aucun destinataire age n'est configuré.
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    if symmetric_fallback && backup_require_asymmetric() {
        return Err("backup REFUSÉ (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) : aucun PLUME_BACKUP_AGE_RECIPIENT \
                    (clé publique age1...) configuré -> un backup symétrique serait déchiffrable par le nœud \
                    (pas d'escrow hors-cluster). Configurez un destinataire age asymétrique, ou levez \
                    l'exigence pour un backup symétrique de dev.".into());
    }
    if symmetric_fallback {
        eprintln!(
            "[backup] ATTENTION : PLUME_BACKUP_AGE_RECIPIENT non configuré -> chiffrement SYMÉTRIQUE par \
             passphrase (= clé SQLCipher, présente sur le nœud). Ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS \
             d'escrow hors-cluster. Configurez une clé publique age (asymétrique, encrypt-only) pour un escrow \
             hors-cluster, ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli.");
    }
    // BALAYAGE DES ORPHELINS — à CHAQUE backup, quel que soit le chemin pris ensuite. Réape les plaintext
    // laissés par un run antérieur crashé/OOM-killé (Drop ne tourne pas sur SIGKILL). Cible le répertoire de
    // STAGING (PLUME_BACKUP_STAGING_DIR = volume éphémère si posé, sinon dossier de <dest>), seuil 1 h ->
    // épargne un backup concurrent en vol. Ne CRÉE rien : il ne fait que supprimer (la garde de staging vide
    // reste donc vraie pendant le chemin streaming).
    let stage_dir = staging_dir(dest);
    let balayage = sweep_orphan_temps(&stage_dir, std::time::Duration::from_secs(BACKUP_ORPHAN_MAX_AGE_SECS));
    let phrase = balayage.phrase(&format!("backup : plaintext dans {}", stage_dir.display()));
    if !phrase.is_empty() {
        eprintln!("{phrase}");
    }

    // ÉCHAPPATOIRE OPÉRATEUR : retour explicite au chemin historique (plaintext matérialisé) sans rebuild.
    if backup_force_plaintext_export() {
        eprintln!("[backup] PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT posé -> chemin HISTORIQUE (sqlcipher_export) : \
                   la base ENTIÈRE est réécrite EN CLAIR dans le staging le temps du backup.");
        return backup_compressed_legacy(db_path, dest, key, recipient);
    }
    // B1 streaming d'abord ; repli legacy si le schéma n'est pas représentable en dump typé.
    match backup_compressed_stream(db_path, dest, &pass, recipient) {
        Ok(st) => Ok(st),
        Err(PlanErr::Unsupported(why)) => {
            eprintln!("[backup] schéma non-B1 ({why}) -> repli sur l'export legacy (plaintext temporaire éphémère)");
            backup_compressed_legacy(db_path, dest, key, recipient)
        }
        Err(PlanErr::Fatal(e)) => {
            let _ = std::fs::remove_file(dest); // pas de backup partiel/trompeur.
            Err(e)
        }
    }
}

/// B1 — RESTORE STREAMING : rejoue un DUMP B1 (déjà déchiffré+dézstd, le magic étant déjà consommé par
/// l'appelant) dans une DB SQLCipher NEUVE `dest_db`. ZÉRO clair sur disque. Tout dans UNE transaction
/// (atomique). Ordre : pre-DDL (tables) -> données (INSERT bindés, types EXACTS) -> sqlite_sequence ->
/// post-DDL (vtables + rebuild FTS + index + triggers + vues).
fn restore_stream<R: std::io::Read>(r: &mut R, dest_db: &str, pass: &str) -> Result<(), String> {
    let re = |x: std::io::Result<u32>| x.map_err(|e| format!("restore : lecture flux : {e}"));
    let conn = open_db_keyed_without_schema_contract(dest_db, Some(pass)).map_err(|e| format!("ouverture dest SQLCipher : {e}"))?;
    let _ = conn.execute_batch("PRAGMA foreign_keys=OFF;"); // ordre d'insertion libre pendant le chargement
    conn.execute_batch("BEGIN").map_err(|e| format!("begin restore : {e}"))?;

    // section 1 : pre-DDL (CREATE TABLE) — crée AUSSI sqlite_sequence si tables AUTOINCREMENT.
    let n_pre = re(rd_u32(r))?;
    for _ in 0..n_pre {
        let sql = rd_str(r).map_err(|e| format!("restore : lecture pre-DDL : {e}"))?;
        conn.execute_batch(&sql).map_err(|e| format!("CREATE TABLE (restore) : {e}"))?;
    }
    // section 2 : données.
    let n_tables = re(rd_u32(r))?;
    for _ in 0..n_tables {
        let name = rd_str(r).map_err(|e| format!("restore : nom table : {e}"))?;
        let ncols = rd_u16(r).map_err(|e| format!("restore : ncols {name} : {e}"))? as usize;
        let insert_sql = rd_str(r).map_err(|e| format!("restore : insert_sql {name} : {e}"))?;
        let mut stmt = conn.prepare(&insert_sql).map_err(|e| format!("prepare INSERT {name} : {e}"))?;
        loop {
            let tag = rd_u8(r).map_err(|e| format!("restore : tag ligne {name} : {e}"))?;
            if tag == 0 { break; }
            if tag != 1 { return Err(format!("restore : tag de ligne inconnu {tag} (table {name})")); }
            let mut vals: Vec<rusqlite::types::Value> = Vec::with_capacity(ncols);
            for _ in 0..ncols { vals.push(read_value(r)?); }
            stmt.execute(rusqlite::params_from_iter(vals.iter())).map_err(|e| format!("INSERT {name} : {e}"))?;
        }
    }
    // section 3 : sqlite_sequence (reproduit EXACTEMENT les compteurs — DELETE puis INSERT, comme SQLite .dump).
    let n_seq = re(rd_u32(r))?;
    if n_seq > 0 {
        let _ = conn.execute_batch("DELETE FROM sqlite_sequence;");
        let mut s = conn.prepare("INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)").map_err(|e| format!("prepare seq : {e}"))?;
        for _ in 0..n_seq {
            let name = rd_str(r).map_err(|e| format!("restore : nom seq : {e}"))?;
            let seq = rd_i64(r).map_err(|e| format!("restore : valeur seq : {e}"))?;
            s.execute(rusqlite::params![name, seq]).map_err(|e| format!("insert seq {name} : {e}"))?;
        }
    }
    // section 4 : post-DDL (vtables, rebuild FTS, index, triggers, vues).
    let n_post = re(rd_u32(r))?;
    for _ in 0..n_post {
        let tag = rd_u8(r).map_err(|e| format!("restore : tag post-DDL : {e}"))?;
        match tag {
            1 => { let sql = rd_str(r).map_err(|e| format!("restore : post-DDL sql : {e}"))?; conn.execute_batch(&sql).map_err(|e| format!("post-DDL (restore) : {e}"))?; }
            2 => {
                let name = rd_str(r).map_err(|e| format!("restore : nom rebuild : {e}"))?;
                let rebuild = format!("INSERT INTO {0}({0}) VALUES('rebuild');", quote_ident(&name));
                conn.execute_batch(&rebuild).map_err(|e| format!("rebuild FTS {name} : {e}"))?;
            }
            other => return Err(format!("restore : tag post-DDL inconnu {other}")),
        }
    }
    // sentinelle de fin.
    let tr = rd_u8(r).map_err(|e| format!("restore : lecture sentinelle : {e}"))?;
    if tr != 0xFF { return Err(format!("restore : sentinelle de fin absente (0x{tr:02X}) — dump tronqué/corrompu")); }
    conn.execute_batch("COMMIT").map_err(|e| format!("commit restore : {e}"))?;
    Ok(())
}

/// RESTAURATION (rejouabilité) — gère les DEUX formats via le MARQUEUR de tête de la charge décompressée :
///  - B1 (`DUMP_MAGIC`)     : rejoue le dump typé dans une DB SQLCipher NEUVE en STREAMING. ZÉRO clair
///    sur disque (`restore_stream`).
///  - LEGACY (`SQLite ...`) : age décrypte -> zstd décode -> DB SQLite EN CLAIR temporaire, puis
///    `sqlcipher_export` -> `<dest_db>` chiffré (garde RAII efface le temporaire).
/// Dans les deux cas : age auto-détecte le stanza (scrypt/passphrase = anciens backups symétriques ;
/// x25519 = identité PRIVÉE escrow si fournie). REFUSE d'écraser `<dest_db>` sauf `overwrite=true`.
pub(crate) fn restore_compressed(src: &str, dest_db: &str, key: Option<&str>, overwrite: bool, identity: Option<&age::x25519::Identity>) -> Result<(), String> {
    use std::io::Read;
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("restore : PLUME_DB_KEY requis (passphrase age)".into()),
    };
    if std::path::Path::new(dest_db).exists() && !overwrite {
        return Err(format!("restore : {dest_db} existe déjà — relancer avec --force pour écraser"));
    }

    // 1) age décrypte -> zstd décode -> flux clair EN MÉMOIRE (jamais tout sur disque pour B1).
    let f = std::fs::File::open(src).map_err(|e| format!("ouverture src : {e}"))?;
    let r = std::io::BufReader::with_capacity(BACKUP_BUF, f);
    let decryptor = age::Decryptor::new_buffered(r).map_err(|e| format!("en-tête age : {e}"))?;
    // AUTO-DÉTECTION : on présente à age DEUX identités et il apparie selon le stanza de l'en-tête :
    //   (1) scrypt/passphrase (= clé SQLCipher) -> anciens backups SYMÉTRIQUES (rétrocompat) ;
    //   (2) x25519 (identité PRIVÉE escrow, si PLUME_BACKUP_AGE_IDENTITY[_FILE] fournie) -> backups ASYMÉTRIQUES.
    // Plafond de travail scrypt FIXE (`backup_scrypt_identity`) : sans lui, age recalcule
    // `target+4` sur la machine qui déchiffre -> un backup restaurable ici serait refusé ailleurs.
    let scrypt_id = backup_scrypt_identity(&pass);
    let mut ids: Vec<&dyn age::Identity> = vec![&scrypt_id as &dyn age::Identity];
    if let Some(x) = identity { ids.push(x as &dyn age::Identity); }
    let reader = decryptor
        .decrypt(ids.into_iter())
        .map_err(|e| message_dechiffrement_age(&e))?;
    let mut zd = zstd::Decoder::new(reader).map_err(|e| format!("init zstd : {e}"))?;

    // 2) MARQUEUR de format : lit les 1ers octets de la charge décompressée pour aiguiller B1 vs legacy.
    let mut magic = [0u8; 11];
    zd.read_exact(&mut magic).map_err(|e| format!("lecture marqueur de format (charge trop courte / corrompue ?) : {e}"))?;

    if &magic == DUMP_MAGIC {
        // --- FORMAT B1 (dump typé streaming) : rejoue dans une DB SQLCipher NEUVE. AUCUN clair sur disque.
        for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_db}{ext}")); }
        restore_stream(&mut zd, dest_db, &pass)
    } else if magic.starts_with(b"SQLite") {
        // --- FORMAT LEGACY (age(zstd(fichier SQLite clair))) : plaintext temporaire + sqlcipher_export.
        let tmp_guard = PlaintextTempGuard(plain_temp_path(dest_db));
        let tmp_plain = tmp_guard.path().to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&tmp_plain);
        {
            let out = std::fs::File::create(&tmp_plain).map_err(|e| format!("création plaintext : {e}"))?;
            let mut out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
            // ré-injecte les octets de tête déjà consommés pour la détection, puis stream le reste.
            std::io::Write::write_all(&mut out, &magic).map_err(|e| format!("écriture en-tête plaintext : {e}"))?;
            stream_copy(&mut zd, &mut out).map_err(|e| format!("flux unzstd : {e}"))?;
            std::io::Write::flush(&mut out).map_err(|e| format!("flush plaintext : {e}"))?;
        }
        for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_db}{ext}")); }
        {
            let conn = open_db_keyed_without_schema_contract(&tmp_plain, None).map_err(|e| format!("ouverture plaintext : {e}"))?;
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
                .map_err(|e| format!("plaintext illisible (passphrase invalide ?) : {e}"))?;
            let sql = format!(
                "ATTACH DATABASE '{}' AS enc KEY '{}'; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;",
                dest_db.replace('\'', "''"), pass.replace('\'', "''"));
            conn.execute_batch(&sql).map_err(|e| format!("re-chiffrement (sqlcipher_export) : {e}"))?;
        }
        Ok(())
    } else {
        Err(format!("restore : format de charge inconnu (ni dump B1 ni fichier SQLite) — backup corrompu ? tête={magic:?}"))
    }
}
