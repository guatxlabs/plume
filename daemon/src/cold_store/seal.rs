//! cold_store::seal — SEAL / INDEX PAR-FICHIER (crash-safety multi-fichiers #18 P2b) — table `cold_seal` dans la
//! MÊME base SQLCipher que les events (chiffrée AT-REST -> l'index `ts_min/ts_max` par fichier est CONFIDENTIEL).
//!
//! Créée PARESSEUSEMENT (seulement quand cold est ON) -> mode 0 (cold off) = base byte-identique (aucune table en
//! trop). Le seal est PAR-FICHIER (PK (env_id, day, seq)) : chaque FICHIER porte son compte, sa fenêtre
//! `[ts_min, ts_max]` (élagage lecteur SANS déchiffrer), son curseur keyset BAS `(lo_ts, lo_id)` exclusif + son id
//! keyset HAUT `hi_id` (borne DELETE de CE fichier), le `max_id` GLOBAL du jour (FIX #1, identique sur tous les
//! fichiers du jour) et deux drapeaux : `purged` (les lignes hot de CE fichier ont été supprimées) et `last_file`
//! (=1 sur le DERNIER seq -> COMMIT ATOMIQUE de la fin de PHASE 1 : tant qu'AUCUN fichier n'a `last_file=1`, la
//! PHASE 2 (delete) ne démarre PAS -> un crash en écriture laisse le hot 100% intact). Cf. l'argument crash-safety
//! dans `age_one_day` (module `aging`).

use super::*;

/// Une ligne de seal PAR-FICHIER (index P2b). `hi_ts == ts_max` (dernière ligne au sens keyset) -> non dupliqué.
pub(super) struct FileSeal {
    pub(super) seq: i64,
    pub(super) expected: i64,
    pub(super) purged: bool,
    pub(super) max_id: i64,
    pub(super) ts_min: i64,
    pub(super) ts_max: i64,
    pub(super) lo_ts: i64,
    pub(super) lo_id: i64,
    pub(super) hi_id: i64,
    pub(super) last_file: bool,
    /// #28 PHASE B — stats/bloom d'ÉLAGAGE DIMENSIONNEL de CE fichier (min/max + bloom sur les dims CIM
    /// universelles), décodées de la colonne `cold_seal.dim_stats`. `None` = fichier scellé AVANT la Phase B
    /// (colonne NULL) OU blob illisible -> « on ne peut pas élaguer -> on GARDE toujours » (fallback CORRECT).
    pub(super) dim_stats: Option<DimStats>,
}

pub(super) fn ensure_cold_seal_table(conn: &Connection) {
    // Schéma PAR-FICHIER (#18 P2b). `max_id` (FIX #1) : borne d'IDENTITÉ monotone durable de l'ensemble scellé du
    // JOUR (identique sur tous les seq). Le DELETE du hot d'un fichier ne vise QUE `id <= max_id` ET sa fenêtre
    // keyset -> une ligne ingérée APRÈS le seal (id > max_id) n'est JAMAIS supprimée sans archive. Le re-run après
    // crash RÉUTILISE `max_id` du seal (jamais re-dérivé du hot rétréci). Table jamais déployée en Phase 1 (doc
    // module) -> schéma redéfini directement, aucune migration ALTER d'un ancien format.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cold_seal(\
           env_id TEXT NOT NULL, \
           day INTEGER NOT NULL, \
           seq INTEGER NOT NULL, \
           expected_rows INTEGER NOT NULL, \
           sealed_ts INTEGER NOT NULL, \
           purged INTEGER NOT NULL DEFAULT 0, \
           max_id INTEGER NOT NULL, \
           ts_min INTEGER NOT NULL, \
           ts_max INTEGER NOT NULL, \
           lo_ts INTEGER NOT NULL, \
           lo_id INTEGER NOT NULL, \
           hi_id INTEGER NOT NULL, \
           last_file INTEGER NOT NULL DEFAULT 0, \
           dim_stats BLOB, \
           PRIMARY KEY(env_id, day, seq))",
    );
    // #28 PHASE B — MIGRATION PARESSEUSE de la colonne `dim_stats` (index d'élagage dimensionnel). Base cold
    // PRÉ-Phase-B (table créée sans la colonne) : `CREATE TABLE IF NOT EXISTS` ne l'ajoute PAS -> on l'ALTER ici
    // (ADD COLUMN nullable, sans DEFAULT -> les lignes de seal existantes prennent NULL). NULL = « pas de stats »
    // -> le lecteur ne peut pas élaguer sur ce fichier -> il le GARDE toujours (fallback correct, zéro perte).
    // NON destructif, idempotent (guardé par `cold_seal_has_col`), et COLD-ONLY (table créée seulement quand cold
    // est ON) -> mode 0 (cold off) reste byte-identique (aucune colonne, aucune table).
    if !cold_seal_has_col(conn, "dim_stats") {
        let _ = conn.execute_batch("ALTER TABLE cold_seal ADD COLUMN dim_stats BLOB");
    }
}

/// La table `cold_seal` porte-t-elle la colonne `col` ? (PRAGMA table_info -> aucune écriture). Sert à la
/// migration paresseuse ADD COLUMN idempotente (#28 Phase B).
fn cold_seal_has_col(conn: &Connection, col: &str) -> bool {
    conn.prepare(SQL_COLONNE_DE_SEAL).and_then(|mut s| s.exists(params![col])).unwrap_or(false)
}

/// Toutes les lignes de seal d'un (env_id, day), TRIÉES par `seq` croissant (prefixe de fichiers scellés).
pub(super) fn file_seals(conn: &Connection, env_id: &str, day: i64) -> Vec<FileSeal> {
    let mut out = Vec::new();
    if let Ok(mut st) = conn.prepare(SQL_SEALS_DU_JOUR) {
        if let Ok(rows) = st.query_map(params![env_id, day], |r| {
            // dim_stats : BLOB nullable (Phase B). NULL / blob illisible -> None (« pas d'élagage possible »).
            let dim_stats = r.get::<_, Option<Vec<u8>>>(10)?.as_deref().and_then(DimStats::decode);
            Ok(FileSeal {
                seq: r.get(0)?,
                expected: r.get(1)?,
                purged: r.get::<_, i64>(2)? != 0,
                max_id: r.get(3)?,
                ts_min: r.get(4)?,
                ts_max: r.get(5)?,
                lo_ts: r.get(6)?,
                lo_id: r.get(7)?,
                hi_id: r.get(8)?,
                last_file: r.get::<_, i64>(9)? != 0,
                dim_stats,
            })
        }) {
            out = rows.flatten().collect();
        }
    }
    out
}

/// RÉSUMÉ AGRÉGÉ par-JOUR (compat des call-sites/tests d'avant le split) : `None` si aucun fichier scellé ;
/// sinon `(expected_total, all_purged, max_id)`. `expected_total` = Σ des lignes des fichiers du jour ;
/// `all_purged` = VRAI seulement si TOUS les fichiers ont `purged=1` (jour entièrement drainé du hot) ;
/// `max_id` = borne d'identité GLOBALE du jour (identique sur tous les fichiers). Utilisé par les TESTS
/// (la production lit directement `file_seals`) -> gaté `#[cfg(test)]` (aucun code mort en build cold_tier).
#[cfg(test)]
pub(super) fn seal_state(conn: &Connection, env_id: &str, day: i64) -> Option<(i64, bool, i64)> {
    let seals = file_seals(conn, env_id, day);
    if seals.is_empty() {
        return None;
    }
    let expected_total: i64 = seals.iter().map(|s| s.expected).sum();
    let all_purged = seals.iter().all(|s| s.purged);
    let max_id = seals[0].max_id;
    Some((expected_total, all_purged, max_id))
}

/// COMPTE + BORNE D'IDENTITÉ de l'ensemble à ager pour un (env_id, day) (FIX #1). EXCLUT les events de
/// CONTRÔLE (RETENTION_NONPURGE : jamais agés/supprimés). Renvoie `(N, max_id)` où `N`=compte et
/// `max_id`=MAX(id) sur EXACTEMENT ces lignes (0 si aucune). `id` = clé du rowid `INTEGER PRIMARY KEY`
/// (monotone à l'insertion). L'ensemble `{env/day/NONPURGE, id<=max_id}` est ainsi FIGÉ : l'ingest n'ajoute
/// que des `id > max_id` -> ni le writer streamé ni le DELETE ne toucheront une ligne arrivée après ce point.
/// Capturé sous UN verrou court, en amont du write -> `N` et `max_id` sont durablement scellés avant tout DELETE.
pub(super) fn count_and_max_id(conn: &Connection, env_id: &str, day: i64) -> Result<(i64, i64), String> {
    let day_start = day * SECS_PER_DAY;
    let day_end = day_start + SECS_PER_DAY;
    // `P10.13-a` — texte UNIQUE dans `enonces` (la sonde de lecture seule rejoue CET énoncé).
    let sql = sql_compte_et_max_id_du_jour();
    conn.query_row(&sql, params![env_id, day_start, day_end], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .map_err(pe)
}

/// MAX(id) sur TOUTE la table `event` = le COMPTEUR DE ROWID GLOBAL de SQLite (`INTEGER PRIMARY KEY` SANS
/// AUTOINCREMENT : le prochain rowid auto-alloué = `MAX(rowid)+1` recalculé À L'INSERTION). O(1) (rowid le
/// plus à droite du b-tree). Renvoie 0 si la table est vide. INCLUT les events de CONTRÔLE (NONPURGE) : une
/// ligne de contrôle jamais supprimable qui détient le tail ÉPINGLE le compteur -> il est correct de la
/// compter comme « tail-holder ». H1 (tail guard, cf. `age_one_day`) : c'est la borne dont dépend la preuve
/// qu'aucun rowid réutilisé <= max_id ne peut apparaître pendant un DELETE d'aging.
pub(super) fn event_table_max_id(conn: &Connection) -> Result<i64, String> {
    conn.query_row(SQL_MAX_ID_DE_LA_TABLE, [], |r| r.get::<_, i64>(0)).map_err(pe)
}

/// Énumère TOUS les fichiers scellés de l'index `cold_seal` (une ligne PAR fichier séquencé) : `(env_id, day, seq)`.
/// Un seal ⟹ le fichier `file_path(cold_dir, env, day, seq)` est FINAL + IMMUABLE (scellé durablement). Requête PURE
/// sur la petite table `cold_seal` (base SQLCipher chiffrée at-rest -> aucune clé de DÉCHIFFREMENT cold requise :
/// on lit des métadonnées, jamais un fichier Parquet). Ordre SQL non spécifié (les appelants qui exigent un ordre
/// TRIENT eux-mêmes). Table absente / requête en échec -> `Vec` vide (fail-safe). PARTAGÉE par `expire_cold_days`
/// (élagage) et `cold_backup_plan` (tier froid 2-tier #18) — source unique de « quels fichiers cold existent ».
pub(super) fn all_sealed_files(conn: &Connection) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    if let Ok(mut st) = conn.prepare(SQL_TOUS_LES_SEALS) {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
            out = rows.flatten().collect();
        }
    }
    out
}

// ====================================================================================================
// #28 PHASE B — ÉLAGAGE DIMENSIONNEL SEAL-RÉSIDENT (« seal-resident dimension pruning »).
// ----------------------------------------------------------------------------------------------------
// OBJET : permettre à une requête cold SÉLECTIVE (`source=X`, `host=Y`, `src_ip=Z`, `severity=N`, …) de SAUTER
// les fichiers qui NE PEUVENT PAS contenir la valeur — SANS les déchiffrer — exactement comme l'élagage
// `ts_min/ts_max` existant. Les fichiers cold sont chiffrés en STREAM (age) : leur footer/bloom Parquet est
// ILLISIBLE sans déchiffrer tout le fichier. Les stats/bloom vivent donc dans la table `cold_seal` (base
// SQLCipher chiffrée at-rest) — JAMAIS dans le Parquet : c'est TOUT l'intérêt (élaguer sans déchiffrer).
//
// SÉCURITÉ : ces stats sont des MÉTADONNÉES D'ÉLAGAGE INTERNES. Elles NE SONT PAS des colonnes de
// `event`/`cold_event` -> jamais projetées, jamais renvoyées à une requête. Élaguer par `dim=value` est une
// OPTIMISATION d'un filtre que la requête APPLIQUE DÉJÀ (le WHERE filtre sur la MÊME valeur BRUTE — le masquage
// #45 agit en SORTIE, jamais sur le prédicat de filtre) : même information, mêmes lignes rendues, même masquage.
// Aucun nouveau canal. De plus, l'extracteur n'émet un prédicat QUE sur les dims qui sont des COLONNES RÉELLES
// (`base.real_cols`) -> un alias d'objet-de-savoir (#46) ne peut JAMAIS les re-router (le réel l'emporte), et un
// filtre sur un champ MASQUÉ est de toute façon REJETÉ à la compilation (oracle de filtre #45) -> il n'atteint
// jamais le chemin cold. Cf. l'argument complet dans le header du reader.
//
// INVARIANT DE CORRECTION (NON NÉGOCIABLE) : après élagage, l'ENSEMBLE des lignes rendues est IDENTIQUE au
// lecteur non-élagué pour la MÊME requête. (a) min/max ne saute un fichier que si la valeur est STRICTEMENT
// HORS de [min,max] (absence PROUVÉE — collation BINARY = égalité octet-à-octet). (b) le bloom ne saute un
// fichier que si une clé est CERTAINEMENT absente ; un faux positif ne fait que GARDER le fichier (un
// déchiffrement de plus), JAMAIS rater une ligne. Le bloom ne PEUT PAS faux-négatif sur une valeur insérée.

/// Dimensions CIM UNIVERSELLES sur lesquelles on élague (GÉNÉRIQUE — clé par NOM de colonne, zéro hardcode
/// vendeur : les fichiers d'une source inconnue portent les MÊMES stats/bloom, et `source=<vendeur inconnu>`
/// élague pareil, sans config). Toutes sont des COLONNES RÉELLES de `event` (cf. `Schema::events().real_cols`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ColdDim {
    Source,
    Category,
    Host,
    SrcIp,
    DstIp,
    Severity,
}

impl ColdDim {
    /// Mappe un NOM de colonne universelle -> dim élaguable. Tout le reste (champs JSON, `url`, `message`, …)
    /// -> `None` (pas d'élagage sur cette dim ; on retombe sur le ts-only, inchangé).
    pub(super) fn from_col(name: &str) -> Option<ColdDim> {
        Some(match name {
            "source" => ColdDim::Source,
            "category" => ColdDim::Category,
            "host" => ColdDim::Host,
            "src_ip" => ColdDim::SrcIp,
            "dst_ip" => ColdDim::DstIp,
            "severity" => ColdDim::Severity,
            _ => return None,
        })
    }
    /// NOM de la colonne réelle de cette dim (inverse de `from_col`). Sert au GARDE COLONNE-DÉNIÉE #45 du chemin
    /// P3.5 : on ne doit JAMAIS élaguer sur le seal d'une colonne déniée (fuite par timing + faux). En production
    /// une dim déniée ne peut de toute façon PAS apparaître dans un prédicat (rejet à la compilation, oracle #45),
    /// mais le harnais peut injecter un deny-set directement -> ce garde est la défense-en-profondeur exigée.
    pub(super) fn col_name(self) -> &'static str {
        match self {
            ColdDim::Source => "source",
            ColdDim::Category => "category",
            ColdDim::Host => "host",
            ColdDim::SrcIp => "src_ip",
            ColdDim::DstIp => "dst_ip",
            ColdDim::Severity => "severity",
        }
    }
    /// Tag d'1 octet PRÉFIXÉ dans la clé du bloom -> `source=X` et `host=X` ne peuvent JAMAIS entrer en
    /// collision dans le bloom PARTAGÉ (une clé de bloom = tag_de_dim ++ octets_de_valeur).
    fn tag(self) -> u8 {
        match self {
            ColdDim::Source => 1,
            ColdDim::Category => 2,
            ColdDim::Host => 3,
            ColdDim::SrcIp => 4,
            ColdDim::DstIp => 5,
            ColdDim::Severity => 6,
        }
    }
}

/// Prédicat d'ÉGALITÉ `dim = value` extrait de la requête (cf. `extract_cold_dim_preds`). `value` = la valeur
/// BRUTE comparée dans le WHERE (le masquage #45 agit en SORTIE, jamais sur le filtre -> élaguer là-dessus est
/// la MÊME information que le filtre déjà appliqué). Pour `Severity`, `value` = le texte décimal de l'entier.
/// Construit UNIQUEMENT par `extract_cold_dim_preds` (champs `pub(super)`) ; le chemin requête ne fait que le
/// transporter (jamais lire ses champs) -> aucune fuite de la métadonnée d'élagage.
#[derive(Clone)]
pub(crate) struct DimEq {
    pub(super) dim: ColdDim,
    pub(super) value: String,
}

// ---- Bloom (fait-main, ZÉRO crate, byte-STABLE À VIE) ------------------------------------------------

/// Bits/octets/hachages du bloom PAR-FICHIER. 1024 bits = 128 octets, k=3. Dimensionné pour que ~3800 fichiers
/// portent un surcoût BORNÉ à quelques Mo (cf. rapport). La CORRECTION NE DÉPEND JAMAIS de ces nombres : le bloom
/// ne fait que GARDER un fichier (un faux positif = un déchiffrement de plus) -> toute taille/k est SÛRE ; plus
/// grand = moins de déchiffrements inutiles (dims à haute cardinalité intra-fichier saturent -> moins d'élagage,
/// jamais d'incorrection). Réglable en test/ops via `PLUME_COLD_BLOOM_*` serait possible mais le format on-disk
/// est FIXE (un blob relu par le lecteur doit hacher à l'identique) -> constantes.
pub(super) const DIM_BLOOM_BITS: usize = 1024;
pub(super) const DIM_BLOOM_BYTES: usize = DIM_BLOOM_BITS / 8; // 128
pub(super) const DIM_BLOOM_K: usize = 3;
const DIM_STATS_VERSION: u8 = 1;

/// FNV-1a 64 bits (fait-main, ZÉRO crate, byte-STABLE PAR SPÉCIFICATION). DÉLIBÉRÉMENT PAS `std DefaultHasher` :
/// un bloom PERSISTÉ sur disque doit hacher À L'IDENTIQUE d'une version de daemon à l'autre — un changement de
/// hachage retournerait des bits en silence et pourrait FAUX-NÉGATIVER (sauter un fichier qui MATCHE = perte de
/// données). FNV-1a est figé par la spec -> le bloom est reproductible pour la VIE du fichier. `seed` sépare deux
/// hachages indépendants (double hachage).
fn fnv1a64(seed: u8, bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    h ^= seed as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Les k positions de bits d'une clé (double hachage Kirsch–Mitzenmacher : g_i = h1 + i·h2, mod BITS). Deux
/// seeds FNV donnent h1/h2 (h2 forcé impair -> visite des résidus distincts). MÊME fonction à l'écriture (insert)
/// et à la lecture (test) -> positions IDENTIQUES.
fn bloom_positions(key: &[u8]) -> [usize; DIM_BLOOM_K] {
    let h1 = fnv1a64(0x01, key);
    let h2 = fnv1a64(0x02, key) | 1;
    let mut out = [0usize; DIM_BLOOM_K];
    for (i, o) in out.iter_mut().enumerate() {
        let g = h1.wrapping_add((i as u64).wrapping_mul(h2));
        *o = (g % DIM_BLOOM_BITS as u64) as usize;
    }
    out
}

/// Clé de bloom = tag_de_dim (1 octet) ++ octets UTF-8 de la valeur -> pas de collision inter-dims.
fn bloom_key(dim: ColdDim, value: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + value.len());
    k.push(dim.tag());
    k.extend_from_slice(value.as_bytes());
    k
}

// ---- DimStats : min/max par dim + bloom des dims-point --------------------------------------------

/// Stats d'élagage PAR-FICHIER (métadonnée INTERNE — jamais une colonne d'`event`/`cold_event`, jamais rendue à
/// une requête ; vit UNIQUEMENT dans le BLOB chiffré `cold_seal.dim_stats`). min/max sur les dims low/mid-card
/// (severity numérique + source/category/host lexicographiques) + un bloom sur les dims-point (source, category,
/// host, src_ip, dst_ip). `src_min/max`+`cat_min/max` toujours présentes (colonnes REQUISES, fichier >=1 ligne) ;
/// `host_*` optionnelles (host nullable -> `None` si le fichier n'a AUCUN host non-null).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DimStats {
    pub(super) sev_min: i64,
    pub(super) sev_max: i64,
    pub(super) src_min: String,
    pub(super) src_max: String,
    pub(super) cat_min: String,
    pub(super) cat_max: String,
    pub(super) host_min: Option<String>,
    pub(super) host_max: Option<String>,
    pub(super) bloom: [u8; DIM_BLOOM_BYTES],
}

/// Accumulateur des stats sur les lignes d'UN fichier (calcul AU MOMENT DE L'ÉCRITURE, cf. `write_one_file`).
pub(super) struct DimStatsBuilder {
    n: u64,
    sev_min: i64,
    sev_max: i64,
    src_min: Option<String>,
    src_max: Option<String>,
    cat_min: Option<String>,
    cat_max: Option<String>,
    host_min: Option<String>,
    host_max: Option<String>,
    bloom: [u8; DIM_BLOOM_BYTES],
}

fn upd_min_max(mn: &mut Option<String>, mx: &mut Option<String>, v: &str) {
    if mn.as_deref().map_or(true, |m| v < m) {
        *mn = Some(v.to_string());
    }
    if mx.as_deref().map_or(true, |m| v > m) {
        *mx = Some(v.to_string());
    }
}

impl Default for DimStatsBuilder {
    fn default() -> Self {
        DimStatsBuilder {
            n: 0,
            sev_min: i64::MAX,
            sev_max: i64::MIN,
            src_min: None,
            src_max: None,
            cat_min: None,
            cat_max: None,
            host_min: None,
            host_max: None,
            bloom: [0u8; DIM_BLOOM_BYTES],
        }
    }
}

impl DimStatsBuilder {
    pub(super) fn new() -> Self {
        Self::default()
    }
    fn set_bit(&mut self, pos: usize) {
        self.bloom[pos >> 3] |= 1u8 << (pos & 7);
    }
    fn bloom_add(&mut self, dim: ColdDim, value: &str) {
        for p in bloom_positions(&bloom_key(dim, value)) {
            self.set_bit(p);
        }
    }
    /// Intègre UNE ligne (dims universelles typées de l'EventRow -> générique). severity: min/max. source &
    /// category (REQUISES) : min/max + bloom. host/src_ip/dst_ip (nullables) : bloom (host aussi min/max) SI
    /// non-null. Les colonnes NON élaguables (url/message/fields/dedup/…) sont ignorées.
    pub(super) fn add_row(&mut self, r: &ColdRow) {
        self.n += 1;
        let sev = r.row.severity;
        if sev < self.sev_min {
            self.sev_min = sev;
        }
        if sev > self.sev_max {
            self.sev_max = sev;
        }
        upd_min_max(&mut self.src_min, &mut self.src_max, &r.row.source);
        self.bloom_add(ColdDim::Source, &r.row.source);
        upd_min_max(&mut self.cat_min, &mut self.cat_max, &r.row.category);
        self.bloom_add(ColdDim::Category, &r.row.category);
        if let Some(h) = r.row.host.as_deref() {
            upd_min_max(&mut self.host_min, &mut self.host_max, h);
            self.bloom_add(ColdDim::Host, h);
        }
        if let Some(ip) = r.row.src_ip.as_deref() {
            self.bloom_add(ColdDim::SrcIp, ip);
        }
        if let Some(ip) = r.row.dst_ip.as_deref() {
            self.bloom_add(ColdDim::DstIp, ip);
        }
    }
    /// Fige les stats. Un fichier n'est scellé qu'avec >=1 ligne -> src/cat min/max sont Some ; fallback défensif
    /// (chaîne vide / 0) sur n==0 pour ne jamais paniquer (le résultat ne serait de toute façon jamais consulté).
    pub(super) fn finish(self) -> DimStats {
        DimStats {
            sev_min: if self.n == 0 { 0 } else { self.sev_min },
            sev_max: if self.n == 0 { 0 } else { self.sev_max },
            src_min: self.src_min.unwrap_or_default(),
            src_max: self.src_max.unwrap_or_default(),
            cat_min: self.cat_min.unwrap_or_default(),
            cat_max: self.cat_max.unwrap_or_default(),
            host_min: self.host_min,
            host_max: self.host_max,
            bloom: self.bloom,
        }
    }
}

impl DimStats {
    fn bloom_maybe_contains(&self, dim: ColdDim, value: &str) -> bool {
        bloom_positions(&bloom_key(dim, value))
            .iter()
            .all(|&p| (self.bloom[p >> 3] >> (p & 7)) & 1 == 1)
    }

    /// CŒUR DE L'INVARIANT DE CORRECTION : renvoie `true` UNIQUEMENT quand le fichier NE PEUT PROUVABLEMENT PAS
    /// contenir de ligne satisfaisant TOUS les prédicats (AND) -> sûr à sauter SANS déchiffrer. min/max ne saute
    /// que si la valeur est STRICTEMENT hors [min,max] (absence exacte, collation BINARY). Le bloom ne saute que
    /// si une clé est CERTAINEMENT absente (tous les bits requis ne sont pas mis) ; un faux positif ne fait que
    /// GARDER (déchiffrement de plus), jamais rater. Sémantique AND : prouver UNE dim absente suffit (aucune
    /// ligne ne peut satisfaire l'ensemble).
    pub(super) fn excluded_by(&self, preds: &[DimEq]) -> bool {
        preds.iter().any(|p| self.excludes_one(p))
    }
    fn excludes_one(&self, p: &DimEq) -> bool {
        match p.dim {
            ColdDim::Severity => match p.value.parse::<i64>() {
                Ok(n) => n < self.sev_min || n > self.sev_max,
                Err(_) => false, // non-entier -> on ne peut pas élaguer (l'extracteur n'émet que du numérique)
            },
            ColdDim::Source => {
                p.value.as_str() < self.src_min.as_str()
                    || p.value.as_str() > self.src_max.as_str()
                    || !self.bloom_maybe_contains(ColdDim::Source, &p.value)
            }
            ColdDim::Category => {
                p.value.as_str() < self.cat_min.as_str()
                    || p.value.as_str() > self.cat_max.as_str()
                    || !self.bloom_maybe_contains(ColdDim::Category, &p.value)
            }
            ColdDim::Host => match (self.host_min.as_deref(), self.host_max.as_deref()) {
                (Some(mn), Some(mx)) => {
                    p.value.as_str() < mn
                        || p.value.as_str() > mx
                        || !self.bloom_maybe_contains(ColdDim::Host, &p.value)
                }
                // Fichier SANS aucun host non-null -> `host='<valeur concrète>'` ne matche RIEN -> on saute.
                _ => true,
            },
            ColdDim::SrcIp => !self.bloom_maybe_contains(ColdDim::SrcIp, &p.value),
            ColdDim::DstIp => !self.bloom_maybe_contains(ColdDim::DstIp, &p.value),
        }
    }

    // ---- Encodage BLOB (version 1) : opaque, self-describing, borné ------------------------------

    /// Sérialise en BLOB : version(1) ++ sev_min ++ sev_max (i64 LE) ++ bloom(128) ++ 4 chaînes REQUISES
    /// (src/cat min/max) ++ 2 chaînes OPTIONNELLES (host min/max). Chaînes préfixées par une longueur u32 LE
    /// (None encodée `u32::MAX`) -> aucune troncature (min/max EXACTS = correction) et borné (source/category/
    /// host sont de petits identifiants).
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 16 + DIM_BLOOM_BYTES + 64);
        b.push(DIM_STATS_VERSION);
        b.extend_from_slice(&self.sev_min.to_le_bytes());
        b.extend_from_slice(&self.sev_max.to_le_bytes());
        b.extend_from_slice(&self.bloom);
        put_str(&mut b, Some(&self.src_min));
        put_str(&mut b, Some(&self.src_max));
        put_str(&mut b, Some(&self.cat_min));
        put_str(&mut b, Some(&self.cat_max));
        put_str(&mut b, self.host_min.as_deref());
        put_str(&mut b, self.host_max.as_deref());
        b
    }

    /// Décode un BLOB `dim_stats`. TOUT blob malformé/court/de version inconnue -> `None` -> « on ne peut pas
    /// élaguer -> on GARDE » (fallback correct, jamais de perte). Rétro-compat : un seal PRÉ-Phase-B a la colonne
    /// NULL -> l'appelant ne passe même pas ici (None direct).
    pub(super) fn decode(blob: &[u8]) -> Option<DimStats> {
        let mut c = BlobCursor { b: blob, pos: 0 };
        if c.u8()? != DIM_STATS_VERSION {
            return None;
        }
        let sev_min = c.i64()?;
        let sev_max = c.i64()?;
        let bloom_sl = c.bytes(DIM_BLOOM_BYTES)?;
        let mut bloom = [0u8; DIM_BLOOM_BYTES];
        bloom.copy_from_slice(bloom_sl);
        let src_min = c.opt_str()??; // REQUISE -> None(absente) rejette le blob (illisible)
        let src_max = c.opt_str()??;
        let cat_min = c.opt_str()??;
        let cat_max = c.opt_str()??;
        let host_min = c.opt_str()?;
        let host_max = c.opt_str()?;
        Some(DimStats { sev_min, sev_max, src_min, src_max, cat_min, cat_max, host_min, host_max, bloom })
    }
}

/// Écrit une chaîne OPTIONNELLE préfixée d'une longueur u32 LE (`None` -> `u32::MAX`).
fn put_str(b: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => b.extend_from_slice(&u32::MAX.to_le_bytes()),
        Some(s) => {
            b.extend_from_slice(&(s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
    }
}

/// Curseur de décodage BORNÉ (toute lecture hors-limites -> `None` -> blob rejeté -> fallback « garde »).
struct BlobCursor<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> BlobCursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.bytes(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i64(&mut self) -> Option<i64> {
        let s = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(i64::from_le_bytes(a))
    }
    /// Chaîne optionnelle (len u32 LE ; `u32::MAX` = None). `Some(None)` = présent-mais-absent (host NULL),
    /// `Some(Some(s))` = présent, `None` = blob illisible (hors-limites / UTF-8 invalide).
    fn opt_str(&mut self) -> Option<Option<String>> {
        let len = self.u32()?;
        if len == u32::MAX {
            return Some(None);
        }
        let s = self.bytes(len as usize)?;
        Some(Some(std::str::from_utf8(s).ok()?.to_string()))
    }
}

// ---- Extraction des prédicats d'égalité depuis le SQL COMPILÉ (parité PAR CONSTRUCTION) -------------
//
// #28 PHASE B — Plutôt que de RE-PARSER le GXQL brut (intrinsèquement sujet à la DÉRIVE face aux pré-passes du
// cœur — F1 « colle » op-char `soql_glue_spaced_ops`, F2 pré-pass `in (...)` `soql_in_collect`), l'extracteur
// lit le SQL que le CŒUR a RÉELLEMENT compilé et qui S'EXÉCUTE sur l'union hot∪cold (le MÊME `sql` masqué #45
// passé à `cold_union_query`). La valeur extraite ne peut donc JAMAIS diverger de ce que la requête filtre : on
// lit la SORTIE du compilateur, pas une ré-inférence parallèle. -> plus aucun repli fail-safe sur les formes à
// op-char/quote, et on RÉTABLIT l'élagage sur le motif courant `host=web1 source in (a,b)` (la clause IN demeure
// non-élaguable, mais l'égalité `"host" = 'web1'` est bel et bien extraite).
//
// LOSSLESS PAR CONSTRUCTION. On n'émet un prédicat que pour un ATOME de la forme EXACTE que le cœur émet pour une
// égalité de COLONNE RÉELLE élaguable — `"col" = 'littéral'` (dims string) ou `"col" = N` (severity, entier nu) —
// ET SEULEMENT quand cet atome est un CONJONCT DE PREMIER NIVEAU (AND) de l'UNIQUE feuille de base `FROM event
// WHERE …` (cf. `table_base`, cœur : le WHERE de la feuille est une pure suite de conjoncts AND-joints ; un OR
// n'y apparaît QUE parenthésé — eventtype/tag). Preuve de correction : la feuille de base est le SEUL accès
// PHYSIQUE à `event` ; si son WHERE impose `"col"=v` en AND de premier niveau, TOUTE ligne qui remonte le scan a
// `col=v`, donc élaguer un fichier cold PROUVÉ sans `col=v` (bloom/min-max) ne peut retirer aucune ligne que la
// requête rende. Tout ce qui SORT de ce cadre — OR, sous-expression parenthésée `(…)`, `IN (…)`, `LIKE`/`REGEXP`/
// `glob`, `<>`/borne, `json_extract(…)`, un WHERE d'un ÉTAGE aval (hors feuille), ou PLUSIEURS feuilles
// `FROM event` (append/join/eventstats corrélé, où une branche filtre AUTRE chose) — soit ne matche pas la forme
// exacte, soit invalide l'unicité de la feuille -> on N'ÉMET RIEN (fichiers gardés, correction inchangée). C'est
// lossless pour TOUTE classe de divergence, connue ou future.
//
// SÉCURITÉ (#45, inchangée) : le SQL qu'on lit est POST-masquage — un filtre sur une dim MASQUÉE/DÉNIÉE a déjà
// ERROR à la compilation (oracle-de-filtre, `soql_filter_field`) AVANT d'atteindre ce point, donc AUCUNE égalité
// sur une dim déniée/masquée ne peut apparaître dans le WHERE compilé qu'on parse. dim_stats restent internes.

/// Octet « de mot » (identifiant SQL) — sert aux bornes de mot du token TABLE `FROM event`.
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Le token TABLE de la feuille event, tel que le cœur l'émet VERBATIM (`table_base` : `FROM {base.table}`).
const FROM_EVENT: &[u8] = b"FROM event";

/// L'octet `i` (en zone CODE) débute-t-il le token `FROM event` avec des bornes de mot des DEUX côtés (évite
/// `XFROM event` / `FROM eventual`) ? Le cœur émet exactement `FROM event` suivi d'un espace, `)` ou fin.
fn match_from_event(b: &[u8], i: usize) -> bool {
    if !b[i..].starts_with(FROM_EVENT) {
        return false;
    }
    let before_ok = i == 0 || !is_word_byte(b[i - 1]);
    let after = i + FROM_EVENT.len();
    let after_ok = after >= b.len() || !is_word_byte(b[after]);
    before_ok && after_ok
}

/// WHERE de la feuille de base, borné à SON niveau de parenthèses : le premier `)` qui FERME la sous-requête
/// englobante (profondeur locale < 0), un mot-clé de clause de premier niveau (`GROUP BY`/`ORDER BY`/`LIMIT`/…),
/// ou la fin de chaîne termine le WHERE. `after` = index juste APRÈS le token `event`. None si aucun `WHERE ` ne
/// suit (feuille sans filtre -> aucun atome). Scan CONSCIENT des littéraux (`'…'` et `"…"`, doublage d'échappt).
fn where_span_after(sql: &str, after: usize) -> Option<(usize, usize)> {
    let b = sql.as_bytes();
    let mut j = after;
    while j < b.len() && b[j] == b' ' {
        j += 1;
    }
    if !b[j..].starts_with(b"WHERE ") {
        return None;
    }
    j += "WHERE ".len();
    while j < b.len() && b[j] == b' ' {
        j += 1;
    }
    let start = j;
    let (mut in_s, mut in_d) = (false, false);
    let mut d = 0i32;
    while j < b.len() {
        let c = b[j];
        if in_s {
            if c == b'\'' {
                if b.get(j + 1) == Some(&b'\'') {
                    j += 2;
                    continue;
                }
                in_s = false;
            }
            j += 1;
            continue;
        }
        if in_d {
            if c == b'"' {
                if b.get(j + 1) == Some(&b'"') {
                    j += 2;
                    continue;
                }
                in_d = false;
            }
            j += 1;
            continue;
        }
        match c {
            b'\'' => in_s = true,
            b'"' => in_d = true,
            b'(' => d += 1,
            b')' => {
                if d == 0 {
                    return Some((start, j)); // ferme la sous-requête englobante -> fin du WHERE de la feuille
                }
                d -= 1;
            }
            _ if d == 0 => {
                for kw in [
                    &b" GROUP BY "[..],
                    b" ORDER BY ",
                    b" LIMIT ",
                    b" HAVING ",
                    b" UNION ",
                    b" WINDOW ",
                ] {
                    if b[j..].starts_with(kw) {
                        return Some((start, j));
                    }
                }
            }
            _ => {}
        }
        j += 1;
    }
    Some((start, b.len()))
}

/// WHERE de l'UNIQUE feuille `FROM event`, ou None si la feuille n'est PAS unique (0 = base metric/autre, rien à
/// élaguer ; >=2 = append/join/eventstats corrélé -> un prédicat global ne contraindrait pas TOUTES les lignes ->
/// bail) ou n'a pas de `WHERE`. Le scan est CONSCIENT DES LITTÉRAUX : un `FROM event` à l'intérieur d'une valeur
/// (`'… FROM event …'`) ou d'un identifiant quoté n'est PAS une vraie feuille (sur-compter -> bail = sûr).
fn single_event_leaf_where(sql: &str) -> Option<&str> {
    let b = sql.as_bytes();
    let (mut in_s, mut in_d) = (false, false);
    let mut count = 0usize;
    let mut span: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_s {
            if c == b'\'' {
                if b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            if c == b'"' {
                if b.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => {
                in_s = true;
                i += 1;
            }
            b'"' => {
                in_d = true;
                i += 1;
            }
            _ => {
                if match_from_event(b, i) {
                    count += 1;
                    if count >= 2 {
                        return None; // plusieurs feuilles -> bail (lossless)
                    }
                    span = where_span_after(sql, i + FROM_EVENT.len());
                    i += FROM_EVENT.len();
                } else {
                    i += 1;
                }
            }
        }
    }
    if count == 1 {
        span.map(|(s, e)| &sql[s..e])
    } else {
        None
    }
}

/// Découpe un WHERE en ses CONJONCTS DE PREMIER NIVEAU (séparés par ` AND ` à profondeur de parenthèse 0, HORS
/// littéraux). Une sous-expression parenthésée `(a OR b)` reste UN segment (elle ne matchera pas la forme
/// d'égalité -> rejetée), un ` AND ` DANS un littéral (`'x AND y'`) ne coupe pas, et un OR de premier niveau
/// (jamais émis par le cœur dans la feuille, mais défendu) laisse un segment à résidu -> rejeté par `parse_eq_atom`.
fn top_level_and_atoms(where_s: &str) -> Vec<&str> {
    let b = where_s.as_bytes();
    let mut out = Vec::new();
    let (mut in_s, mut in_d) = (false, false);
    let mut d = 0i32;
    let mut seg = 0usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_s {
            if c == b'\'' {
                if b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            if c == b'"' {
                if b.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => {
                in_s = true;
                i += 1;
            }
            b'"' => {
                in_d = true;
                i += 1;
            }
            b'(' => {
                d += 1;
                i += 1;
            }
            b')' => {
                d = (d - 1).max(0);
                i += 1;
            }
            _ => {
                if d == 0 && b[i..].starts_with(b" AND ") {
                    out.push(where_s[seg..i].trim());
                    i += " AND ".len();
                    seg = i;
                } else {
                    i += 1;
                }
            }
        }
    }
    out.push(where_s[seg..].trim());
    out
}

/// `"ident"…` -> (identifiant dé-quoté, reste APRÈS le guillemet fermant). None si `s` ne débute pas par un
/// identifiant entre guillemets doubles. Gère l'échappement SQL `""` -> `"`.
fn parse_quoted_ident(s: &str) -> Option<(String, &str)> {
    let b = s.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    let mut escaped = false;
    loop {
        match b.get(i) {
            Some(&b'"') if b.get(i + 1) == Some(&b'"') => {
                escaped = true;
                i += 2;
            }
            Some(&b'"') => {
                let raw = &s[1..i];
                let id = if escaped { raw.replace("\"\"", "\"") } else { raw.to_string() };
                return Some((id, &s[i + 1..]));
            }
            Some(_) => i += 1,
            None => return None, // identifiant non fermé -> rejette
        }
    }
}

/// `after_q` = tout ce qui suit le guillemet simple OUVRANT du littéral. Renvoie la valeur DÉ-ÉCHAPPÉE (`''` ->
/// `'`) SI le littéral couvre TOUT l'atome (rien d'autre que d'éventuels espaces après le guillemet fermant),
/// sinon None (résidu = ce n'est pas une pure égalité `col = 'lit'` -> on s'abstient, ce qui neutralise aussi un
/// OR de premier niveau `'a' OR "x" = 'b'`). Le dé-échappement rend la valeur BYTE-IDENTIQUE à l'octet stocké
/// dans la colonne (le bloom/min-max ont été calculés sur ces octets bruts).
fn parse_full_string_literal(after_q: &str) -> Option<String> {
    let b = after_q.as_bytes();
    let mut i = 0;
    let mut escaped = false;
    loop {
        match b.get(i) {
            Some(&b'\'') if b.get(i + 1) == Some(&b'\'') => {
                escaped = true;
                i += 2;
            }
            Some(&b'\'') => {
                if !after_q[i + 1..].trim().is_empty() {
                    return None; // résidu après le guillemet fermant -> pas une pure égalité
                }
                let raw = &after_q[..i];
                return Some(if escaped { raw.replace("''", "'") } else { raw.to_string() });
            }
            Some(_) => i += 1,
            None => return None, // littéral non fermé -> rejette
        }
    }
}

/// Entier décimal simple (signe `-` optionnel) — la SEULE forme que le cœur émet pour `severity = N` (branche
/// numérique de `table_conds`). Décimal / vide / non-chiffre -> false (non extrait, repli sûr).
fn is_plain_int(s: &str) -> bool {
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// Un CONJONCT de premier niveau -> `DimEq` SI c'est EXACTEMENT `"col" = 'lit'` (dim string) ou `"col" = N`
/// (severity, entier). Toute autre forme (`<>`, `>=`/borne, `LIKE`, `REGEXP`, `IN`, `(…)`, `json_extract(…)`,
/// RHS numérique nu sur une dim string, RHS quoté sur severity) -> None (on n'élague pas dessus).
fn parse_eq_atom(atom: &str) -> Option<DimEq> {
    let atom = atom.trim();
    let (col, rest) = parse_quoted_ident(atom)?;
    let dim = ColdDim::from_col(&col)?;
    // ÉGALITÉ STRICTE : le cœur émet ` = ` (espaces) pour `=`/`:` ; `<>`/`>=`/`<=`/`>`/`<`/` REGEXP `/` LIKE `/
    // ` COLLATE `/` IN ` ne commencent PAS par ` = ` -> automatiquement rejetés.
    let rest = rest.strip_prefix(" = ")?;
    if let Some(after_q) = rest.strip_prefix('\'') {
        // Littéral string : le cœur ne l'émet (branche string de `table_conds`) que pour une valeur NON
        // numérique -> jamais pour severity. On n'extrait donc severity QUE de la forme numérique nue (ci-dessous).
        if dim == ColdDim::Severity {
            return None;
        }
        Some(DimEq { dim, value: parse_full_string_literal(after_q)? })
    } else {
        // RHS numérique nu : le cœur ne l'émet (branche cast/numérique) que pour une valeur numérique. Comparer
        // une colonne string à un entier nu est AMBIGU (affinité/collation) -> on ne l'extrait QUE pour severity
        // (seule dim réellement numérique), en miroir exact de la branche qu'a prise le compilateur.
        if dim != ColdDim::Severity || !is_plain_int(rest) {
            return None;
        }
        Some(DimEq { dim, value: rest.trim().to_string() })
    }
}

/// #28 PHASE B — EXTRAIT les prédicats d'ÉGALITÉ `dim = value` SÛRS depuis le SQL COMPILÉ (le MÊME que celui
/// exécuté sur l'union hot∪cold par `cold_union_query`). Cf. l'argument LOSSLESS-PAR-CONSTRUCTION dans le header
/// de section : on ne lit QUE les conjoncts AND de premier niveau de l'UNIQUE feuille `FROM event WHERE …`, et on
/// n'émet que la forme d'égalité exacte sur une dim CIM élaguable (générique — clé par NOM de colonne réelle, un
/// nouveau vendeur en bénéficie sans config). Aucune feuille unique / aucune égalité -> `Vec` vide (repli ts-only).
pub(crate) fn extract_cold_dim_preds(compiled_sql: &str) -> Vec<DimEq> {
    let mut out = Vec::new();
    let where_s = match single_event_leaf_where(compiled_sql) {
        Some(w) => w,
        None => return out,
    };
    for atom in top_level_and_atoms(where_s) {
        if let Some(eq) = parse_eq_atom(atom) {
            out.push(eq);
        }
    }
    out
}
