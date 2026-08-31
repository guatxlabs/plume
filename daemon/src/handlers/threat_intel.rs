//! Threat-Intel (#23) — IOC store + match-on-ingest + admin surface. The PURE STIX parse/normalize lives
//! in `guatx_core::ti` (shared, vendor-agnostic) ; here we own the SQLCipher `ioc` table, the in-memory
//! match cache (keyed by db_path, refreshed periodically — NEVER a per-event DB scan), the enrich-on-ingest
//! core (`ti_match_event`) and the admin routes (list / bulk-add / STIX import / coverage).
//!
//! INVARIANT ABSOLU mode 0 : IOC store VIDE (état prod) -> cache vide -> `ti_match_event` renvoie les
//! fields INCHANGÉS -> ligne stockée BYTE-IDENTIQUE. L'enrichissement ENRICHIT (ajoute `fields.threat_intel`
//! + `fields.ti_match=1`), il NE SUPPRIME JAMAIS un event (enrich-not-suppress, comme le CIM/dparsers).
use crate::*;

// ============================================================================================
// CACHE DE MATCH EN MÉMOIRE (keyé par db_path — MT-KEY, comme PARSERS). value NORMALISÉE ->
// métadonnées de l'IOC. Rechargé périodiquement (rollup loop, ~120 s) + après chaque mutation admin.
// Le match-on-ingest LIT ce cache en O(1) (HashMap) : JAMAIS de SELECT par event (discipline
// host_rollup : « jamais scanner event par requête au volume »).
// ============================================================================================

/// Métadonnées d'un IOC servies à l'enrichissement (jamais de secret ; IOC = donnée de renseignement).
#[derive(Clone, Debug)]
pub(crate) struct IocMeta {
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) confidence: i64,
    pub(crate) severity: i64,
}

pub(crate) static IOC_SET: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, HashMap<String, IocMeta>>>> =
    std::sync::OnceLock::new();
pub(crate) fn ioc_set() -> &'static parking_lot::RwLock<HashMap<String, HashMap<String, IocMeta>>> {
    IOC_SET.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

// ============================================================================================
// INDEX D'APPARTENANCE (#30) — PRÉ-FILTRE en tête du chemin chaud, DEVANT le magasin exact.
//
// Le magasin `IOC_SET` (value -> IocMeta) reste la SOURCE DE VÉRITÉ et porte les métadonnées ; il ne
// bouge pas (mode-0 byte-identique). `IocIndex` fronte UNIQUEMENT le test « cette valeur PEUT-elle être
// un IOC ? » :
//   - `maybe_contains` == false  -> NÉGATIF DÉFINITIF : on saute le lookup exact (skip rapide) ;
//   - `maybe_contains` == true    -> POSSIBLE : l'appelant CONFIRME TOUJOURS contre `IOC_SET` (qui
//                                    fournit la meta) — un faux positif du filtre ne peut donc JAMAIS
//                                    fabriquer un faux match.
// INVARIANT ABSOLU : jamais de faux NÉGATIF (toute valeur insérée -> `maybe_contains` == true), sinon on
// raterait un vrai IOC. Le bloom respecte cet invariant par construction (aucune suppression de bit).
//
// Deux implémentations, sélectionnées au reload :
//   (a) HashSetIocIndex = DÉFAUT. Appartenance EXACTE (== `IOC_SET.contains_key`). Le pré-filtre ne
//       change alors STRICTEMENT rien au résultat -> comportement actuel/mode-0 inchangé, byte-identique.
//   (b) BloomIocIndex   = filtre de Bloom sans dépendance (k hachages sur un vecteur de bits, dimensionné
//       depuis N attendu + FP cible). Reconstruit au MÊME reload périodique. Absorbe les ~99,9 % de
//       négatifs définitifs sans toucher au gros HashMap -> passage à l'échelle (millions d'IOC).
// Sélection : env `PLUME_IOC_BLOOM=1` (forçage) OU seuil auto (N > `PLUME_IOC_BLOOM_MIN`, défaut 50000).
// ============================================================================================

/// Pré-filtre d'appartenance devant le magasin exact d'IOC (voir bloc ci-dessus). `Send + Sync` : partagé
/// derrière un `RwLock` statique multi-thread.
pub(crate) trait IocIndex: Send + Sync {
    /// PEUT contenir `value` ? `false` = négatif DÉFINITIF (aucun faux négatif) ; `true` = POSSIBLE
    /// (l'appelant DOIT confirmer contre le magasin exact). `kind` est indicatif (le type d'une valeur
    /// d'event est inconnu à l'ingest -> non haché ici pour préserver l'invariant « jamais de faux nég »).
    fn maybe_contains(&self, kind: &str, value: &str) -> bool;
    /// (Re)construit le filtre depuis l'ensemble courant d'IOC actifs (paires (kind, value) NORMALISÉES).
    fn rebuild(&mut self, iocs: &[(String, String)]);
    /// Nom de l'implémentation (observabilité / tests).
    fn kind_name(&self) -> &'static str;
}

/// (a) DÉFAUT — appartenance EXACTE. `maybe_contains` == `HashSet::contains` : le pré-filtre est alors
/// une pure redondance du magasin -> sortie IDENTIQUE à aujourd'hui (mode-0 byte-identique préservé).
#[derive(Default)]
pub(crate) struct HashSetIocIndex {
    set: std::collections::HashSet<String>,
}
impl IocIndex for HashSetIocIndex {
    fn maybe_contains(&self, _kind: &str, value: &str) -> bool {
        self.set.contains(value)
    }
    fn rebuild(&mut self, iocs: &[(String, String)]) {
        self.set = iocs.iter().map(|(_k, v)| v.clone()).collect();
    }
    fn kind_name(&self) -> &'static str {
        "hashset"
    }
}

/// (b) Filtre de Bloom sans dépendance : `k` hachages (double-hachage Kirsch-Mitzenmacher `h1 + i*h2`)
/// sur un vecteur de bits de `m` bits (empaqueté en mots u64). Dimensionné depuis N attendu + FP cible.
/// AUCUN bit n'est jamais remis à 0 -> tout élément inséré reste positif (aucun faux négatif). Les faux
/// POSITIFS sont bénins : rattrapés par le confirm exact côté appelant.
pub(crate) struct BloomIocIndex {
    bits: Vec<u64>, // m bits empaquetés
    m: u64,         // nombre de bits (>=64)
    k: u32,         // nombre de hachages (>=1)
}
impl BloomIocIndex {
    /// FP cible du filtre (0,1 %). Compromis mémoire/précision ; le confirm exact rattrape les FP.
    const TARGET_FP: f64 = 0.001;

    /// Filtre VIDE (aucun IOC). `rebuild` le redimensionne. Un filtre vide -> `maybe_contains` toujours
    /// `false` (aucun bit posé) = négatif définitif correct quand le magasin est vide.
    pub(crate) fn new() -> Self {
        BloomIocIndex { bits: vec![0u64; 1], m: 64, k: 1 }
    }

    /// Dimensionnement optimal : m = -n·ln(p)/(ln2)² bits ; k = (m/n)·ln2 hachages. Bornes basses
    /// défensives (m>=64, k>=1) pour n petit.
    fn sizing(n: usize) -> (u64, u32) {
        let n = n.max(1) as f64;
        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * Self::TARGET_FP.ln()) / (ln2 * ln2)).ceil();
        let m = (m as u64).max(64);
        let k = ((m as f64 / n) * ln2).round() as u32;
        (m, k.clamp(1, 32))
    }

    /// Deux hachages 64-bit décorrélés d'une valeur : FNV-1a (h1) puis un mix splitmix64 de h1 (h2 rendu
    /// impair et non nul pour un pas de stepping propre). Value-only (voir invariant de `maybe_contains`).
    fn hash2(value: &str) -> (u64, u64) {
        let mut h1: u64 = 0xcbf29ce484222325;
        for b in value.as_bytes() {
            h1 ^= *b as u64;
            h1 = h1.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut h2 = h1;
        h2 ^= h2 >> 33;
        h2 = h2.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h2 ^= h2 >> 33;
        h2 = h2.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h2 ^= h2 >> 33;
        (h1, h2 | 1)
    }

    /// Positions de bits (k) d'une valeur, via double-hachage h1 + i·h2 mod m.
    fn positions(&self, value: &str) -> impl Iterator<Item = usize> + '_ {
        let (h1, h2) = Self::hash2(value);
        let (m, k) = (self.m, self.k);
        (0..k).map(move |i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize)
    }

    fn set_bit(&mut self, value: &str) {
        for bit in self.positions(value).collect::<Vec<_>>() {
            self.bits[bit / 64] |= 1u64 << (bit % 64);
        }
    }
}
impl IocIndex for BloomIocIndex {
    fn maybe_contains(&self, _kind: &str, value: &str) -> bool {
        // Tous les k bits posés -> POSSIBLE ; un seul à 0 -> négatif DÉFINITIF.
        self.positions(value).all(|bit| self.bits[bit / 64] & (1u64 << (bit % 64)) != 0)
    }
    fn rebuild(&mut self, iocs: &[(String, String)]) {
        let (m, k) = Self::sizing(iocs.len());
        self.m = m;
        self.k = k;
        self.bits = vec![0u64; ((m + 63) / 64) as usize];
        for (_kind, value) in iocs {
            self.set_bit(value);
        }
    }
    fn kind_name(&self) -> &'static str {
        "bloom"
    }
}

pub(crate) static IOC_INDEX: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Box<dyn IocIndex>>>> =
    std::sync::OnceLock::new();
/// Index d'appartenance par db_path (MT-KEY, miroir de `IOC_SET`). Reconstruit au même reload.
pub(crate) fn ioc_index() -> &'static parking_lot::RwLock<HashMap<String, Box<dyn IocIndex>>> {
    IOC_INDEX.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// L'ISSUE DU DERNIER RECHARGEMENT DU CACHE IOC, par db_path (MT-KEY, comme `IOC_SET`/`IOC_INDEX` —
/// une base tenant ne peut pas hériter du verdict d'une autre).
///
/// LE DÉFAUT QUE CET ÉTAT FERME (`P10.7-k`). `ioc_cache_reload` construisait sa table par
/// `if let Ok(..) = prepare` / `if let Ok(..) = query_map` / `rows.flatten()`, puis l'INSTALLAIT
/// inconditionnellement. Une lecture ratée produisait donc un ensemble VIDE, et cet ensemble vide
/// REMPLAÇAIT ATOMIQUEMENT le cache vivant : `ti_lookup` prend son fast-path `set.is_empty() -> None`
/// et le match-on-ingest devient un no-op. Aucune route ne ment, aucun corps n'est servi, aucune garde
/// de texte ne peut l'exprimer — et la détection par indicateurs est ÉTEINTE jusqu'au prochain
/// rechargement réussi. Un `.flatten()` interrompu était pire encore : un ensemble PLUS PETIT que la
/// table, donc MOINS de détection, sans même un ensemble vide pour le trahir.
///
/// LE REMÈDE EST CELUI DE `S32`, PAS UN NOUVEAU VOCABULAIRE : la lecture rend une `Mesure`. `Lue(n)` =
/// la table a été lue ENTIÈREMENT et le cache porte `n` indicateurs actifs. `Illisible` = la lecture a
/// échoué, le cache VIVANT a été CONSERVÉ, et la cause est une clé de l'ensemble fermé. Perdre la mise
/// à jour est un moindre mal que perdre la détection ; le taire était le vrai défaut.
pub(crate) static IOC_RELOAD: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, crate::mesure_environnement::Mesure<u64>>>> =
    std::sync::OnceLock::new();
pub(crate) fn ioc_reload_etat() -> &'static parking_lot::RwLock<HashMap<String, crate::mesure_environnement::Mesure<u64>>> {
    IOC_RELOAD.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
/// CE QUE LE DERNIER RECHARGEMENT DE CE db_path A VALU. `None` = aucun rechargement n'a encore eu lieu
/// (démarrage) — que la surface distingue d'un `Lue(0)`, lequel est un VRAI zéro d'indicateurs actifs.
pub(crate) fn ioc_reload_dernier(db_path: &str) -> Option<crate::mesure_environnement::Mesure<u64>> {
    ioc_reload_etat().read().get(db_path).cloned()
}

/// Seuil d'auto-bascule vers le bloom : N IOC actifs > ce seuil (défaut 50000). Sous ce seuil, le
/// HashSet exact suffit et évite tout faux positif.
fn ioc_bloom_min() -> usize {
    std::env::var("PLUME_IOC_BLOOM_MIN").ok().and_then(|s| s.parse().ok()).unwrap_or(50_000)
}
/// Forçage explicite du bloom (`PLUME_IOC_BLOOM=1`), indépendamment du volume.
fn ioc_bloom_forced() -> bool {
    std::env::var("PLUME_IOC_BLOOM").ok().as_deref() == Some("1")
}
/// Construit l'impl d'index adaptée à `pairs` (bloom si forcé OU N>seuil, sinon HashSet exact).
fn build_ioc_index(pairs: &[(String, String)]) -> Box<dyn IocIndex> {
    let mut idx: Box<dyn IocIndex> = if ioc_bloom_forced() || pairs.len() > ioc_bloom_min() {
        Box::new(BloomIocIndex::new())
    } else {
        Box::new(HashSetIocIndex::default())
    };
    idx.rebuild(pairs);
    idx
}

/// LES IOC ACTIFS DE LA TABLE, ENTIÈREMENT OU PAS DU TOUT. Les IOC expirés (expires<=now) sont EXCLUS
/// -> expiry/rétention servie à la lecture (aucune purge de ligne requise).
///
/// UN PARCOURS INTERROMPU N'EST PAS UN PARCOURS COMPLET — même doctrine que `profondeur_file_depuis`
/// (`S32`) et pour la même raison, mais avec un enjeu plus dur : ici le compte partiel n'est pas une
/// série creuse, c'est de la DÉTECTION EN MOINS. `.flatten()` sautait la ligne indécodable et rendait
/// un ensemble plus petit que la table ; l'appelant l'installait comme s'il était la table. Une erreur
/// de ligne interrompt donc la lecture et remonte, plutôt que de rétrécir le jeu en silence.
fn lire_iocs_actifs(conn: &Connection, now_ts: i64) -> rusqlite::Result<HashMap<String, IocMeta>> {
    let mut st = conn.prepare(
        "SELECT type,value,source,confidence,severity FROM ioc WHERE expires IS NULL OR expires > ?1",
    )?;
    let rows = st.query_map(params![now_ts], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut map: HashMap<String, IocMeta> = HashMap::new();
    for ligne in rows {
        let (kind, value, source, confidence, severity) = ligne?;
        // La `value` est déjà normalisée à l'insertion ; on la garde telle quelle comme CLÉ.
        map.insert(value, IocMeta { kind, source, confidence, severity });
    }
    Ok(map)
}

/// Recharge le set d'IOC ACTIFS de CE db_path depuis la table `ioc` (sous le lock writer côté appelant,
/// ex. rollup loop, ~120 s, plus après chaque mutation admin).
///
/// `P10.7-k` — ON NE REMPLACE PAS UN ÉTAT VIVANT PAR UN ÉTAT VIDE. La publication n'a lieu QUE si la
/// table a été lue ENTIÈREMENT. Si la lecture échoue, le cache précédent est CONSERVÉ tel quel : la
/// correspondance continue sur le jeu d'indicateurs de la dernière lecture réussie, et c'est la MISE À
/// JOUR qui est perdue, pas la DÉTECTION. Le rechargement ne renonce pas non plus : il est retenté au
/// tick suivant, exactement comme avant.
///
/// ET IL LE DIT — le silence était l'autre moitié du défaut. L'issue est publiée dans `IOC_RELOAD`
/// (servie par `/api/threat-intel/coverage`, la route qui existe déjà pour l'état de ce magasin) ; le
/// journal ne porte que les BASCULES, parce qu'un aveu répété à chaque tick de rollup se lirait comme
/// du bruit et non comme un événement. Table absente (base pas encore migrée) : c'est `forme_inconnue`,
/// la même clé que `run_due_rules` rend pour une table manquante — il n'y a alors rien à conserver et
/// rien n'est installé, donc `ti_lookup` retombe sur son fast-path exactement comme avant.
pub(crate) fn ioc_cache_reload(conn: &Connection, db_path: &str) {
    use crate::mesure_environnement::{Mesure, VERDICT_ILLISIBLE};
    let avant = ioc_reload_etat().read().get(db_path).map(Mesure::verdict);
    let bilan = match lire_iocs_actifs(conn, now()) {
        Ok(map) => {
            let actifs = map.len() as u64;
            // (#30) Reconstruit l'index d'appartenance depuis LE MÊME jeu d'IOC (paires (kind, value)).
            // Sélection bloom/HashSet selon volume+env. Fait AVANT la publication du set : les deux
            // structures sont écrites sous des locks distincts non imbriqués (ordre reload : set puis
            // index ; lecture ti_lookup : set puis index) -> aucun interblocage possible.
            let pairs: Vec<(String, String)> = map.iter().map(|(v, m)| (m.kind.clone(), v.clone())).collect();
            let idx = build_ioc_index(&pairs);
            { let mut w = ioc_set().write();
                w.insert(db_path.to_string(), map); // MT-KEY : set de CE db_path (remplacement atomique)
            }
            { let mut wi = ioc_index().write();
                wi.insert(db_path.to_string(), idx); // MT-KEY : index de CE db_path (remplacement atomique)
            }
            Mesure::Lue(actifs)
        }
        Err(e) => {
            // LE GESTE : rien n'est écrit. Le set et l'index de CE db_path restent ceux de la dernière
            // lecture entière. Le compte conservé part dans l'aveu — sans lui, un exploitant ne sait pas
            // si la détection tourne encore ni sur combien d'indicateurs.
            let conserves = ioc_set().read().get(db_path).map_or(0, |m| m.len());
            Mesure::Illisible {
                cause: crate::bilan_de_tick::cause_sql(&e),
                detail: format!(
                    "rechargement du cache IOC de `{db_path}` : la table `ioc` n'a pas pu être lue entièrement \
                     ({e}) — {conserves} indicateur(s) de la dernière lecture réussie CONSERVÉ(S), la \
                     correspondance continue sur ce jeu et la mise à jour est perdue ; installer un ensemble \
                     vide aurait ÉTEINT la correspondance sans qu'aucun corps servi ne le dise"
                ),
            }
        }
    };
    // LA BASCULE, PAS L'ÉTAT : le chemin nominal reste MUET (aucune ligne de journal sur un `Lue`), et un
    // aveu qui se répète 720 fois par jour cesse d'être lu.
    match (&bilan, avant) {
        (Mesure::Illisible { detail, .. }, precedent) if precedent != Some(VERDICT_ILLISIBLE) => {
            eprintln!("[ti] WARN {detail}");
        }
        (Mesure::Lue(n), Some(VERDICT_ILLISIBLE)) => {
            eprintln!("[ti] rechargement du cache IOC RÉTABLI pour `{db_path}` : {n} indicateur(s) actif(s)");
        }
        _ => {}
    }
    ioc_reload_etat().write().insert(db_path.to_string(), bilan);
}

/// Clé de lookup canonique d'une valeur candidate d'event (miroir LÉGER de normalize_ioc : toutes ses
/// sorties sont trim+minuscule). On ne connaît pas le type d'une valeur d'event -> une seule forme.
fn ti_lookup_key(v: &str) -> String {
    v.trim().to_ascii_lowercase()
}

/// Cherche le PREMIER IOC correspondant à une valeur indicatrice de l'event (ip/dst/url de colonne +
/// domain/dns/hash extraits des fields). Lecture O(1) du cache. Renvoie (valeur_matchée, meta). FAST
/// PATH : set de CE db_path absent/vide -> None immédiat (aucun travail chaud, mode 0 byte-identique).
fn ti_lookup(db_path: &str, ip: Option<&str>, dst: Option<&str>, url: Option<&str>, fields: Option<&str>) -> Option<(String, IocMeta)> {
    let guard = ioc_set().read();
    let set = guard.get(db_path)?;
    if set.is_empty() {
        return None;
    }
    // (#30) Index d'appartenance de CE db_path (pré-filtre). Absent (ne devrait pas arriver, reload écrit
    // les deux) -> None -> confirm exact seul (sûr : jamais de faux négatif). Verrou lecture nesté sous
    // celui de `set` (même ordre que le reload -> pas d'interblocage).
    let iguard = ioc_index().read();
    let index: Option<&Box<dyn IocIndex>> = iguard.get(db_path);
    // Candidats de colonne (déjà promus par l'ingest) + candidats extraits des fields JSON.
    let probe = |raw: Option<&str>| -> Option<(String, IocMeta)> {
        let raw = raw?;
        if raw.is_empty() {
            return None;
        }
        let k = ti_lookup_key(raw);
        // Pré-filtre : négatif DÉFINITIF -> skip du lookup exact (fast skip). Positif POSSIBLE -> on
        // CONFIRME contre le magasin exact (qui porte la meta) : un faux positif du filtre ne peut pas
        // fabriquer un faux match. HashSet (défaut) == appartenance exacte -> résultat inchangé.
        if let Some(idx) = index {
            if !idx.maybe_contains("", &k) {
                return None;
            }
        }
        set.get(&k).map(|m| (k, m.clone()))
    };
    if let Some(h) = probe(ip) { return Some(h); }
    if let Some(h) = probe(dst) { return Some(h); }
    if let Some(h) = probe(url) { return Some(h); }
    // Champs indicateurs usuels dans le JSON `fields` (domaine / requête DNS / hachages / url|ip alt).
    if let Some(fj) = fields {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(fj) {
            for key in ["domain", "dns_query", "query", "url", "md5", "sha1", "sha256", "hash", "src_ip", "dst_ip"] {
                if let Some(s) = m.get(key).and_then(|x| x.as_str()) {
                    if let Some(h) = probe(Some(s)) {
                        return Some(h);
                    }
                }
            }
        }
    }
    None
}

/// Un hit threat-intel PROMU en contribution de risque (#24, composition RBA). `entity_type` dérivé du
/// type d'IOC (ip->ip ; domain/url/email/hash_*->le type lui-même : ce sont des entités distinctes qui
/// accumulent leur propre risque). Data-only (aucun secret). Renvoyé À CÔTÉ des fields enrichis pour que
/// l'ingest émette un `risk_event` SANS refaire le lookup (un seul O(1) par event).
#[derive(Clone, Debug)]
pub(crate) struct TiHit {
    pub(crate) entity_type: String,
    pub(crate) entity: String,
    pub(crate) severity: i64,
    pub(crate) source: String,
}

/// Mappe un type d'IOC vers un `entity_type` de risque (les hachages -> 'file'). Vendor-agnostic.
fn ti_entity_type(ioc_kind: &str) -> &'static str {
    match ioc_kind {
        "ip" => "ip",
        "domain" => "domain",
        "url" => "url",
        "email" => "email",
        "hash_md5" | "hash_sha1" | "hash_sha256" => "file",
        _ => "ioc",
    }
}

/// MATCH-ON-INGEST ÉTENDU (#24) : comme `ti_match_event` mais renvoie AUSSI le hit brut (`TiHit`) pour la
/// composition RBA (l'ingest en fait un `risk_event`). UN SEUL lookup O(1). Pas de hit -> (fields inchangés,
/// None) = fast path mode 0 byte-identique.
pub(crate) fn ti_match_event_ex(db_path: &str, ip: Option<&str>, dst: Option<&str>, url: Option<&str>, fields: Option<String>) -> (Option<String>, Option<TiHit>) {
    match ti_lookup(db_path, ip, dst, url, fields.as_deref()) {
        None => (fields, None), // pas de hit -> fields inchangés (fast path mode 0)
        Some((matched, meta)) => {
            let hit = TiHit {
                entity_type: ti_entity_type(&meta.kind).to_string(),
                entity: matched.clone(),
                severity: meta.severity,
                source: meta.source.clone(),
            };
            (Some(ti_enrich(fields, &matched, &meta)), Some(hit))
        }
    }
}

/// MATCH-ON-INGEST (cœur, appelé par l'ingest sous le lock writer). Prend `fields` PAR VALEUR et le
/// renvoie : INCHANGÉ s'il n'y a pas de hit (byte-identique), ou ENRICHI (ajoute `threat_intel`
/// {source,confidence,ioc_type,value} + `ti_match=1`) sur le 1er hit. ENRICH-NOT-SUPPRESS : ne DROP
/// jamais l'event (renvoie toujours des fields, jamais None-comme-drop). Efficace : lookup cache O(1).
/// Fin wrapper de `ti_match_event_ex` (ignore le hit RBA) -> API #23 inchangée (tests/anciens appels).
pub(crate) fn ti_match_event(db_path: &str, ip: Option<&str>, dst: Option<&str>, url: Option<&str>, fields: Option<String>) -> Option<String> {
    ti_match_event_ex(db_path, ip, dst, url, fields).0
}

/// Injecte l'enrichissement threat-intel dans le JSON `fields` (créé s'il est absent/illisible). MERGE
/// non destructif : n'écrase pas une clé existante autre que les nôtres. Renvoie le JSON sérialisé.
fn ti_enrich(fields: Option<String>, matched: &str, meta: &IocMeta) -> String {
    let mut obj = match fields.as_deref().and_then(|f| serde_json::from_str::<Value>(f).ok()) {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    obj.insert(
        "threat_intel".into(),
        json!({ "source": meta.source, "confidence": meta.confidence, "ioc_type": meta.kind, "value": matched, "severity": meta.severity }),
    );
    // Marqueurs PLATS requêtables en GXQL par une règle de détection : `search ti_match=1 | stats count`.
    // `ti_confidence`/`ti_severity` sont aplatis (en plus du nid `threat_intel`) pour que la règle d'alerte
    // TI (#23 activation) puisse filtrer `ti_confidence>=80` et DÉRIVER la sévérité de l'alerte de la
    // sévérité de l'IOC (`ti_severity>=4` -> alerte haute ; `<=3` -> moyenne) — json_extract sur un champ
    // NUMÉRIQUE plat, comparable directement (comme `status>=500` des règles web). AJOUTÉ UNIQUEMENT sur le
    // chemin ENRICHI (un hit IOC) : mode 0 (store vide -> ti_enrich jamais appelé) reste BYTE-IDENTIQUE.
    obj.insert("ti_match".into(), json!(1));
    obj.insert("ti_confidence".into(), json!(meta.confidence));
    obj.insert("ti_severity".into(), json!(meta.severity));
    Value::Object(obj).to_string()
}

// ============================================================================================
// ROUTES ADMIN — magasin d'IOC (list / add bulk / import STIX) + coverage (lecture viewer+).
// Les routes MUTANTES sont ADMIN-only par le default-deny de route_min_role (hors allowlist éditoriale) ;
// on re-check `au.is_admin()` ici (défense en profondeur, comme les connecteurs).
// ============================================================================================

// =================================================================================================
// `P11.17-f` — L'INVENTAIRE DES INDICATEURS DIT CE QU'IL SERT, ET CE QU'IL NE SERT PAS
//
// LE DÉFAUT, ET POURQUOI IL EST LE PLUS GRAVE DE SA FAMILLE. `GET /api/threat-intel/iocs` bornait sa
// lecture à deux mille lignes et rendait un TABLEAU NU : ni total, ni indicateur de troncature, ni
// même une enveloppe où en poser un. Un inventaire d'indicateurs tronqué en silence ne se lit pas
// comme une liste incomplète : il se lit comme une COUVERTURE. Un analyste qui cherche si un
// indicateur est connu du magasin et ne le voit pas conclut qu'il n'y est pas — alors qu'il peut
// simplement être hors fenêtre. L'écart va donc dans le sens dangereux, et il grandit : rien ne purge
// `ioc` (l'expiration est calculée À LA LECTURE, aucune ligne n'est supprimée), la table ne fait que
// croître et la fenêtre en couvre une part toujours plus petite.
//
// CE QUE LA CLÉ ET LES INDEX DE **CETTE** TABLE PERMETTENT — vérifiés plutôt que supposés, parce que
// c'est la FORME qui se reprend d'un flux à l'autre et jamais le littéral SQL :
//   * `ioc.id` est `INTEGER PRIMARY KEY` (migration v79), donc l'alias du `rowid`. Les index de la
//     table sont `idx_ioc_value(value)`, `idx_ioc_expires(expires) WHERE expires IS NOT NULL` et
//     l'auto-index de `UNIQUE(type,value,source,env_id)`. **`last_seen` N'EST INDEXÉ PAR AUCUN.**
//   * IL S'ENSUIT QUE LA BORNE NE BORNE PAS LA LECTURE, seulement l'ENVOI : `ORDER BY last_seen DESC,
//     id DESC` sans index sur `last_seen` impose au moteur de parcourir la table ENTIÈRE et de la
//     trier avant de couper à la fenêtre. C'est l'inverse de la file de riposte (`P11.17-e`), dont la
//     fenêtre `ORDER BY id DESC` est un parcours arrière de la clé primaire, O(N). Le total borné
//     ajouté ici coûte donc, dans le pire cas, MOINS que la fenêtre qu'il accompagne.
//   * LE CURSEUR N'EST PAS CONSTRUIT, ET LA RAISON EST DANS LA DONNÉE : `ioc_upsert` RÉÉCRIT
//     `last_seen` à chaque ré-apport d'un indicateur par son flux. Une clé de pagination
//     `(last_seen,id)` désignerait donc une ligne qui SE DÉPLACE entre deux pages — un indicateur
//     ré-apporté pendant le parcours remonterait en tête et une ligne serait sautée sans que rien ne
//     le dise. Ce serait le défaut de cette clé, reproduit sous un autre nom. Un curseur sur `id`
//     seul serait stable mais servirait l'ordre des CRÉATIONS, pas celui des dernières vues, donc
//     pas la liste que ce panneau montre.
//   * LE VOISIN COMPTE DÉJÀ, ET C'EST CE QUI RENDAIT LE SILENCE VISIBLE : `GET
//     /api/threat-intel/coverage` sert un `COUNT(*)` EXACT de la même table, affiché en tuile juste
//     au-dessus de la liste. Les deux chiffres étaient donc côte à côte à l'écran sans qu'aucun ne
//     dise que le second était une fenêtre du premier. Ce comptage-là n'est pas touché : il répond à
//     une autre question (l'état du magasin) et son coût est celui d'un comptage d'arbre.
// =================================================================================================

/// TAILLE DE LA FENÊTRE servie par `GET /api/threat-intel/iocs` — les `IOCS_WINDOW` indicateurs vus le
/// plus récemment. Nommée plutôt qu'écrite dans l'énoncé : la vue la REÇOIT, et le test la lit ici au
/// lieu de la recopier.
pub(crate) const IOCS_WINDOW: i64 = 2000;

/// LE SEUL fabricant du COMPTAGE de l'inventaire — écrit une fois pour que le test mesure CE QUI EST
/// ÉMIS et non une copie. `SELECT 1` ne demande aucune colonne, `LIMIT CAP+1` ARRÊTE le balayage au
/// plafond partagé : sous le plafond le total est EXACT, au-dessus il est plafonné ET annoncé.
pub(crate) fn iocs_total_sql() -> String {
    crate::handlers::liste_bornee::sql_du_comptage_borne("ioc")
}

/// LE SEUL fabricant de la FENÊTRE servie. Projection et ordre INCHANGÉS : ce correctif ajoute un
/// chiffre à côté de la liste, il ne touche pas à la liste.
pub(crate) fn iocs_window_sql() -> String {
    format!(
        "SELECT id,type,value,source,confidence,severity,first_seen,last_seen,expires,stix_id,env_id \
         FROM ioc ORDER BY last_seen DESC, id DESC LIMIT {IOCS_WINDOW}"
    )
}

/// Fenêtre + total borné de l'inventaire d'indicateurs. Fonction PURE sur `&Connection` -> testable
/// sans `AppState`.
///
/// Rend `{iocs, served, window, total, total_capped}` — forme RENDUE par le fabricant partagé
/// `handlers::liste_bornee` (`P11.22-f`) au lieu d'être recopiée ici pour la quatrième fois. `served`
/// est le nombre de lignes RENDUES et `window` la borne de la route : leur égalité est précisément ce
/// qui dit à la vue que la borne MORD. `total`/`total_capped` valent `null` — jamais `0` — quand le
/// comptage n'a pas pu être lu : « non compté » et « aucun indicateur » sont deux faits différents, et
/// sur un inventaire de renseignement l'écart va dans le sens dangereux (un magasin qu'on croit vide
/// n'alarme personne). MÊME RAISON POUR LA LECTURE DES LIGNES : elle est avouée si elle échoue.
pub(crate) fn iocs_page(conn: &Connection, now_ts: i64) -> Value {
    use crate::handlers::liste_bornee as aveu;
    let lignes = aveu::lire(conn, &iocs_window_sql(), |r| {
        let expires: Option<i64> = r.get(8)?;
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "type": r.get::<_, String>(1)?,
            "value": r.get::<_, String>(2)?,
            "source": r.get::<_, String>(3)?,
            "confidence": r.get::<_, i64>(4)?,
            "severity": r.get::<_, i64>(5)?,
            "first_seen": r.get::<_, Option<i64>>(6)?,
            "last_seen": r.get::<_, Option<i64>>(7)?,
            "expires": expires,
            "expired": expires.map(|e| e <= now_ts).unwrap_or(false),
            "stix_id": r.get::<_, Option<String>>(9)?,
            "env_id": r.get::<_, String>(10)?,
        }))
    });
    let total = aveu::TotalBorne::depuis_un_comptage_borne(
        conn.query_row(&iocs_total_sql(), [], |r| r.get::<_, i64>(0)),
        PAGINATION_COUNT_CAP,
    );
    aveu::corps("iocs", lignes, IOCS_WINDOW, total)
}

/// RANG DE COUPE de la ventilation par source servie par `/api/threat-intel/coverage`. Nommé plutôt
/// qu'écrit dans l'énoncé : la vue le REÇOIT (`by_source_window`) et le test le lit ici au lieu de le
/// recopier.
pub(crate) const TI_COVERAGE_SOURCES_MAX: usize = 50;

/// GET /api/threat-intel/iocs — fenêtre des IOC du tenant courant, servie AVEC son total borné. viewer+
/// (donnée de renseignement, pas un secret). Retourne aussi le statut expiré (calculé au read).
pub(crate) async fn iocs_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    Json(iocs_page(&conn, now())).into_response()
}

/// UPSERT d'un IOC (INSERT OR sur UNIQUE(type,value,source,env_id)). `first_seen` conservé au conflit ;
/// `last_seen`/confidence/severity/expires/stix_id mis à jour. Renvoie true si écrit (insert ou update).
#[allow(clippy::too_many_arguments)]
pub(crate) fn ioc_upsert(conn: &Connection, kind: &str, value: &str, source: &str, confidence: i64, severity: i64, expires: Option<i64>, stix_id: Option<&str>, env_id: &str, now_ts: i64) -> bool {
    conn.execute(
        "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,stix_id,env_id) \
         VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8,?9) \
         ON CONFLICT(type,value,source,env_id) DO UPDATE SET \
           last_seen=excluded.last_seen, confidence=excluded.confidence, severity=excluded.severity, \
           expires=excluded.expires, stix_id=COALESCE(excluded.stix_id, ioc.stix_id)",
        params![kind, value, source, confidence, severity, now_ts, expires, stix_id, env_id],
    )
    .is_ok()
}

/// Sévérité (0..4) bornée depuis une valeur JSON (défaut 2).
fn clamp_sev(v: Option<i64>) -> i64 {
    v.unwrap_or(2).clamp(0, 4)
}
/// Confiance (0..100) bornée depuis une valeur JSON (défaut 50).
fn clamp_conf(v: Option<i64>) -> i64 {
    v.unwrap_or(50).clamp(0, 100)
}

/// POST /api/threat-intel/iocs — ajout MANUEL / bulk d'IOC (admin). Corps : un objet unique
/// {type,value,...} OU {iocs:[…], source?, env_id?}. Chaque valeur est NORMALISÉE (guatx_core::ti) ;
/// une valeur illégale pour son type est IGNORÉE avec raison (jamais une ligne corrompue). Recharge le
/// cache après écriture (effet immédiat au prochain event). Audité (ledger + event).
pub(crate) async fn ioc_add(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let default_source = b.get("source").and_then(|x| x.as_str()).unwrap_or("manual").trim().to_string();
    let default_source = if default_source.is_empty() { "manual".to_string() } else { default_source };
    let env_id = b.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").to_string();
    if !env_slug_ok(&env_id) {
        return bad_req("env_id invalide (alnum + _/-)");
    }
    // Corps : liste explicite `iocs`, sinon l'objet lui-même est un IOC unique.
    let items: Vec<Value> = match b.get("iocs").and_then(|x| x.as_array()) {
        Some(arr) => arr.clone(),
        None => vec![b.clone()],
    };
    if items.is_empty() {
        return bad_req("aucun IOC (corps: {iocs:[…]} ou {type,value})");
    }
    let now_ts = now();
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let mut added = 0i64;
    let mut skipped: Vec<Value> = Vec::new();
    let outcome: rusqlite::Result<()> = (|| {
        for it in &items {
            let kind = it.get("type").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if !guatx_core::ti::IOC_TYPES.contains(&kind.as_str()) {
                skipped.push(json!({ "value": it.get("value"), "reason": format!("type inconnu '{kind}'") }));
                continue;
            }
            let raw = it.get("value").and_then(|x| x.as_str()).unwrap_or("");
            let value = match guatx_core::ti::normalize_ioc(&kind, raw) {
                Some(v) => v,
                None => {
                    skipped.push(json!({ "value": raw, "reason": format!("valeur invalide pour {kind}") }));
                    continue;
                }
            };
            let source = it.get("source").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| default_source.clone());
            let confidence = clamp_conf(it.get("confidence").and_then(|x| x.as_i64()));
            let severity = clamp_sev(it.get("severity").and_then(|x| x.as_i64()));
            let expires = it.get("expires").and_then(|x| x.as_i64());
            let stix_id = it.get("stix_id").and_then(|x| x.as_str());
            if ioc_upsert(&conn, &kind, &value, &source, confidence, severity, expires, stix_id, &env_id, now_ts) {
                added += 1;
            }
        }
        audit_config_change(
            &conn,
            "config.ioc.add",
            &format!("{added} IOC ajouté(s)/mis à jour par {} (skipped={})", au.name, skipped.len()),
            2,
            &format!("{added} indicateur(s) de compromission ajouté(s)/mis à jour par {} (source par défaut '{default_source}', env={env_id})", au.name),
            &json!({ "added": added, "skipped": skipped.len(), "env_id": env_id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            // Recharge le cache de match SOUS le lock writer courant (effet immédiat).
            let db_path = req_db_path(&st, &au);
            ioc_cache_reload(&conn, &db_path);
            Json(json!({ "added": added, "skipped": skipped })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction (aucune modification): {e}"))
        }
    }
}

/// POST /api/threat-intel/import — import d'un BUNDLE STIX 2.1 (admin). Corps : {bundle:{…}, source?,
/// env_id?} ou directement le bundle. La traduction est PURE (guatx_core::ti::stix_bundle_to_iocs) :
/// chaque `indicator` SDO traduisible -> IOC(s) ; un pattern non supporté -> skipped {id,reason} (jamais
/// un IOC qui sous/sur-matche en silence). `valid_until` STIX -> `expires`. Recharge le cache. Audité.
pub(crate) async fn stix_import(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let source = b.get("source").and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "stix-import".to_string());
    let env_id = b.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").to_string();
    if !env_slug_ok(&env_id) {
        return bad_req("env_id invalide (alnum + _/-)");
    }
    // Le bundle peut être fourni sous `bundle`, `objects`-porteur, ou être l'objet racine lui-même.
    let bundle = b.get("bundle").cloned().unwrap_or_else(|| b.clone());
    let imp = guatx_core::ti::stix_bundle_to_iocs(&bundle);
    let skipped: Vec<Value> = imp.skipped.iter().map(|s| json!({ "id": s.id, "reason": s.reason })).collect();
    if imp.iocs.is_empty() {
        // Rien à écrire : on renvoie quand même le détail des skips (feedback d'import fidèle).
        return Json(json!({ "imported": 0, "skipped": skipped })).into_response();
    }
    let now_ts = now();
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let mut imported = 0i64;
    let outcome: rusqlite::Result<()> = (|| {
        for ioc in &imp.iocs {
            // valid_until (ISO8601 UTC) -> expires (epoch s). Réutilise minio_to_epoch (RFC3339 -> epoch).
            let expires = ioc.valid_until.as_deref().map(|s| minio_to_epoch(Some(s))).filter(|&e| e > 0);
            let confidence = clamp_conf(ioc.confidence);
            // sévérité : dérivée de la confiance si non fournie par STIX (>=80 -> 3, sinon 2).
            let severity = if confidence >= 80 { 3 } else { 2 };
            if ioc_upsert(&conn, &ioc.kind, &ioc.value, &source, confidence, severity, expires, ioc.stix_id.as_deref(), &env_id, now_ts) {
                imported += 1;
            }
        }
        audit_config_change(
            &conn,
            "config.ioc.import",
            &format!("import STIX de {imported} IOC (skipped={}) par {}", skipped.len(), au.name),
            2,
            &format!("import STIX 2.1 : {imported} indicateur(s) importé(s), {} ignoré(s) par {} (source '{source}', env={env_id})", skipped.len(), au.name),
            &json!({ "imported": imported, "skipped": skipped.len(), "source": source, "env_id": env_id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            let db_path = req_db_path(&st, &au);
            ioc_cache_reload(&conn, &db_path);
            Json(json!({ "imported": imported, "skipped": skipped })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction import (aucune modification): {e}"))
        }
    }
}

/// GET /api/threat-intel/coverage — DONNÉES du panneau de couverture threat-intel (viewer+). CHEAP :
/// ne lit QUE la table `ioc` (petite), JAMAIS un scan de `event`. Renvoie l'état du magasin (total,
/// actifs/expirés, ventilation par type et par source). Les HITS dans le temps sont servis par le
/// chemin GXQL (`search ti_match=1 | timechart count`) — l'enrichissement écrit `ti_match` dans fields,
/// donc déjà requêtable/graphable via Explore sans scan dédié ici.
/// LE CORPS DE `/api/threat-intel/coverage`, FONCTION PURE — aucun `AppState`, aucun cache. Extrait
/// pour la même raison que le corps de `/api/soql/schema` l'a été sous `P11.22-e` : sans extraction on
/// prouverait que la coupe est CALCULÉE, jamais qu'elle ATTEINT le client. La seule chose que la route
/// ajoute par-dessus est le relevé du cache de correspondance, qui exige un chemin de base.
pub(crate) fn ti_coverage_json(conn: &Connection, now_ts: i64) -> Value {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap_or(0);
    let active: i64 = conn.query_row("SELECT COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1", params![now_ts], |r| r.get(0)).unwrap_or(0);
    let by_type: Vec<Value> = conn
        .prepare("SELECT type, COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1 GROUP BY type ORDER BY 2 DESC")
        .and_then(|mut s| {
            s.query_map(params![now_ts], |r| Ok(json!({ "type": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? })))
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    // `P11.22-f` — L'INVENTAIRE PAR SOURCE EST BORNÉ, ET IL LE DIT. Le geste est celui de `P11.22-e` :
    // on demande UNE LIGNE DE PLUS que le rang de coupe, on en sert le rang de coupe, et l'EXISTENCE de
    // la ligne excédentaire — jamais servie — fonde l'aveu. Un magasin qui porte PILE le rang de coupe
    // n'est PAS écourté, et le lui faire dire serait un aveu inconditionnel, donc sans valeur.
    let lues: Vec<Value> = conn
        .prepare(&format!(
            "SELECT source, COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1 GROUP BY source ORDER BY 2 DESC LIMIT {}",
            TI_COVERAGE_SOURCES_MAX + 1
        ))
        .and_then(|mut s| {
            s.query_map(params![now_ts], |r| Ok(json!({ "source": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? })))
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let (by_source, by_source_capped) =
        crate::handlers::liste_bornee::couper_a_la_borne(lues, TI_COVERAGE_SOURCES_MAX);
    json!({
        "total": total,
        "active": active,
        "expired": total - active,
        "by_type": by_type,
        "by_source": by_source,
        // `P11.22-f` — CE QUI MANQUAIT, ET POURQUOI C'ÉTAIT LE PLUS GRAVE DES VINGT-ET-UN. `total` et
        // `active` comptent le magasin ENTIER : posés à côté d'une ventilation par source coupée en
        // silence, ils la faisaient lire comme une COUVERTURE. Un exploitant qui n'y voit pas son flux
        // en conclut « ce flux n'alimente pas le magasin » — le défaut même qui vient d'être fermé pour
        // la liste voisine. Le rang de coupe est rendu À CÔTÉ de l'aveu : sans lui, la vue ne peut pas
        // dire de combien, et un aveu sans son ampleur cesse d'être lu.
        "by_source_window": TI_COVERAGE_SOURCES_MAX,
        "by_source_capped": by_source_capped,
        // indice pour l'UI : les hits IOC dans le temps se requêtent en GXQL (aucun scan serveur ici).
        "hits_query": "search ti_match=1 | timechart count",
    })
}

pub(crate) async fn ti_coverage(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    let mut sortie = ti_coverage_json(&conn, now());
    // `P10.7-k` — CE QUE LE MAGASIN CONTIENT N'EST PAS CE AVEC QUOI ON DÉTECTE. `active` compte les
    // lignes de la TABLE ; la correspondance à l'ingest, elle, ne lit QUE le cache mémoire. Les deux
    // divergent dès qu'un rechargement échoue, et c'est précisément l'état où ce panneau annonçait
    // « N indicateurs actifs » pendant que la détection tournait sur un jeu plus ancien — ou, avant ce
    // lot, sur rien du tout. `cache_actifs` est donc publié À CÔTÉ de `active`, sous la convention de
    // `S32` : la valeur n'apparaît QUE si elle a été lue, et le verdict/la cause disent le reste.
    // Aucun rechargement encore (démarrage) -> AUCUNE clé posée : l'absence se lit « pas encore »,
    // jamais « zéro indicateur ».
    if let (Some(m), Some(o)) = (ioc_reload_dernier(&db_path), sortie.as_object_mut()) {
        m.poser_dans(o, "cache_actifs");
    }
    Json(sortie)
}
