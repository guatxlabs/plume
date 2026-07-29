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
// CACHE DE MATCH EN MÉMOIRE (keyé par db_path — MT-KEY, comme AUTOINDEX_SET). value NORMALISÉE ->
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

/// Recharge le set d'IOC ACTIFS (non expirés) de CE db_path depuis la table `ioc` (sous le lock writer
/// côté appelant, ex. rollup loop). Les IOC expirés (expires<=now) sont EXCLUS -> expiry/rétention
/// servie à la lecture (aucune purge de ligne requise). Table absente (pré-v79) -> set vide (no-op).
pub(crate) fn ioc_cache_reload(conn: &Connection, db_path: &str) {
    let now_ts = now();
    let mut map: HashMap<String, IocMeta> = HashMap::new();
    if let Ok(mut st) = conn.prepare(
        "SELECT type,value,source,confidence,severity FROM ioc WHERE expires IS NULL OR expires > ?1",
    ) {
        if let Ok(rows) = st.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        }) {
            for (kind, value, source, confidence, severity) in rows.flatten() {
                // La `value` est déjà normalisée à l'insertion ; on la garde telle quelle comme CLÉ.
                map.insert(value, IocMeta { kind, source, confidence, severity });
            }
        }
    }
    // (#30) Reconstruit l'index d'appartenance depuis LE MÊME jeu d'IOC (paires (kind, value)). Sélection
    // bloom/HashSet selon volume+env. Fait AVANT la publication du set : les deux structures sont écrites
    // sous des locks distincts non imbriqués (ordre reload : set puis index ; lecture ti_lookup : set puis
    // index) -> aucun interblocage possible.
    let pairs: Vec<(String, String)> = map.iter().map(|(v, m)| (m.kind.clone(), v.clone())).collect();
    let idx = build_ioc_index(&pairs);
    { let mut w = ioc_set().write();
        w.insert(db_path.to_string(), map); // MT-KEY : set de CE db_path (remplacement atomique)
    }
    { let mut wi = ioc_index().write();
        wi.insert(db_path.to_string(), idx); // MT-KEY : index de CE db_path (remplacement atomique)
    }
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

/// GET /api/threat-intel/iocs — liste (cappée) des IOC du tenant courant. viewer+ (donnée de
/// renseignement, pas un secret). Retourne aussi le statut expiré (calculé au read).
pub(crate) async fn iocs_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let now_ts = now();
    let list: Vec<Value> = match conn.prepare(
        "SELECT id,type,value,source,confidence,severity,first_seen,last_seen,expires,stix_id,env_id \
         FROM ioc ORDER BY last_seen DESC, id DESC LIMIT 2000",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
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
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Json(Value::Array(list)).into_response()
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
pub(crate) async fn ti_coverage(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let now_ts = now();
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap_or(0);
    let active: i64 = conn.query_row("SELECT COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1", params![now_ts], |r| r.get(0)).unwrap_or(0);
    let by_type: Vec<Value> = conn
        .prepare("SELECT type, COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1 GROUP BY type ORDER BY 2 DESC")
        .and_then(|mut s| {
            s.query_map(params![now_ts], |r| Ok(json!({ "type": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? })))
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let by_source: Vec<Value> = conn
        .prepare("SELECT source, COUNT(*) FROM ioc WHERE expires IS NULL OR expires > ?1 GROUP BY source ORDER BY 2 DESC LIMIT 50")
        .and_then(|mut s| {
            s.query_map(params![now_ts], |r| Ok(json!({ "source": r.get::<_, String>(0)?, "n": r.get::<_, i64>(1)? })))
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    Json(json!({
        "total": total,
        "active": active,
        "expired": total - active,
        "by_type": by_type,
        "by_source": by_source,
        // indice pour l'UI : les hits IOC dans le temps se requêtent en GXQL (aucun scan serveur ici).
        "hits_query": "search ti_match=1 | timechart count",
    }))
}
