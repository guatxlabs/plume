//! Glue GXQL côté daemon (le compilateur lui-même vit dans `guatx_core::soql`). Regroupe : tokenisation
//! de la barre de recherche (`search_tokens`/`field_col`), contrat CIM (`CIM_*` + `cim_category_ok`),
//! cache d'auto-indexation Phase 3 clé par db_path (`AUTOINDEX_*` statics + `autoindex_has/reload/note*`,
//! whitelists `HOT_FIELDS`/`AUTOINDEX_DENY`, attribution du slow), toggles cachés (`FTS_FIELDS_ON`) et le
//! point d'entrée unique d'émission GXQL->SQL `soql_to_sql_x` (traverse le store). Statics OnceLock +
//! accesseurs. MT-KEY: par db_path. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// Tokenise la barre en respectant les guillemets " (regex="motif avec espaces") ; ' et ( restent
// dans le token (échappement SQL fait par chaque handler, ( = groupe regex). Pas de split sur l'espace
// à l'intérieur des guillemets.
pub(crate) fn search_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => { if !cur.is_empty() { out.push(std::mem::take(&mut cur)); } }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}

// Champs filtrables depuis la barre (alias -> colonne réelle). Whitelist = anti-injection de nom de
// colonne ; regex `~` / joker `*` / exact s'appliquent ensuite à N'IMPORTE lequel (host, src_ip,
// message/event, source, category, dst_ip, url, xff, fields).
pub(crate) fn field_col(name: &str) -> Option<&'static str> {
    Some(match name {
        "source" => "source",
        "category" | "cat" => "category",
        "severity" | "sev" => "severity",
        "src_ip" | "ip" => "src_ip",
        "dst_ip" => "dst_ip",
        "host" => "host",
        "message" | "msg" | "event" => "message",
        "url" => "url",
        "xff" => "xff",
        "fields" | "field" => "fields",
        _ => return None,
    })
}
// CONTRAT CIM déplacé dans le cœur partagé (P1-M2) : `CIM_VERSION`/`CIM_CATEGORIES`/`CIM_CORE_FIELDS`/
// `CIM_ACTION_VOCAB` + le validateur pur `cim_category_ok` vivent désormais dans `guatx_core::cim`
// (constantes pures + validateur, ZÉRO rusqlite). On les RÉ-EXPORTE ici (`pub(crate)`) : le glob
// `soql_glue::*` (main.rs) les rend accessibles au daemon comme avant -> aucun call-site changé. Le
// parser du DSL d'ingest (spécifique ingest) RESTE au daemon ; seul le vocabulaire de contrat remonte.
// `CIM_CATEGORIES`/`CIM_ACTION_VOCAB` n'étaient utilisés que par le test (d'où l'`allow(dead_code)`
// d'origine) -> on préserve l'intention via `unused_imports` pour les builds non-test.
#[allow(unused_imports)]
pub(crate) use guatx_core::cim::{
    cim_category_ok, compliance_framework_ok, CIM_ACTION_VOCAB, CIM_CATEGORIES, CIM_CORE_FIELDS,
    CIM_VERSION, COMPLIANCE_FRAMEWORKS,
};

// ── GARDE-FOU CIM à la COMPILATION (ceinture ET bretelles avec le test runtime
// `cim_const_mirror_matches_config_schema`) ──────────────────────────────────────────────
// `build.rs` extrait la `"version"` du contrat CIM EMBARQUÉ dans le dépôt plume
// (`config.d/cim/cim.v1.json`) et l'émet ici en `CIM_CONFIG_VERSION`. On const-assert qu'elle
// égale `guatx_core::cim::CIM_VERSION` du cœur LINKÉ. Si un build lie un cœur STALE/faux (version
// divergente — ce qui a déjà coûté un cycle de diagnostic : scaffold contre un core v1.1 vs le
// v1.2 déployé), la COMPILATION ÉCHOUE ici avec le message ci-dessous — plus jamais un simple
// échec de test. 100 % compile-time : `const _` n'émet aucun code, `const_str_eq` n'est jamais
// appelée au runtime -> binaire byte-identique.
include!(concat!(env!("OUT_DIR"), "/cim_config_version.rs"));

// `==` sur `&str` n'est pas disponible en contexte const -> comparaison octet-à-octet.
const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = {
    assert!(
        const_str_eq(CIM_CONFIG_VERSION, guatx_core::cim::CIM_VERSION),
        "CIM version mismatch: config.d/cim/cim.v1.json vs linked guatx_core::cim::CIM_VERSION \
         — you are building against a STALE/wrong core"
    );
};

// whitelist FERMÉE des champs chauds indexés par index expression (Phase 2 v41 : les 7 premiers ;
// v49 : +verb,resource,operation). Cardinalité bornée (énumérés/identités d'un parc borné), tous TEXTUELS.
//   v49 — FILTRES chauds des sources d'audit (kube-audit/vault-audit), validés EXPLAIN SCAN->SEARCH sur
//   l'instance : `verb` (RBAC : verb=delete/deletecollection), `resource` (qui touche secrets : resource=
//   secrets), `operation` (vault : operation=delete/create). Petits index partiels (kube-audit ~60k,
//   vault-audit ~15k lignes) -> RAM négligeable, servent la RÉPONSE-INCIDENT (rares mais doivent être
//   instantanés, hors heat-driven autoindex que les rollups étouffent). DÉLIBÉRÉMENT EXCLUS : champs
//   NUMÉRIQUES (status/dport/code) — les parsers regex les stockent en TEXT et field_is_indexed drope le
//   CAST AS REAL (soql_filter_field) -> `json_extract(...)=500` comparerait '500' à 500 = FAUX ; et
//   path/exe/key (haute cardinalité / firehose auditd 2,6M -> ~73 Mo/index, budget 2 Go) — leur GROUP-BY
//   est servi par les rollups v49 et l'autoindex peut les indexer à la demande. `dir` exclu : déjà
//   auto-indexé (idx_ev_auto_dir).
pub(crate) const HOT_FIELDS: &[&str] = &[
    "action", "user", "owner", "kind", "ns", "role", "scope",
    "verb", "resource", "operation",
];

// DENYLIST cardinalité (Phase 3) : champs JAMAIS éligibles à l'auto-index (explosion disque).
// `src_ip` est déjà une colonne réelle + index composés (v31) ; les autres sont haute cardinalité.
// PARSER PHASE 2 : les champs EXTRAITS génériques à FORTE cardinalité (un index expression coûte
// ~73 Mo sur 2,6 M lignes -> RAM, budget 2 Go) sont déniés D'OFFICE. `msg`/`message` (texte libre
// du log), `time` (horodatage ~unique), `logSource`, les ids de corrélation distribuée
// (request_id/trace_id/span_id), les mesures de latence (latency/duration) et `thread` ne doivent
// JAMAIS se faire indexer : leur GROUP-BY/agrégation passe par les rollups, leur filtre est rare.
pub(crate) const AUTOINDEX_DENY: &[&str] = &[
    "path", "src_ip", "uid", "pid", "url", "message", "dedup", "remote_address",
    // PHASE 2 — champs extraits haute-cardinalité (cardinalité -> RAM : ~73 Mo/index).
    "msg", "time", "logSource", "request_id", "trace_id", "span_id", "latency", "duration", "thread",
];

/// Cache mémoire des champs réellement indexés par un index AUTO (`idx_ev_auto_<field>`,
/// Phase 3). Rechargé depuis `autoindex` (indexed=1) après bind et à chaque tick de
/// maintenance. Lu par `field_is_indexed` -> garde anti-CAST. Vide tant que Phase 3 OFF.
// MT-KEY: par db_path (R4). Le set des champs indexés est clé par base : la garde anti-CAST d'un tenant ne
// voit que SES propres index auto. En mono-tenant : une seule entrée -> identique.
pub(crate) static AUTOINDEX_SET: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, std::collections::HashSet<String>>>> =
    std::sync::OnceLock::new();
pub(crate) fn autoindex_set() -> &'static parking_lot::RwLock<HashMap<String, std::collections::HashSet<String>>> {
    AUTOINDEX_SET.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
/// Le champ JSON `name` a-t-il un index auto actif sur CE db_path ? (lecture cache, jamais de DB).
pub(crate) fn autoindex_has(db_path: &str, name: &str) -> bool {
    autoindex_set().read().get(db_path).map(|s| s.contains(name)).unwrap_or(false)
}
/// Recharge le set des champs indexed=1 de CE db_path depuis la table `autoindex` (sous lock writer côté appelant).
pub(crate) fn autoindex_reload(conn: &Connection, db_path: &str) {
    let mut set = std::collections::HashSet::new();
    if let Ok(mut st) = conn.prepare("SELECT field FROM autoindex WHERE indexed=1") {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
            for f in rows.flatten() {
                set.insert(f);
            }
        }
    }
    { let mut w = autoindex_set().write();
        w.insert(db_path.to_string(), set); // MT-KEY : set de CE db_path
    }
}

/// Un index expression existe-t-il pour ce champ JSON sur CE db_path (Phase 2 figé OU Phase 3 auto) ?
/// -> on émet alors la forme canonique json_extract(...) SANS CAST pour que le planner le prenne.
pub(crate) fn field_is_indexed(db_path: &str, name: &str) -> bool {
    HOT_FIELDS.contains(&name) || autoindex_has(db_path, name)
}

/// Buffer de CHALEUR (Phase 3) : compte par champ JSON résolu en json_extract (hors colonne réelle,
/// hors champ chaud figé) le nombre de requêtes l'ayant ciblé (hits) et combien furent LENTES (slow).
/// Borné (cap 256 entrées distinctes / cycle de flush). FLUSHÉ vers la table `autoindex` par la
/// tâche de fond `autoindex_maintain_background`. JAMAIS écrit en DB sur le chemin chaud.
// MT-KEY: par db_path (R4). Buffer de chaleur (hits/slow) clé par base : la chaleur d'un tenant ne
// contamine jamais les décisions d'index d'un autre. Cap de 256 champs distincts PAR db_path (buffer
// minuscule : ~256×(clé+2×u32)). En mono-tenant : une seule entrée -> identique.
pub(crate) static AUTOINDEX_BUF: std::sync::OnceLock<Mutex<HashMap<String, HashMap<String, (u32, u32)>>>> =
    std::sync::OnceLock::new();
pub(crate) fn autoindex_buf() -> &'static Mutex<HashMap<String, HashMap<String, (u32, u32)>>> {
    AUTOINDEX_BUF.get_or_init(|| Mutex::new(HashMap::new()))
}

// ===== ATTRIBUTION DU SLOW (Phase SURE) ====================================================
// AVANT : une requête lente bumpait slow_hits pour TOUS les champs json vus ce cycle (filtres ET
// projections/tris) -> bruit, un champ seulement PROJETÉ (jamais filtré) pouvait se faire indexer
// alors qu'un index ne l'aiderait pas (un index expression n'accélère que les WHERE/JOIN/ORDER, pas
// une projection de valeur). MAINTENANT : on ne crédite le slow_hits qu'aux champs en position de
// FILTRE (WHERE), les vrais candidats à indexer. La collecte se fait par requête via un thread-local
// (la compilation soql d'une requête est synchrone sur UN thread) que `soql_filter_field` alimente et
// que `autoindex_mark_slow_if` consomme. `soql_field` (projection/group-by/sort) ne l'alimente PAS.
//
// SÉLECTIVITÉ (heuristique documentée) : si plusieurs filtres dans la même requête, on n'attribue le
// slow qu'au(x) plus SÉLECTIF(s) — un index sert surtout une égalité. Rang décroissant :
//   3 = égalité exacte (=, :, != sans joker)      -> très sélectif, l'index aide le plus
//   2 = préfixe LIKE 'x%' / borne numérique (<,>) -> sargable partiel, l'index aide
//   1 = regex (=~, ~) / LIKE '%x%' (contains)     -> non sargable, l'index n'aide quasi pas
// On ne bumpe que les champs au rang MAX vu dans la requête (égalité l'emporte sur regex). À défaut de
// vraie cardinalité au moment de la compilation, c'est l'approximation raisonnable et stable.
thread_local! {
    static AUTOINDEX_FILTER_FIELDS: std::cell::RefCell<Vec<(String, u8)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// Rang de sélectivité d'un filtre (cf. doc ci-dessus). Plus haut = plus sélectif = meilleur candidat.
pub(crate) const AUTOINDEX_SEL_EQ: u8 = 3; // égalité exacte
pub(crate) const AUTOINDEX_SEL_RANGE: u8 = 2; // préfixe LIKE / borne numérique
pub(crate) const AUTOINDEX_SEL_SCAN: u8 = 1; // regex / contains (non sargable)
/// Note (cheap, thread-local) qu'une requête a FILTRÉ sur le champ JSON `name` avec la sélectivité
/// `sel`. Sert UNIQUEMENT à l'attribution du slow_hits (cf. autoindex_mark_slow_if). No-op si OFF /
/// champ chaud / dénié (mêmes gardes que autoindex_note). N'écrit PAS le buffer de hits.
pub(crate) fn autoindex_note_filter(name: &str, sel: u8) {
    if !autoindex_enabled() || HOT_FIELDS.contains(&name) || AUTOINDEX_DENY.contains(&name) {
        return;
    }
    AUTOINDEX_FILTER_FIELDS.with(|f| {
        let mut v = f.borrow_mut();
        if v.len() < 64 && !v.iter().any(|(n, _)| n == name) {
            v.push((name.to_string(), sel));
        }
    });
}
/// Vide et retourne les champs FILTRÉS collectés pour la requête courante (thread-local). Appelé en
/// FIN de traitement d'une requête (par autoindex_mark_slow_if) -> remet le thread-local à zéro pour
/// la requête suivante sur ce thread, qu'elle ait été lente ou non (pas de fuite inter-requêtes).
pub(crate) fn autoindex_take_filter_fields() -> Vec<(String, u8)> {
    AUTOINDEX_FILTER_FIELDS.with(|f| std::mem::take(&mut *f.borrow_mut()))
}
/// Toggle maître Phase 3 (PLUME_AUTOINDEX) mis en cache au boot — évite un load_config() par requête
/// sur le chemin chaud de compilation. 0 (OFF) par défaut -> autoindex_note() est no-op.
pub(crate) static AUTOINDEX_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn autoindex_enabled() -> bool {
    AUTOINDEX_ON.load(std::sync::atomic::Ordering::Relaxed)
}
/// Toggle maître Phase 1 (PLUME_FTS_FIELDS) mis en cache au boot — le search libre bascule sur
/// event_fields_fts (UNION avec event_fts) au lieu de `message LIKE '%tok%'`. 0 (OFF) par défaut.
pub(crate) static FTS_FIELDS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn fts_fields_enabled() -> bool {
    FTS_FIELDS_ON.load(std::sync::atomic::Ordering::Relaxed)
}
/// Toggle Phase B (PLUME_SOQL_PRUNE_MESSAGE) — opt-in de l'ÉLAGAGE DE PROJECTION `message` du cœur
/// (`Schema::with_message_pruning` / gate `message_prunable`). OFF par défaut -> `with_message_pruning(false)`
/// -> SELECT de base STRICTEMENT INCHANGÉ = `Schema::events()` d'aujourd'hui (mode 0 byte-identique, invariant
/// ABSOLU). ON -> le compilo peut retirer `message` du SELECT QUAND prouvé inutile en aval (sinon conservé,
/// défaut conservateur) : jamais une ligne de résultat en moins, seulement une matérialisation RAM bornée.
/// Lu UNE FOIS (OnceLock) au premier compile via `cfg`/`load_config` (env PLUME_* > conf > défaut) — JAMAIS
/// un `env::var` par requête (chemin chaud). Posé au choke-point store (query `/api/query` + détection).
static SOQL_PRUNE_MESSAGE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
pub(crate) fn soql_prune_message() -> bool {
    *SOQL_PRUNE_MESSAGE.get_or_init(|| {
        let conf = load_config();
        matches!(cfg(&conf, "PLUME_SOQL_PRUNE_MESSAGE", "").trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}
/// Un token est-il SÛR comme requête FTS5 MATCH (un seul terme) ? On rejette les caractères qui sont
/// des opérateurs/syntaxe FTS5 (guillemets, parenthèses, étoile, `:`, `-`, `^`, `%`...) -> dans ce cas
/// on RETOMBE sur le LIKE classique (fallback automatique, jamais d'erreur FTS5 « malformed MATCH »).
pub(crate) fn fts_safe(tok: &str) -> bool {
    !tok.is_empty()
        && tok.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '/' | '@'))
}
/// Note (cheap, mémoire) qu'une requête a ciblé le champ JSON `name` via json_extract.
/// No-op si Phase 3 OFF, si `name` est chaud/dénié, ou si le buffer est plein (cap 256).
pub(crate) fn autoindex_note(db_path: &str, name: &str) {
    if !autoindex_enabled() || HOT_FIELDS.contains(&name) || AUTOINDEX_DENY.contains(&name) {
        return;
    }
    { let mut top = autoindex_buf().lock();
        let buf = top.entry(db_path.to_string()).or_default(); // MT-KEY : buffer de CE db_path
        if let Some(e) = buf.get_mut(name) {
            e.0 = e.0.saturating_add(1);
        } else if buf.len() < 256 {
            buf.insert(name.to_string(), (1, 0));
        }
    }
}
/// Crédite slow_hits aux SEULS champs en position de FILTRE (WHERE) les plus sélectifs de la requête
/// lente (cf. doc ATTRIBUTION DU SLOW). `fields` = (nom, rang_sélectivité) collectés ce cycle. On ne
/// bumpe que le(s) champ(s) au rang MAX (égalité l'emporte sur regex). Cheap, mémoire, no-op si OFF ou
/// si la requête lente ne portait aucun filtre json (ex : free-text seul -> rien à indexer ici).
pub(crate) fn autoindex_note_slow(db_path: &str, fields: &[(String, u8)]) {
    if !autoindex_enabled() || fields.is_empty() {
        return;
    }
    let best = fields.iter().map(|(_, s)| *s).max().unwrap_or(0);
    { let mut top = autoindex_buf().lock();
        if let Some(buf) = top.get_mut(db_path) { // MT-KEY : buffer de CE db_path (absent -> rien à créditer)
            for (name, _) in fields.iter().filter(|(_, s)| *s == best) {
                // n'incrémente le slow QUE pour un champ déjà connu en hits ce cycle (il a bien été vu par
                // autoindex_note via soql_filter_field). Si absent (buffer plein, cap 256), on l'ignore.
                if let Some(e) = buf.get_mut(name) {
                    e.1 = e.1.saturating_add(1);
                }
            }
        }
    }
}
/// Seuil (ms) au-delà duquel une requête soql est comptée LENTE (PLUME_AUTOINDEX_SLOW_MS, def 800).
/// Mis en cache au boot (pas de load_config par requête). 0 tant que non initialisé -> no-op effectif.
pub(crate) static AUTOINDEX_SLOW_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(800);
/// Si la requête soql qui vient de tourner fut LENTE (elapsed_ms du résultat run_query, ou le watchdog
/// l'a interrompue), bump slow_hits des champs json touchés ce cycle. Appelé sur le chemin de LECTURE
/// soql uniquement (pas à l'ingest). `interrupted` = le watchdog s'est déclenché (-> compté lent).
pub(crate) fn autoindex_mark_slow_if(db_path: &str, result: &Result<Value, String>) {
    if !autoindex_enabled() {
        return;
    }
    // On DRAINE toujours les champs filtrés de la requête courante (même si elle ne fut pas lente) ->
    // pas de fuite vers la requête suivante sur ce même thread (réutilisé par le pool/runtime).
    let filters = autoindex_take_filter_fields();
    let thresh = AUTOINDEX_SLOW_MS.load(std::sync::atomic::Ordering::Relaxed) as f64;
    let slow = match result {
        // watchdog/erreur d'exécution -> on considère lent (la requête a dépassé le budget).
        Err(_) => true,
        Ok(v) => v
            .get("stats")
            .and_then(|s| s.get("elapsed_ms"))
            .and_then(|m| m.as_f64())
            .map(|ms| ms >= thresh)
            .unwrap_or(false),
    };
    if slow {
        autoindex_note_slow(db_path, &filters);
    }
}

// Colonnes RÉELLES de la table event (le reste vit dans le JSON `fields`).
pub(crate) const EVENT_COLS: &[&str] = &["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", "dedup", "id"];

// Découpe sur les pipes de PREMIER niveau (ignore les `|` à l'intérieur des crochets [ ... ]).
// soql_split_pipes : SUPPRIMÉ (P1-H3) — copie locale byte-identique de
// guatx_core::soql::soql_split_pipes. Sites d'appel fully-qualifiés.

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  ALIAS DE LECTURE CIM — `exec` ⊃ `process`.  DETTE DE MIGRATION, PÉREMPTION 2027-07-23.
// ───────────────────────────────────────────────────────────────────────────────────────────────
//  LE DÉFAUT. Les deux collecteurs Windows (`collectors/windows/plume-collector.ps1`,
//  `agent/src/source/windows.rs`) ont déclaré `category='process'` pour la création de processus
//  (EventID 4688) jusqu'au 2026-07-23. `process` n'appartient PAS à `CIM_CATEGORIES` ; le nom
//  canonique de la création de processus en CIM v1.3 est `exec`. Les collecteurs émettent `exec`
//  désormais.
//
//  POURQUOI UN ALIAS ET PAS UNE MIGRATION. La rétention est de 365 jours et le tier froid est
//  SCELLÉ (Parquet chiffré + identité de seal, jamais réécrit) : l'historique portant `process` est
//  IMMUABLE par construction. Renommer la catégorie côté collecteurs sans rien d'autre rendrait
//  toute règle `category=exec` AVEUGLE sur cet historique. La réconciliation se fait donc à la
//  LECTURE, sans toucher une seule ligne stockée.
//
//  PÉREMPTION — 2027-07-23. Dernier événement `process` émis : 2026-07-23 (bascule des collecteurs).
//  Rétention 365 jours -> le dernier Parquet le portant sort de rétention le 2027-07-23. Après cette
//  date (une fois la purge passée), ce bloc ENTIER se supprime, avec ses SEULS dépendants (mesurés) :
//  `ingest/store.rs` ×3, `handlers/search.rs` ×1, la garde `carries_cim_read_alias` de
//  `cold_store/planner.rs` (et ses 2 sites), les tests `cim_read_alias_exec_finds_sealed_process_history`
//  et `cim_aliased_query_is_never_vectorized`, et la section 5.2 de `docs/CIM.md`.
//
//  CE QUE CE N'EST PAS. Pas un moteur de réécriture de requêtes : aucune table d'alias, aucune
//  config, aucun ENV. UNE équivalence, écrite en dur ci-dessous, inatteignable pour toute autre
//  valeur. La reconnaissance est DÉRIVÉE de la grammaire du cœur (mêmes opérateurs, même ordre,
//  même règle de quotation, mêmes étages que `table_conds`/`compile_where`), pas énumérée.
//
//  CONSÉQUENCES MESURÉES (lecture du cœur v0.2.1, pas une supposition) :
//   • `x in (a,b)` positif textuel est émis `COLLATE NOCASE` (`soql_in_cond`) -> une requête
//     `category=exec` devient insensible à la casse SUR CETTE COLONNE. SUR-match, jamais un
//     sous-match : aucun événement ne peut disparaître d'un résultat à cause de l'alias.
//   • `idx_event_category` (collation BINARY, `maintenance.rs`) n'est pas utilisable par un
//     `IN … COLLATE NOCASE` -> le filtre category cesse d'être servi par cet index ; la fenêtre `ts`
//     porte alors le balayage. Coût NON MESURÉ en charge réelle (pas d'accès prod ici).
//   • `extract_cold_dim_preds` (cold_store/seal.rs) REFUSE explicitement la forme ` IN ` -> aucun
//     élagage bloom/min-max sur category pour une requête aliasée -> tous les fichiers froids de la
//     fenêtre sont lus. CONSERVATEUR : jamais un fichier sauté à tort.
//
//  LIMITES CONNUES (non couvertes, délibérément — surface tenue au minimum) :
//   • une macro (`` `nom(args)` ``) dont le CORPS écrit `category=exec` : le cœur détend les macros
//     APRÈS ce pré-pass ; l'auteur de la macro écrit l'alias lui-même s'il en a besoin ;
//   • un `eventtype` (knowledge object) dont le filtre stocké écrit `category=exec` : détendu dans
//     le cœur, hors de portée d'ici ;
//   • `category!=exec` / `category=exec*` / `category=~exec` : formes NON aliasées (une négation
//     aliasée changerait le sens du prédicat ; un glob/regex est déjà l'outil de l'analyste).
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Nom CANONIQUE (CIM v1.3, `CIM_CATEGORIES`) de la création de processus.
pub(crate) const CIM_EXEC_CANON: &str = "exec";
/// Nom LEGACY hors taxonomie écrit par les collecteurs Windows jusqu'au 2026-07-23.
pub(crate) const CIM_EXEC_LEGACY: &str = "process";

/// L'UNIQUE équivalence, sous la forme que le cœur sait compiler dans un filtre de base ET dans un
/// `where` (clause `in (…)` entière — vérifié dans `table_conds` et `in_clause_whole`).
fn cim_exec_alias_clause() -> String {
    format!("category in ({CIM_EXEC_CANON},{CIM_EXEC_LEGACY})")
}

/// ALIAS DE LECTURE : rend le GXQL dans lequel toute ÉGALITÉ de filtre `category=exec` retrouve AUSSI
/// l'historique `category=process`. `Cow::Borrowed` (aucune allocation, aucune sémantique changée) dès
/// que la requête ne porte pas cette égalité — c'est le cas de la quasi-totalité du trafic.
pub(crate) fn cim_read_alias_exec(soql: &str) -> std::borrow::Cow<'_, str> {
    // Garde de coût : sans la sous-chaîne `exec` nulle part, il n'y a rien à faire (memchr).
    if !soql.contains(CIM_EXEC_CANON) {
        return std::borrow::Cow::Borrowed(soql);
    }
    match alias_pipeline(soql, 0) {
        Some(s) => std::borrow::Cow::Owned(s),
        None => std::borrow::Cow::Borrowed(soql),
    }
}

/// Parcourt le pipeline EXACTEMENT là où le cœur lit un filtre `champ=valeur` : le filtre de la BASE
/// `search` (étage 0, `table_conds`), l'étage `where` (`compile_where`, condition UNIQUE — d'où la
/// clause `in (…)` entière) et, récursivement, la sous-recherche entre crochets (recompilée au depth+1
/// par le cœur). Tout autre étage (`stats`/`eval`/`rename`/`fields`/`timechart`/…) est rendu VERBATIM :
/// `| eval category="exec"` n'est PAS un filtre et ne doit pas être touché. `None` = rien à réécrire.
/// Borne de récursion IDENTIQUE à `compile_depth` (> 3 = refusé par le cœur de toute façon).
fn alias_pipeline(text: &str, depth: u32) -> Option<String> {
    if depth > 3 {
        return None;
    }
    let stages = guatx_core::soql::soql_split_pipes(text);
    if stages.is_empty() {
        return None;
    }
    let mut changed = false;
    let mut out: Vec<String> = Vec::with_capacity(stages.len());
    for (i, stage) in stages.iter().enumerate() {
        let t = stage.trim();
        let rewritten = if i == 0 {
            // BASE. `table_base` (cœur) accepte DEUX écritures du MÊME filtre : `search <filtres>` et —
            // quand l'étage ne nomme AUCUNE base connue — le spec ENTIER pris comme filtres (`category=exec
            // | stats count` est une requête valide). On couvre les deux, sinon la seconde écriture rendrait
            // une réponse PARTIELLE en silence. `metric …` est la seule autre base du schéma `events()`
            // (`alts` est vide) : elle n'a pas de filtre `table_conds` -> laissée VERBATIM.
            match t.strip_prefix("search ") {
                Some(body) => alias_filter_body(body).map(|b| format!("search {b}")),
                None if t == "search" || t == "metric" || t.starts_with("metric ") => None,
                None => alias_filter_body(t),
            }
        } else if let Some(expr) = t.strip_prefix("where ") {
            alias_filter_body(expr).map(|e| format!("where {e}"))
        } else if let (Some(a), Some(b)) = (t.find('['), t.rfind(']')) {
            // SOUS-RECHERCHE (`append [search …]` / `join … [search …]`) : le cœur la recompile telle
            // quelle au depth+1 -> son filtre de base doit être aliasé de la MÊME façon.
            (b > a + 1)
                .then(|| alias_pipeline(&t[a + 1..b], depth + 1))
                .flatten()
                .map(|inner| format!("{}[{}]{}", &t[..a], inner, &t[b + 1..]))
        } else {
            None
        };
        match rewritten {
            Some(r) => {
                changed = true;
                out.push(r);
            }
            None => out.push(t.to_string()),
        }
    }
    // Rejoint sur ` | ` : `soql_split_pipes` trime et jette les étages vides, et le cœur RE-DÉCOUPE
    // avec la MÊME fonction -> il reverra EXACTEMENT ces étages-là (aucune dérive de découpage).
    changed.then(|| out.join(" | "))
}

/// Réécrit les JETONS d'un corps de filtre. Frontière de jeton = celle du cœur (blanc hors
/// guillemets, `soql_tokenize_marked`) ; les blancs d'origine sont recopiés à l'identique.
fn alias_filter_body(body: &str) -> Option<String> {
    let mut out = String::with_capacity(body.len() + 24);
    let mut changed = false;
    let mut in_q = false;
    let mut start: Option<usize> = None;
    for (i, c) in body.char_indices() {
        if c == '"' {
            in_q = !in_q;
        }
        if c.is_whitespace() && !in_q {
            if let Some(s) = start.take() {
                changed |= push_span(&mut out, &body[s..i]);
            }
            out.push(c);
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        changed |= push_span(&mut out, &body[s..]);
    }
    changed.then_some(out)
}

/// Pousse un jeton, ALIASÉ s'il est l'égalité `category=exec`. Rend `true` s'il a été aliasé.
fn push_span(out: &mut String, span: &str) -> bool {
    if span_is_category_exec_equality(span) {
        out.push_str(&cim_exec_alias_clause());
        true
    } else {
        out.push_str(span);
        false
    }
}

/// Ce jeton est-il l'ÉGALITÉ `category=exec` ? Reconnaissance DÉRIVÉE de la grammaire du cœur :
///  • MÊME LISTE, MÊME ORDRE d'opérateurs que `table_conds` -> `!=`/`=~`/`>=`/`<=` sont vus AVANT `=`,
///    donc `category!=exec` et `category=~exec` sont rejetés au lieu d'être pris pour des égalités ;
///  • partie GAUCHE quotée = PHRASE plein-texte (règle `SoqlTok::quoted_prefix`), jamais un champ ;
///  • le nom du champ doit être la COLONNE RÉELLE `category` — `cat` est un alias de la barre
///    `/api/search` (`field_col`), que le compilateur GXQL ne résout PAS vers la colonne ;
///  • la valeur doit être EXACTEMENT `exec` (guillemets retirés comme le fait le tokeniseur) — ce qui
///    exclut MÉCANIQUEMENT `~exec` (regex), `exec*` (joker) et `execve` sans les énumérer.
fn span_is_category_exec_equality(span: &str) -> bool {
    for op in ["=~", ">=", "<=", "!=", "=", ":", ">", "<"] {
        let Some(pos) = span.find(op) else { continue };
        if op != "=" && op != ":" {
            return false;
        }
        let lhs = &span[..pos];
        if lhs.contains('"') || lhs != "category" {
            return false;
        }
        let rhs = &span[pos + op.len()..];
        return rhs.chars().filter(|c| *c != '"').eq(CIM_EXEC_CANON.chars());
    }
    false
}

/// POINT D'ENTRÉE UNIQUE de génération du SQL de base depuis une requête soql, partagé par les 3
/// sites (query / compile_panel_sql / rule_sql). Le compilo soql vit DÉSORMAIS ENTIÈREMENT dans
/// `guatx_core::soql` (cœur partagé Plume/Forge) : l'ancien compilo legacy de main.rs et le toggle
/// PLUME_SOQL_CORE ont été supprimés — `guatx_core::soql::to_sql(.., &Schema::events())` est l'UNIQUE
/// chemin de compilation.
/// NE touche PAS au rollup-route / budget / pagination / SWR / apply_rollup_stats (chemins intacts).
/// `env` (#2d) : `Some("<env>")` -> le schéma injecte `env_id='<env>'` au WHERE de la base `event`
/// (FILTRE par environnement). `None` (mode 0 / en-tête absent / `__all__`) -> SQL byte-identique au
/// legacy (invariant absolu). La détection (rule_sql) passe TOUJOURS None : les règles sont tenant-wide (D7).
pub(crate) fn soql_to_sql_x(soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, String> {
    // COUTURE STORE : l'émission GXQL->SQL traverse désormais l'UNIQUE point qu'est le store (qui compile
    // via `guatx_core::soql` = Dialect). Corps byte-identique à l'ancien inline. Tous les sites de lecture
    // GXQL (query/panels/export/règles) passent par `soql_to_sql_x` -> donc par le store.
    store().soql_to_sql(soql, from, to, env)
}

/// FIELD FILTERS (#45) — variante de `soql_to_sql_x` avec masques de champ EFFECTIFS. Utilisée par les
/// chemins de lecture RÔLE-SCOPÉS (query/export/panels) : le daemon résout `effective_masks(db_path, role,
/// tenant, env)` PUIS compile ici. `masks` VIDE -> STRICTEMENT identique à `soql_to_sql_x` (mode 0). La
/// détection/les rollups (tenant-wide, sans appelant) continuent d'appeler `soql_to_sql_x` (jamais masqué).
pub(crate) fn soql_to_sql_masked_x(soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
    store().soql_to_sql_masked(soql, from, to, env, masks)
}

/// KEYSET (#28) — variante keyset de `soql_to_sql_masked_x` : compile avec la clé de tri stable `id` AJOUTÉE
/// en fin de projection (`with_cursor_id(true)`). Utilisée UNIQUEMENT par la branche BROWSE de `query.rs`
/// (pagination par CURSEUR `(ts,id)` : parcours INTÉGRAL du match-set sans plafond, remplace le cap 10 000 qui
/// cachait des événements). Tous les autres sites de lecture (query non-keyset/panneaux/export/détection)
/// restent sur `soql_to_sql(_masked)_x` (cursor_id=false) -> SQL byte-identique (mode 0). Traverse le store
/// (choke-point unique de compilation GXQL->SQL). `masks` VIDE -> keyset mode 0 (mêmes colonnes + `id`).
pub(crate) fn soql_to_sql_masked_keyset_x(soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
    store().soql_to_sql_masked_keyset(soql, from, to, env, masks)
}
