//! cold_store::planner — #18 P4a : PLANNER / ROUTEUR du moteur colonnaire (premier CÂBLAGE RUNTIME).
//!
//! RÔLE : décider si une requête est **pur-froid ET vectorisable** ; si oui, l'exécuter via les KERNELS
//! vectorisés (`vectorized.rs`) — sinon rendre `None` pour que l'appelant retombe VERBATIM sur le chemin de
//! production actuel (`cold_union_query`, hydrate-SQLite). Le routeur ne DUPLIQUE JAMAIS le fallback : il route
//! AUTOUR (l'appelant garde son `cold_union_query` inchangé).
//!
//! INVARIANT — RÉÉNONCÉ APRÈS MESURE. Il disait : « pour TOUTE requête, `résultat_routé == résultat_actuel` ;
//! le câblage ne change QUE la vitesse ». Cet énoncé traitait `cold_union_query` comme une référence de VÉRITÉ.
//! Il ne l'est pas : au-delà de `cold_hydrate_row_cap`, il hydrate un ÉCHANTILLON puis agrège dessus — mesuré
//! au banc, `search source=auditd severity>=2 | stats count` rend 289 là où la vérité est 58 747 (×203). Une
//! parité avec un nombre faux n'est pas une vertu, c'est la propagation du défaut. L'invariant devient :
//!
//!     résultat_routé == `cold_union_query` QUAND celui-ci est EXACT ; résultat_routé == EXACT sinon.
//!
//! Concrètement : sous le plafond, l'oracle reste l'oracle et la parité est prouvée comme avant (`p4a_*`/`p4b_*`) ;
//! au-dessus, l'AGRÉGAT est calculé par les kernels sur TOUT le froid, et c'est LUI qui a raison. Ce que le
//! routeur ne sait pas calculer exactement n'est pas approximé : il retombe sur le chemin d'union, qui REFUSE
//! de sérialiser une valeur dérivée d'un ensemble tronqué (`cold_store::exactness`). Le masquage #45 reste
//! identique sur les deux chemins. La parité CHAUD/FROID elle-même — la même requête avec et sans tier froid —
//! est désormais un TEST (`parity_hot_vs_cold_over_the_row_cap`), pas seulement une observation de banc.
//!
//! CONDITION DE ROUTAGE (CONSERVATRICE — dans le doute, FALLBACK) : route SSI les CINQ tiennent :
//!   1. cold tier ON (runtime `PLUME_COLD_TIER`, garanti par l'appelant qui a déjà calculé `boundary`).
//!   2. FENÊTRE PUR-FROID : `0 < q_to < boundary` (borne HAUTE STRICTEMENT sous la frontière jour hot/froid).
//!      `q_to == boundary` (touche le hot) OU `q_to <= 0` (non borné -> atteint « maintenant » = hot) -> FALLBACK
//!      (sinon on raterait des lignes hot ; le merge hot∪cold vectorisé est P4b, hors scope). La frontière est
//!      RÉUTILISÉE telle quelle (`cold_query_boundary`), jamais réinventée.
//!   3. MASQUES VIDES : aucun masque de champ (Mask/Hash/Redact/Deny) actif pour l'appelant. En production
//!      `effective_masks` replie DENY dans le `FieldMaskSet` -> `masks.is_empty()` <=> aucune colonne déniée ->
//!      la garde MASQUES-VIDES suffit à écarter tout ce que le kernel ne saurait reproduire (HASH/MASK) ET tout
//!      cas de colonne déniée. (Le kernel IMPLÉMENTE néanmoins le masquage #45 via `denied()` — exercé
//!      directement par le harnais — pour la défense en profondeur et P4b.)
//!   4. FORME VECTORISABLE : le GXQL mappe sur une des formes supportées (count / group-by count / top-N /
//!      matérialisation `| table`) SUR COLONNES PHYSIQUES, prédicat WHERE `=`/`:`/`!=`/`=~`/glob-LIKE/`in`(non,
//!      cf. plus bas)/comparaison INT sur ts|severity. Toute forme non couverte (json_extract, jointure, bare
//!      free-text, dim/proj non-physique, agrégat autre que count, `in(...)`, `where`, `eval`, …) -> FALLBACK.
//!   5. PAS DE TRONCATURE — **pour la MATÉRIALISATION SEULEMENT**. `cold_union_query` hydrate le froid dans
//!      SQLite BORNÉ à `cold_hydrate_row_cap` (défaut 5000) ; au-delà il TRONQUE. Pour une matérialisation, les
//!      deux chemins rendent alors un PRÉFIXE de lignes VRAIES — mais pas le même : le routeur décline donc
//!      (iso-oracle, aucun des deux n'étant faux). Pour un AGRÉGAT, décliner reviendrait à servir un nombre
//!      calculé sur 5 000 lignes : la gate SAUTE, les kernels balaient tout le froid, et la RAM est bornée non
//!      plus par le nombre de LIGNES mais par le nombre de GROUPES (`cold_group_max`, refus explicite au-delà).
//!      C'est LA correction ; le reste du fichier en découle.
//!
//! SÉLECTION DE FICHIERS : RÉUTILISE EXACTEMENT la sélection de `hydrate_cold`/`open_cold_union` (jours spannés ×
//! `file_seals` dont `[ts_min,ts_max]` chevauche la fenêtre, ordre canonique (day, seq)) + le MÊME
//! `verify_parquet_rows` fail-closed + le MÊME ÉLAGAGE DIMENSIONNEL SEAL (#28 P3.5, `DimStats::excluded_by`, les
//! mêmes `dim_preds` que le chemin oracle) : un fichier dont le seal PROUVE 0 match (min/max hors bornes OU bloom
//! certain-absent) est SAUTÉ sans le déchiffrer -> c'est LE levier ×10-100 des requêtes sélectives longue-portée.
//! COHÉRENCE DU GATE CAP (matérialisation) : le chemin oracle (`cold_union_query`) reçoit les MÊMES `dim_preds` et
//! élague les MÊMES fichiers -> `window_rows` (calculé ici sur les fichiers NON élagués) == lignes que l'oracle
//! hydraterait -> décision de troncature IDENTIQUE sur cette forme-là. `dim_preds=&[]`
//! (ou dims non sealées / colonne déniée) -> pas d'élagage -> sélection ts-only, conservatrice, inchangée.

use super::*;
use super::reader::{cold_hydrate_row_cap, cold_read_parallelism, cold_union_query, distinct_seal_envs, PARQUET_COLS};
use super::vectorized::{
    can_vectorize, vec_count, vec_group_count, vec_materialize, vec_materialize_keyset, GroupKey, IntOp, MatRow, Pred,
};
use parquet::file::reader::FileReader;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// RÉPLIQUE VERBATIM de `guatx_core::soql::soql_num` (privé dans le cœur) : « entier/décimal signé » — c'est
/// le MÊME test que le compilateur applique pour décider d'une comparaison NUMÉRIQUE (parité de mapping). Sync
/// obligatoire si le cœur change sa règle (source unique côté cœur ; ici copie testée).
fn soql_num(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    let mut parts = s.split('.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next();
    parts.next().is_none()
        && !int.is_empty()
        && int.bytes().all(|b| b.is_ascii_digit())
        && frac.map_or(true, |f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

// ====================================================================================================
// COMPTEURS DE ROUTE (observabilité + preuve de test). `vectorized` = requêtes servies par les kernels ;
// `fallback` = requêtes renvoyées au chemin actuel. Le harnais RESET puis lit ces compteurs pour prouver
// QUELLE route a servi chaque requête (bords de fenêtre, formes non supportées, masques, …).
// ====================================================================================================
static ROUTE_VEC: AtomicU64 = AtomicU64::new(0);
static ROUTE_FALLBACK: AtomicU64 = AtomicU64::new(0);
// #28 P3.5 — ÉLAGAGE SEAL du chemin vectorisé : fichiers SAUTÉS (seal prouve 0 match, jamais déchiffrés) vs
// fichiers SÉLECTIONNÉS (scannés/déchiffrés). Le harnais RESET puis lit ces compteurs pour PROUVER l'élagage
// (files_pruned == N-1 sur `source=rare`) SANS toucher au chemin oracle. `scanned` = fichiers effectivement remis
// aux kernels (== nombre de `open_verified` sur le chemin heureux). Cumulés (comme les compteurs de route).
static PRUNE_PRUNED: AtomicU64 = AtomicU64::new(0);
static PRUNE_SCANNED: AtomicU64 = AtomicU64::new(0);

/// (vectorized, fallback) — compteurs cumulés de décisions de route.
#[allow(dead_code)] // consommé par le harnais de parité (cfg(test)) + l'observabilité future.
pub(crate) fn route_counters() -> (u64, u64) {
    (ROUTE_VEC.load(Ordering::Relaxed), ROUTE_FALLBACK.load(Ordering::Relaxed))
}

/// (files_pruned, files_scanned) — #28 P3.5 : compteurs cumulés d'élagage seal du chemin vectorisé.
#[allow(dead_code)] // consommé par le harnais de preuve d'élagage (cfg(test)) + l'observabilité future.
pub(crate) fn prune_counters() -> (u64, u64) {
    (PRUNE_PRUNED.load(Ordering::Relaxed), PRUNE_SCANNED.load(Ordering::Relaxed))
}

/// RESET des compteurs (tests). Non utilisé en production (le handler ne remet jamais à zéro).
#[allow(dead_code)]
pub(crate) fn route_counters_reset() {
    ROUTE_VEC.store(0, Ordering::Relaxed);
    ROUTE_FALLBACK.store(0, Ordering::Relaxed);
    PRUNE_PRUNED.store(0, Ordering::Relaxed);
    PRUNE_SCANNED.store(0, Ordering::Relaxed);
}

fn note_vec() {
    ROUTE_VEC.fetch_add(1, Ordering::Relaxed);
}
fn note_fallback() {
    ROUTE_FALLBACK.fetch_add(1, Ordering::Relaxed);
}
fn note_prune(pruned: usize, scanned: usize) {
    PRUNE_PRUNED.fetch_add(pruned as u64, Ordering::Relaxed);
    PRUNE_SCANNED.fetch_add(scanned as u64, Ordering::Relaxed);
}

/// GATE 0 — le routeur vectorisé est-il ARMÉ ? **DÉFAUT : OUI** dès que le tier froid est actif.
/// `PLUME_COLD_VECTORIZED=0` le désarme explicitement.
///
/// CE N'EST PLUS UN INTERRUPTEUR DE PERFORMANCE, et son défaut a donc changé. Il avait été posé en
/// kill-switch de déploiement DARK, sous l'hypothèse que les deux chemins étaient ÉQUIVALENTS et que
/// seul l'un allait plus vite. La mesure a réfuté l'hypothèse : le chemin d'union hydrate au plus
/// `cold_hydrate_row_cap` lignes puis AGRÈGE SUR CET ÉCHANTILLON (`stats count` mesuré à 289 au lieu
/// de 58 747, ×203), là où les kernels balaient tout le froid et rendent la valeur EXACTE. Un
/// interrupteur qui choisit entre « exact » et « faux » ne peut pas avoir « faux » pour défaut — et
/// laisser le défaut à OFF aurait rendu la correction invisible en production, ce qui est exactement
/// comment le défaut a survécu jusqu'ici.
///
/// `=0` reste honoré et reste SÛR : il ne rétablit pas le nombre faux (l'invariant de `exactness` le
/// refuse au moment de rendre), il rétablit le REFUS. Le rollback instantané qu'il offrait porte donc
/// désormais sur la vitesse et le risque de chemin, jamais sur la correction.
pub(crate) fn cold_vectorized_armed(conf: &HashMap<String, String>) -> bool {
    crate::cfg(conf, "PLUME_COLD_VECTORIZED", "1") != "0"
}

/// PLAFOND DE GROUPES d'un agrégat `count by …` calculé côté froid (knob `PLUME_COLD_GROUP_MAX`,
/// clampé [1, 5 000 000]). C'est une BORNE RAM, pas une borne de résultat.
///
/// POURQUOI IL EXISTE MAINTENANT : tant que le routeur déclinait toute fenêtre de plus de
/// `cold_hydrate_row_cap` lignes (l'ancienne GATE 5), le nombre de groupes était borné PAR ACCIDENT
/// (au plus 5 000 lignes -> au plus 5 000 groupes). En levant cette gate pour les agrégats — la
/// correction elle-même — on expose un `| stats count by src_ip` d'un an de froid : des millions de
/// clés en RAM, sous un budget de 2 Gio. La borne accidentelle doit donc devenir EXPLICITE.
///
/// Au-delà, on REFUSE (Err nommée) : on ne rend jamais une map partielle, qui serait précisément le
/// défaut qu'on ferme. 500 000 groupes ≈ quelques dizaines de Mio (clés courtes + un i64), très loin
/// du budget, et très au-delà de tout group-by qu'un humain lit.
fn cold_group_max(conf: &HashMap<String, String>) -> usize {
    crate::cfg(conf, "PLUME_COLD_GROUP_MAX", "")
        .parse::<usize>()
        .ok()
        .filter(|&n| n > 0 && n <= 5_000_000)
        .unwrap_or(500_000)
}

/// REFUS nommé quand le plafond de groupes est atteint. Nomme la cause, le plafond, sa variable, et
/// les voies exactes — un refus qui ne dit pas quoi faire est un mur.
fn refuse_group_explosion(n: usize, max: usize) -> String {
    format!(
        "refus de rendre un agrégat INCOMPLET : ce group-by dépasse {max} groupes distincts sur \
         l'historique froid ({n} atteints, plafond RAM PLUME_COLD_GROUP_MAX={max}) — poursuivre \
         obligerait soit à dépasser le budget mémoire, soit à rendre une liste partielle de groupes \
         présentée comme complète. Voies EXACTES : restreindre la fenêtre, filtrer avant de grouper, \
         ou grouper sur une dimension de moindre cardinalité."
    )
}

// #18 P6 — JAUGE DE CONCURRENCE (test-only) : compte les fichiers cold en cours de décode/déchiffrement EN
// PARALLÈLE. `MAX` = pic observé = BORNE RAM effective (chaque décode simultané = 1 buffer déchiffré + 1
// ColumnBatch). Le test PROUVE `MAX <= degree` (jamais > `cold_read_parallelism`), INDÉPENDAMMENT du nombre de
// fichiers -> RAM bornée par le pool, pas par le volume. Compilée UNIQUEMENT en test (aucun effet prod).
#[cfg(test)]
static DECODE_INFLIGHT: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static DECODE_INFLIGHT_MAX: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn gauge_enter() {
    let cur = DECODE_INFLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
    DECODE_INFLIGHT_MAX.fetch_max(cur, Ordering::SeqCst);
}
#[cfg(test)]
fn gauge_exit() {
    DECODE_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
}
/// (in-flight courant, pic) — le test lit le PIC pour prouver la borne de concurrence == borne RAM.
#[cfg(test)]
pub(crate) fn decode_gauge() -> (u64, u64) {
    (DECODE_INFLIGHT.load(Ordering::SeqCst), DECODE_INFLIGHT_MAX.load(Ordering::SeqCst))
}
#[cfg(test)]
pub(crate) fn decode_gauge_reset() {
    DECODE_INFLIGHT.store(0, Ordering::SeqCst);
    DECODE_INFLIGHT_MAX.store(0, Ordering::SeqCst);
}

// ====================================================================================================
// PLAN — la forme vectorisable extraite du GXQL (WHERE -> Pred + agrégat/projection).
// ====================================================================================================

/// Forme d'exécution vectorisée reconnue. `dims`/`proj` = colonnes PHYSIQUES (`&'static` de `PARQUET_COLS`).
enum VecAgg {
    /// `| stats count` -> scalaire (colonne `count`).
    Count,
    /// `| stats count by d1[,d2,…]` -> group-by count (colonnes `d1,…,count`).
    GroupCount(Vec<&'static str>),
    /// `| stats count by dims | sort ±count [| head N]` -> top-N (count DESC/ASC, tie-break clé ASC).
    TopN(Vec<&'static str>, bool /* asc */, usize),
    /// `| table c1,c2,… [| head N]` -> matérialisation projetée bornée (ordre canonique day/seq/position).
    Materialize(Vec<&'static str>, Option<usize> /* head */),
}

struct VecPlan {
    pred: Pred,
    agg: VecAgg,
}

/// Colonnes de la sortie d'un plan (pour construire {columns,rows}). `count` toujours en fin d'agrégat.
fn plan_columns(agg: &VecAgg) -> Vec<String> {
    match agg {
        VecAgg::Count => vec!["count".to_string()],
        VecAgg::GroupCount(d) | VecAgg::TopN(d, _, _) => {
            let mut c: Vec<String> = d.iter().map(|s| s.to_string()).collect();
            c.push("count".to_string());
            c
        }
        VecAgg::Materialize(p, _) => p.iter().map(|s| s.to_string()).collect(),
    }
}

// ====================================================================================================
// QUELLES COLONNES SONT « PHYSIQUES » — ET POUR QUOI FAIRE.
// ----------------------------------------------------------------------------------------------------
// `PARQUET_COLS` dit ce que le tier froid STOCKE. Ça ne dit PAS ce que le compilateur GXQL considère
// comme une colonne : il a DEUX listes distinctes, et une colonne hors liste est résolue en
// `json_extract(fields,'$.<nom>')`.
//   `real_cols`   : filtrables dans un WHERE (events : + `dedup`, `id`).
//   `select_cols` : projetables / groupables (events : SANS `dedup` ni `id`).
// Le tier froid stocke EN PLUS `engagement_id`, `origin`, `env_id`, que le schéma events ne déclare NI
// filtrables NI projetables.
//
// LE DÉFAUT QUE ÇA CAUSAIT (trouvé par le test de parité, pas par une relecture) : `phys()` acceptait
// TOUT `PARQUET_COLS`, donc `search | stats count by dedup` était ROUTÉ vers les kernels, qui rendaient
// les vraies valeurs de la colonne `dedup` — tandis que la MÊME requête sans tier froid rendait
// `json_extract(fields,'$.dedup')`, c'est-à-dire NULL, en UN seul groupe. Deux réponses pour une
// question, selon la route. Latent jusqu'ici parce que le routeur était dormant par défaut ; l'armer
// l'aurait publié.
//
// LES DEUX ENSEMBLES SONT DÉRIVÉS DU CŒUR, pas recopiés : `Schema::events()` en est la source, calculée
// une fois. Si le cœur déclare demain `origin` projetable, l'intersection le suit sans qu'on touche ici.
// ====================================================================================================

/// `PARQUET_COLS` ∩ colonnes RÉELLES (filtrables) du schéma GXQL. Calculée UNE FOIS depuis le cœur.
fn phys_pred_cols() -> &'static [&'static str] {
    static C: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let s = guatx_core::soql::Schema::events();
        PARQUET_COLS.iter().copied().filter(|c| s.default.real_cols.iter().any(|r| r == c)).collect()
    })
}

/// `PARQUET_COLS` ∩ colonnes de PROJECTION du schéma GXQL (dims de group-by, `| table`). Idem.
fn phys_proj_cols() -> &'static [&'static str] {
    static C: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let s = guatx_core::soql::Schema::events();
        PARQUET_COLS.iter().copied().filter(|c| s.default.select_cols.iter().any(|r| r == c)).collect()
    })
}

/// Colonne utilisable dans un PRÉDICAT ; sinon `None` (fallback -> le compilateur décide, un seul résultat).
fn phys_pred(col: &str) -> Option<&'static str> {
    phys_pred_cols().iter().copied().find(|c| *c == col)
}

/// Colonne utilisable en DIMENSION / PROJECTION ; sinon `None` (fallback).
fn phys_proj(col: &str) -> Option<&'static str> {
    phys_proj_cols().iter().copied().find(|c| *c == col)
}

/// Colonne INT physique du cold (les SEULES INT64 : `ts`/`severity`). Les comparaisons NUMÉRIQUES ne sont
/// mappées QUE pour celles-ci (sinon affinité TEXT/INT SQLite non triviale -> fallback, iso-résultat garanti).
fn int_phys(col: &'static str) -> Option<&'static str> {
    matches!(col, "ts" | "severity").then_some(col)
}

// ====================================================================================================
// MAPPING GXQL -> plan. CONSERVATEUR : `None` au moindre écart aux formes supportées (fall-through).
// ====================================================================================================

/// ANTI-DIVERGENCE — ALIAS DE LECTURE CIM (`exec` ⊃ `process`, dette de migration expirant le
/// 2027-07-23, cf. `soql_glue::cim_read_alias_exec`). Le moteur colonnaire parse le GXQL LUI-MÊME
/// (`build_pred`, miroir de `table_conds`) alors que l'alias est posé à l'ÉMISSION SQL (store) : sans
/// cette garde, une requête `category=exec` rendrait `StrEq{exec}` ICI et `IN ('exec','process')` dans
/// l'oracle -> DEUX jeux de lignes différents selon la route choisie, silencieusement. On DÉCLINE donc
/// la vectorisation de ces requêtes-là : l'appelant retombe sur `cold_union_query`, qui exécute le SQL
/// COMPILÉ (donc aliasé) -> un seul résultat possible. Coût borné aux requêtes qui écrivent
/// littéralement `category=exec` ; se retire AVEC l'alias.
pub(super) fn carries_cim_read_alias(soql: &str) -> bool {
    matches!(crate::soql_glue::cim_read_alias_exec(soql), std::borrow::Cow::Owned(_))
}

/// TEST-ONLY — expose la DÉCISION des mappeurs (le plan lui-même reste d'un type privé) pour que le
/// test d'anti-divergence de l'alias CIM morde sur les VRAIS mappeurs, et non sur une copie de la garde.
#[cfg(test)]
pub(super) fn vec_agg_routable(soql: &str) -> bool {
    map_soql(soql).is_some()
}
#[cfg(test)]
pub(super) fn vec_keyset_routable(soql: &str) -> bool {
    map_keyset_soql(soql).is_some()
}

/// MAPPE un GXQL en `VecPlan`, ou `None` (forme non vectorisable -> fallback). PUR (aucun I/O) -> testable.
fn map_soql(soql: &str) -> Option<VecPlan> {
    if carries_cim_read_alias(soql) {
        return None;
    }
    let stages = guatx_core::soql::soql_split_pipes(soql);
    if stages.is_empty() {
        return None;
    }
    // --- STAGE 0 : base `search [filtres]` UNIQUEMENT (jamais `metric`/autre). ---
    let f0 = stages[0].trim();
    let body = if f0 == "search" {
        ""
    } else if let Some(r) = f0.strip_prefix("search ") {
        r.trim()
    } else {
        return None;
    };
    let pred = build_pred(body)?;

    let rest = &stages[1..];
    // search NU (aucun pipe) : projection implicite du sac `fields` + ordre non défini -> FALLBACK (on n'expose
    // le moteur qu'aux formes à sortie EXPLICITE et déterministe). `| table` requis pour matérialiser.
    if rest.is_empty() {
        return None;
    }

    let s0: Vec<&str> = rest[0].split_whitespace().collect();

    // --- TABLE : `| table c1,c2,… [| head N]`. ---
    if s0.first() == Some(&"table") {
        let raw = rest[0].strip_prefix("table").unwrap_or("").trim();
        if raw.is_empty() || raw == "*" {
            return None; // `table` nu / `table *` = passe-plat (projection implicite) -> fallback
        }
        let proj = map_cols(raw)?;
        let head = parse_trailing_head(rest, 1)?;
        return Some(VecPlan { pred, agg: VecAgg::Materialize(proj, head) });
    }

    // --- STATS COUNT [BY dims] [| sort ±count] [| head N]. ---
    if s0.first() != Some(&"stats") || s0.get(1) != Some(&"count") {
        return None;
    }
    // `| stats count` sans `by` : scalaire (aucune commande en trop).
    if s0.get(2).is_none() {
        if rest.len() != 1 {
            return None;
        }
        return Some(VecPlan { pred, agg: VecAgg::Count });
    }
    if s0.get(2) != Some(&"by") {
        return None;
    }
    let dims = map_cols(&s0[3..].join(" "))?;
    if dims.is_empty() {
        return None;
    }
    // Optionnel : `| sort -count|+count|count` puis `| head N`.
    let mut idx = 1;
    let mut asc: Option<bool> = None;
    if let Some(stage) = rest.get(idx) {
        let t: Vec<&str> = stage.split_whitespace().collect();
        if t.first() == Some(&"sort") {
            if t.len() != 2 {
                return None;
            }
            // Le compilateur cœur (`compile_sort`) n'accepte QUE `-<champ>` (DESC) ou `<champ>` (ASC) — un
            // `+count` y est un IDENTIFIANT INVALIDE (erreur de compilation). Pour ne JAMAIS router une requête
            // que l'oracle REJETTE, on n'accepte ici que `-count` / `count` (jamais `+count`).
            asc = Some(match t[1] {
                "-count" => false,
                "count" => true,
                _ => return None,
            });
            idx += 1;
        }
    }
    let head = parse_trailing_head(rest, idx)?;
    match (asc, head) {
        (None, None) => Some(VecPlan { pred, agg: VecAgg::GroupCount(dims) }),
        // top-N : un tri sur count (avec ou sans head) -> ordonnancement count-first, tie-break clé ASC. Sans
        // head -> N = usize::MAX (liste ordonnée complète).
        (Some(a), h) => Some(VecPlan { pred, agg: VecAgg::TopN(dims, a, h.unwrap_or(usize::MAX)) }),
        // head SANS sort sur un group-by -> ordre non défini (l'oracle GROUP BY sans ORDER BY) -> FALLBACK.
        (None, Some(_)) => None,
    }
}

/// `| head N` en fin de pipeline à partir de l'index `idx` : `Ok(Some(N))` si présent+seul, `Ok(None)` si
/// aucune étape restante, `None` (Err de forme) si `head` mal formé OU si une étape EN TROP suit.
fn parse_trailing_head(rest: &[String], idx: usize) -> Option<Option<usize>> {
    match rest.get(idx) {
        None => Some(None),
        Some(stage) => {
            let t: Vec<&str> = stage.split_whitespace().collect();
            if t.first() != Some(&"head") || t.len() != 2 {
                return None;
            }
            let n: i64 = t[1].parse().ok()?;
            if n < 0 {
                return None;
            }
            if rest.get(idx + 1).is_some() {
                return None; // commande en trop après head
            }
            Some(Some(n as usize))
        }
    }
}

/// `c1, c2, …` -> `Vec<&'static>` PHYSIQUE (ordre préservé). `None` si UNE colonne n'est pas physique/valide.
fn map_cols(raw: &str) -> Option<Vec<&'static str>> {
    let mut out = Vec::new();
    for c in raw.split(',') {
        let c = c.trim();
        if c.is_empty() || !soql_ident_ok(c) {
            return None;
        }
        out.push(phys_proj(c)?);
    }
    (!out.is_empty()).then_some(out)
}

/// CONSTRUIT le `Pred` du filtre `search` — MIROIR EXACT du sous-ensemble de `table_conds` (core soql.rs) que
/// le moteur sait vectoriser. `None` au moindre écart (terme libre, `in(…)`, `>`/`<` sur string, champ
/// non-physique, colonne masquée, regex invalide, comparaison numérique hors ts|severity) -> FALLBACK.
/// Body vide -> `Pred::True` (match-all).
fn build_pred(body: &str) -> Option<Pred> {
    if body.is_empty() {
        return Some(Pred::True);
    }
    let mut conds: Vec<Pred> = Vec::new();
    for tk in guatx_core::soql::soql_tokenize(body) {
        // `*` seul = joker « tous les événements » -> aucun filtre (parité `table_conds`). Un `*` DANS une
        // valeur (`champ=v*`) est traité par le branch glob plus bas (le token contient un opérateur).
        if tk == "*" {
            continue;
        }
        // `in`/`not in`/listes/formes espacées -> parenthèses/tokens inattendus -> non supporté ici.
        if tk.contains('(') || tk.contains(')') {
            return None;
        }
        // Détection d'opérateur — ORDRE IDENTIQUE au compilateur (`=~` avant `=`, `!=` avant `=`, …).
        let mut found: Option<(&str, &str, &str)> = None;
        for op in ["=~", ">=", "<=", "!=", "=", ":", ">", "<"] {
            if let Some(pos) = tk.find(op) {
                found = Some((op, &tk[..pos], &tk[pos + op.len()..]));
                break;
            }
        }
        // Aucun opérateur -> terme LIBRE (message LIKE) : sémantique de casse/ILIKE non triviale -> FALLBACK.
        let (op, field, val) = found?;
        if !soql_ident_ok(field) {
            return None;
        }
        let fcol = phys_pred(field)?;
        let p = build_leaf(op, fcol, val)?;
        conds.push(p);
    }
    Some(match conds.len() {
        0 => Pred::True,
        1 => conds.into_iter().next().unwrap(),
        _ => Pred::And(conds),
    })
}

/// UNE feuille `champ op valeur` -> `Pred`, mirroir EXACT de `table_conds`. `None` si non vectorisable.
fn build_leaf(op: &str, fcol: &'static str, val: &str) -> Option<Pred> {
    // `=~` -> REGEXP (UDF `regexp` = crate `regex`, MÊME moteur -> parité). Regex invalide -> FALLBACK.
    if op == "=~" {
        return regex::Regex::new(val).ok().map(|re| Pred::Regex { col: fcol, re });
    }
    // `=`/`:`/`!=` avec valeur `~…` -> REGEXP sur le reste (parité `table_conds` ligne "val.starts_with('~')").
    if matches!(op, "=" | ":") && val.starts_with('~') {
        return regex::Regex::new(&val[1..]).ok().map(|re| Pred::Regex { col: fcol, re });
    }
    // `=`/`:`/`!=` avec `*` -> glob LIKE (`*`->`%`) ; `!=` -> NOT LIKE (négation 3-valuée).
    if matches!(op, "=" | ":" | "!=") && val.contains('*') {
        let like = Pred::Like { col: fcol, pat: val.replace('*', "%") };
        return Some(if op == "!=" { Pred::Not(Box::new(like)) } else { like });
    }
    // Valeur NUMÉRIQUE (et pas regex) : comparaison INT — UNIQUEMENT sur ts|severity (les seules INT64 cold).
    if soql_num(val) {
        let icol = int_phys(fcol)?; // champ non-int (numérique-sur-string) -> affinité SQLite -> FALLBACK
        let n: i64 = val.parse().ok()?; // décimal (`3.5`) -> échec parse i64 -> FALLBACK (pas de compare float)
        let iop = match op {
            "=" | ":" => IntOp::Eq,
            "!=" => IntOp::Ne,
            ">" => IntOp::Gt,
            "<" => IntOp::Lt,
            ">=" => IntOp::Ge,
            "<=" => IntOp::Le,
            _ => return None,
        };
        return Some(Pred::Int { col: icol, op: iop, val: n });
    }
    // Valeur TEXTE : seuls `=`/`:`/`!=` (égalité) sont vectorisés ; `>`/`<`/`>=`/`<=` sur string -> FALLBACK.
    match op {
        "=" | ":" => Some(Pred::StrEq { col: fcol, val: val.to_string() }),
        "!=" => Some(Pred::Not(Box::new(Pred::StrEq { col: fcol, val: val.to_string() }))),
        _ => None,
    }
}

// ====================================================================================================
// EXÉCUTION — sélection de fichiers (mirror hydrate/open_cold_union) + kernels + construction du `Value`.
// ====================================================================================================

/// UN fichier cold sélectionné (place canonique + identité/borne du seal pour `verify_parquet_rows`).
struct Sel {
    day: i64,
    seq: i64,
    expected: usize,
    ts_min: i64,
    ts_max: i64,
}

/// Ouvre la base HOT du tenant en RO+clé (pour lire l'index `cold_seal`) — MÊME ouverture que `open_cold_union`.
fn open_seal_conn(db_path: &str) -> Result<Connection, String> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(pe)?;
    apply_key_for(&conn, db_path);
    let _ = conn.execute_batch("PRAGMA busy_timeout=3000;");
    Ok(conn)
}

/// Sélectionne les fichiers cold d'`env` chevauchant `[lo, hi]`, ORDRE CANONIQUE (day, seq) — RÉUTILISE la
/// MÊME logique que `hydrate_cold`/`open_cold_union` (jours spannés × `file_seals` × chevauchement `[ts_min,ts_max]`),
/// PUIS #28 P3.5 : élague dimensionnellement via le seal (min/max/bloom) SANS déchiffrer — le MÊME primitif
/// `DimStats::excluded_by` et la MÊME condition que le chemin oracle (`hydrate_cold`, reader.rs) -> parité PAR
/// CONSTRUCTION. `pruned` est INCRÉMENTÉ pour chaque fichier sauté (chevauchant la fenêtre mais prouvé sans match).
/// INVARIANT : on ne saute QUE si `dim_stats` PROUVE 0 match (dim_stats=None -> gardé ; faux positif bloom -> gardé).
fn select_files(conn: &Connection, env: &str, lo: i64, hi: i64, dim_preds: &[DimEq], pruned: &mut usize) -> Vec<Sel> {
    let lo_day = lo.div_euclid(SECS_PER_DAY);
    let hi_day = hi.div_euclid(SECS_PER_DAY);
    let mut out: Vec<Sel> = Vec::new();
    for day in lo_day..=hi_day {
        for s in file_seals(conn, env, day) {
            if s.ts_min <= hi && s.ts_max >= lo {
                // #28 P3.5 — ÉLAGAGE DIMENSIONNEL (encore SANS déchiffrer), IDENTIQUE à `hydrate_cold` : si la
                // requête porte des égalités sur des dims universelles ET que le seal de CE fichier PROUVE
                // l'absence de la valeur (min/max hors bornes OU bloom certain-absent), on le SAUTE. `dim_stats`
                // None (pré-Phase-B / illisible) -> pas d'élagage -> GARDÉ (fallback correct). Un faux positif de
                // bloom ne fait que GARDER (un déchiffrement de plus), JAMAIS rater une ligne.
                if !dim_preds.is_empty() {
                    if let Some(stats) = &s.dim_stats {
                        if stats.excluded_by(dim_preds) {
                            *pruned += 1;
                            continue;
                        }
                    }
                }
                out.push(Sel { day, seq: s.seq, expected: s.expected as usize, ts_min: s.ts_min, ts_max: s.ts_max });
            }
        }
    }
    out.sort_by(|a, b| a.day.cmp(&b.day).then(a.seq.cmp(&b.seq)));
    out
}

/// Ouvre+VÉRIFIE (fail-closed, identité liée) UN fichier cold puis renvoie son reader parquet déchiffré.
/// MÊME chaîne que `decode_one_file` (verify d'abord, puis ré-ouverture pour lecture aléatoire du footer).
fn open_verified(cold_dir: &std::path::Path, env: &str, s: &Sel, pass: &str) -> Result<impl FileReader, String> {
    let path = file_path(cold_dir, env, s.day, s.seq);
    let ident = FileIdent { env_id: env, day: s.day, seq: s.seq, ts_min: s.ts_min, ts_max: s.ts_max };
    verify_parquet_rows(&path, s.expected, Some(ident), pass)?;
    open_cold_reader(&path, pass)
}

/// La totalité des fichiers sélectionnés de tous les env de la fenêtre `[lo,hi]`, prêts à scanner. Fail-closed :
/// une clé absente -> `Ok(vec![])` (comme hydrate) ; un env non conforme -> ignoré ; corruption -> Err au scan.
struct ColdScan {
    cold_dir: std::path::PathBuf,
    pass: String,
    files: Vec<(String, Sel)>, // (env, fichier) — APRÈS élagage seal (les fichiers prouvés sans match sont retirés)
    pruned: usize,             // #28 P3.5 — fichiers ÉLAGUÉS (chevauchant la fenêtre mais sautés par le seal)
}

fn plan_scan(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    lo: i64,
    hi: i64,
    dim_preds: &[DimEq],
) -> Result<Option<ColdScan>, String> {
    let pass = match cold_aead_passphrase(conf, db_path) {
        Some(p) => p,
        None => return Ok(None), // pas de clé -> pas de tier cold lisible (comme hydrate_cold)
    };
    let cold_dir = cold_root(conf, db_path);
    let conn = open_seal_conn(db_path)?;
    let envs: Vec<String> = match env_filter {
        Some(e) if !e.trim().is_empty() => vec![e.to_string()],
        _ => distinct_seal_envs(&conn, lo, hi),
    };
    let mut files: Vec<(String, Sel)> = Vec::new();
    let mut pruned = 0usize;
    for env in envs {
        if !env_id_ok(&env) {
            continue; // anti-traversée (mirror open_cold_union)
        }
        for s in select_files(&conn, &env, lo, hi, dim_preds, &mut pruned) {
            files.push((env.clone(), s));
        }
    }
    Ok(Some(ColdScan { cold_dir, pass, files, pruned }))
}

/// GATE CAP (P4a §5, RÉUTILISÉ par P4b) : compte les lignes de la fenêtre froide `[lo, hi]` (ts-only) et
/// s'ARRÊTE dès que le total dépasse `cap`. Renvoie `Ok(None)` si `> cap` (l'oracle `cold_union_query`
/// TRONQUERAIT l'hydratation cold -> le routeur DOIT fallback pour préserver le résultat capé de l'oracle) ;
/// `Ok(Some(rows))` si `<= cap` (aucune troncature -> l'agrégat vectorisé COMPLET == l'agrégat oracle COMPLET).
/// PERF : un fichier ENTIÈREMENT couvert (`ts_min>=lo && ts_max<=hi`) compte GRATUITEMENT ses `expected`
/// lignes (métadonnée seal, aucun déchiffrement) ; seuls les fichiers de BORD (partiels, ≤ 2) sont décodés
/// pour un comptage EXACT (ts-only). MÊME logique que l'ancien bloc inline de `cold_vectorized_try` (extrait
/// verbatim pour être partagé avec le merge hot∪cold P4b) — comportement IDENTIQUE (invariant P4a intact).
fn window_rows_capped(scan: &ColdScan, lo: i64, hi: i64, deny: &std::collections::HashSet<String>, cap: i64) -> Result<Option<i64>, String> {
    let ts_pred = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: lo },
        Pred::Int { col: "ts", op: IntOp::Le, val: hi },
    ]);
    let mut window_rows: i64 = 0;
    let mut partials: Vec<&(String, Sel)> = Vec::new();
    for fs in &scan.files {
        let s = &fs.1;
        if s.ts_min >= lo && s.ts_max <= hi {
            window_rows += s.expected as i64; // couvert -> compte gratuit (seal)
        } else {
            partials.push(fs); // bord -> comptage exact par décodage ci-dessous
        }
        if window_rows > cap {
            return Ok(None); // dépassé rien qu'avec les fichiers couverts -> l'oracle tronquerait
        }
    }
    for (env, s) in partials {
        let reader = open_verified(&scan.cold_dir, env, s, &scan.pass)?;
        window_rows += vec_count(&reader, &ts_pred, deny)?; // lignes de CE fichier DANS la fenêtre (ts-only)
        if window_rows > cap {
            return Ok(None);
        }
    }
    Ok(Some(window_rows))
}

/// #18 P4a — ROUTE DECISION + EXÉCUTION. Renvoie `Ok(Some(value))` si la requête a été SERVIE par le moteur
/// vectorisé (value = résultat {columns,rows,stats}, iso-`run_on_conn`) ; `Ok(None)` si elle DOIT tomber en
/// fallback (l'appelant appelle alors `cold_union_query` VERBATIM) ; `Err` sur corruption cold (fail-closed,
/// comme l'oracle). Met à jour les compteurs de route. À appeler depuis `spawn_blocking` (I/O + déchiffrement).
///
/// `q_from`/`q_to` = fenêtre de requête (l'appelant a déjà garanti `q_from < boundary`). `masks_empty` = le
/// `FieldMaskSet` de l'appelant est vide (gate #3). `boundary` = `cold_query_boundary` (frontière RÉUTILISÉE).
/// `dim_preds` = égalités de dims universelles extraites du SQL COMPILÉ par le MÊME `extract_cold_dim_preds` que le
/// chemin oracle (`cold_union_query`) — les DEUX chemins reçoivent DONC les MÊMES prédicats d'élagage -> l'ensemble
/// de fichiers sauté est IDENTIQUE des deux côtés (cohérence du gate cap P3.5/P4a, cf. corps). `&[]` = pas d'élagage
/// dimensionnel (on retombe sur la sélection ts-only, inchangée).
#[allow(clippy::too_many_arguments)]
pub(crate) fn cold_vectorized_try(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    soql: &str,
    masks_empty: bool,
    _budget_ms: u64,
    dim_preds: &[DimEq],
) -> Result<Option<Value>, String> {
    let t0 = Instant::now();

    // GATE 0 : ARMÉ PAR DÉFAUT (cf. `cold_vectorized_armed`). `PLUME_COLD_VECTORIZED=0` désarme -> fallback
    // vers `cold_union_query`, qui REFUSE alors toute valeur dérivée d'un ensemble tronqué : l'opt-out coûte
    // des refus, jamais des nombres faux. Le défaut DORMANT d'origine était la cause MESURÉE du défaut de
    // correction (aucune des 105 cellules froides du banc n'atteignait les kernels).
    if !cold_vectorized_armed(conf) {
        note_fallback();
        return Ok(None);
    }
    // GATE 1 : cold ON (le PLUME_COLD_TIER est vérifié par l'appelant qui a calculé `boundary` ; on re-checke
    // par sûreté -> sans le flag, aucun tier cold, fallback).
    if !cold_tier_runtime_on(conf) {
        note_fallback();
        return Ok(None);
    }
    // GATE 3 : masques vides (HASH/MASK/DENY non reproductibles ici / colonne déniée) -> fallback.
    if !masks_empty {
        note_fallback();
        return Ok(None);
    }
    // GATE 2 : fenêtre PUR-FROID stricte. borne haute bornée (>0) ET strictement sous la frontière.
    if !(q_to > 0 && q_to < boundary) {
        note_fallback();
        return Ok(None);
    }
    // GATE 4 : forme vectorisable.
    let plan = match map_soql(soql) {
        Some(p) => p,
        None => {
            note_fallback();
            return Ok(None);
        }
    };
    // Défense en profondeur : toutes les colonnes référencées (pred + dims/proj) doivent être physiques.
    let extra: Vec<&str> = match &plan.agg {
        VecAgg::Count => vec![],
        VecAgg::GroupCount(d) | VecAgg::TopN(d, _, _) => d.iter().map(|s| &**s).collect(),
        VecAgg::Materialize(p, _) => p.iter().map(|s| &**s).collect(),
    };
    if !can_vectorize(&plan.pred, &extra) {
        note_fallback();
        return Ok(None);
    }

    // Fenêtre froide EFFECTIVE (mirror `open_cold_union`) : borne haute = q_to (garanti < boundary) ; borne
    // basse = q_from si bornée, sinon le plus vieux jour scellé.
    let hi = q_to; // gate: 0 < q_to < boundary
    let conn = open_seal_conn(db_path)?;
    let lo = if q_from > 0 {
        q_from
    } else {
        conn.query_row("SELECT MIN(day) FROM cold_seal", [], |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten()
            .map(|d| d * SECS_PER_DAY)
            .unwrap_or(hi)
    };
    drop(conn);

    // Deny-set du tenant (mirror open_cold_union) — VIDE quand masks_empty en production ; le harnais peut le
    // peupler DIRECTEMENT pour exercer le masquage kernel #45 (denied()).
    let deny: std::collections::HashSet<String> =
        crate::field_deny_cols_cell().read().get(db_path).cloned().unwrap_or_default();

    // #28 P3.5 — GARDE COLONNE-DÉNIÉE #45 : on N'ÉLAGUE JAMAIS sur le seal d'une dim DÉNIÉE (fuite par timing +
    // faux). En production une dim déniée ne peut PAS apparaître dans un prédicat (rejet à la compilation, oracle
    // #45) donc ce filtre est un NO-OP ; le harnais peut néanmoins injecter un deny-set directement -> ce garde
    // est la défense-en-profondeur exigée. Les prédicats sur dims NON déniées restent élaguables normalement.
    let eff_preds: Vec<DimEq> = if deny.is_empty() {
        dim_preds.to_vec()
    } else {
        // Garde masquage : MÊME règle que `vectorized::denied()` (insensible à la casse ASCII), pas `contains`
        // (sensible casse) — cohérence stricte avec le kernel #45 / `union_proj` (défense en profondeur).
        dim_preds
            .iter()
            .filter(|p| !deny.iter().any(|d| d.eq_ignore_ascii_case(p.dim.col_name())))
            .cloned()
            .collect()
    };

    // Prédicat de FENÊTRE (ts-only) — sert au COMPTAGE de troncature ET est AND-é au prédicat utilisateur.
    let ts_pred = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: lo },
        Pred::Int { col: "ts", op: IntOp::Le, val: hi },
    ]);

    let scan = match plan_scan(db_path, conf, env_filter, lo, hi, &eff_preds)? {
        Some(s) => s,
        None => {
            // Pas de clé cold -> ensemble vide == l'oracle (hydrate renvoie table vide). Résultat "vide" routé.
            let v = build_empty(&plan.agg, t0);
            note_vec();
            return Ok(Some(v));
        }
    };
    // #28 P3.5 — PREUVE d'élagage : les fichiers ÉLAGUÉS (retirés de `scan.files` par le seal) ne seront JAMAIS
    // remis à `open_verified`/`open_cold_reader` -> jamais déchiffrés. Compteurs enregistrés dès la sélection.
    note_prune(scan.pruned, scan.files.len());

    // GATE 5 : PAS DE TRONCATURE — DÉSORMAIS RESTREINTE À LA MATÉRIALISATION.
    //
    // CE QUI A CHANGÉ, ET POURQUOI. L'ancien contrat était « ne router que ce que l'oracle rendrait à
    // l'identique », donc : fallback dès que l'oracle TRONQUERAIT. Ce contrat traitait l'oracle comme une
    // référence de VÉRITÉ. Il ne l'est pas. Au-delà du cap, l'oracle hydrate `cold_hydrate_row_cap` lignes
    // puis agrège SUR CET ÉCHANTILLON : son `stats count` vaut 289 là où la vérité vaut 58 747 (×203, mesuré).
    // Préserver la parité avec ce nombre-là, c'est préserver le défaut. Le contrat DEVIENT :
    //     résultat routé == oracle QUAND l'oracle est exact ; résultat routé == EXACT sinon.
    //
    //   • AGRÉGATS (count / count by / top-N) : le kernel balaie TOUT le froid sans jamais matérialiser les
    //     lignes -> exact ET borné en RAM (un i64, ou une map bornée par `cold_group_max`). Il n'y a aucune
    //     raison de lui préférer un échantillon : la gate SAUTE. C'est LA correction.
    //   • MATÉRIALISATION : les deux chemins rendent un PRÉFIXE de lignes VRAIES — mais pas le même (l'oracle
    //     hydrate en ordre canonique puis laisse SQLite ordonner). Aucun des deux n'est faux ; on garde donc
    //     l'ancien comportement, iso-oracle, et la gate reste.
    //
    // PERF (inchangée) : pour un fichier ENTIÈREMENT couvert par la fenêtre (`ts_min>=lo && ts_max<=hi`),
    // toutes ses `expected` lignes (métadonnée de seal) sont dans la fenêtre -> aucun déchiffrement pour les
    // compter. Seuls les fichiers PARTIELS (bords) sont décodés (rare, <= 2).
    if matches!(plan.agg, VecAgg::Materialize(..)) {
        let cap = cold_hydrate_row_cap() as i64;
        if window_rows_capped(&scan, lo, hi, &deny, cap)?.is_none() {
            note_fallback();
            return Ok(None); // > cap -> l'oracle TRONQUERAIT ses LIGNES -> fallback (préfixe de l'oracle préservé)
        }
    }

    // Prédicat COMPLET = filtre utilisateur ∧ fenêtre. (window_rows <= cap -> aucune troncature -> l'agrégat
    // vectorisé COMPLET == l'agrégat oracle COMPLET sur les MÊMES lignes.)
    let full = match plan.pred {
        Pred::True => ts_pred,
        other => Pred::And(vec![other, ts_pred]),
    };

    // `exec_agg` peut décider un FALLBACK tardif (ex. tie de count STRADDLE le head-cut d'un top-N : le SET
    // renvoyé serait ambigu vs l'ordre intra-égalité indéfini de l'oracle) -> il renvoie `Ok(None)` et le routeur
    // retombe sur `cold_union_query` (invariant préservé).
    match exec_agg(&scan, &plan.agg, &full, &deny, cold_group_max(conf), t0)? {
        Some(mut value) => {
            note_vec();
            // TRANSPARENCE (parité ignore `stats` — comparée sur columns+rows) : couverture d'élagage seal.
            value["stats"]["cold_files_pruned"] = json!(scan.pruned);
            value["stats"]["cold_files_scanned"] = json!(scan.files.len());
            Ok(Some(value))
        }
        None => {
            note_fallback();
            Ok(None)
        }
    }
}

// ====================================================================================================
// #18 ①a — MATÉRIALISATION KEYSET du BRUT froid (browse Explore raw par curseur, SANS cap).
// ----------------------------------------------------------------------------------------------------
// Insight FRONTIÈRE : hot `ts>=boundary`, cold `ts<boundary` -> en `ts DESC` les tiers NE S'INTERLEAVENT PAS
// (hot d'abord, puis cold). Le handler pagine HOT-puis-COLD séquentiellement ; CE morceau = la matérialisation
// keyset PUR-FROID. Chaque page borne la RAM à `limit` lignes (le kernel `vec_materialize_keyset` + le tas GLOBAL
// ci-dessous, tous deux plafonnés) -> 2 Go-safe QUEL QUE SOIT le volume froid. PARCOURS INTÉGRAL (fin du cap qui
// tronquait `cold_union_query`). Formes supportées : `search [filtres]` NU (liste brute). `| table`/agrégats/
// masques/offset -> `None` (FALLBACK au chemin `cold_union_query` keyset INCHANGÉ).

/// Projection d'une LIGNE BRUTE `search` — MIROIR EXACT de `guatx_core::soql::Schema::events()` `select_cols`
/// (colonnes RÉELLES projetées d'un `search` nu). Le hot keyset émet CES colonnes + `id` (cf. `append_cursor_id_col`)
/// -> le cold doit rendre le MÊME jeu, MÊME ORDRE, pour qu'une page hot∪cold (franchissement de frontière) soit
/// homogène. Toutes ∈ `PARQUET_COLS` (physiques) -> vectorisable. SYNC obligatoire si le cœur change `select_cols`.
const KEYSET_EVENT_COLS: [&str; 11] =
    ["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields"];

/// MAPPE un GXQL keyset -> (prédicat, projection physique) ou `None` (forme non supportée -> FALLBACK). Seul
/// `search [filtres]` NU (aucun pipe) est routé : c'est LA forme du browse Explore raw (liste de lignes brutes,
/// sortie déterministe `ts,id` desc). `| table`/`| stats`/… -> `None` (le hot keyset de ces formes ne projette
/// pas forcément `ts`+`id`, et l'agrégation n'a pas de sens keyset) -> l'appelant retombe sur `cold_union_query`.
fn map_keyset_soql(soql: &str) -> Option<(Pred, Vec<&'static str>)> {
    if carries_cim_read_alias(soql) {
        return None;
    }
    let stages = guatx_core::soql::soql_split_pipes(soql);
    if stages.len() != 1 {
        return None; // pipes -> non supporté ici (bare search uniquement)
    }
    let f0 = stages[0].trim();
    let body = if f0 == "search" {
        ""
    } else if let Some(r) = f0.strip_prefix("search ") {
        r.trim()
    } else {
        return None;
    };
    let pred = build_pred(body)?;
    // Résout chaque colonne par défaut vers son `&'static` de `PARQUET_COLS` (garantit l'identité de pointeur
    // attendue par le kernel + `can_vectorize`).
    let proj: Vec<&'static str> = KEYSET_EVENT_COLS.iter().filter_map(|c| phys_proj(c)).collect();
    if proj.len() != KEYSET_EVENT_COLS.len() {
        return None; // divergence schéma cold (défensif) -> fallback
    }
    Some((pred, proj))
}

/// FUSION de deux listes `(ts,id) DÉCROISSANTES` en gardant les `limit` plus grandes (merge classique). Clés
/// UNIQUES entre `a` (accumulateur global) et `b` (fichier courant) : disjointes par construction (une ligne
/// appartient à un seul fichier). RAM bornée à `limit`.
fn ks_merge_desc(a: Vec<(i64, i64, MatRow)>, b: Vec<(i64, i64, MatRow)>, limit: usize) -> Vec<(i64, i64, MatRow)> {
    let mut ai = a.into_iter().peekable();
    let mut bi = b.into_iter().peekable();
    let mut out: Vec<(i64, i64, MatRow)> = Vec::with_capacity(limit);
    while out.len() < limit {
        let pick_a = match (ai.peek(), bi.peek()) {
            (Some(x), Some(y)) => (x.0, x.1) >= (y.0, y.1),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if pick_a {
            out.push(ai.next().unwrap());
        } else {
            out.push(bi.next().unwrap());
        }
    }
    out
}

/// #18 ①a — UNE page keyset PUR-FROIDE : les <= `limit` lignes brutes de PLUS HAUT `(ts,id)` STRICTEMENT sous
/// `cursor` (`ts,id` desc), `id` synthétique appendé en dernière colonne. `Ok(Some((columns, rows)))` = servi par
/// le moteur colonnaire (COMPLET, sans cap) ; `Ok(None)` = FALLBACK (gate off / masque / forme non supportée) ->
/// l'appelant utilise `cold_union_query` keyset VERBATIM ; `Err` = corruption froid (fail-closed, comme l'oracle).
///
/// FICHIERS parcourus en `ts_max DÉCROISSANT` + EARLY-STOP inter-fichiers : dès que le tas global tient `limit`
/// lignes ET que `fichier.ts_max < ts` de la `limit`-ème, AUCUN fichier restant ne peut contribuer -> on ARRÊTE
/// (le gros levier : une page ne touche que les ~1-2 fichiers autour du curseur, pas tout le tier). Sélection +
/// élagage seal (#28 P3.5) RÉUTILISÉS de `plan_scan` (mêmes `dim_preds` que l'oracle -> mêmes fichiers). RAM =
/// tas global (`limit`) + le kernel d'UN fichier (`limit`) + un batch -> 2 Go-safe indépendamment du volume.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cold_keyset_page(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    soql: &str,
    masks_empty: bool,
    cursor: Option<(i64, i64)>,
    limit: usize,
    dim_preds: &[DimEq],
) -> Result<Option<(Vec<String>, Vec<Vec<Value>>)>, String> {
    // GATES (miroir `cold_vectorized_try`) : GATE 0 (armé par défaut, cf. `cold_vectorized_armed`) + cold ON +
    // masques vides. Sinon FALLBACK. Ici aussi le défaut ARMÉ est un choix de CORRECTION : le fallback
    // (`cold_union_query` keyset) hydrate au plus `cold_hydrate_row_cap` lignes PUIS filtre le curseur -> il
    // est STRUCTURELLEMENT incapable de paginer au-delà du plafond, donc de montrer l'historique froid.
    if !cold_vectorized_armed(conf) {
        return Ok(None);
    }
    if !cold_tier_runtime_on(conf) {
        return Ok(None);
    }
    if !masks_empty {
        return Ok(None);
    }
    // FORME : `search [filtres]` NU uniquement.
    let (pred, proj) = match map_keyset_soql(soql) {
        Some(x) => x,
        None => return Ok(None),
    };
    let extra: Vec<&str> = proj.iter().map(|s| &**s).collect();
    if !can_vectorize(&pred, &extra) {
        return Ok(None);
    }
    // Colonnes de sortie = projection + `id` synthétique (dernier), MÊME forme/ordre que le hot keyset.
    let mut columns: Vec<String> = proj.iter().map(|s| s.to_string()).collect();
    columns.push("id".to_string());

    // Deny-set (#45) — VIDE quand masks_empty en prod ; le harnais peut le peupler pour éprouver `denied()`.
    let deny: std::collections::HashSet<String> = crate::field_deny_cols_cell().read().get(db_path).cloned().unwrap_or_default();
    // Garde colonne-déniée #45 sur l'élagage seal (mêmes règles que `cold_vectorized_try`).
    let eff_preds: Vec<DimEq> = if deny.is_empty() {
        dim_preds.to_vec()
    } else {
        dim_preds
            .iter()
            .filter(|p| !deny.iter().any(|d| d.eq_ignore_ascii_case(p.dim.col_name())))
            .cloned()
            .collect()
    };

    // Fenêtre froide EFFECTIVE : borne haute = min(q_to|B-1, cursor_ts) (le curseur ÉLAGUE les fichiers au-dessus) ;
    // borne basse = q_from si bornée, sinon le plus vieux jour scellé.
    let mut hi = if q_to > 0 { q_to.min(boundary - 1) } else { boundary - 1 };
    if let Some((cts, _)) = cursor {
        hi = hi.min(cts);
    }
    let conn = open_seal_conn(db_path)?;
    let lo = if q_from > 0 {
        q_from
    } else {
        conn.query_row("SELECT MIN(day) FROM cold_seal", [], |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten()
            .map(|d| d * SECS_PER_DAY)
            .unwrap_or(hi)
    };
    // GATE MONO-ENV. `cold_synth_id = seq*COLD_FILE_MAX_ROWS + position` intègre
    // `seq`+`position` mais PAS `env_id` (TEXT, non packable), et `seq` REDÉMARRE à 0 par partition `(env_id, day)`.
    // Deux envs avec même `(seq, position)` au MÊME `ts` (donc même jour) reçoivent le MÊME id -> clé de curseur
    // `(ts,id)` non unique -> gap/dup en pagination (classe « ligne SOC ratée »). En MONO-ENV l'id EST unique
    // ((ts,id) unique par env : jour fixe -> `seq` unique + `position < cap` ; jours distincts -> `ts` distinct).
    // Donc : env SCOPÉ (`Some`) -> sûr ; env NON-SCOPÉ (`None`) avec >1 env distinct dans la fenêtre -> FALLBACK
    // `cold_union_query` (rowid oracle global, unique tous-envs, capé mais correct). Log = pas de cap silencieux.
    if env_filter.is_none() {
        let envs = distinct_seal_envs(&conn, lo, hi);
        if envs.len() > 1 {
            eprintln!(
                "[cold] keyset: fallback cap\u{e9} (multi-env non-scop\u{e9}, {} envs dans [{lo},{hi}]) \u{2014} raw-completeness servie via oracle cold_union_query",
                envs.len()
            );
            drop(conn);
            return Ok(None);
        }
    }
    drop(conn);
    if hi < lo || limit == 0 {
        return Ok(Some((columns, Vec::new()))); // fenêtre vide -> page cold vide (COMPLET, pas un fallback)
    }

    // Prédicat COMPLET = filtre utilisateur ∧ fenêtre `[lo,hi]` (le tie-break `id` du curseur est appliqué PAR LIGNE
    // dans le kernel). Le kernel élague les row-groups via ces bornes `ts` (`rg_can_match`) + le curseur.
    let ts_pred = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: lo },
        Pred::Int { col: "ts", op: IntOp::Le, val: hi },
    ]);
    let full = match pred {
        Pred::True => ts_pred,
        other => Pred::And(vec![other, ts_pred]),
    };

    let scan = match plan_scan(db_path, conf, env_filter, lo, hi, &eff_preds)? {
        Some(s) => s,
        None => return Ok(Some((columns, Vec::new()))), // pas de clé cold -> vide == oracle (hydrate vide)
    };
    note_prune(scan.pruned, scan.files.len());

    // Fichiers en `ts_max DÉCROISSANT` (tie-break day/seq desc, déterministe) -> EARLY-STOP inter-fichiers correct.
    let mut order: Vec<&(String, Sel)> = scan.files.iter().collect();
    order.sort_by(|a, b| b.1.ts_max.cmp(&a.1.ts_max).then(b.1.day.cmp(&a.1.day)).then(b.1.seq.cmp(&a.1.seq)));

    // TAS GLOBAL borné à `limit` (Vec trié desc). Parcours séquentiel ts-desc : chaque fichier rend son propre
    // top-`limit` (RAM bornée), fusionné dans l'accumulateur global (bornée à `limit`). EARLY-STOP dès que plus
    // aucun fichier restant ne peut battre la `limit`-ème ligne courante.
    let mut acc: Vec<(i64, i64, MatRow)> = Vec::new();
    for (env, s) in order {
        if acc.len() >= limit && s.ts_max < acc[limit - 1].0 {
            break; // ts_max desc -> tous les suivants aussi < la limit-ème -> aucun ne contribue.
        }
        let floor = if acc.len() >= limit { Some(acc[limit - 1].0) } else { None };
        let reader = open_verified(&scan.cold_dir, env, s, &scan.pass)?;
        let file_rows = vec_materialize_keyset(&reader, s.seq, &full, &proj, cursor, floor, limit, &deny)?;
        acc = ks_merge_desc(acc, file_rows, limit);
    }

    // Lignes JSON : valeurs projetées (mêmes types que l'oracle via `sqlval_to_json`) + `id` synthétique en fin.
    let rows: Vec<Vec<Value>> = acc
        .into_iter()
        .map(|(_, id, row)| {
            let mut r: Vec<Value> = row.into_iter().map(sqlval_to_json).collect();
            r.push(json!(id));
            r
        })
        .collect();
    Ok(Some((columns, rows)))
}

/// Résultat VIDE (aucune ligne cold) pour chaque forme — colonnes correctes, 0 ligne (count -> 0).
fn build_empty(agg: &VecAgg, t0: Instant) -> Value {
    let cols = plan_columns(agg);
    match agg {
        VecAgg::Count => finalize(cols, vec![vec![json!(0)]], false, t0),
        _ => finalize(cols, vec![], false, t0),
    }
}

// ====================================================================================================
// #18 P6 — DÉCODE ROW-GROUP/FICHIER PARALLÈLE BORNÉ. Le décode + le DÉCHIFFREMENT age (coûteux) d'un fichier
// cold sont INDÉPENDANTS d'un fichier à l'autre : on les répartit sur un POOL BORNÉ de `degree` workers, chacun
// produisant l'AGRÉGAT PARTIEL de SON fichier (count / map group-by / lignes matérialisées bornées), fusionné
// par le consommateur unique. LA PARALLÉLISATION NE CHANGE QUE LA VITESSE (invariant PARITÉ) :
//   • count / group-by : fusion COMMUTATIVE (somme / union de maps) -> l'ordre d'achèvement des workers est SANS
//     effet sur le résultat (fold streaming -> au plus `degree` partiels EN VOL, borne RAM).
//   • matérialisation / top-N : l'ORDRE final est RÉ-IMPOSÉ après fusion (réindexation canonique day/seq puis tri
//     déterministe des groupes) -> identique au chemin séquentiel/oracle.
// BORNE RAM 2Go (invariant) : le pool réutilise `cold_read_parallelism()` (MÊME knob que le lecteur P2b, défaut
// PETIT 2-4) et un canal BORNÉ à `degree` -> au plus `degree` fichiers DÉCHIFFRÉS simultanément (le buffer age
// déchiffré + 1 ColumnBatch par worker), EXACTEMENT le profil RAM déjà éprouvé/expédié de `hydrate_cold`. Aucune
// croissance avec le NOMBRE de fichiers (back-pressure du canal). `degree<=1` (knob=1 ou 1 seul fichier) = chemin
// SÉQUENTIEL pur = l'ORACLE interne de parité (aucun thread).
// ====================================================================================================

/// FOLD PARALLÈLE COMMUTATIF sur les fichiers cold RETENUS : chaque fichier est `map`é (open_verified DANS le
/// worker -> déchiffrement/décodage parallélisés) en un partiel `T`, `fold`u dans `acc` sur le consommateur unique
/// DANS L'ORDRE D'ARRIVÉE (donc `fold` DOIT être commutatif+associatif : somme de counts / union de maps). Borne
/// RAM = `degree` partiels en vol (canal borné) + `acc`. FAIL-CLOSED : la 1re erreur de worker est propagée (Err),
/// AUCUN résultat partiel — on continue toutefois de DRAINER le canal pour débloquer les workers (jamais de join
/// pendu, même motif que `hydrate_cold`).
fn par_fold_files<T, A>(
    scan: &ColdScan,
    init: A,
    map: impl Fn(&str, &Sel) -> Result<T, String> + Sync,
    mut fold: impl FnMut(&mut A, T),
) -> Result<A, String>
where
    T: Send,
{
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let n = scan.files.len();
    let degree = cold_read_parallelism().min(n).max(1);
    // CHEMIN SÉQUENTIEL (== oracle interne) : knob=1 OU <= 1 fichier -> aucun thread, borne RAM triviale.
    if degree <= 1 {
        let mut acc = init;
        for (env, s) in &scan.files {
            #[cfg(test)]
            gauge_enter();
            let r = map(env, s);
            #[cfg(test)]
            gauge_exit();
            fold(&mut acc, r?);
        }
        return Ok(acc);
    }
    let next = AtomicUsize::new(0);
    let abort = AtomicBool::new(false);
    // Canal BORNÉ (capacité = degré) = back-pressure -> au plus `degree` partiels EN VOL (borne RAM, pas de
    // croissance avec le nombre de fichiers).
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<T, String>>(degree);
    let mut acc = init;
    let mut first_err: Option<String> = None;
    std::thread::scope(|scope| {
        // N WORKERS décodeurs (déchiffrement/décodage CPU indépendants ; work-stealing par index atomique).
        for _ in 0..degree {
            let tx = tx.clone();
            let next = &next;
            let abort = &abort;
            let map = &map;
            let files = &scan.files;
            scope.spawn(move || loop {
                if abort.load(Ordering::Relaxed) {
                    break; // arrêt anticipé (Err ailleurs) -> ne tire plus de fichier.
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let (env, s) = &files[i];
                #[cfg(test)]
                gauge_enter();
                let res = map(env, s);
                #[cfg(test)]
                gauge_exit();
                let is_err = res.is_err();
                if tx.send(res).is_err() {
                    break; // récepteur parti
                }
                if is_err {
                    abort.store(true, Ordering::Relaxed); // fail-closed : signale les autres workers.
                    break;
                }
            });
        }
        drop(tx); // seuls les clones-workers gardent un tx -> rx se ferme quand tous ont fini.

        // CONSOMMATEUR UNIQUE : fold commutatif (ordre d'arrivée SANS importance). On CONTINUE de drainer même
        // après une erreur (débloque tout worker en `send` -> pas de deadlock au join du scope).
        while let Ok(res) = rx.recv() {
            match res {
                Ok(t) => {
                    if first_err.is_none() {
                        fold(&mut acc, t);
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    abort.store(true, Ordering::Relaxed);
                }
            }
        }
    });
    match first_err {
        Some(e) => Err(format!("cold vectorisé parallèle: fichier invalide -> requête ÉCHOUÉE (aucun résultat partiel): {e}")),
        None => Ok(acc),
    }
}

/// COLLECTE PARALLÈLE INDEXÉE (matérialisation) : chaque fichier `map`é en `T`, renvoyé APPARIÉ à son INDEX
/// canonique (position dans `scan.files`, déjà trié day/seq) puis RÉORDONNÉ -> l'appelant concatène dans l'ORDRE
/// CANONIQUE == le streaming séquentiel. Utilisé UNIQUEMENT pour la matérialisation, dont la SOMME de lignes sur
/// TOUS les fichiers est <= `cap` (garantie gate 5) -> collecter tous les partiels reste borné RAM. Mêmes
/// garanties fail-closed / drain-on-error que `par_fold_files`.
fn par_collect_indexed<T: Send>(
    scan: &ColdScan,
    map: impl Fn(&str, &Sel) -> Result<T, String> + Sync,
) -> Result<Vec<(usize, T)>, String> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let n = scan.files.len();
    let degree = cold_read_parallelism().min(n).max(1);
    if degree <= 1 {
        let mut out = Vec::with_capacity(n);
        for (i, (env, s)) in scan.files.iter().enumerate() {
            #[cfg(test)]
            gauge_enter();
            let r = map(env, s);
            #[cfg(test)]
            gauge_exit();
            out.push((i, r?));
        }
        return Ok(out); // déjà en ordre canonique
    }
    let next = AtomicUsize::new(0);
    let abort = AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::sync_channel::<(usize, Result<T, String>)>(degree);
    let mut out: Vec<(usize, T)> = Vec::with_capacity(n);
    let mut first_err: Option<String> = None;
    std::thread::scope(|scope| {
        for _ in 0..degree {
            let tx = tx.clone();
            let next = &next;
            let abort = &abort;
            let map = &map;
            let files = &scan.files;
            scope.spawn(move || loop {
                if abort.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let (env, s) = &files[i];
                #[cfg(test)]
                gauge_enter();
                let res = map(env, s);
                #[cfg(test)]
                gauge_exit();
                let is_err = res.is_err();
                if tx.send((i, res)).is_err() {
                    break;
                }
                if is_err {
                    abort.store(true, Ordering::Relaxed);
                    break;
                }
            });
        }
        drop(tx);
        while let Ok((i, res)) = rx.recv() {
            match res {
                Ok(t) => {
                    if first_err.is_none() {
                        out.push((i, t));
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    abort.store(true, Ordering::Relaxed);
                }
            }
        }
    });
    if let Some(e) = first_err {
        return Err(format!("cold vectorisé parallèle: fichier invalide -> requête ÉCHOUÉE (aucun résultat partiel): {e}"));
    }
    // RÉ-IMPOSE l'ORDRE CANONIQUE (day/seq puis position intra-fichier préservée par le kernel) -> == séquentiel.
    out.sort_by_key(|(i, _)| *i);
    Ok(out)
}

/// COUNT(*) PARALLÈLE sur tous les fichiers cold : somme des counts partiels (fusion commutative). Remplace le
/// `for (env,s) … vec_count` séquentiel des deux chemins (pur-froid + merge P4b).
fn par_count(scan: &ColdScan, pred: &Pred, deny: &std::collections::HashSet<String>) -> Result<i64, String> {
    par_fold_files(
        scan,
        0i64,
        |env, s| {
            let reader = open_verified(&scan.cold_dir, env, s, &scan.pass)?;
            vec_count(&reader, pred, deny)
        },
        |acc, c| *acc += c,
    )
}

/// MATÉRIALISATION PARALLÈLE : chaque fichier rend ses lignes matchantes (bornées à `cap` ; SOMME <= `cap` par
/// gate 5) ; réordonnées canoniquement puis CONCATÉNÉES -> ORDRE == le streaming séquentiel. L'appelant applique
/// ensuite sa propre logique de plafond/head (troncature déterministe).
fn par_materialize_files(
    scan: &ColdScan,
    pred: &Pred,
    proj: &[&'static str],
    cap: usize,
    deny: &std::collections::HashSet<String>,
) -> Result<Vec<MatRow>, String> {
    let parts = par_collect_indexed(scan, |env, s| {
        let reader = open_verified(&scan.cold_dir, env, s, &scan.pass)?;
        let (rows, _tr) = vec_materialize(&reader, pred, proj, cap, deny)?;
        Ok(rows)
    })?;
    let mut out: Vec<MatRow> = Vec::new();
    for (_i, rows) in parts {
        out.extend(rows);
    }
    Ok(out)
}

/// Exécute l'agrégat/projection sur l'ensemble de fichiers `scan` avec le prédicat COMPLET, et construit le
/// `Value` {columns,rows,stats} iso-`run_on_conn`. Renvoie `Ok(None)` = FALLBACK TARDIF demandé (seul cas :
/// top-N dont l'égalité de count STRADDLE le head-cut -> SET ambigu, cf. arm `TopN`) ; l'appelant retombe alors
/// sur `cold_union_query`.
fn exec_agg(scan: &ColdScan, agg: &VecAgg, full: &Pred, deny: &std::collections::HashSet<String>, group_max: usize, t0: Instant) -> Result<Option<Value>, String> {
    let cols = plan_columns(agg);
    match agg {
        VecAgg::Count => {
            // #18 P6 — somme des counts partiels PARALLÈLES (fusion commutative) ; == somme séquentielle.
            let total = par_count(scan, full, deny)?;
            Ok(Some(finalize(cols, vec![vec![json!(total)]], false, t0)))
        }
        VecAgg::GroupCount(dims) => {
            let agg_map = scan_group(scan, full, dims, deny, group_max)?;
            // ORDRE canonique DÉTERMINISTE (clé ASC) : GROUP BY SQL est un SAC non ordonné -> on rend un ordre
            // stable (l'invariant porte sur les DONNÉES ; le harnais compare normalisé). N'ALTÈRE aucune donnée.
            let mut rows: Vec<(GroupKey, i64)> = agg_map.into_iter().collect();
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(Some(finalize(cols, group_rows(&rows, dims), false, t0)))
        }
        VecAgg::TopN(dims, asc, n) => {
            let agg_map = scan_group(scan, full, dims, deny, group_max)?;
            // Tri COMPLET par count (DESC par défaut, ASC si `sort +count`), tie-break clé pour un affichage
            // stable. On ne tronque PAS encore : il faut inspecter la ligne JUSTE APRÈS le head-cut.
            let mut ranked: Vec<(GroupKey, i64)> = agg_map.into_iter().collect();
            if *asc {
                ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            } else {
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
            // FIX A — FALLBACK-SUR-TIE au bord du head-cut. Si la dernière ligne INCLUSE (index n-1) a le MÊME
            // count que la première EXCLUE (index n), l'égalité STRADDLE la frontière -> QUELS membres de
            // l'égalité entrent dans le top-N est AMBIGU (l'ordre intra-égalité de l'oracle SQLite `ORDER BY
            // count DESC` est INDÉFINI) -> on ne peut PAS garantir le MÊME SET -> fallback. Cut STRICT
            // (`count[n-1] > count[n]`), moins de N groupes, ou head=0 -> le SET est déterminé par le COUNT SEUL
            // == oracle (l'harnais normalise l'ordre des lignes) -> on sert le vectorisé.
            if *n >= 1 && *n < ranked.len() && ranked[*n - 1].1 == ranked[*n].1 {
                return Ok(None); // tie au bord -> fallback vers cold_union_query
            }
            ranked.truncate(*n);
            Ok(Some(finalize(cols, group_rows(&ranked, dims), false, t0)))
        }
        VecAgg::Materialize(proj, head) => {
            // Cap = head si fourni, sinon le plafond d'hydratation (mêmes bornes que l'oracle). Ordre CANONIQUE
            // (fichiers day/seq, row-groups, positions) == l'ordre d'insertion de `cold_event` (rowid) que
            // l'oracle sert (`SELECT proj FROM (union)`) en pur-froid (côté hot vide) -> ordre iso.
            //
            // FIX B — un `head N` EXPLICITE = `LIMIT N` de l'oracle : il ne TRONQUE JAMAIS (`truncated=false`
            // même si plus de N lignes matchent). Seul le cap IMPLICITE `cold_hydrate_row_cap` (head absent) est
            // la VRAIE troncature de sécurité (miroir de l'hydratation bornée de l'oracle) -> `truncated=true`.
            let explicit_head = head.is_some();
            let cap = head.unwrap_or_else(cold_hydrate_row_cap);
            // #18 P6 — matérialisation PARALLÈLE, réordonnée en ORDRE CANONIQUE (day/seq puis position) == le
            // streaming séquentiel. La SOMME de lignes matchantes sur TOUS les fichiers est <= `cold_hydrate_row_cap`
            // (gate 5, ts-only >= le prédicat complet) -> `all.len()` est borné ; on n'excède `cap` que lorsque
            // `head N < total` (head EXPLICITE, jamais une VRAIE troncature). MÊME résultat que le head-cut séquentiel :
            // « les `cap` premières lignes de l'ensemble matché en ordre canonique ».
            let mut all = par_materialize_files(scan, full, proj, cap, deny)?;
            let truncated = all.len() > cap && !explicit_head; // cap IMPLICITE dépassé = seule VRAIE troncature
            all.truncate(cap);
            let out: Vec<Vec<Value>> = all
                .into_iter()
                .map(|r| r.into_iter().map(sqlval_to_json).collect())
                .collect();
            Ok(Some(finalize(cols, out, truncated, t0)))
        }
    }
}

/// Balaye tous les fichiers -> `HashMap<GroupKey,count>` fusionné (group-by count cross-fichier). #18 P6 —
/// décode PARALLÈLE borné : chaque fichier produit sa map partielle (dans un worker), fusionnées par UNION
/// COMMUTATIVE (somme par clé) sur le consommateur -> résultat IDENTIQUE au balayage séquentiel (l'ordre
/// d'achèvement des workers n'entre PAS dans la somme). RAM bornée à `degree` maps partielles en vol.
///
/// BORNE RAM DE LA MAP FUSIONNÉE (`group_max`) : depuis que GATE 5 ne s'applique plus aux agrégats, la
/// fenêtre froide balayée n'est plus bornée -> le nombre de clés distinctes ne l'est plus non plus. On
/// REFUSE (Err nommée) au-delà du plafond, on ne TRONQUE JAMAIS la map : une map tronquée rendrait des
/// groupes manquants et des counts justes, présentés comme complets — c'est-à-dire le défaut qu'on ferme,
/// déplacé d'un cran.
fn scan_group(
    scan: &ColdScan,
    full: &Pred,
    dims: &[&'static str],
    deny: &std::collections::HashSet<String>,
    group_max: usize,
) -> Result<std::collections::HashMap<GroupKey, i64>, String> {
    let mut overflow: Option<usize> = None;
    let map = par_fold_files(
        scan,
        std::collections::HashMap::<GroupKey, i64>::new(),
        |env, s| {
            let reader = open_verified(&scan.cold_dir, env, s, &scan.pass)?;
            vec_group_count(&reader, full, dims, deny)
        },
        |acc, part| {
            for (k, c) in part {
                *acc.entry(k).or_insert(0) += c;
            }
            if acc.len() > group_max && overflow.is_none() {
                overflow = Some(acc.len());
            }
        },
    )?;
    match overflow {
        Some(n) => Err(refuse_group_explosion(n, group_max)),
        None => Ok(map),
    }
}

/// (GroupKey, count) -> lignes JSON : chaque composant de dim converti selon le TYPE physique (int -> nombre,
/// string -> texte, None -> null), puis `count` (entier) en fin. MÊMES types que la projection oracle.
fn group_rows(rows: &[(GroupKey, i64)], dims: &[&'static str]) -> Vec<Vec<Value>> {
    rows.iter()
        .map(|(k, c)| {
            let mut row: Vec<Value> = Vec::with_capacity(dims.len() + 1);
            for (i, d) in dims.iter().enumerate() {
                let comp = k.get(i).and_then(|o| o.as_ref());
                row.push(match comp {
                    None => Value::Null,
                    Some(s) => {
                        if int_phys(d).is_some() {
                            // INT physique (ts/severity) : le kernel stocke `v.to_string()` -> re-parse en entier
                            // pour restituer le MÊME type JSON que `SELECT severity …` de l'oracle.
                            s.parse::<i64>().map(|n| json!(n)).unwrap_or(Value::Null)
                        } else {
                            json!(s)
                        }
                    }
                });
            }
            row.push(json!(c));
            row
        })
        .collect()
}

/// `rusqlite::types::Value` (kernel materialize) -> `serde_json::Value` — MÊME mapping que `run_on_conn`
/// (Integer/Real/Text/Null ; Blob -> marqueur, jamais présent en cold projeté).
fn sqlval_to_json(v: rusqlite::types::Value) -> Value {
    use rusqlite::types::Value as S;
    match v {
        S::Null => Value::Null,
        S::Integer(n) => json!(n),
        S::Real(f) => json!(f),
        S::Text(t) => json!(t),
        S::Blob(b) => json!(format!("<blob {} o>", b.len())),
    }
}

/// Construit le `Value` final {columns,rows,stats} — MÊME forme que `run_on_conn` (stats: elapsed_ms/rows/
/// truncated). `served_from`/`cold` sont posés par le HANDLER (comme pour le chemin oracle).
///
/// PLAFOND DE SORTIE (un SEUL site, pour TOUTES les formes). `run_on_conn` — le chemin SQLite qui sert le
/// hot comme l'oracle — borne sa SORTIE à `PLUME_QUERY_MAX` lignes et pose `truncated`. Tant que GATE 5
/// écartait toute fenêtre de plus de `cap` lignes, le vectorisé ne pouvait PAS dépasser ce plafond : la
/// parité était accidentelle. En levant la gate pour les agrégats, un `| stats count by <dim>` peut
/// désormais rendre plus de `cap` GROUPES là où le hot en rendrait `cap` + `truncated` -> divergence
/// INTRODUITE par la correction. On applique donc ICI le MÊME plafond, une fois, pour toute forme
/// présente ou future : c'est une troncature de SORTIE (chaque ligne rendue reste exacte), pas la
/// troncature d'ENTRÉE que `exactness` interdit.
fn finalize(columns: Vec<String>, mut rows: Vec<Vec<Value>>, truncated: bool, t0: Instant) -> Value {
    let out_cap = cold_hydrate_row_cap();
    let truncated = truncated || rows.len() > out_cap;
    rows.truncate(out_cap);
    let n = rows.len();
    let elapsed_ms = (t0.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
    json!({
        "columns": columns,
        "rows": rows,
        "stats": { "elapsed_ms": elapsed_ms, "rows": n, "truncated": truncated },
    })
}

// ====================================================================================================
// #18 P4b — MERGE hot∪cold VECTORISÉ (fenêtres CHEVAUCHANTES). Le P4a ne route QUE le pur-froid
// (`q_to < boundary`) ; une fenêtre qui CHEVAUCHE la frontière (`q_from < boundary <= q_to`, ex. « 30
// derniers jours » = froid + hot) tombait en fallback `cold_union_query` (hydrate TOUT le froid dans SQLite).
// P4b ROUTE aussi ces fenêtres : partie FROIDE `[lo, boundary-1]` via les KERNELS vectorisés (le chemin
// pur-froid, déjà prouvé) + partie HOT `[boundary, q_to]` via le chemin SQLite hot EXISTANT (réutilise
// VERBATIM la machinerie de `cold_union_query` en la restreignant au hot : `open_cold_union` avec
// `q_from=boundary` -> `hi=boundary-1 < lo=boundary` -> AUCUNE hydratation cold -> vue = `event WHERE
// ts>=boundary` seule), puis MERGE au niveau OPÉRATEUR.
//
// INVARIANT (gate déploiement) : résultat routé P4b == `cold_union_query` (l'oracle qui fait DÉJÀ hot∪cold)
// pour TOUTE requête chevauchante. Le merge ne change QUE la vitesse ; le masquage #45 est identique des DEUX
// côtés (froid via `denied()`, hot via le `union_proj`/masque du SQL compilé — le MÊME que l'oracle).
//
// MERGE PAR OPÉRATEUR (distributif sur l'`UNION ALL` de l'oracle) :
//   • count            -> somme des deux counts.
//   • count by dims    -> fusion des deux maps : somme des counts PAR CLÉ (clé des DEUX côtés = ADDITION).
//                         GARDE cap (`oracle_would_truncate_groups`) : l'oracle groupe (froid∪hot) via
//                         `run_on_conn` qui borne sa SORTIE à `cap` GROUPES, et son HOT-arm interne est LUI-MÊME
//                         capé à `cap` -> si le hot a rendu `>= cap` groupes (tronqué possible) OU si les
//                         groupes MERGÉS `> cap` (l'oracle caperait le combiné) -> FALLBACK (merge incomplet).
//   • sort ±count|head N -> fusionne les groupes PUIS re-trie PUIS re-head N. MÊME garde cap que ci-dessus
//                         (AVANT la garde tie), PUIS garde tie-au-bord de P4a : une égalité de count qui
//                         STRADDLE le head-cut APRÈS merge -> fallback (SET ambigu).
//   • table cols|head N -> concat des lignes. L'ordre de l'`UNION ALL` de l'oracle (hot-arm puis cold-arm, sous
//                         plan SQLite) n'est PAS reproductible de façon fiable : on ne route la matérialisation
//                         que quand l'oracle NE TRONQUERAIT PAS (`oracle_would_truncate_rows`). L'oracle borne
//                         sa sortie à `cap` (`run_on_conn`) EN PLUS du `LIMIT N` -> borne effective `min(N,cap)`
//                         pour un head explicite, `cap` sinon ; `total > borne` -> FALLBACK (conservateur).
// ====================================================================================================

/// #18 P4b — PRINCIPE UNIFICATEUR « oracle_would_truncate ». P4b ne route QUE lorsque l'oracle
/// (`cold_union_query` -> `run_on_conn`) ne TRONQUERAIT PAS son résultat : `run_on_conn` borne sa SORTIE à
/// `cap == cold_hydrate_row_cap() == PLUME_QUERY_MAX` (LIGNES pour une matérialisation, GROUPES pour un
/// group-by). Dès que l'oracle tronquerait, son résultat capé (`truncated=true`, ensemble incomplet) DIFFÈRE
/// du merge P4b (plus complet côté hot, non borné en volume) -> DIVERGENCE. Ces deux prédicats répondent
/// « l'oracle tronquerait-il ? » pour chaque forme ; au moindre doute -> `true` (fallback conservateur).
///
/// FORME MATÉRIALISÉE (`table [cols] [| head N]`) : l'oracle rend `min(N, cap, total)` lignes. La borne de
/// sortie effective est `min(N, cap)` pour un `head N` EXPLICITE, `cap` sinon. `total > out_cap` -> tronqué.
fn oracle_would_truncate_rows(total: i64, head: Option<usize>, cap: i64) -> bool {
    let out_cap = match head {
        Some(n) => std::cmp::min(n as i64, cap),
        None => cap,
    };
    total > out_cap
}

/// FORME GROUP-BY / TOP-N (`stats count by dims [| sort ±count | head N]`) : DEUX sources de troncature côté
/// oracle. (1) son HOT-arm interne (`count by dims` sans limite) passe par `run_on_conn` -> capé à `cap`
/// GROUPES : un hot ayant rendu `>= cap` groupes est POSSIBLEMENT tronqué (subset arbitraire) -> le merge
/// P4b raterait des groupes (et un top-N pourrait manquer un groupe à fort count). (2) le COMBINÉ (froid∪hot
/// groupé) repasse par `run_on_conn` -> capé à `cap` : `merged > cap` -> l'oracle tronque le combiné alors
/// que P4b le rendrait complet. `>= cap` côté hot est conservateur (on ne distingue pas « pile cap groupes »
/// de « > cap tronqué à cap » depuis le seul compte de lignes rendues).
fn oracle_would_truncate_groups(hot_groups: i64, merged_groups: i64, cap: i64) -> bool {
    hot_groups >= cap || merged_groups > cap
}

/// CLÉ CANONIQUE d'un tuple de dims JSON (fusion group-by hot∪cold). Sérialisation JSON déterministe : deux
/// tuples de dims ÉGAUX (même type + valeur, ex. `severity=2` entier des deux côtés, `src_ip='10.0.0.1'`
/// texte des deux côtés) produisent la MÊME clé -> leurs counts s'ADDITIONNENT (jamais dupliqués/écrasés).
fn dims_key(dims: &[Value]) -> String {
    Value::Array(dims.to_vec()).to_string()
}

/// Découpe une ligne d'agrégat `[dim0,…,dimK,count]` en (dims, count). `count` = DERNIÈRE colonne (entier).
fn split_group_row(mut row: Vec<Value>) -> (Vec<Value>, i64) {
    let count = row.pop().and_then(|v| v.as_i64()).unwrap_or(0);
    (row, count)
}

/// Lignes `rows` d'un `Value` {columns,rows} -> `Vec<Vec<Value>>` (clone). Vide si absent/mal formé.
fn value_rows(v: &Value) -> Vec<Vec<Value>> {
    v["rows"]
        .as_array()
        .map(|rs| rs.iter().filter_map(|r| r.as_array().cloned()).collect())
        .unwrap_or_default()
}

/// #18 P4b — HOT PARTIAL : agrégat/projection de BASE (SANS `sort`/`head`) sur la partie HOT `[boundary, q_to]`,
/// via la machinerie EXACTE de l'oracle restreinte au hot. `hot_base_soql` = `search <filtres> | <stats
/// count[ by dims] | table cols>` (les étapes `sort`/`head` sont RETIRÉES : le merge re-trie/re-head APRÈS
/// fusion). Compile masques VIDES (gate #3) + `env` (parité avec le SQL de l'oracle) puis exécute via
/// `cold_union_query(q_from=boundary, q_to, boundary)` -> pas d'hydratation cold -> vue `event WHERE
/// ts>=boundary` (masquée #45 comme l'oracle). Renvoie le `Value` {columns,rows} du hot.
#[allow(clippy::too_many_arguments)]
fn hot_partial(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    boundary: i64,
    q_to: i64,
    hot_base_soql: &str,
    dim_preds: &[DimEq],
    budget_ms: u64,
    qid: Option<&str>,
) -> Result<Value, String> {
    let masks = guatx_core::soql::FieldMaskSet::new(); // gate #3 : masques vides -> compile byte-identique
    let hot_sql = crate::soql_glue::soql_to_sql_masked_x(hot_base_soql, boundary, q_to, env_filter, &masks)?;
    // q_from=boundary -> open_cold_union : hi=boundary-1 < lo=boundary -> AUCUNE hydratation cold -> la vue
    // d'union = `event WHERE ts>=boundary` SEULE (cold-arm vide). C'est EXACTEMENT la contribution hot de
    // l'oracle (même masquage/authorizer/budget) -> parité hot par CONSTRUCTION.
    // `q_from = boundary` -> AUCUNE hydratation froide -> la réponse est STRUCTURELLEMENT exacte. Un
    // `Truncated` ici serait un bug de ce chemin, pas une requête trop large -> Err fail-closed.
    let (answer, _meta) = cold_union_query(db_path, conf, env_filter, boundary, q_to, boundary, &hot_sql, None, budget_ms, qid, dim_preds)?;
    let (v, _total) = answer.expect_exact("P4b hot_partial")?;
    Ok(v)
}

/// #18 P4b — ROUTE DECISION + EXÉCUTION du merge hot∪cold pour une fenêtre CHEVAUCHANTE. Renvoie
/// `Ok(Some(value))` si SERVI par le merge vectorisé (== `cold_union_query`) ; `Ok(None)` si la requête DOIT
/// tomber en fallback (l'appelant appelle alors `cold_union_query` VERBATIM) ; `Err` sur corruption cold
/// (fail-closed). Met à jour les compteurs de route. À appeler depuis `spawn_blocking` (I/O + déchiffrement +
/// requête hot SQLite). Gates : GATE 0 (armé par défaut), cold ON, masques vides, FENÊTRE CHEVAUCHANTE
/// (`q_from < boundary <= q_to`, ou `q_to<=0` = non borné haut = atteint le hot), forme vectorisable, cap
/// (froid `[lo,boundary-1]` <= cap sinon l'oracle tronquerait ; + total matérialisé pour `table`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn cold_vectorized_merge_try(
    db_path: &str,
    conf: &HashMap<String, String>,
    env_filter: Option<&str>,
    q_from: i64,
    q_to: i64,
    boundary: i64,
    soql: &str,
    masks_empty: bool,
    budget_ms: u64,
    qid: Option<&str>,
    dim_preds: &[DimEq],
) -> Result<Option<Value>, String> {
    let t0 = Instant::now();

    // GATE 0 : ARMÉ PAR DÉFAUT (comme P4a) ; `=0` désarme et fait retomber sur un chemin qui REFUSE.
    if !cold_vectorized_armed(conf) {
        note_fallback();
        return Ok(None);
    }
    // GATE 1 : cold ON.
    if !cold_tier_runtime_on(conf) {
        note_fallback();
        return Ok(None);
    }
    // GATE 3 : masques vides (HASH/MASK non reproductibles par le kernel) -> fallback.
    if !masks_empty {
        note_fallback();
        return Ok(None);
    }
    // GATE 2 : fenêtre CHEVAUCHANTE (strictement DANS la fenêtre). froid présent : q_from < boundary. hot
    // atteint : q_to >= boundary OU q_to <= 0 (non borné haut -> atteint « maintenant » = hot). Le pur-froid
    // (`0 < q_to < boundary`, routé par P4a) et le pur-hot (`boundary <= q_from`) sont DÉCLINÉS ici.
    let straddles = q_from < boundary && (q_to <= 0 || q_to >= boundary);
    if !straddles {
        note_fallback();
        return Ok(None);
    }
    // GATE 4 : forme vectorisable (count / group-by / top-N / table sur colonnes physiques).
    let plan = match map_soql(soql) {
        Some(p) => p,
        None => {
            note_fallback();
            return Ok(None);
        }
    };
    let extra: Vec<&str> = match &plan.agg {
        VecAgg::Count => vec![],
        VecAgg::GroupCount(d) | VecAgg::TopN(d, _, _) => d.iter().map(|s| &**s).collect(),
        VecAgg::Materialize(p, _) => p.iter().map(|s| &**s).collect(),
    };
    if !can_vectorize(&plan.pred, &extra) {
        note_fallback();
        return Ok(None);
    }

    // Fenêtre FROIDE effective `[lo, boundary-1]` (mirror `open_cold_union` : le cold s'arrête à boundary-1).
    // borne basse = q_from si bornée, sinon le plus vieux jour scellé.
    let hi = boundary - 1;
    let conn = open_seal_conn(db_path)?;
    let lo = if q_from > 0 {
        q_from
    } else {
        conn.query_row("SELECT MIN(day) FROM cold_seal", [], |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten()
            .map(|d| d * SECS_PER_DAY)
            .unwrap_or(hi)
    };
    drop(conn);

    // Deny-set du tenant (mirror open_cold_union / P4a) — VIDE quand masks_empty en production ; le harnais
    // peut l'injecter DIRECTEMENT pour exercer le masquage kernel #45 (denied()) côté froid ; côté hot, le
    // MÊME deny est appliqué par `cold_union_query` (via `union_proj`) -> masquage identique des deux côtés.
    let deny: std::collections::HashSet<String> =
        crate::field_deny_cols_cell().read().get(db_path).cloned().unwrap_or_default();

    // #28 P3.5 — GARDE COLONNE-DÉNIÉE #45 : jamais d'élagage seal sur une dim déniée (identique à P4a).
    let eff_preds: Vec<DimEq> = if deny.is_empty() {
        dim_preds.to_vec()
    } else {
        dim_preds
            .iter()
            .filter(|p| !deny.iter().any(|d| d.eq_ignore_ascii_case(p.dim.col_name())))
            .cloned()
            .collect()
    };

    let scan = match plan_scan(db_path, conf, env_filter, lo, hi, &eff_preds)? {
        Some(s) => s,
        None => {
            // Pas de clé cold lisible -> partie froide VIDE ; le résultat == la SEULE partie hot (l'oracle
            // hydrate 0 ligne cold). On délègue au fallback complet (cold_union_query) : plus simple et sûr
            // (aucune duplication du chemin hot pur ; ce cas est marginal : cold ON mais clé absente).
            note_fallback();
            return Ok(None);
        }
    };
    note_prune(scan.pruned, scan.files.len());

    // GATE 5 (cap FROID) — MÊME restriction qu'en P4a : elle ne vaut plus que pour la MATÉRIALISATION.
    // Pour un agrégat, retomber sur l'oracle au-delà du cap, c'est retomber sur un agrégat calculé sur
    // `cold_hydrate_row_cap` lignes, donc sur un nombre faux. Le merge, lui, calcule le froid EXACTEMENT
    // (kernels) et le hot EXACTEMENT (SQLite), et la somme de deux exacts est exacte.
    // (Le gate d'oracle qui SUBSISTE côté groupes — `oracle_would_truncate_groups` — porte sur autre chose :
    // le HOT-arm de l'oracle borne sa SORTIE à `cap` GROUPES, donc au-delà le merge lui-même serait incomplet.)
    let cap = cold_hydrate_row_cap() as i64;
    if matches!(plan.agg, VecAgg::Materialize(..)) && window_rows_capped(&scan, lo, hi, &deny, cap)?.is_none() {
        note_fallback();
        return Ok(None);
    }

    // Prédicat COMPLET froid = filtre utilisateur ∧ fenêtre `[lo, boundary-1]`.
    let ts_pred = Pred::And(vec![
        Pred::Int { col: "ts", op: IntOp::Ge, val: lo },
        Pred::Int { col: "ts", op: IntOp::Le, val: hi },
    ]);
    let full = match &plan.pred {
        Pred::True => ts_pred,
        _ => Pred::And(vec![clone_pred(&plan.pred), ts_pred]),
    };

    // GXQL de base HOT (SANS sort/head) : `stages[0] | stages[1]` (map_soql garantit >= 2 étages ; l'étage 1
    // porte le `stats count[ by …]` OU le `table …`, les `sort`/`head` éventuels sont en aval -> retirés).
    let stages = guatx_core::soql::soql_split_pipes(soql);
    if stages.len() < 2 {
        note_fallback();
        return Ok(None); // défense (map_soql l'exclut déjà)
    }
    let hot_base = format!("{} | {}", stages[0].trim(), stages[1].trim());

    let cols = plan_columns(&plan.agg);
    match &plan.agg {
        VecAgg::Count => {
            // FROID : somme des counts vectorisés (#18 P6 : décode PARALLÈLE, fusion commutative). HOT : count
            // SQLite sur `[boundary, q_to]`.
            let cold_total = par_count(&scan, &full, &deny)?;
            let hv = hot_partial(db_path, conf, env_filter, boundary, q_to, &hot_base, dim_preds, budget_ms, qid)?;
            let hot_total = value_rows(&hv).first().and_then(|r| r.first()).and_then(|v| v.as_i64()).unwrap_or(0);
            note_vec();
            Ok(Some(finalize(cols, vec![vec![json!(cold_total + hot_total)]], false, t0)))
        }
        VecAgg::GroupCount(dims) | VecAgg::TopN(dims, _, _) => {
            // FROID : group-by count vectorisé (map non tronquée). HOT : group-by count SQLite (SANS head).
            let cold_map = scan_group(&scan, &full, dims, &deny, cold_group_max(conf))?;
            let hv = hot_partial(db_path, conf, env_filter, boundary, q_to, &hot_base, dim_preds, budget_ms, qid)?;
            let hot_rows = value_rows(&hv);
            // FIX #18 P4b-cap — l'oracle groupe (froid∪hot) via `run_on_conn`, qui BORNE sa SORTIE à `cap`
            // GROUPES ; et son HOT-arm interne (`count by dims` SANS limite) est LUI-MÊME capé à `cap`. Le nombre
            // de groupes HOT rendus est donc `hot_rows.len()` (déjà capé par `run_on_conn`) : `>= cap` = hot
            // POSSIBLEMENT tronqué (subset arbitraire) -> le merge/top-N raterait des groupes. On mémorise ce
            // compte AVANT la fusion (la garde `oracle_would_truncate_groups` teste hot ET le combiné mergé).
            let hot_group_count = hot_rows.len() as i64;
            // FUSION par clé canonique de dims -> somme des counts (clé des DEUX côtés = ADDITION).
            let mut merged: std::collections::HashMap<String, (Vec<Value>, i64)> = std::collections::HashMap::new();
            let cold_pairs: Vec<(GroupKey, i64)> = cold_map.into_iter().collect();
            for row in group_rows(&cold_pairs, dims) {
                let (d, c) = split_group_row(row);
                let e = merged.entry(dims_key(&d)).or_insert((d, 0));
                e.1 += c;
            }
            for row in hot_rows {
                let (d, c) = split_group_row(row);
                let e = merged.entry(dims_key(&d)).or_insert((d, 0));
                e.1 += c;
            }
            let mut groups: Vec<(Vec<Value>, i64)> = merged.into_values().collect();
            // FIX #18 P4b-cap (group-by ET top-N, AVANT la garde tie-au-bord) : si l'oracle tronquerait — HOT-arm
            // capé (`hot_group_count >= cap`) OU groupes MERGÉS `> cap` (l'oracle caperait le COMBINÉ) — P4b ne
            // peut PAS garantir la parité (merge incomplet / sur-ensemble) -> FALLBACK vers `cold_union_query`.
            if oracle_would_truncate_groups(hot_group_count, groups.len() as i64, cap) {
                note_fallback();
                return Ok(None);
            }
            match &plan.agg {
                VecAgg::TopN(_, asc, n) => {
                    // Re-tri COMPLET par count (DESC défaut / ASC si `sort +count`), tie-break clé canonique
                    // (déterministe ; l'ordre intra-égalité n'est PAS observable — le harnais compare le
                    // multiset). On n'a PAS encore tronqué : il faut inspecter la ligne juste APRÈS le head-cut.
                    if *asc {
                        groups.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| dims_key(&a.0).cmp(&dims_key(&b.0))));
                    } else {
                        groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| dims_key(&a.0).cmp(&dims_key(&b.0))));
                    }
                    // Garde tie-au-bord (P4a, APRÈS merge) : si count[n-1]==count[n], l'égalité STRADDLE le
                    // head-cut -> quels membres entrent est AMBIGU (ordre intra-égalité de l'oracle indéfini) ->
                    // fallback. Cut strict / < n groupes / n==0 -> SET déterminé par le count seul == oracle.
                    if *n >= 1 && *n < groups.len() && groups[*n - 1].1 == groups[*n].1 {
                        note_fallback();
                        return Ok(None);
                    }
                    groups.truncate(*n);
                }
                _ => {
                    // group-by nu : ordre canonique déterministe (le harnais compare normalisé).
                    groups.sort_by(|a, b| dims_key(&a.0).cmp(&dims_key(&b.0)));
                }
            }
            let rows: Vec<Vec<Value>> = groups
                .into_iter()
                .map(|(mut d, c)| {
                    d.push(json!(c));
                    d
                })
                .collect();
            note_vec();
            Ok(Some(finalize(cols, rows, false, t0)))
        }
        VecAgg::Materialize(proj, head) => {
            // FROID : matérialise TOUTES les lignes matchantes (<= cold window <= cap, gate 5) SANS head.
            // #18 P6 — décode PARALLÈLE borné ; l'ordre (canonique) n'est de toute façon PAS observable ici (le
            // merge ne route QUE sans troncature -> comparaison multiset), mais on le préserve gratuitement.
            let cold_rows: Vec<Vec<Value>> = par_materialize_files(&scan, &full, proj, cap as usize, &deny)?
                .into_iter()
                .map(|r| r.into_iter().map(sqlval_to_json).collect())
                .collect();
            // HOT : matérialise TOUTES les lignes hot matchantes (hot_base = `| table cols`, SANS head).
            let hv = hot_partial(db_path, conf, env_filter, boundary, q_to, &hot_base, dim_preds, budget_ms, qid)?;
            let hot_rows = value_rows(&hv);
            let total = (cold_rows.len() + hot_rows.len()) as i64;
            // L'ordre de l'`UNION ALL` de l'oracle (hot-arm puis cold-arm, sous plan SQLite) n'est PAS
            // reproductible de façon fiable. On ne route donc la matérialisation QUE quand elle ne TRONQUE
            // PAS -> le multiset rendu == l'oracle quel que soit l'ordre. Sinon FALLBACK (conservateur).
            //
            // FIX #18 P4b-cap — l'oracle borne sa SORTIE à `cap` (`run_on_conn`) EN PLUS du `LIMIT N` : il rend
            // `min(N, cap, total)` lignes, `truncated` dès que `total > min(N, cap)`. Un `head N` EXPLICITE ne
            // suffit donc PAS à garantir la parité si `N > cap` (l'ancienne garde ne testait que `total > N` et
            // ROUTAIT un résultat plus complet que l'oracle tronqué -> DIVERGENCE). La borne de sortie effective
            // est `min(N, cap)` pour un head explicite, `cap` sinon (`oracle_would_truncate_rows`).
            if oracle_would_truncate_rows(total, *head, cap) {
                note_fallback();
                return Ok(None);
            }
            // Pas de troncature -> concat (hot puis cold, comme l'`UNION ALL` de l'oracle ; l'ordre n'est de
            // toute façon pas observable ici puisqu'on ne tronque pas). truncated=false (parité).
            let mut rows = hot_rows;
            rows.extend(cold_rows);
            note_vec();
            Ok(Some(finalize(cols, rows, false, t0)))
        }
    }
}

/// CLONE d'un `Pred` (le merge combine `plan.pred` avec la fenêtre froide SANS consommer `plan`). `regex::Regex`
/// est `Clone` ; les autres variantes le sont trivialement. Miroir structurel de `Pred`.
fn clone_pred(p: &Pred) -> Pred {
    match p {
        Pred::True => Pred::True,
        Pred::Int { col, op, val } => Pred::Int { col, op: *op, val: *val },
        Pred::StrEq { col, val } => Pred::StrEq { col, val: val.clone() },
        Pred::StrIn { col, vals } => Pred::StrIn { col, vals: vals.clone() },
        Pred::Like { col, pat } => Pred::Like { col, pat: pat.clone() },
        Pred::Contains { col, needle } => Pred::Contains { col, needle: needle.clone() },
        Pred::Regex { col, re } => Pred::Regex { col, re: re.clone() },
        Pred::And(v) => Pred::And(v.iter().map(clone_pred).collect()),
        Pred::Or(v) => Pred::Or(v.iter().map(clone_pred).collect()),
        Pred::Not(q) => Pred::Not(Box::new(clone_pred(q))),
    }
}
