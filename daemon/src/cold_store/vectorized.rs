//! cold_store::vectorized — #18 P2 : MOTEUR DE REQUÊTE VECTORISÉ sur les `ColumnBatch` (buffers colonnes typés
//! d'un row-group), STREAMING row-group par row-group, SANS jamais matérialiser toutes les lignes ni passer par
//! SQLite. C'est ici que se RÉALISE le gain de perf du tier colonnaire : count / group-by (mono ET multi-dim) /
//! filtre WHERE (plage ts, comparaison severity, égalité dims, LIKE/substring, regex) / top-N / matérialisation
//! BORNÉE (uniquement les colonnes projetées des lignes sélectionnées). RAM bornée : agrégats + résultat plafonné
//! seulement, jamais tout le dataset en lignes.
//!
//! MASQUAGE #45 (invariant sécu, NON NÉGOCIABLE — RÉUTILISÉ, jamais ré-inventé) : le moteur consulte le MÊME
//! deny-set que le chemin hydraté (`field_deny_cols_cell()`, keyé db_path) via `denied()`, dont la règle
//! (`eq_ignore_ascii_case`) est IDENTIQUE à `union_proj`/`open_cold_union` de `reader.rs`. Une colonne déniée
//! (1) n'est JAMAIS décodée (mirroir du `needed` de `open_cold_union` qui l'exclut) et (2) lit NULL partout —
//! filtre, clé de group-by, projection — EXACTEMENT comme `union_proj` émet `NULL AS c` avant que le SQL compilé
//! ne s'exécute. Une clé de group-by NULL forme le groupe NULL (comme `GROUP BY` de SQLite).
//!
//! LOGIQUE TRIVALENTE (TRUE/FALSE/UNKNOWN — parité EXACTE avec le WHERE SQL 3VL) : le prédicat est évalué en
//! DEUX masques parallèles `sel` (valeur de vérité quand connue) + `known` (false == UNKNOWN). Une égalité / IN /
//! LIKE / instr NATIVE sur NULL vaut UNKNOWN (`NULL = x` -> NULL en SQLite) ; l'UDF `regexp` (utilisée AUSSI en
//! hot) renvoie un FALSE CONCRET sur NULL/non-texte (`Ok(false)`) donc `col REGEXP p` sur NULL vaut FALSE connu
//! (parité hot). `Not` respecte NOT T=F, NOT F=T, **NOT U=U** : une négation ne « ressuscite » JAMAIS une ligne
//! NULL/déniée (le bug corrigé). La SÉLECTION finale (ce que count/group-by/materialize consomment) = TRUE SEUL
//! (`known && sel`) : FALSE ET UNKNOWN sont exclus — exactement `WHERE`.
//!
//! CORRECTION > VITESSE : les FORMES SOQL couvertes ci-dessous sont vectorisées ; toute forme NON couverte DOIT
//! tomber en fallback SQLite (jamais un faux résultat). `can_vectorize` matérialise ce principe (le planner
//! complet est P4). Ex. non couverts ICI (fallback) : extraction JSON `json_extract(fields,'$.k')` comme clé/
//! prédicat (le kernel opère sur les COLONNES PHYSIQUES + la colonne `fields` en TEXTE brut), OR/agrégats
//! autres que COUNT, DISTINCT multi-colonnes hors group-by.
//!
//! P2 = les KERNELS + la PARITÉ + le BENCH prouvés. AUCUN câblage dans le routeur de requête live (c'est P4).

// P2 consomme la surface de décodage colonnaire du sibling `reader` (pub(super)) + le trait FileReader parquet.
// P3 ajoute le driver d'élagage row-group `for_each_batch_pruned` + les compteurs `RgPruneStats`.
use super::reader::{decode_batch, for_each_batch_pruned, ColData, ColumnBatch, RgPruneStats, PARQUET_COLS};
use parquet::file::metadata::RowGroupMetaData;
use parquet::file::reader::FileReader;
use parquet::file::statistics::Statistics;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// Opérateur de comparaison entier (sur `ts` / `severity`). Sémantique SQLite : NULL op x -> non-vrai.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IntOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl IntOp {
    fn apply(self, a: i64, b: i64) -> bool {
        match self {
            IntOp::Eq => a == b,
            IntOp::Ne => a != b,
            IntOp::Lt => a < b,
            IntOp::Le => a <= b,
            IntOp::Gt => a > b,
            IntOp::Ge => a >= b,
        }
    }
    /// Rendu SQL de l'opérateur (pour l'oracle de parité).
    pub(super) fn sql(self) -> &'static str {
        match self {
            IntOp::Eq => "=",
            IntOp::Ne => "<>",
            IntOp::Lt => "<",
            IntOp::Le => "<=",
            IntOp::Gt => ">",
            IntOp::Ge => ">=",
        }
    }
}

/// Prédicat WHERE vectorisé. Évalué en LOGIQUE TRIVALENTE -> deux masques `sel`/`known` par batch (PAS de
/// matérialisation de lignes ; cf. `eval_pred`). Colonnes NULL (déniées OU def=0) -> UNKNOWN pour les feuilles
/// natives (=/IN/LIKE/instr), FALSE concret pour `Regex` (UDF `regexp` -> hot). Sélection finale = TRUE seul.
pub(super) enum Pred {
    /// Aucun filtre (tout sélectionné).
    True,
    /// `col <op> val` sur une colonne INT64 (`ts` / `severity`).
    Int { col: &'static str, op: IntOp, val: i64 },
    /// `col = val` (égalité exacte) sur une colonne string.
    StrEq { col: &'static str, val: String },
    /// `col IN (…)` sur une colonne string.
    StrIn { col: &'static str, vals: HashSet<String> },
    /// `col LIKE pat` — sémantique SQLite LIKE par défaut : repli ASCII (A-Z<->a-z), `%` = 0+ caractères,
    /// `_` = exactement 1 caractère, pas d'ESCAPE. Le reste littéral (avec repli ASCII).
    Like { col: &'static str, pat: String },
    /// Sous-chaîne sensible à la casse (== `str::contains` == `instr(col, needle) > 0` binaire).
    Contains { col: &'static str, needle: String },
    /// Regex `regex::Regex::is_match` — sémantique IDENTIQUE à l'UDF SQLite `regexp` (NULL/non-texte -> faux).
    Regex { col: &'static str, re: regex::Regex },
    And(Vec<Pred>),
    Or(Vec<Pred>),
    Not(Box<Pred>),
}

/// MASQUAGE #45 — RÉUTILISE la règle EXACTE de `union_proj`/`open_cold_union` (`reader.rs`) : une colonne est
/// déniée si le deny-set du tenant la contient (comparaison insensible à la casse ASCII). AUCUNE ré-invention :
/// le deny-set provient de `field_deny_cols_cell()`, la MÊME source que le chemin hydraté.
pub(super) fn denied(deny: &HashSet<String>, col: &str) -> bool {
    deny.iter().any(|d| d.eq_ignore_ascii_case(col))
}

/// Colonnes RÉFÉRENCÉES par un prédicat (pour calculer le set à décoder = référencées ∪ group ∪ proj, MOINS deny).
fn pred_cols<'a>(p: &'a Pred, out: &mut Vec<&'a str>) {
    match p {
        Pred::True => {}
        Pred::Int { col, .. } => out.push(col),
        Pred::StrEq { col, .. } => out.push(col),
        Pred::StrIn { col, .. } => out.push(col),
        Pred::Like { col, .. } => out.push(col),
        Pred::Contains { col, .. } => out.push(col),
        Pred::Regex { col, .. } => out.push(col),
        Pred::And(v) | Pred::Or(v) => v.iter().for_each(|q| pred_cols(q, out)),
        Pred::Not(q) => pred_cols(q, out),
    }
}

// ---- ACCÈS COLONNE avec MASQUAGE #45 (déni -> NULL, jamais décodé) --------------------------------

/// Vue d'une colonne INT64 pour un batch, masquage appliqué. `Some(slice)` = colonne décodée présente ;
/// `None` = déniée (#45) -> lue NULL partout (comparaison FAUSSE). Colonne absente non-déniée = bug moteur (Err).
fn int_view<'a>(b: &'a ColumnBatch, deny: &HashSet<String>, col: &str) -> Result<Option<&'a [i64]>, String> {
    if denied(deny, col) {
        return Ok(None); // #45 : déniée -> NULL (jamais décodée)
    }
    match b.col(col) {
        Some(ColData::I64(v)) => Ok(Some(v.as_slice())),
        Some(ColData::Str(_)) => Err(format!("vectorisé: colonne '{col}' attendue INT64, trouvée string")),
        None => Err(format!("vectorisé: colonne INT64 '{col}' non décodée (bug moteur : référencée mais absente)")),
    }
}

/// Vue d'une colonne string pour un batch, masquage appliqué. `Some(slice)` = décodée ; `None` = déniée (#45)
/// -> NULL partout. Colonne absente non-déniée = bug moteur (Err).
fn str_view<'a>(b: &'a ColumnBatch, deny: &HashSet<String>, col: &str) -> Result<Option<&'a [Option<String>]>, String> {
    if denied(deny, col) {
        return Ok(None);
    }
    match b.col(col) {
        Some(ColData::Str(v)) => Ok(Some(v.as_slice())),
        Some(ColData::I64(_)) => Err(format!("vectorisé: colonne '{col}' attendue string, trouvée INT64")),
        None => Err(format!("vectorisé: colonne string '{col}' non décodée (bug moteur : référencée mais absente)")),
    }
}

// ---- LIKE façon SQLite (repli ASCII, % et _) ------------------------------------------------------

/// Match `LIKE` compatible SQLite (par défaut) : repli de casse ASCII SEULEMENT, `%` = 0+ caractères Unicode,
/// `_` = exactement 1 caractère Unicode, pas d'ESCAPE. Implémentation glob par backtracking sur `Vec<char>`.
fn like_match(pat_chars: &[char], text: &str) -> bool {
    // Repli ASCII des DEUX côtés (SQLite ne replie QUE A-Z) -> comparaison de caractères déjà repliés.
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    glob(pat_chars, &t)
}

fn glob(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '%' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if pi < p.len() && (p[pi] == '_' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

// ---- ÉVALUATION TRIVALENTE DU PRÉDICAT -> (sel, known) --------------------------------------------

/// Évalue `pred` sur `b` en LOGIQUE TRIVALENTE, écrivant DEUX masques parallèles (longueur == `b.nrows`) :
/// `sel[i]` = valeur de vérité de la ligne QUAND connue ; `known[i]` = true si connue (false == UNKNOWN, la
/// valeur de `sel[i]` est alors non signifiante). Masquage #45 appliqué (colonne déniée -> lue NULL). Table de
/// vérité SQL 3VL respectée EXACTEMENT (feuilles natives NULL -> UNKNOWN ; `Regex` NULL -> FALSE connu, comme
/// l'UDF `regexp` en hot ; And/Or/Not 3-valués ; NOT U = U). Incohérence de colonne -> Err (fail-closed).
///
/// NB : ce n'est PAS le masque de sélection final — dérive-le en UN POINT via `eval_selection` (`known && sel`).
fn eval_pred(pred: &Pred, b: &ColumnBatch, deny: &HashSet<String>, sel: &mut [bool], known: &mut [bool]) -> Result<(), String> {
    debug_assert_eq!(sel.len(), b.nrows);
    debug_assert_eq!(known.len(), b.nrows);
    // Applique une feuille STRING générique : `pred_true(s)` = valeur de vérité sur une valeur PRÉSENTE ;
    // `null_known` = comportement sur NULL (déniée ou def=0) : `false` == UNKNOWN (natif =/IN/LIKE/instr),
    // `true` (avec sel=false) == FALSE connu (UDF `regexp`). Une colonne déniée -> vue None -> tout NULL.
    fn str_leaf(
        b: &ColumnBatch,
        deny: &HashSet<String>,
        col: &str,
        sel: &mut [bool],
        known: &mut [bool],
        null_known: bool,
        mut pred_true: impl FnMut(&str) -> bool,
    ) -> Result<(), String> {
        let view = str_view(b, deny, col)?; // None == déniée (tout NULL)
        for i in 0..b.nrows {
            match view.and_then(|v| v[i].as_ref()) {
                Some(s) => {
                    known[i] = true;
                    sel[i] = pred_true(s);
                }
                None => {
                    // NULL : UNKNOWN (natif) ou FALSE connu (regexp).
                    known[i] = null_known;
                    sel[i] = false;
                }
            }
        }
        Ok(())
    }
    match pred {
        Pred::True => {
            for i in 0..b.nrows {
                known[i] = true;
                sel[i] = true;
            }
        }
        // ts/severity : REQUIRED (jamais NULL) -> known=true. Si DÉNIÉE (int_view None) -> NULL -> UNKNOWN
        // (parité `union_proj` : `severity >= x` sur NULL -> NULL en SQLite).
        Pred::Int { col, op, val } => match int_view(b, deny, col)? {
            None => known.iter_mut().for_each(|k| *k = false), // déniée -> NULL -> UNKNOWN
            Some(v) => {
                for i in 0..b.nrows {
                    known[i] = true;
                    sel[i] = op.apply(v[i], *val);
                }
            }
        },
        // Feuilles NATIVES (=/IN/LIKE/instr) : NULL -> UNKNOWN (`null_known=false`).
        Pred::StrEq { col, val } => str_leaf(b, deny, col, sel, known, false, |s| s == val.as_str())?,
        Pred::StrIn { col, vals } => str_leaf(b, deny, col, sel, known, false, |s| vals.contains(s))?,
        Pred::Like { col, pat } => {
            let pc: Vec<char> = pat.chars().map(|c| c.to_ascii_lowercase()).collect();
            str_leaf(b, deny, col, sel, known, false, |s| like_match(&pc, s))?
        }
        Pred::Contains { col, needle } => {
            str_leaf(b, deny, col, sel, known, false, |s| s.contains(needle.as_str()))?
        }
        // `Regex` : l'UDF `regexp` (hot ET oracle) renvoie un FALSE CONCRET sur NULL/non-texte (`Ok(false)`),
        // pas NULL -> `col REGEXP p` sur NULL = FALSE CONNU (`null_known=true`, sel=false). Conséquence :
        // `NOT (col REGEXP p)` sur NULL = TRUE (parité hot), là où une feuille native donnerait UNKNOWN.
        Pred::Regex { col, re } => str_leaf(b, deny, col, sel, known, true, |s| re.is_match(s))?,
        // AND 3VL : F si un enfant F (même si l'autre U) ; T si tous T ; sinon U.
        Pred::And(qs) => {
            // acc = TRUE (identité de AND).
            for i in 0..b.nrows {
                known[i] = true;
                sel[i] = true;
            }
            let mut cs = vec![false; b.nrows];
            let mut ck = vec![true; b.nrows];
            for q in qs {
                eval_pred(q, b, deny, &mut cs, &mut ck)?;
                for i in 0..b.nrows {
                    let a_false = known[i] && !sel[i];
                    let b_false = ck[i] && !cs[i];
                    let a_true = known[i] && sel[i];
                    let b_true = ck[i] && cs[i];
                    if a_false || b_false {
                        known[i] = true;
                        sel[i] = false; // F
                    } else if a_true && b_true {
                        known[i] = true;
                        sel[i] = true; // T
                    } else {
                        known[i] = false; // U
                    }
                }
            }
        }
        // OR 3VL : T si un enfant T (même si l'autre U) ; F si tous F ; sinon U.
        Pred::Or(qs) => {
            // acc = FALSE (identité de OR).
            for i in 0..b.nrows {
                known[i] = true;
                sel[i] = false;
            }
            let mut cs = vec![false; b.nrows];
            let mut ck = vec![true; b.nrows];
            for q in qs {
                eval_pred(q, b, deny, &mut cs, &mut ck)?;
                for i in 0..b.nrows {
                    let a_true = known[i] && sel[i];
                    let b_true = ck[i] && cs[i];
                    let a_false = known[i] && !sel[i];
                    let b_false = ck[i] && !cs[i];
                    if a_true || b_true {
                        known[i] = true;
                        sel[i] = true; // T
                    } else if a_false && b_false {
                        known[i] = true;
                        sel[i] = false; // F
                    } else {
                        known[i] = false; // U
                    }
                }
            }
        }
        // NOT 3VL : NOT T=F, NOT F=T, NOT U=U (le CŒUR du fix : UNKNOWN reste UNKNOWN, jamais ressuscité).
        Pred::Not(q) => {
            eval_pred(q, b, deny, sel, known)?;
            for i in 0..b.nrows {
                if known[i] {
                    sel[i] = !sel[i];
                }
            }
        }
    }
    Ok(())
}

/// MASQUE DE SÉLECTION FINALE (== `WHERE` SQL) : une ligne passe SSI TRUE (`known && sel`) — FALSE et UNKNOWN
/// exclus. POINT UNIQUE de dérivation de la logique trivalente vers le `Vec<bool>` que consomment
/// count/group-by/materialize. Alloue seulement le masque `known` auxiliaire (le buffer appelant sert de `sel`).
pub(super) fn eval_selection(pred: &Pred, b: &ColumnBatch, deny: &HashSet<String>, out: &mut [bool]) -> Result<(), String> {
    let mut known = vec![true; b.nrows];
    eval_pred(pred, b, deny, out, &mut known)?; // `out` tient `sel`
    for i in 0..b.nrows {
        out[i] = known[i] && out[i]; // TRUE seul
    }
    Ok(())
}

// ---- SET DE COLONNES À DÉCODER (référencées ∪ group ∪ proj, MOINS deny ; "ts" jamais forcé ici) ---

fn decode_set(pred: &Pred, extra: &[&str], deny: &HashSet<String>) -> Vec<&'static str> {
    let mut refs: Vec<&str> = Vec::new();
    pred_cols(pred, &mut refs);
    refs.extend_from_slice(extra);
    // Canonique + dédup + EXCLUSION des déniées (jamais décodées : #45, miroir de `open_cold_union.needed`).
    PARQUET_COLS
        .iter()
        .copied()
        .filter(|c| refs.contains(c) && !denied(deny, c))
        .collect()
}

// ---- #18 P3 : ÉLAGAGE ROW-GROUP (pushdown de prédicat sur les STATISTIQUES NATIVES Parquet) ---------
//
// PRINCIPE : chaque row-group porte, dans le footer Parquet (déchiffré), des statistiques CHUNK min/max +
// null_count par colonne (writer par défaut `EnabledStatistics::Page` -> stats de chunk écrites ; tronquées à
// 64 octets, ce qui reste une BORNE VALIDE — min <= toutes les valeurs <= max — donc seulement PLUS
// conservateur). AUCUN bloom filter Parquet (désactivé par défaut) : l'élagage d'égalité string repose sur
// min/max lexical (ordre BINARY/unsigned == comparaison d'octets). NB : le bloom d'égalité PRÉCIS existe, mais
// au niveau SEAL (#28 Phase B, `DimStats`), AVANT déchiffrement — couche orthogonale à ce pushdown intra-fichier.
//
// INVARIANT ABSOLU : `rg_can_match` renvoie `false` (skip) UNIQUEMENT quand les stats PROUVENT qu'aucune ligne
// ne peut satisfaire `pred`. Dans le MOINDRE doute -> `true` (décode). Un skip à tort = lignes manquantes =
// fausse détection SOC (même principe que le `seal` : « jamais rater une ligne »).

/// Index de fichier (== position dans `PARQUET_COLS`, schéma PLAT -> leaf index) d'une colonne physique.
fn col_file_idx(col: &str) -> Option<usize> {
    PARQUET_COLS.iter().position(|c| *c == col)
}

/// (min, max) INT64 du row-group pour `col` (ts/severity). `None` si stats absentes / min|max manquant / type
/// inattendu -> l'appelant reste conservateur (ne PRUNE PAS).
fn int_stats(rg: &RowGroupMetaData, col: &str) -> Option<(i64, i64)> {
    let idx = col_file_idx(col)?;
    match rg.column(idx).statistics()? {
        Statistics::Int64(vs) => Some((*vs.min_opt()?, *vs.max_opt()?)),
        _ => None,
    }
}

/// (min, max) OCTETS du row-group pour une colonne string `col` (ordre BINARY/unsigned == comparaison de
/// slices d'octets). `None` si stats absentes / colonne toute-NULL (min|max non posés) -> conservateur.
fn str_stats_bytes<'a>(rg: &'a RowGroupMetaData, col: &str) -> Option<(&'a [u8], &'a [u8])> {
    let idx = col_file_idx(col)?;
    let st = rg.column(idx).statistics()?;
    Some((st.min_bytes_opt()?, st.max_bytes_opt()?))
}

/// Une valeur INT `val` sous l'opérateur `op` est-elle PROUVÉE absente de `[min,max]` ? (ts/severity REQUIRED
/// -> jamais NULL ; les stats bornent TOUTES les lignes). Skip SÛR ssi aucune ligne ne peut satisfaire.
fn int_op_proves_empty(op: IntOp, val: i64, min: i64, max: i64) -> bool {
    match op {
        IntOp::Ge => max < val,             // toutes < val
        IntOp::Gt => max <= val,            // toutes <= val
        IntOp::Le => min > val,             // toutes > val
        IntOp::Lt => min >= val,            // toutes >= val
        IntOp::Eq => val < min || val > max, // val hors plage
        IntOp::Ne => min == max && min == val, // toutes == val -> aucune != val
    }
}

/// CŒUR DU PUSHDOWN : le row-group `rg` NE PEUT-IL PROUVABLEMENT contenir AUCUNE ligne satisfaisant `pred` ?
/// (Sur les statistiques natives min/max UNIQUEMENT.) Retourne `true` == PROUVÉ VIDE (skip sûr). Conservateur
/// PARTOUT ailleurs (`false` == on décode). Table de décision : cf. `rg_can_match`.
fn proves_no_match(pred: &Pred, rg: &RowGroupMetaData, deny: &HashSet<String>) -> bool {
    match pred {
        // Aucun filtre / négation / formes non-élaguables -> jamais de preuve de vide (on décode).
        Pred::True => false,
        // Not : CONSERVATEUR. min/max prouve rarement « TOUTES les lignes matchent » ; ne JAMAIS élaguer sous
        // Not (une preuve de vide sur l'enfant ne prouve PAS que `Not(enfant)` est vide — au contraire).
        Pred::Not(_) => false,
        Pred::Like { .. } | Pred::Contains { .. } | Pred::Regex { .. } => false,
        // AND : PROUVÉ vide si UN conjonct est prouvé vide (aucune ligne ne peut satisfaire l'ensemble).
        Pred::And(qs) => qs.iter().any(|q| proves_no_match(q, rg, deny)),
        // OR : PROUVÉ vide SEULEMENT si TOUS les disjoncts sont prouvés vides (non-vide requiert >=1 disjonct).
        Pred::Or(qs) => !qs.is_empty() && qs.iter().all(|q| proves_no_match(q, rg, deny)),
        // Int sur ts/severity. DÉNIÉE (#45) -> lue NULL par le moteur : NE JAMAIS élaguer sur ses vraies stats
        // (faux ET fuite d'info par timing/résultat) -> `false` (décode ; la feuille donnera UNKNOWN comme P2).
        Pred::Int { col, op, val } => {
            if denied(deny, col) {
                return false;
            }
            match int_stats(rg, col) {
                Some((min, max)) => int_op_proves_empty(*op, *val, min, max),
                None => false, // stats absentes -> conservateur
            }
        }
        // StrEq : PROUVÉ vide si `val` (octets) est STRICTEMENT hors [min,max] (absence exacte). DÉNIÉE -> false.
        Pred::StrEq { col, val } => {
            if denied(deny, col) {
                return false;
            }
            match str_stats_bytes(rg, col) {
                Some((mn, mx)) => {
                    let v = val.as_bytes();
                    v < mn || v > mx
                }
                None => false,
            }
        }
        // StrIn : PROUVÉ vide si TOUTES les valeurs cherchées sont hors [min,max]. DÉNIÉE -> false. IN vide ->
        // `all` sur ensemble vide == true (ne matche rien) -> skip correct.
        Pred::StrIn { col, vals } => {
            if denied(deny, col) {
                return false;
            }
            match str_stats_bytes(rg, col) {
                Some((mn, mx)) => vals.iter().all(|val| {
                    let v = val.as_bytes();
                    v < mn || v > mx
                }),
                None => false,
            }
        }
    }
}

/// #18 P3 — DÉCISION D'ÉLAGAGE ROW-GROUP. Renvoie `false` (SKIP le décode) SEULEMENT quand `proves_no_match`
/// établit qu'AUCUNE ligne du row-group ne peut satisfaire `pred` ; sinon `true` (on décode — conservateur).
///
/// TABLE DE DÉCISION CONSERVATRICE :
///   • `Int{col,op,val}` sur ts/severity (REQUIRED) : compare `val` au [min,max] du row-group.
///       Ge: skip si max<val · Gt: skip si max<=val · Le: skip si min>val · Lt: skip si min>=val
///       Eq: skip si val<min || val>max · Ne: skip si min==max==val · sinon décode.
///   • `StrEq{col,val}` : skip si `val` (octets) < min || > max (ordre BINARY/unsigned == octets).
///   • `StrIn{col,vals}` : skip si TOUTES les valeurs sont hors [min,max].
///   • `Like`/`Contains`/`Regex` : NON élaguable -> décode.
///   • `And(v)` : skip si UN enfant prouve vide. `Or(v)` : skip si TOUS prouvent vide. `Not(_)` : décode
///       (jamais d'élagage sous Not). `True` : décode.
///   • COLONNE DÉNIÉE (#45) : prédicat sur colonne déniée -> décode (elle est lue NULL : élaguer sur ses vraies
///       valeurs serait FAUX et une fuite d'info par timing/résultat).
///   • Stats absentes / min|max manquant / colonne toute-NULL : décode (conservateur).
pub(super) fn rg_can_match(pred: &Pred, rg: &RowGroupMetaData, deny: &HashSet<String>) -> bool {
    !proves_no_match(pred, rg, deny)
}

// ---- KERNEL : COUNT ------------------------------------------------------------------------------

/// COUNT(*) vectorisé sur `[pred]` : popcount du masque, accumulé cross-row-group, AVEC élagage row-group P3.
/// RAM O(1) hors le batch courant. Wrapper à pruning ON (`prune=true`) ; `vec_count_ex` expose le toggle + stats.
pub(super) fn vec_count(reader: &dyn FileReader, pred: &Pred, deny: &HashSet<String>) -> Result<i64, String> {
    let mut stats = RgPruneStats::default();
    vec_count_ex(reader, pred, deny, true, &mut stats)
}

/// COUNT(*) vectorisé avec toggle d'élagage `prune` + compteurs `RgPruneStats` (preuve on/off P3). `prune=false`
/// -> décode TOUS les row-groups (chemin de parité). Résultat IDENTIQUE quel que soit `prune` (invariant P3).
pub(super) fn vec_count_ex(
    reader: &dyn FileReader,
    pred: &Pred,
    deny: &HashSet<String>,
    prune: bool,
    stats: &mut RgPruneStats,
) -> Result<i64, String> {
    let cols = decode_set(pred, &[], deny);
    let mut total: i64 = 0;
    for_each_batch_pruned(reader, &cols, prune, stats, |rg| rg_can_match(pred, rg, deny), |b| {
        let mut mask = vec![false; b.nrows];
        eval_selection(pred, b, deny, &mut mask)?;
        total += mask.iter().filter(|m| **m).count() as i64;
        Ok(true)
    })?;
    Ok(total)
}

// ---- KERNEL : GROUP-BY (mono ET multi-dim), agrégat COUNT -----------------------------------------

/// Clé de group-by = un composant par dimension. Colonnes INT (`severity`) -> `Some(v.to_string())` (bijectif) ;
/// string -> `Option<String>` clonée ; déniée/NULL -> `None` (groupe NULL, comme `GROUP BY` de SQLite).
pub(super) type GroupKey = Vec<Option<String>>;

/// GROUP-BY vectorisé sur `dims` (1..N colonnes PHYSIQUES) avec agrégat COUNT, filtré par `pred`. Balayage
/// colonnaire des lignes SÉLECTIONNÉES -> `HashMap<clé, count>` accumulé cross-batch. RAM bornée aux GROUPES
/// DISTINCTS (agrégat), jamais aux lignes. C'est LA cible du group-by multi-dim (32s SQLite en prod).
pub(super) fn vec_group_count(
    reader: &dyn FileReader,
    pred: &Pred,
    dims: &[&'static str],
    deny: &HashSet<String>,
) -> Result<HashMap<GroupKey, i64>, String> {
    let mut stats = RgPruneStats::default();
    vec_group_count_ex(reader, pred, dims, deny, true, &mut stats)
}

/// GROUP-BY vectorisé avec toggle d'élagage `prune` + compteurs `RgPruneStats` (preuve on/off P3). `prune=false`
/// -> décode TOUS les row-groups (parité). Résultat IDENTIQUE quel que soit `prune` (invariant P3).
pub(super) fn vec_group_count_ex(
    reader: &dyn FileReader,
    pred: &Pred,
    dims: &[&'static str],
    deny: &HashSet<String>,
    prune: bool,
    stats: &mut RgPruneStats,
) -> Result<HashMap<GroupKey, i64>, String> {
    let cols = decode_set(pred, dims, deny);
    let mut agg: HashMap<GroupKey, i64> = HashMap::new();
    for_each_batch_pruned(reader, &cols, prune, stats, |rg| rg_can_match(pred, rg, deny), |b| {
        let mut mask = vec![false; b.nrows];
        eval_selection(pred, b, deny, &mut mask)?;
        // Pré-résout la vue de CHAQUE dimension (déniée -> None -> composant NULL).
        enum DimView<'a> {
            Null,
            Int(&'a [i64]),
            Str(&'a [Option<String>]),
        }
        let mut views: Vec<DimView> = Vec::with_capacity(dims.len());
        for d in dims {
            if denied(deny, d) {
                views.push(DimView::Null);
            } else {
                match b.col(d) {
                    Some(ColData::I64(v)) => views.push(DimView::Int(v.as_slice())),
                    Some(ColData::Str(v)) => views.push(DimView::Str(v.as_slice())),
                    None => return Err(format!("vectorisé group-by: dimension '{d}' non décodée")),
                }
            }
        }
        for i in 0..b.nrows {
            if !mask[i] {
                continue;
            }
            let mut key: GroupKey = Vec::with_capacity(dims.len());
            for v in &views {
                key.push(match v {
                    DimView::Null => None,
                    DimView::Int(s) => Some(s[i].to_string()),
                    DimView::Str(s) => s[i].clone(),
                });
            }
            *agg.entry(key).or_insert(0) += 1;
        }
        Ok(true)
    })?;
    Ok(agg)
}

/// TOP-N par count décroissant, tie-break DÉTERMINISTE (clé croissante lexicographique, `None` avant `Some`) —
/// aligné sur l'oracle `ORDER BY count DESC, k1 ASC, k2 ASC … LIMIT n`. Tri partiel (sélection des N premiers).
/// (Le planner P4a fait son propre tri complet pour détecter un tie au bord du head-cut ; ce kernel reste
/// exercé par le harnais de parité.)
#[allow(dead_code)]
pub(super) fn top_n(agg: &HashMap<GroupKey, i64>, n: usize) -> Vec<(GroupKey, i64)> {
    let mut v: Vec<(GroupKey, i64)> = agg.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

// ---- KERNEL : MATÉRIALISATION BORNÉE (search/list) -----------------------------------------------

/// Ligne matérialisée = valeurs des colonnes PROJETÉES (masquage #45 appliqué : déniée -> NULL). `Value` réutilisé
/// pour la parité de type avec le chemin SQLite.
pub(super) type MatRow = Vec<rusqlite::types::Value>;

/// MATÉRIALISE UNIQUEMENT les colonnes `proj` des lignes SÉLECTIONNÉES par `pred`, PLAFONNÉ à `cap` lignes
/// (fail-safe RAM, comme `cold_hydrate_row_cap`). `truncated=true` si le plafond est atteint. Arrêt anticipé du
/// streaming dès le plafond -> on ne décode pas les row-groups au-delà. Colonne déniée -> `Value::Null`.
pub(super) fn vec_materialize(
    reader: &dyn FileReader,
    pred: &Pred,
    proj: &[&'static str],
    cap: usize,
    deny: &HashSet<String>,
) -> Result<(Vec<MatRow>, bool), String> {
    let mut stats = RgPruneStats::default();
    vec_materialize_ex(reader, pred, proj, cap, deny, true, &mut stats)
}

/// MATÉRIALISATION vectorisée avec toggle d'élagage `prune` + compteurs `RgPruneStats` (preuve on/off P3).
/// `prune=false` -> décode TOUS les row-groups (parité). L'ensemble de lignes rendu est IDENTIQUE quel que soit
/// `prune` (invariant P3) — l'arrêt anticipé au plafond `cap` reste piloté par `f` (row-groups au-delà non
/// décodés), orthogonal à l'élagage.
#[allow(clippy::too_many_arguments)]
pub(super) fn vec_materialize_ex(
    reader: &dyn FileReader,
    pred: &Pred,
    proj: &[&'static str],
    cap: usize,
    deny: &HashSet<String>,
    prune: bool,
    stats: &mut RgPruneStats,
) -> Result<(Vec<MatRow>, bool), String> {
    use rusqlite::types::Value;
    let cols = decode_set(pred, proj, deny);
    let mut out: Vec<MatRow> = Vec::new();
    let mut truncated = false;
    for_each_batch_pruned(reader, &cols, prune, stats, |rg| rg_can_match(pred, rg, deny), |b| {
        let mut mask = vec![false; b.nrows];
        eval_selection(pred, b, deny, &mut mask)?;
        // Vue pré-résolue de chaque colonne projetée (déniée -> None -> NULL).
        enum PView<'a> {
            Null,
            Int(&'a [i64]),
            Str(&'a [Option<String>]),
        }
        let mut views: Vec<PView> = Vec::with_capacity(proj.len());
        for p in proj {
            if denied(deny, p) {
                views.push(PView::Null);
            } else {
                match b.col(p) {
                    Some(ColData::I64(v)) => views.push(PView::Int(v.as_slice())),
                    Some(ColData::Str(v)) => views.push(PView::Str(v.as_slice())),
                    None => return Err(format!("vectorisé materialize: colonne '{p}' non décodée")),
                }
            }
        }
        for i in 0..b.nrows {
            if !mask[i] {
                continue;
            }
            if out.len() >= cap {
                truncated = true;
                return Ok(false); // plafond -> stoppe le streaming (row-groups suivants non décodés)
            }
            let mut row: MatRow = Vec::with_capacity(proj.len());
            for v in &views {
                row.push(match v {
                    PView::Null => Value::Null,
                    PView::Int(s) => Value::Integer(s[i]),
                    PView::Str(s) => match &s[i] {
                        Some(t) => Value::Text(t.clone()),
                        None => Value::Null,
                    },
                });
            }
            out.push(row);
        }
        Ok(true)
    })?;
    Ok((out, truncated))
}

// ---- KERNEL : MATÉRIALISATION KEYSET (browse brut froid par curseur, RAM bornée à `limit`) --------
//
// ①a — Le browse Explore raw (`search source=X`) pagine des LIGNES BRUTES par curseur `(ts,id)`, ordre
// `ts DESC, id DESC`. L'ancien chemin (`cold_union_query` + `keyset_page_sql`) HYDRATE le froid dans SQLite
// PLAFONNÉ à `cold_hydrate_row_cap` PUIS filtre le curseur -> IMPOSSIBLE de paginer au-delà du cap. Ce kernel
// matérialise UNE page keyset DIRECTEMENT depuis le colonnaire, RAM bornée à `limit` lignes (MIN-tas) + un batch,
// QUEL QUE SOIT le volume froid -> 2 Go-safe, parcours INTÉGRAL sans cap.

/// `id` SYNTHÉTIQUE STABLE d'une ligne froide (le cold ne stocke PAS de rowid ; cf. `PARQUET_COLS`). Formule :
/// `seq * COLD_FILE_MAX_ROWS + position-dans-fichier`. `COLD_FILE_MAX_ROWS` (= plafond DUR de lignes/fichier) est
/// STRICTEMENT > toute position -> l'`id` est UNIQUE par `(day)` (un `seq` distinct par fichier, une position
/// distincte par ligne), donc UNIQUE par `ts` (un `ts` fixe -> un seul `day` = `floor(ts/86400)`). Il est MONOTONE
/// dans l'ordre canonique `(seq, position)` -> `(ts,id) DESC` restitue EXACTEMENT l'ordre que l'oracle
/// `cold_union_query` sert (rowid éphémère assigné dans le MÊME ordre canonique day/seq/position). DÉTERMINISTE
/// (fichier immuable) -> reproductible page après page (le `id` de curseur renvoyé au client se recalcule à
/// l'identique au scan suivant). Tie-break NÉCESSAIRE (firehose : N lignes au même `ts`) et cohérent avec le hot
/// (dont le tie-break est `event.id`, croissant dans le MÊME ordre d'insertion) — jamais comparé au hot (les tiers
/// ne partagent aucun `ts` : hot `ts>=boundary` > cold `ts<boundary`).
fn cold_synth_id(seq: i64, position: usize) -> i64 {
    seq.saturating_mul(super::COLD_FILE_MAX_ROWS as i64)
        .saturating_add(position as i64)
}

/// Entrée du MIN-tas borné de la matérialisation keyset : clé de tri `(ts,id)` + ligne projetée. `Ord` INVERSÉ
/// (plus PETITE clé == plus GRANDE au sens du tas) -> `BinaryHeap` devient un MIN-tas : `peek()` == la plus petite
/// clé retenue (candidate à l'éviction quand le tas est plein à `limit`). Comparaison sur la SEULE clé (la ligne
/// n'est pas ordonnable ; les clés sont UNIQUES -> pas d'ambiguïté).
struct KsItem {
    key: (i64, i64),
    row: MatRow,
}
impl PartialEq for KsItem {
    fn eq(&self, o: &Self) -> bool {
        self.key == o.key
    }
}
impl Eq for KsItem {}
impl PartialOrd for KsItem {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for KsItem {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        o.key.cmp(&self.key) // INVERSÉ : la plus petite clé = la plus grande -> racine du tas = min à évincer.
    }
}

/// #18 ①a — MATÉRIALISATION KEYSET COLONNAIRE d'UN fichier cold `seq` : renvoie ses <= `limit` lignes de PLUS HAUT
/// `(ts,id)` STRICTEMENT sous `cursor` (`ts < cts OR (ts = cts AND id < cid)`), triées `(ts,id) DESC`. RAM BORNÉE
/// à `limit` lignes (MIN-tas) + un batch -> 2 Go-safe indépendamment du volume du fichier.
///
/// PUSHDOWN `ts` (sens CORRECT), un row-group est SAUTÉ sans décodage si l'UNE tient :
///   (a) `!rg_can_match` (les stats natives prouvent 0 match du prédicat/fenêtre — RÉUTILISÉ verbatim de P3) ;
///   (b) curseur `Some((cts,_))` ET `min_ts > cts` -> toutes ses lignes sont > le curseur (DÉJÀ rendues). STRICT :
///       `min_ts == cts` est GARDÉ (des lignes `ts==cts, id<cid` restent dues -> jamais un `>=` qui les raterait) ;
///   (c) tas plein ET `max_ts < floor` -> aucune ligne du groupe ne peut battre la `limit`-ème courante, où
///       `floor = max(floor_ts global du planner, ts de la limit-ème du tas LOCAL)`.
/// La POSITION avance de `num_rows` MÊME sur un skip -> l'`id` synthétique reste EXACT. `proj` fixe l'ORDRE des
/// colonnes de sortie (déniée #45 -> NULL). Masquage #45 RÉUTILISÉ (`denied()`/`eval_selection`), jamais réinventé.
#[allow(clippy::too_many_arguments)]
pub(super) fn vec_materialize_keyset(
    reader: &dyn FileReader,
    seq: i64,
    pred: &Pred,
    proj: &[&'static str],
    cursor: Option<(i64, i64)>,
    floor_ts: Option<i64>,
    limit: usize,
    deny: &HashSet<String>,
) -> Result<Vec<(i64, i64, MatRow)>, String> {
    use rusqlite::types::Value;
    if limit == 0 {
        return Ok(Vec::new());
    }
    // Set à décoder = proj ∪ {ts} (clé) ∪ colonnes du prédicat, MOINS deny (miroir `decode_set`, ordre canonique).
    let mut extra: Vec<&str> = proj.iter().copied().collect();
    extra.push("ts");
    let cols = decode_set(pred, &extra, deny);
    let idx_of: Vec<usize> = cols
        .iter()
        .map(|c| PARQUET_COLS.iter().position(|x| x == c).expect("colonne de decode_set ∈ PARQUET_COLS"))
        .collect();
    let md = reader.metadata();
    let mut heap: BinaryHeap<KsItem> = BinaryHeap::new();
    let mut pos_base: usize = 0; // position CANONIQUE de la 1re ligne du row-group courant (avance TOUJOURS).
    for g in 0..reader.num_row_groups() {
        let rgm = md.row_group(g);
        let nrows = rgm.num_rows().max(0) as usize;
        let mut skip = !rg_can_match(pred, rgm, deny);
        let tss = if skip { None } else { int_stats(rgm, "ts") };
        // (b) curseur : min_ts > cts -> tout le groupe est au-dessus du curseur (déjà rendu). STRICT.
        if !skip {
            if let (Some((cts, _)), Some((mn, _))) = (cursor, tss) {
                if mn > cts {
                    skip = true;
                }
            }
        }
        // (c) plancher (tas plein) : max_ts < floor -> le groupe ne peut battre la limit-ème courante.
        if !skip {
            let local_floor = if heap.len() >= limit { heap.peek().map(|m| m.key.0) } else { None };
            let eff_floor = match (floor_ts, local_floor) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
            if let (Some(f), Some((_, mx))) = (eff_floor, tss) {
                if mx < f {
                    skip = true;
                }
            }
        }
        if skip {
            pos_base += nrows;
            continue;
        }
        let rg = reader.get_row_group(g).map_err(super::pe)?;
        let batch = decode_batch(&*rg, &idx_of)?;
        let mut mask = vec![false; batch.nrows];
        eval_selection(pred, &batch, deny, &mut mask)?;
        let ts_col = match batch.col("ts") {
            Some(ColData::I64(v)) => v.as_slice(),
            _ => return Err("keyset materialize: colonne 'ts' absente/non-INT64".to_string()),
        };
        // Vues projetées pré-résolues (déniée -> NULL), miroir `vec_materialize_ex`.
        enum PView<'a> {
            Null,
            Int(&'a [i64]),
            Str(&'a [Option<String>]),
        }
        let mut views: Vec<PView> = Vec::with_capacity(proj.len());
        for p in proj {
            if denied(deny, p) {
                views.push(PView::Null);
            } else {
                match batch.col(p) {
                    Some(ColData::I64(v)) => views.push(PView::Int(v.as_slice())),
                    Some(ColData::Str(v)) => views.push(PView::Str(v.as_slice())),
                    None => return Err(format!("keyset materialize: colonne projetée '{p}' non décodée")),
                }
            }
        }
        for i in 0..batch.nrows {
            if !mask[i] {
                continue;
            }
            let ts = ts_col[i];
            let id = cold_synth_id(seq, pos_base + i);
            let key = (ts, id);
            // FILTRE CURSEUR (== `keyset_page_sql`) : `(ts,id) < (cts,cid)` STRICT (tie-break id).
            if let Some((cts, cid)) = cursor {
                if !(ts < cts || (ts == cts && id < cid)) {
                    continue;
                }
            }
            // Perf : n'alloue/copie la ligne QUE si elle peut entrer dans le tas borné.
            if heap.len() >= limit {
                if let Some(min) = heap.peek() {
                    if key <= min.key {
                        continue;
                    }
                }
            }
            let mut row: MatRow = Vec::with_capacity(proj.len());
            for v in &views {
                row.push(match v {
                    PView::Null => Value::Null,
                    PView::Int(s) => Value::Integer(s[i]),
                    PView::Str(s) => match &s[i] {
                        Some(t) => Value::Text(t.clone()),
                        None => Value::Null,
                    },
                });
            }
            if heap.len() < limit {
                heap.push(KsItem { key, row });
            } else if let Some(min) = heap.peek() {
                if key > min.key {
                    heap.pop();
                    heap.push(KsItem { key, row });
                }
            }
        }
        pos_base += nrows;
    }
    // MIN-tas -> Vec ordonné `(ts,id) DÉCROISSANT` (tri déterministe explicite ; <= `limit` éléments).
    let mut out: Vec<(i64, i64, MatRow)> = heap.into_vec().into_iter().map(|it| (it.key.0, it.key.1, it.row)).collect();
    out.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    Ok(out)
}

// ---- FALLBACK GATE (correction > vitesse) ---------------------------------------------------------

/// Colonnes PHYSIQUES cold que le moteur vectorisé sait décoder/masquer (== `PARQUET_COLS`). Toute référence
/// HORS de ce set (ex. clé JSON `json_extract(fields,'$.k')`) N'EST PAS vectorisable ICI -> le planner (P4) DOIT
/// tomber en fallback SQLite. `fields` est décodable en TEXTE brut (regex/like/contains dessus OK), mais une
/// EXTRACTION de sous-champ JSON ne l'est pas dans ce kernel.
pub(super) fn is_physical_col(col: &str) -> bool {
    PARQUET_COLS.contains(&col)
}

/// VRAI si toutes les colonnes référencées par `pred` + `dims`/`proj` sont physiques cold -> la forme est
/// vectorisable. FAUX -> le planner DOIT router vers le fallback SQLite (JAMAIS un faux résultat vectorisé).
pub(super) fn can_vectorize(pred: &Pred, extra: &[&str]) -> bool {
    let mut refs: Vec<&str> = Vec::new();
    pred_cols(pred, &mut refs);
    refs.extend_from_slice(extra);
    refs.iter().all(|c| is_physical_col(c))
}
