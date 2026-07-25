//! Rollup-route (CHANGEMENT 3) : réécrit ultra-conservateur d'un SOQL au motif exact vers une table
//! pré-agrégée (event_rollup / event_dim_rollup) pour répondre en ms au lieu d'un scan déchiffré.
//! `struct RollupRoute`, garde d'injection `rollup_source_ok`, routeur `try_rollup_route`, transparence
//! SOC `apply_rollup_stats` (served_from/approx/truncated) et `dur_ms`. Au moindre écart au motif ->
//! None (fall-through vers le compilo soql normal). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// =====================================================================================
// ROLLUP-ROUTE (CHANGEMENT 3) — réécrit un SOQL au MOTIF EXACT vers une table pré-agrégée (event_rollup /
// event_dim_rollup) -> réponse en quelques ms au lieu d'un scan déchiffré de ~2,4 M lignes. ULTRA-
// CONSERVATEUR : au MOINDRE écart au motif, renvoie None -> le compilateur soql normal prend le relais
// (correctness > vitesse). NE compile JAMAIS d'entrée utilisateur en SQL brut : seuls une valeur `source`
// (charset restreint + échappée) et un nom de `dim` issu d'une whitelist interne traversent la frontière.
//
// TRANSPARENCE SOC : porte aussi (approx, truncated, note) pour que l'analyste sache si le chiffre est EXACT,
// PARTIEL, ou d'une FRAÎCHEUR limitée. Grain bucket = 3600 s (horaire, cf. rollup_insert_sql_into /
// dim_rollup_insert_sql).
//   - event_rollup ne cappe QUE src_ip (top-N/bucket, le reste lumpé '' puis RÉ-AGRÉGÉ = jamais perdu) -> les
//     counts par source y sont EXACTS EN SOMME (aucune valeur abandonnée), truncated:false. MAIS le grain est
//     HORAIRE : les bornes temporelles sont alignées au bucket (from floored à l'heure, `to` inclut le bucket
//     couvrant `to`) -> à une frontière SOUS-HORAIRE le compte DIFFÈRE du scan raw exact `ts>=from AND ts<=to`
//     (sur-compte les heures partielles de tête/queue). Donc approx:true (QRY-1) : la route ne prétend JAMAIS
//     être exacte au grain sous-horaire — seul le scan raw (fall-through) l'est.
//   - event_dim_rollup cappe CHAQUE dim au top-N (défaut PLUME_ROLLUP_DIM_TOPN=50) PAR bucket et ABANDONNE le
//     reste -> counts par <dim> potentiellement SOUS-COMPTÉS et liste de valeurs INCOMPLÈTE -> approx:true,
//     truncated:true (l'analyste ne doit JAMAIS croire un chiffre rollup tronqué exact).
// RECENCY GUARD (QRY-1) : si la borne haute `to` tombe dans le bucket horaire COURANT (potentiellement pas
//   encore matérialisé par le tick de rollup_events), une requête « 15 dernières min » SOUS-COMPTERAIT les
//   événements récents. On garde la route (perf des dashboards « dernières N h »), mais on pose `note` =
//   « bucket courant non matérialisé » -> jamais un sous-comptage SILENCIEUX. served_from:"rollup" signale déjà
//   la nature agrégée au frontend.
pub(crate) struct RollupRoute {
    pub(crate) sql: String,
    pub(crate) approx: bool,
    pub(crate) truncated: bool,
    /// Caveat de FRAÎCHEUR optionnel (ex. « bucket courant non matérialisé ») — surfacé en stats.rollup_note.
    pub(crate) note: Option<String>,
}

/// Valeur de `source` sûre à injecter (en plus de l'échappement) : charset borné, jamais d'espace/quote.
pub(crate) fn rollup_source_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

// =====================================================================================
// B2 (fix#2) — GROUP-BY MULTI-DIM HOT sur le grain EXACT d'`event_rollup`. Un `stats count by
// source,severity,action` sur le HOT (SQLite, ~10 M lignes) scanne+agrège en ~32 s ; ROUTE A-multi le
// réécrit vers les compteurs PRÉ-AGRÉGÉS d'`event_rollup` (réponse en ms). GÉNÉRALISE la ROUTE A
// single-`source` existante à un SOUS-ENSEMBLE du grain exact.
//
// POURQUOI SEULEMENT `source`,`severity` (et PAS `action`/`host`/`src_ip`) : le grain d'`event_rollup` est
// (bucket,source,severity,action,src_ip,host,env_id). MAIS le grain routable exact se limite aux dims
// EXACTES EN SOMME **ET** SANS RE-LABÉLISATION NULL/'' à la matérialisation :
//   - `source`,`severity` sont NOT NULL en base ET matérialisés NUS (pas de COALESCE) -> le compilo RAW
//     (`soql_field`) émet la MÊME valeur -> chaque event tombe dans EXACTEMENT une ligne de grain, aucune
//     valeur abandonnée, aucune fusion -> `SUM(n) GROUP BY <sous-ensemble>` == `count by` raw (au GRAIN
//     HORAIRE près : bornes alignées au bucket -> approx:true, JAMAIS exact au sous-horaire ; seul le scan
//     raw l'est).
//   - `host` (colonne nullable) et `action` (clé JSON `$.action` potentiellement absente) sont matérialisés
//     `COALESCE(host,'')` / `COALESCE(json_extract(fields,'$.action'),'')` -> le rollup RELABÉLISE NULL en
//     '' ET FUSIONNE un NULL avec un '' EXPLICITE. Le compilo RAW garde ces valeurs en NULL NU (pas de
//     COALESCE) -> divergence : le groupe NULL DISPARAÎT du résultat routé et '' est SUR-COMPTÉ. Ce n'est
//     PAS l'approx horaire (démontré par les tests `b2_adverse_*`, tous events dans UNE heure) -> ce serait
//     un FAUX group-by servi sous `approx:true`. Donc `host`/`action` sont EXCLUS du grain routable :
//     tout `by`-set les incluant DÉCLINE -> scan raw (correct, NULL préservé), jamais un faux compte.
//   - `src_ip` est CAPPÉ top-N/bucket (le reste lumpé '') -> un `by src_ip` SOUS-COMPTERAIT -> EXCLU aussi.
// LIMITATION ASSUMÉE (correction > couverture) : B2 n'accélère QUE `count by source,severity` (± filtre
// `source=`). Le cas douloureux mesuré en prod `count by source,severity,action` (~32 s) N'EST PAS accéléré
// tant que la sémantique NULL/'' d'`action` n'est pas résolue proprement -> follow-up scopé : soit le rollup
// PRÉSERVE NULL (pas de COALESCE, distinct de ''), soit il DÉCLINE honnêtement ces dims (état actuel).
// GATE STRICT (correction > vitesse) : dès qu'UNE dim n'est pas dans ce grain (action/host/JSON hors-grain,
// src_ip, dim non rollée) OU qu'il y a un DOUBLON -> `multidim_routable` renvoie false -> fall-through
// (ROUTE B puis scan raw). SÉCU/MASQUAGE (#45) : identique à ROUTE A — l'appelant (query.rs) ne tente AUCUNE route quand
// le jeu de masques est NON VIDE (event_rollup porte source/host/severity/action EN CLAIR) ; une dim déniée
// -> masks non vide -> route non tentée -> chemin masqué/authorizer.
//
// -------------------------------------------------------------------------------------
// B2b (UPGRADE) — MERGE `rollup ∪ raw-partiels` : RÉSULTAT EXACT ET SANS RETARD DE FRAÎCHEUR.
// -------------------------------------------------------------------------------------
// L'ancien B2 arrondissait la fenêtre `[from,to]` aux BUCKETS HORAIRES -> sur/sous-comptait les heures
// PARTIELLES (tête/queue + heure courante) -> résultat `approx:true` + note de fraîcheur. B2b applique le
// pattern P4b (merge rollup ∪ raw) au grain multi-dim et rend le compte EXACT == scan raw complet :
//   - CORPS rollup : la sous-fenêtre alignée-heure ENTIÈREMENT contenue dans `[from,to]` **ET** DÉFINITIVE
//     (`bucket < recent`, recent = plancher-heure(now)-3600 = frontière au-delà de laquelle le job rollup
//     re-agrège encore = VOLATILE d'un tick). Servie par `event_rollup` (exact-en-somme sur buckets complets,
//     rapide). Les dims {source,severity} NOT NULL nues -> `SUM(n) GROUP BY` == `count by` raw sur ces buckets.
//   - RAW PARTIELS : tête `[from, H_lo)` ∪ queue `[body_hi, to]` (H_lo = plafond-heure de `from` ; body_hi =
//     min(plancher-heure(to+1), recent)). Servis par un SCAN BRUT d'`event` (borné à <1h de tête + <=2h de
//     queue par l'index `idx_event_ts`/`idx_event_src_ts` -> coût petit). `event` est À JOUR (aucun retard) et
//     retient AU MOINS aussi longtemps qu'`event_rollup` (même `global_cutoff`, cf. retention_run) -> pour le
//     HOT le raw partiel est TOUJOURS complet -> `approx:false`, `note:none`. La queue englobe l'heure courante
//     ET l'heure précédente (toutes deux volatiles côté rollup) -> plus AUCUN sous-comptage de fraîcheur.
//   - MERGE : `SUM(c) GROUP BY (source,severity)` sur `UNION ALL(corps, tête, queue)`. Régions DISJOINTES
//     (tête `ts<H_lo`, corps `bucket∈[H_lo,body_hi)`, queue `ts>=body_hi`) et d'union `[from,to]` -> ni double
//     comptage ni trou -> == scan raw complet `count by source,severity` sur `[from,to]`.
//   - DÉCLINE (None -> scan raw normal) quand AUCUN bucket définitif complet n'existe (`body_hi<=body_lo` :
//     fenêtre sub-horaire OU entièrement dans les ~2h volatiles) -> le raw seul est déjà borné+rapide+exact.
// RÉSIDU APPROX HONNÊTE : (1) COLD — sous la frontière hot/cold `B`, `event` est agé/purgé (Parquet) -> un
// partiel de TÊTE deep-past (from<B non aligné-heure) ne peut PAS être scanné raw -> il est REPLIÉ dans le
// corps rollup (approx bornée à la sliver sub-horaire) -> `approx:true` UNIQUEMENT dans ce cas ; queue récente
// (>=B) reste raw-exacte. (2) Un event BACKDATÉ arrivant APRÈS le passage du watermark (ts < recent) échappe au
// rollup définitif — limitation PRÉEXISTANTE du rollup (pas introduite par le merge), négligeable, non couverte.
// GATE OFF (`PLUME_ROLLUP_MULTIDIM=0`) : `multidim_routable` non atteint -> None -> scan raw byte-identique.
// =====================================================================================

/// Dimensions du grain EXACT d'`event_rollup` routables en group-by (B2) : STRICTEMENT les colonnes NOT NULL
/// matérialisées NUES (sans COALESCE), donc SANS divergence NULL/'' avec le compilo RAW. `source`,`severity`
/// sont NOT NULL en base et écrits tels quels -> `SUM(n) GROUP BY` == `count by` raw (au grain horaire près).
/// DÉLIBÉRÉMENT ABSENTS : `action` (clé JSON absente = NULL, COALESCE'd '' à la matérialisation -> fusion
/// NULL+'' -> faux group-by), `host` (colonne nullable, idem COALESCE '' -> même fusion), `src_ip` (cappé
/// top-N = approx). Tout `by`-set les incluant DÉCLINE -> scan raw exact (NULL préservé). Voir le bloc B2
/// ci-dessus (LIMITATION ASSUMÉE + follow-up) : n'accélère QUE `source,severity`.
pub(crate) const ROLLUP_EXACT_DIMS: &[&str] = &["source", "severity"];

/// Kill-switch RUNTIME du group-by multi-dim (B2). DÉFAUT ACTIVÉ (délivre le fix 32 s -> ms) ;
/// `PLUME_ROLLUP_MULTIDIM` ∈ {0,false,off} -> désactivé -> fallback scan brut (comportement pré-B2, byte-
/// identique). Réversible sans redéploiement — la ROUTE A single-dim historique n'est pas gated ; B2 l'est
/// par prudence (nouveau chemin), sans jamais toucher le contrat de ROUTE A.
fn rollup_multidim_enabled() -> bool {
    !matches!(std::env::var("PLUME_ROLLUP_MULTIDIM").ok().as_deref(), Some("0") | Some("false") | Some("off"))
}

/// TRUE si `by_fields` (>= 2 dims) est un sous-ensemble SANS DOUBLON du grain EXACT -> routable multi-dim.
/// Single-dim (len 1) n'est PAS pris ici : il reste sur ROUTE A (source) / ROUTE B (dim rollée) / scan raw —
/// B2 ne change QUE le multi-dim (zéro régression sur le single-dim). Doublon (`by source,source`) -> refus.
fn multidim_routable(by_fields: &[String]) -> bool {
    if by_fields.len() < 2 || !by_fields.iter().all(|f| ROLLUP_EXACT_DIMS.contains(&f.as_str())) {
        return false;
    }
    let mut seen = by_fields.to_vec();
    seen.sort();
    seen.dedup();
    seen.len() == by_fields.len()
}

/// Projection `<dim> AS "<dim>"` pour chaque dim du grain exact (dims ∈ `ROLLUP_EXACT_DIMS` = colonnes
/// réelles d'event_rollup/cold_rollup, littéraux whitelistés -> sûrs en position de colonne). Alias quoté
/// (`soql_qid`) -> mêmes NOMS de colonnes de sortie que le compilo raw (`<f> AS <soql_qid(f)>`).
fn multidim_select(fields: &[String]) -> String {
    fields.iter().map(|f| format!("{f} AS {}", guatx_core::soql::soql_qid(f))).collect::<Vec<_>>().join(", ")
}

/// Plancher/plafond à l'heure (bucket = 3600 s). `ts` supposé >= 0 (epoch ; appelants gardent `>0`).
fn hour_floor(ts: i64) -> i64 {
    (ts / 3600) * 3600
}
fn hour_ceil(ts: i64) -> i64 {
    ((ts + 3599) / 3600) * 3600
}

/// Découpe temporelle du MERGE `rollup ∪ raw-partiels` (B2b). Voir le bloc B2b : le CORPS rollup sert les
/// buckets alignés-heure COMPLETS **et** DÉFINITIFS `[body_lo, body_hi)` ; les partiels TÊTE/QUEUE sont
/// scannés en brut sur `event` (exact, à jour). Régions DISJOINTES, union == `[from,to]`.
struct MergeSplit {
    /// Corps rollup : `bucket >= body_lo AND bucket < body_hi` (exclusif). `body_lo` peut valoir 0 (from non borné).
    body_lo: i64,
    body_hi: i64,
    /// Tête partielle raw sur `event` : `ts ∈ [lo, hi)` (`lo==0` -> pas de borne basse). None -> pas de tête.
    head: Option<(i64, i64)>,
    /// Queue partielle raw sur `event` : `ts ∈ [lo, hi]` (`hi==0` -> jusqu'à maintenant, pas de borne haute). None -> pas de queue.
    tail: Option<(i64, i64)>,
    /// Un partiel n'a PAS pu être servi raw (sous le plancher `event` = agé/purgé en cold) -> replié dans le
    /// corps rollup (approx bornée). `false` pour le HOT (event retient toute la fenêtre) -> résultat EXACT.
    approx: bool,
}

impl MergeSplit {
    /// Y a-t-il au moins un bucket DÉFINITIF complet à servir depuis le rollup ? Sinon l'appelant DÉCLINE
    /// (None) : le scan raw seul (fenêtre <~2h ou sub-horaire) est déjà borné, rapide et exact.
    fn has_body(&self) -> bool {
        self.body_hi > self.body_lo
    }
}

/// Calcule le MERGE exact-et-frais pour `[from,to]` à `now_ts`. `event_floor` = plus petit `ts` pour lequel un
/// scan brut d'`event` est COMPLET : `i64::MIN` pour le HOT (event retient toute la fenêtre du rollup), = la
/// frontière `B` pour le COLD (event agé/purgé sous B). `wm` = watermark RÉEL finalisé par le job de rollup
/// (`event_rollup_wm` dans `meta`, cf rollups.rs) : plus petit `bucket` que le corps peut lire du rollup SANS
/// risque de péremption. CORPS = buckets DÉFINITIFS complets `[_, min(recent, wm))` ; partiels TÊTE/QUEUE =
/// scan brut d'`event` quand `>= event_floor` (exact, à jour), sinon REPLIÉS dans le corps (approx bornée).
///
/// FIX (sous-comptage silencieux) : `recent = plancher-heure(now_REQUÊTE)-3600` court en AVANT du watermark
/// RÉEL du job juste après une frontière d'heure (cadence tick ~5 min) -> lire tous les buckets `< recent`
/// depuis le rollup y inclut des buckets encore VOLATILES côté job. Un event ingéré EN RETARD (ingestion
/// décalée 30-90 min) tombant dans un tel bucket serait lu depuis le rollup PÉRIMÉ et jamais rattrapé par la
/// queue raw (qui ne rescannait que `>= recent`) -> sous-compté ET servi sous `approx:false` (mensonge). On
/// borne donc le corps par le vrai watermark : `body_hi = min(h_hi, recent, wm)`. La queue raw descend alors
/// jusqu'à `wm` (fenêtre hot, index-servie `idx_event_ts`/`idx_event_src_ts` -> bornée + peu chère) et rattrape
/// TOUT event `>= wm` -> exact ET frais. `wm = i64::MIN` (watermark absent : DB neuve / jamais tické) -> body_hi
/// effondré -> `!has_body` -> tout servi en raw (exact, jamais de corps périmé).
fn plan_merge(from: i64, to: i64, now_ts: i64, event_floor: i64, wm: i64) -> MergeSplit {
    let cur = hour_floor(now_ts);
    let recent = (cur - 3600).max(0);
    let h_lo = if from > 0 { hour_ceil(from) } else { 0 };
    let h_hi = if to > 0 { hour_floor(to + 1) } else { cur };
    let mut body_lo = h_lo;
    let mut body_hi = h_hi.min(recent).min(wm);
    let mut head = None;
    let mut tail = None;
    let mut approx = false;
    // TÊTE `[from, H_lo)` (existe ssi `from` n'est pas déjà aligné-heure).
    if from > 0 && from < h_lo {
        if from >= event_floor {
            head = Some((from, h_lo)); // raw-servable -> exact
        } else {
            body_lo = hour_floor(from); // replie le bucket de tête dans le corps (sur-compte `[floor(from), from)`)
            approx = true;
        }
    }
    // QUEUE `[body_hi, to]` (existe ssi elle n'est pas vide).
    let tail_exists = if to > 0 { body_hi <= to } else { true };
    if tail_exists {
        if body_hi >= event_floor {
            tail = Some((body_hi, if to > 0 { to } else { 0 })); // raw-servable (jusqu'au watermark) -> exact & frais
        } else {
            // body_hi < event_floor : la sous-fenêtre `[body_hi, event_floor)` n'est PAS raw-servable (event
            // agé/purgé sous la frontière cold `B`) -> repliée dans le corps rollup (approx bornée). Deux cas :
            //   - COLD `wm < B` : `[wm, B)` non raw-scannable -> corps (cold_rollup retient), `approx:true`+note ;
            //     `[B, to]` reste RAW-exact (event retenu au-dessus de B).
            //   - deep-past whole-window (`to < B`) : tout le corps ; on cappe au bucket couvrant `to` (pas de
            //     sur-couverture) et il n'y a pas de queue raw.
            let cover_cap = if to > 0 { hour_floor(to) + 3600 } else { i64::MAX };
            body_hi = event_floor.min(cover_cap);
            if to <= 0 || event_floor <= to {
                tail = Some((event_floor, if to > 0 { to } else { 0 })); // `[B, to]` raw-exact
            }
            approx = true;
        }
    }
    MergeSplit { body_lo, body_hi, head, tail, approx }
}

/// Construit le SQL du MERGE multi-dim : `SUM(c) GROUP BY <cols>` au-dessus d'un `UNION ALL` de fragments
/// (corps rollup ∪ tête ∪ queue), chacun projetant `<cols>, c`. `cold_boundary` : None = HOT (corps =
/// `event_rollup`) ; Some(B) = COLD (corps = `event_rollup[bucket>=B] ∪ cold_rollup[bucket<B]`, partitions
/// DISJOINTES à B). `src_cond`/`env_cond` : filtres `source='…'` / `env_id='…'` (littéraux validés+échappés,
/// s'appliquent aux TROIS surfaces — rollup, cold_rollup et `event` — qui portent toutes source+env_id).
/// `cols` = grain routable {source,severity} NOT NULL nu -> `event` (COUNT(*)) et rollup (`SUM(n)`) émettent
/// EXACTEMENT les mêmes valeurs -> le merge == `count by <cols>` raw. Appelé UNIQUEMENT si `split.has_body()`.
fn build_merge_sql(
    by_fields: &[String],
    src_cond: &[String],
    env_cond: &[String],
    split: &MergeSplit,
    order: &str,
    lim: &str,
    cold_boundary: Option<i64>,
) -> String {
    let cols = by_fields.join(", ");
    let sel = multidim_select(by_fields);
    let base_cond = |extra: &[String]| -> Vec<String> {
        let mut c = src_cond.to_vec();
        c.extend(env_cond.iter().cloned());
        c.extend(extra.iter().cloned());
        c
    };
    let mut parts: Vec<String> = Vec::new();
    // --- CORPS ROLLUP : buckets DÉFINITIFS complets `[body_lo, body_hi)` ---
    let body_range = vec![format!("bucket >= {}", split.body_lo), format!("bucket < {}", split.body_hi)];
    match cold_boundary {
        None => {
            let c = base_cond(&body_range);
            parts.push(format!("SELECT {cols}, SUM(n) AS c FROM event_rollup WHERE {} GROUP BY {cols}", c.join(" AND ")));
        }
        Some(b) => {
            let mut hot = body_range.clone();
            hot.push(format!("bucket >= {b}"));
            let mut cold = body_range.clone();
            cold.push(format!("bucket < {b}"));
            let ch = base_cond(&hot);
            let cc = base_cond(&cold);
            parts.push(format!("SELECT {cols}, SUM(n) AS c FROM event_rollup WHERE {} GROUP BY {cols}", ch.join(" AND ")));
            parts.push(format!("SELECT {cols}, SUM(n) AS c FROM cold_rollup WHERE {} GROUP BY {cols}", cc.join(" AND ")));
        }
    }
    // --- TÊTE / QUEUE : scan BRUT d'`event` (exact, à jour ; borné <1h tête / <=2h queue par idx_event_ts) ---
    let raw_part = |lo: i64, hi: i64, hi_incl: bool| -> String {
        let mut tc: Vec<String> = Vec::new();
        if lo > 0 {
            tc.push(format!("ts >= {lo}"));
        }
        if hi > 0 {
            tc.push(if hi_incl { format!("ts <= {hi}") } else { format!("ts < {hi}") });
        }
        let c = base_cond(&tc);
        format!("SELECT {cols}, COUNT(*) AS c FROM event WHERE {} GROUP BY {cols}", c.join(" AND "))
    };
    if let Some((lo, hi)) = split.head {
        parts.push(raw_part(lo, hi, false)); // `[lo, hi)`
    }
    if let Some((lo, hi)) = split.tail {
        parts.push(raw_part(lo, hi, true)); // `[lo, hi]` (hi==0 -> pas de borne haute)
    }
    format!(
        "SELECT {sel}, SUM(c) AS \"count\" FROM ({}) GROUP BY {cols} ORDER BY \"count\" {order}{lim}",
        parts.join(" UNION ALL ")
    )
}

/// Filtre `source='…'` (littéral validé `rollup_source_ok` + échappé) pour le MERGE, ou vide. Partagé HOT/COLD.
fn merge_src_cond(source_filter: &Option<String>) -> Vec<String> {
    source_filter.as_ref().map(|s| vec![format!("source='{}'", guatx_core::soql::soql_esc(s))]).unwrap_or_default()
}
/// Filtre `env_id='…'` (validé en amont `env_slug_ok` + ré-échappé) pour le MERGE, ou vide. Partagé HOT/COLD.
fn merge_env_cond(env: Option<&str>) -> Vec<String> {
    env.filter(|e| !e.is_empty()).map(|e| vec![format!("env_id='{}'", guatx_core::soql::soql_esc(e))]).unwrap_or_default()
}

/// Lit le watermark FINALISÉ du job de rollup (`event_rollup_wm` dans `meta`, écrit par `rollup_events`,
/// cf rollups.rs) : plus grand `bucket` au-delà duquel le rollup est encore VOLATILE (re-agrégé à chaque
/// tick). Per-DB/tenant (la table `meta` vit dans la base tenant). ABSENT (DB neuve / jamais tické) ou
/// illisible -> `i64::MIN` : le MERGE traite alors tout en raw (exact, jamais de corps périmé). À passer à
/// `try_rollup_route` / `try_cold_rollup_route` pour BORNER le corps rollup au réellement-finalisé (cf. `plan_merge`).
pub(crate) fn event_rollup_wm(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key='event_rollup_wm'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(i64::MIN)
}

/// Tente de router un SOQL vers un rollup. None = motif non reconnu -> compiler normalement (fall-through).
/// `env` (#2d) : `Some("<env>")` -> ajoute `env_id='<env>'` au WHERE du rollup (event_rollup /
/// event_dim_rollup portent env_id depuis v67) -> agrégats FILTRÉS par environnement, cohérents avec le
/// chemin raw. `None` (mode 0 / `__all__`) -> aucune condition -> agrégats tous-env (comportement identique).
/// Valeur validée en amont (env_slug_ok) + ré-échappée (soql_esc) -> jamais d'injection.
/// `wm` = watermark rollup RÉEL (via `event_rollup_wm`) -> borne le corps du MERGE multi-dim au finalisé
/// (anti sous-comptage silencieux, cf. `plan_merge`) ; passer `i64::MIN` = tout raw ; sans effet sur ROUTE A/B.
pub(crate) fn try_rollup_route(soql: &str, from: i64, to: i64, env: Option<&str>, wm: i64) -> Option<RollupRoute> {
    try_rollup_route_at(soql, from, to, env, now(), wm)
}

/// Cœur testable de `try_rollup_route` : `now_ts` injecté (recency guard QRY-1) pour tester le caveat de
/// fraîcheur sans horloge murale. Voir `try_rollup_route` pour le contrat public (production = `now()`).
pub(crate) fn try_rollup_route_at(soql: &str, from: i64, to: i64, env: Option<&str>, now_ts: i64, wm: i64) -> Option<RollupRoute> {
    let sh = parse_stats_by_shape(soql)?;
    let tconds = rollup_time_conds(from, to, env);
    let order = if sh.asc { "ASC" } else { "DESC" };
    let lim = sh.limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default();
    // RECENCY GUARD (QRY-1) : la borne haute tombe-t-elle dans le bucket horaire COURANT (ou est-elle non
    // bornée -> `to<=0` = « jusqu'à maintenant ») ? Ce bucket peut n'être PAS ENCORE matérialisé par le tick
    // de rollup_events -> compte récent potentiellement sous-estimé. On SIGNALE (note) sans dérouter (perf).
    let cur_hour = (now_ts / 3600) * 3600;
    let recent = to <= 0 || to >= cur_hour;
    let recency_note = || recent.then(|| "bucket courant non matérialisé (compte récent potentiellement sous-estimé)".to_string());

    // --- ROUTE A-multi (B2b) : `... | stats count by <dims⊆grain>` -> MERGE `event_rollup ∪ raw-partiels`. ---
    // Généralise ROUTE A au group-by MULTI-DIM sur le grain exact {source,severity} (dims NOT NULL sans
    // COALESCE -> zéro divergence NULL/''). `multidim_routable` GARANTIT (>=2 dims, toutes ∈ grain, sans
    // doublon) que `SUM(n) GROUP BY <dims>` reproduit EXACTEMENT `count by <dims>` raw sur les buckets servis.
    // B2b : le CORPS (buckets DÉFINITIFS complets) vient d'`event_rollup` (rapide) ; la TÊTE `[from,H_lo)` et la
    // QUEUE `[body_hi,to]` (heure courante+précédente) viennent d'un SCAN BRUT d'`event` (exact, à jour) ->
    // résultat EXACT == scan raw complet, SANS retard de fraîcheur (`approx:false`, `note:none`). HOT :
    // event_floor = i64::MIN (event retient toute la fenêtre du rollup, cf. retention_run) -> partiels TOUJOURS
    // raw-servables -> `split.approx` toujours false. Une dim hors grain OU le flag OFF -> route non prise.
    if rollup_multidim_enabled() && multidim_routable(&sh.by_fields) {
        let split = plan_merge(from, to, now_ts, i64::MIN, wm);
        if !split.has_body() {
            // Aucun bucket DÉFINITIF complet (fenêtre sub-horaire OU entièrement dans les ~2h volatiles) : le
            // scan raw seul est déjà borné, rapide et exact -> on DÉCLINE (fall-through vers le compilo raw).
            return None;
        }
        let src_cond = merge_src_cond(&sh.source_filter);
        let env_cond = merge_env_cond(env);
        let sql = build_merge_sql(&sh.by_fields, &src_cond, &env_cond, &split, order, &lim, None);
        // MERGE HOT : EXACT & FRAIS. `approx = split.approx` (toujours false ici) ; truncated:false (dims exactes,
        // rien d'abandonné) ; note:none (aucun sous-comptage de fraîcheur — l'heure courante est raw-servie).
        return Some(RollupRoute { sql, approx: split.approx, truncated: false, note: None });
    }

    // --- ROUTE A : `... | stats count by source` -> event_rollup (counts EXACTS). ---
    // EXPRESSIBILITÉ du GROUP-BY : `source` EST une colonne réelle d'event_rollup -> exprimable (les filtres,
    // eux, ont déjà été bornés à `source=` propre en STAGE 0). Tout AUTRE champ de group-by ne peut PAS être
    // exprimé par cette route -> chute vers ROUTE B (dim) puis, à défaut, vers le scan RAW.
    if sh.by_fields.len() == 1 && sh.by_fields[0] == "source" {
        let mut conds = tconds.clone();
        if let Some(s) = &sh.source_filter {
            conds.push(format!("source='{}'", guatx_core::soql::soql_esc(s)));
        }
        let wc = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
        let sql = format!(
            "SELECT source AS \"source\", SUM(n) AS \"count\" FROM event_rollup{wc} GROUP BY source ORDER BY \"count\" {order}{lim}"
        );
        // approx:true (QRY-1) : counts exacts EN SOMME mais grain HORAIRE -> jamais « exact » au sous-horaire.
        // truncated:false (aucune source abandonnée). note = caveat de fraîcheur si la fenêtre touche l'heure courante.
        return Some(RollupRoute { sql, approx: true, truncated: false, note: recency_note() });
    }

    // --- ROUTE B : `search source=X | stats count by <dim>` -> event_dim_rollup (source IMPLIQUÉ). ---
    // Single-dim UNIQUEMENT (un multi-dim non routable en A-multi n'est PAS exprimable par event_dim_rollup,
    // clé (bucket,source,dim,val) mono-dim) -> multi-dim résiduel = None -> scan RAW.
    let by = match sh.by_fields.as_slice() {
        [f] => f.as_str(),
        _ => return None,
    };
    let src = sh.source_filter.as_deref()?; // une dim n'a de sens que pour une source donnée (partition du rollup)
    // spec EFFECTIVE = défauts + env PLUME_ROLLUP_DIMS (cf. dim_rollup_specs) -> une dim ajoutée par
    // déploiement est routable ICI sans recompiler, DÈS LORS que le job l'a matérialisée.
    // EXPRESSIBILITÉ du GROUP-BY : le champ n'est routable que s'il est une DIM matérialisée pour cette
    // source (event_dim_rollup, clé (bucket,source,dim,val)). Sinon -> non exprimable -> scan RAW. NB : les
    // colonnes RÉELLES servies exactes hors rollup (ex `src_ip`, ABSENT à dessein des dims web) tombent ICI,
    // donc `search source=web … | stats count by src_ip` DÉCLINE -> raw (correct), jamais un 0 de rollup.
    let dim_rolled = dim_rollup_specs().iter().any(|(s, dims)| s.as_str() == src && dims.iter().any(|d| d.as_str() == by));
    if !dim_rolled {
        return None; // (source, dim) non pré-agrégé -> fall-through
    }
    let mut conds = vec![format!("source='{}'", guatx_core::soql::soql_esc(src)), format!("dim='{}'", guatx_core::soql::soql_esc(by))];
    conds.extend(tconds);
    let sql = format!(
        "SELECT val AS {}, SUM(n) AS \"count\" FROM event_dim_rollup WHERE {} GROUP BY val ORDER BY \"count\" {order}{lim}",
        guatx_core::soql::soql_qid(by),
        conds.join(" AND ")
    );
    // dim cappée top-N/bucket à la POPULATION -> sous-comptage possible + valeurs manquantes -> partiel.
    // note = caveat de fraîcheur additionnel si la fenêtre touche l'heure courante (recency guard QRY-1).
    Some(RollupRoute { sql, approx: true, truncated: true, note: recency_note() })
}

/// MOTIF `stats count by <field>` reconnu (partagé par le rollup-route HOT et le rollup-route COLD #28). Champs
/// = résultat de `parse_stats_by_shape` : filtre source EXCLUSIF éventuel, champ de group-by, sens du tri, LIMIT.
pub(crate) struct StatsByShape {
    pub(crate) source_filter: Option<String>,
    /// Champs du group-by DANS L'ORDRE (>= 1). B2 : multi-dim reconnu (`by a,b,c`) ; single-dim = 1 élément.
    /// Découpé EXACTEMENT comme `by_fields` du compilo raw (join puis split ',') -> motif routé == motif raw.
    pub(crate) by_fields: Vec<String>,
    pub(crate) asc: bool,
    pub(crate) limit: Option<i64>,
}

/// PARSE ULTRA-CONSERVATEUR du SEUL motif rollup-able : `search [source=X] | stats count by <field> [| sort
/// -count|+count|count] [| head N]`, RIEN d'autre. `None` au moindre écart (fall-through vers le scan RAW —
/// correctness > vitesse). Source unique de vérité du motif -> le rollup HOT et le rollup COLD reconnaissent
/// EXACTEMENT la même chose (pas de divergence). Ne compile JAMAIS d'entrée utilisateur : seuls une valeur
/// `source` (charset restreint, `rollup_source_ok`) et les `by_fields` (chacun `soql_ident_ok`) franchissent la frontière.
pub(crate) fn parse_stats_by_shape(soql: &str) -> Option<StatsByShape> {
    let stages = guatx_core::soql::soql_split_pipes(soql);
    if stages.is_empty() {
        return None;
    }
    // --- STAGE 0 : `search` avec des filtres UNIQUEMENT `source=X` en égalité stricte. ---
    // EXPRESSIBILITÉ (SOUNDNESS) : le rollup-route est une OPTIMISATION qui ne doit s'appliquer QUE si elle est
    // PROVABLEMENT équivalente au scan RAW. Le rollup (event_rollup / event_dim_rollup / leurs miroirs cold) ne
    // sait appliquer qu'UN filtre de PARTITION `source=X` (+ bornes bucket/env). Au MOINDRE autre champ de filtre
    // (`status>=500`, `action=blocked`, `path=…`) -> dimension déjà FONDUE dans l'agrégat -> on DÉCLINE (raw).
    let f0 = stages[0].trim();
    let body = if f0 == "search" {
        ""
    } else if let Some(r) = f0.strip_prefix("search ") {
        r.trim()
    } else {
        return None; // base `metric ...` ou autre -> jamais de rollup-route
    };
    let mut source_filter: Option<String> = None;
    if !body.is_empty() {
        let toks = guatx_core::soql::soql_tokenize(body);
        let mut src_eq_count = 0usize;
        for tok in &toks {
            let val = match tok.strip_prefix("source=") {
                Some(v) if !v.is_empty() && !v.starts_with('=') && !v.starts_with('~') && !v.contains('*') && rollup_source_ok(v) => v,
                _ => return None,
            };
            src_eq_count += 1;
            source_filter = Some(val.to_string());
        }
        if src_eq_count > 1 {
            return None; // deux filtres `source=` -> ambigu, non exprimable par une partition unique
        }
    }
    // --- STAGES SUIVANTS : `stats count by <field>` [| sort -count|+count|count] [| head N], rien d'autre. ---
    let rest = &stages[1..];
    if rest.is_empty() {
        return None;
    }
    let s0: Vec<&str> = rest[0].split_whitespace().collect();
    if s0.len() < 4 || s0[0] != "stats" || s0[1] != "count" || s0[2] != "by" {
        return None;
    }
    // B2 : découpe `by a,b,c` EXACTEMENT comme le compilo raw (`by_fields`) — join des tokens après `by`,
    // split sur ',', trim, filtre vide, `soql_ident_ok` par champ. Tolère les espaces (`a, b`) sans jamais
    // accepter un champ invalide (espace interne / caractère hors [A-Za-z0-9_]) -> le motif routé ici est
    // le MÊME multiset de dims que celui compilé en RAW (parité du group-by par construction).
    let by_fields: Vec<String> = s0[3..].join(" ").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if by_fields.is_empty() || by_fields.iter().any(|f| !soql_ident_ok(f)) {
        return None;
    }
    let mut asc = false; // défaut : ORDER BY count DESC
    let mut limit: Option<i64> = None;
    let mut idx = 1;
    if let Some(stage) = rest.get(idx) {
        let t: Vec<&str> = stage.split_whitespace().collect();
        if t.first() == Some(&"sort") {
            if t.len() != 2 {
                return None;
            }
            match t[1] {
                "-count" => asc = false,
                "+count" | "count" => asc = true,
                _ => return None,
            }
            idx += 1;
        }
    }
    if let Some(stage) = rest.get(idx) {
        let t: Vec<&str> = stage.split_whitespace().collect();
        if t.first() == Some(&"head") {
            if t.len() != 2 {
                return None;
            }
            let n: i64 = t[1].parse().ok()?;
            if n <= 0 {
                return None;
            }
            limit = Some(n);
            idx += 1;
        }
    }
    if rest.get(idx).is_some() {
        return None; // commande EN TROP (eval/where/timechart/...) -> fall-through
    }
    Some(StatsByShape { source_filter, by_fields, asc, limit })
}

/// Bornes temporelles + filtre environnement PARTAGÉS (bucket aligné au grain horaire, inclut le bucket couvrant
/// `from`). `env` None -> agrégats tous-env. Réutilisé par le rollup HOT et le rollup COLD.
fn rollup_time_conds(from: i64, to: i64, env: Option<&str>) -> Vec<String> {
    let mut tconds: Vec<String> = Vec::new();
    if from > 0 {
        tconds.push(format!("bucket >= {}", (from / 3600) * 3600));
    }
    if to > 0 {
        tconds.push(format!("bucket <= {to}"));
    }
    if let Some(e) = env.filter(|e| !e.is_empty()) {
        tconds.push(format!("env_id='{}'", guatx_core::soql::soql_esc(e)));
    }
    tconds
}

// =====================================================================================
// #28 PHASE A — ROLLUP-ROUTE COLD : réécrit le MÊME motif `stats count by` vers l'UNION des rollups HOT + COLD
// (event_rollup ∪ cold_rollup / event_dim_rollup ∪ cold_dim_rollup), coupée à la frontière jour `B` : HOT sert
// `bucket >= B`, COLD sert `bucket < B`. Les deux tables vivent DANS LA BASE TENANT -> la requête tourne sur le
// pool de lecture normal, ZÉRO fichier Parquet ouvert (tout le gain de #28). Partitions DISJOINTES (>=B vs <B)
// -> `SUM(n)` sur l'union ne DOUBLE JAMAIS un bucket frontière. `count` est additif -> l'union-de-lignes puis
// une seule agrégation au-dessus = EXACT (== scan brut hot∪cold, cf. tests). `dc()`/distinct N'EST PAS un motif
// `count by` -> `parse_stats_by_shape` renvoie None -> l'appelant retombe sur le chemin brut cold_union_query
// (correct, plus lent). MÊME approx/truncated que le HOT (grain horaire ; dim cappée top-N).
//
// SÉCURITÉ : cette route N'EST TENTÉE QUE quand le jeu de masques de l'appelant est VIDE (l'appelant, query.rs,
// applique la MÊME garde que le rollup HOT). Un masque/deny actif -> route NON tentée -> chemin brut
// cold_union_query (masquage émis dans le SQL + authorizer DENY appliqués aux lignes cold). De plus, l'authorizer
// traite cold_rollup/cold_dim_rollup comme des MIROIRS de event/event_rollup (query_exec.rs) -> un `SELECT
// src_ip FROM cold_rollup` en SQL brut est DÉNIÉ comme sur event. Aucune valeur de dim déniée ne fuit par cette route.

/// Tente de router un `stats count by` COLD+HOT vers l'union des rollups (aucun Parquet). `boundary` = `B`
/// (frontière jour hot/cold, `cold_query_boundary`). None = motif non `count by` -> l'appelant retombe sur le
/// chemin brut hot∪cold. La fenêtre `[from, to]` atteint SOUS `B` (garanti par l'appelant : `from < B`).
#[cfg(feature = "cold_tier")]
pub(crate) fn try_cold_rollup_route(soql: &str, from: i64, to: i64, env: Option<&str>, boundary: i64, wm: i64) -> Option<RollupRoute> {
    try_cold_rollup_route_at(soql, from, to, env, boundary, now(), wm)
}

/// Cœur testable de `try_cold_rollup_route` (`now_ts` injecté pour le recency guard, comme le HOT). `wm` =
/// watermark rollup RÉEL (cf `event_rollup_wm`) -> borne le corps au finalisé (anti sous-comptage silencieux).
#[cfg(feature = "cold_tier")]
pub(crate) fn try_cold_rollup_route_at(soql: &str, from: i64, to: i64, env: Option<&str>, boundary: i64, now_ts: i64, wm: i64) -> Option<RollupRoute> {
    let sh = parse_stats_by_shape(soql)?;
    let base_tconds = rollup_time_conds(from, to, env);
    let order = if sh.asc { "ASC" } else { "DESC" };
    let lim = sh.limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default();
    let cur_hour = (now_ts / 3600) * 3600;
    let recent = to <= 0 || to >= cur_hour;
    let recency_note = || {
        let base = "servi depuis rollup cold+hot (aucun fichier Parquet ouvert)".to_string();
        Some(if recent {
            format!("{base} ; bucket courant non matérialisé (compte récent potentiellement sous-estimé)")
        } else {
            base
        })
    };
    // Construit `WHERE` pour un côté (hot: bucket>=B ; cold: bucket<B) à partir des conds communes + le split
    // frontière + un éventuel filtre `source=`/`dim=`. Toutes les valeurs sont des littéraux i64 / échappés.
    let side_where = |extra: &[String], boundary_cond: &str| -> String {
        let mut c = extra.to_vec();
        c.extend(base_tconds.iter().cloned());
        c.push(boundary_cond.to_string());
        format!(" WHERE {}", c.join(" AND "))
    };

    // --- ROUTE A-multi (B2b) : multi-dim grain exact -> MERGE (event_rollup ∪ cold_rollup) ∪ raw-partiels. ---
    // MÊME gate/parité que le HOT (multidim_routable). CORPS = union des rollups EN BASE (event_rollup[bucket>=B]
    // ∪ cold_rollup[bucket<B], partitions DISJOINTES -> aucun bucket frontière doublé), restreint aux buckets
    // DÉFINITIFS complets `[body_lo, body_hi)`. QUEUE récente `[body_hi, to]` (>=B) = SCAN BRUT d'`event` (exact,
    // à jour, ZÉRO Parquet) -> l'heure courante n'est PLUS en retard d'un tick. RÉSIDU APPROX (honnête) : sous B,
    // `event` est agé/purgé (Parquet) -> un partiel de TÊTE deep-past (from<B non aligné-heure) est REPLIÉ dans
    // le corps rollup (approx bornée à la sliver sub-horaire) -> `plan_merge(event_floor=boundary)` pose alors
    // `split.approx=true`. Fenêtres COLD alignées-heure (dashboards) -> approx=false, EXACT & FRAIS.
    if rollup_multidim_enabled() && multidim_routable(&sh.by_fields) {
        let split = plan_merge(from, to, now_ts, boundary, wm);
        if !split.has_body() {
            return None; // aucun bucket définitif complet -> fall-through vers le brut cold_union_query
        }
        let src_cond = merge_src_cond(&sh.source_filter);
        let env_cond = merge_env_cond(env);
        let sql = build_merge_sql(&sh.by_fields, &src_cond, &env_cond, &split, order, &lim, Some(boundary));
        // note = caveat UNIQUEMENT si un résidu deep-past est resté approx (tête sub-horaire repliée) ; sinon
        // None (EXACT). truncated:false (dims exactes, rien d'abandonné sur {source,severity}).
        let note = split
            .approx
            .then(|| "rollup cold+hot + raw event (queue à jour) ; tête sub-horaire deep-past (<B, agé) repliée sur le rollup (approx bornée)".to_string());
        return Some(RollupRoute { sql, approx: split.approx, truncated: false, note });
    }

    // --- ROUTE A : `stats count by source` -> (event_rollup[bucket>=B] ∪ cold_rollup[bucket<B]). ---
    if sh.by_fields.len() == 1 && sh.by_fields[0] == "source" {
        let src_cond: Vec<String> = sh
            .source_filter
            .as_ref()
            .map(|s| vec![format!("source='{}'", guatx_core::soql::soql_esc(s))])
            .unwrap_or_default();
        let hot_w = side_where(&src_cond, &format!("bucket >= {boundary}"));
        let cold_w = side_where(&src_cond, &format!("bucket < {boundary}"));
        let sql = format!(
            "SELECT source AS \"source\", SUM(n) AS \"count\" FROM (\
               SELECT source, n FROM event_rollup{hot_w} \
               UNION ALL \
               SELECT source, n FROM cold_rollup{cold_w}) \
             GROUP BY source ORDER BY \"count\" {order}{lim}"
        );
        return Some(RollupRoute { sql, approx: true, truncated: false, note: recency_note() });
    }

    // --- ROUTE B : `search source=X | stats count by <dim>` -> (event_dim_rollup ∪ cold_dim_rollup). ---
    let by = match sh.by_fields.as_slice() {
        [f] => f.as_str(),
        _ => return None, // multi-dim non exprimable par le dim_rollup mono-dim -> brut cold_union_query
    };
    let src = sh.source_filter.as_deref()?;
    let dim_rolled = dim_rollup_specs().iter().any(|(s, dims)| s.as_str() == src && dims.iter().any(|d| d.as_str() == by));
    if !dim_rolled {
        return None; // (source, dim) non pré-agrégé -> fall-through vers le brut cold_union_query
    }
    let dim_cond = vec![
        format!("source='{}'", guatx_core::soql::soql_esc(src)),
        format!("dim='{}'", guatx_core::soql::soql_esc(by)),
    ];
    let hot_w = side_where(&dim_cond, &format!("bucket >= {boundary}"));
    let cold_w = side_where(&dim_cond, &format!("bucket < {boundary}"));
    let sql = format!(
        "SELECT val AS {}, SUM(n) AS \"count\" FROM (\
           SELECT val, n FROM event_dim_rollup{hot_w} \
           UNION ALL \
           SELECT val, n FROM cold_dim_rollup{cold_w}) \
         GROUP BY val ORDER BY \"count\" {order}{lim}",
        guatx_core::soql::soql_qid(by),
    );
    Some(RollupRoute { sql, approx: true, truncated: true, note: recency_note() })
}

/// Injecte les champs de TRANSPARENCE dans `stats` (chemin soql uniquement). rollup -> served_from:"rollup"
/// + approx/truncated du rollup (truncated OR-é avec le plafond de lignes existant) + `rollup_note` optionnel
/// (caveat de fraîcheur QRY-1) ; sinon raw -> exact.
pub(crate) fn apply_rollup_stats(v: &mut Value, meta: &Option<(bool, bool, Option<String>)>) {
    match meta {
        Some((approx, trunc, note)) => {
            v["stats"]["served_from"] = json!("rollup");
            v["stats"]["approx"] = json!(*approx);
            let prev = v["stats"]["truncated"].as_bool().unwrap_or(false);
            v["stats"]["truncated"] = json!(prev || *trunc);
            if let Some(n) = note {
                v["stats"]["rollup_note"] = json!(n);
            }
        }
        None => {
            v["stats"]["served_from"] = json!("raw");
            v["stats"]["approx"] = json!(false);
        }
    }
}

/// Arrondit une durée en millisecondes à 3 décimales (même format que stats.elapsed_ms).
pub(crate) fn dur_ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1_000_000.0).round() / 1000.0
}
