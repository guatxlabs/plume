//! Requête analytique (P3) en lecture seule : handler `query` (SQL brut réservé admin / SOQL ouvert),
//! annulation `cancel`, et export (`export_max_rows`, `csv_cell`/`result_to_csv`/
//! `result_to_json_records`, `safe_export_name`, handler `export`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// COUNT de pagination BORNÉ (perf) — plafond de lignes comptées pour le `total` d'une page. AU-DESSOUS du
/// plafond : le total est EXACT (dernière page + numéros justes pour les petits résultats). AU plafond : on
/// renvoie `total = PAGINATION_COUNT_CAP` + `total_capped:true` (le SPA rend « … sur 10 000+ »). POURQUOI :
/// `SELECT COUNT(*) FROM (<compilé>)` non borné déchiffre+scanne TOUT le match-set (auditd-7d ~millions) juste
/// pour un total, alors que la page n'est que `LIMIT ~100`. On WRAP en `SELECT COUNT(*) FROM (SELECT 1 FROM
/// (<compilé>) LIMIT CAP+1)` : SQLite aplatit la sous-requête (le SELECT 1 n'a besoin d'aucune colonne grasse)
/// -> avec idx_event_src_ts le balayage est INDEX-ONLY et s'ARRÊTE à CAP+1 lignes (jamais le full-scan). Si le
/// compte atteint CAP+1 -> il y a > CAP lignes -> capé ; sinon exact. Best-effort inchangé : un COUNT qui dépasse
/// le watchdog reste `total=-1` (UI ◀ ▶ sans numéros).
pub(crate) const PAGINATION_COUNT_CAP: i64 = 10_000;

/// KEYSET (#28) — APPLICABILITÉ. Le browse keyset ordonne par la clé stable `(ts,id)` dans un wrap EXTERNE
/// (`keyset_page_sql`). Un stage de PROJECTION explicite (`| table …`, `| fields …`) RE-PROJETTE la sortie et
/// peut RETIRER `ts`/`id` du SELECT de tête -> le wrap `ORDER BY ts DESC, id DESC` référencerait alors une
/// colonne absente (« no such column: ts/id »). Ces requêtes projetées ne sont PAS keyset-ables : elles
/// retombent sur la pagination OFFSET (le `| sort` interne ordonne déjà ; borné, correct, = comportement
/// pré-keyset byte-identique). Détection : un stage de pipeline (segment après un `|`) dont la commande de
/// tête est `table` ou `fields`. Un `|` dans une valeur citée peut produire un FAUX POSITIF -> sûr (offset).
/// Le `search` brut nu (sans projection) garde le keyset (parcours intégral du brut, le cas d'usage central).
pub(crate) fn soql_projects_away_keyset(soql: &str) -> bool {
    soql.split('|').skip(1).any(|stage| {
        let cmd = stage.trim_start().split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        cmd == "table" || cmd == "fields"
    })
}

/// KEYSET (#28) — construit le SQL d'UNE page keyset autour du SQL compilé `sql` (qui projette `id` en fin,
/// via cursor_id). Tri STABLE `ts DESC, id DESC` (le plus récent d'abord). Sans curseur = PREMIÈRE page.
/// Avec curseur `(cts,cid)` = page SUIVANTE strictement APRÈS la dernière ligne rendue : `ts < cts OR (ts = cts
/// AND id < cid)` -> le tiebreak `id` garantit ZÉRO chevauchement / ZÉRO trou aux `ts` égaux (auditd firehose).
/// SÉCURITÉ : `cts`/`cid` sont des `i64` (parsés stricts en amont) formatés directement -> injection impossible.
/// PAS de plafond de comptage : le curseur pilote le parcours INTÉGRAL du match-set (fin du cap qui cachait).
pub(crate) fn keyset_page_sql(sql: &str, cursor: Option<(i64, i64)>, offset: i64, lim: i64) -> String {
    match cursor {
        // CURSEUR (Suivant/Précédent séquentiel) : O(page), rapide — PRIORITAIRE sur offset.
        Some((cts, cid)) => format!(
            "SELECT * FROM ({sql}) WHERE ts < {cts} OR (ts = {cts} AND id < {cid}) ORDER BY ts DESC, id DESC LIMIT {lim}"
        ),
        // SAUT À UNE PAGE (clic sur un numéro / Dernière) : OFFSET ponctuel (borné par le budget) ; la page atterrie
        // fournit son `next_cursor` -> le Suivant repart en curseur rapide. `offset` = i64 validé (>=0) -> pas d'injection.
        None if offset > 0 => format!("SELECT * FROM ({sql}) ORDER BY ts DESC, id DESC LIMIT {lim} OFFSET {offset}"),
        // PREMIÈRE page.
        None => format!("SELECT * FROM ({sql}) ORDER BY ts DESC, id DESC LIMIT {lim}"),
    }
}

/// KEYSET (#28) — finalise la réponse d'une page keyset : pose `has_more` + `next_cursor` (le `(ts,id)` de la
/// DERNIÈRE ligne) sur le résultat run_query_ex. `has_more` = la page a rendu EXACTEMENT `lim` lignes (il reste
/// probablement des lignes) OU a été tronquée au plafond run_query_ex (il en reste sûrement) -> dans les deux cas
/// on fournit le curseur de continuation. MOINS de `lim` lignes -> DERNIÈRE page (`next_cursor:null`,
/// `has_more:false`). Volontairement PAS de `total` : le curseur pilote le parcours complet, sans plafond de
/// comptage. DÉFENSIF : si les colonnes `ts`/`id` sont absentes (curseur inextractible — p.ex. une projection
/// `| table` qui a retiré `id`), on n'affirme PAS `has_more` (mieux vaut s'arrêter que boucler à l'infini).
/// `id` est une colonne SIMPLE (jamais masquée) -> `next_cursor` ne fuit aucune donnée sensible.
pub(crate) fn keyset_finalize(v: &mut Value, lim: i64) {
    let cols: Vec<&str> = v
        .get("columns")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("")).collect())
        .unwrap_or_default();
    let ts_i = cols.iter().position(|c| *c == "ts");
    let id_i = cols.iter().position(|c| *c == "id");
    let rows = v.get("rows").and_then(|r| r.as_array());
    let n = rows.map(|r| r.len()).unwrap_or(0) as i64;
    let truncated = v.get("stats").and_then(|s| s.get("truncated")).and_then(|t| t.as_bool()).unwrap_or(false);
    let more = truncated || n == lim;
    let next = if more {
        match (ts_i, id_i, rows.and_then(|r| r.last())) {
            (Some(ti), Some(ii), Some(last)) => {
                match (last.get(ti).and_then(|x| x.as_i64()), last.get(ii).and_then(|x| x.as_i64())) {
                    (Some(t), Some(id)) => json!({ "ts": t, "id": id }),
                    _ => Value::Null,
                }
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    // `has_more` HONNÊTE : true seulement si on a AUSSI un curseur de continuation exploitable.
    v["has_more"] = json!(more && !next.is_null());
    v["next_cursor"] = next;
    v["limit"] = json!(lim);
}

/// ①a — UNE page keyset hot∪cold SANS CAP, servie par le moteur colonnaire (matérialisation keyset du brut froid).
/// SÉQUENCE HOT-PUIS-COLD (insight frontière : hot `ts>=boundary` puis cold `ts<boundary` ne s'interleavent PAS en
/// `ts DESC`) :
///   • curseur SOUS le hot (ou 1re page) -> remplit depuis le HOT (keyset SQLite EXISTANT, borné `ts>=boundary` pour
///     PARITÉ avec l'union oracle qui exclut les stragglers hot `ts<boundary`) ; si le hot rend < N (épuisé), COMPLÈTE
///     avec les `N - hot` premières lignes du COLD (`cold_keyset_page`, curseur=None = sommet du froid) ;
///   • curseur DANS le cold (`cts < boundary`) -> page ENTIÈREMENT depuis le COLD (`cold_keyset_page`, curseur porté).
/// `Ok(Some(v))` = page assemblée (COMPLÈTE, `has_more = rendu==N`, aucun `truncated` cap-artefact) ; `Ok(None)` =
/// forme non routable / divergence colonnes hot∪cold -> l'appelant retombe sur `cold_union_query` keyset VERBATIM ;
/// `Err` = corruption froid (fail-closed). Le masquage #45 est déjà garanti par la garde masques-vides de l'appelant.
#[cfg(feature = "cold_tier")]
#[allow(clippy::too_many_arguments)]
fn cold_keyset_vectorized_page(
    db_path: &str,
    conf: &std::collections::HashMap<String, String>,
    env: Option<&str>,
    sql: &str,
    soql: &str,
    from: i64,
    to: i64,
    boundary: i64,
    cursor: Option<(i64, i64)>,
    n: i64,
    budget_ms: u64,
    qid: Option<&str>,
    preds: &[crate::cold_store::DimEq],
) -> Result<Option<Value>, String> {
    // Curseur DANS le cold -> page pur-froide (aucune ligne hot due : hot `ts>=boundary > cts`).
    let pure_cold = matches!(cursor, Some((cts, _)) if cts < boundary);
    // HOT part : le keyset SQLite existant, WRAPPÉ `WHERE ts >= boundary` -> PARITÉ EXACTE avec l'union oracle
    // (`event WHERE ts>=B` ∪ `cold WHERE ts<B`), qui EXCLUT les stragglers hot de `ts<B` (jamais un doublon/extra).
    let (hot_cols, mut rows): (Option<Vec<Value>>, Vec<Value>) = if pure_cold {
        (None, Vec::new())
    } else {
        let hot_sql = format!("SELECT * FROM ({sql}) WHERE ts >= {boundary}");
        let page_sql = keyset_page_sql(&hot_sql, cursor, 0, n);
        match run_query_ex(db_path, &page_sql, budget_ms, qid) {
            Ok(hv) => {
                let cols = hv.get("columns").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                let rws = hv.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                (Some(cols), rws)
            }
            // FAIL-CLOSED, PAS de fallback silencieux. Cette requête EST routable au
            // chemin keyset vectorisé (id synthétique) ; un fallback `cold_union_query` émettrait un curseur en
            // ROWID oracle (autre espace d'id). Une erreur hot TRANSITOIRE (budget/watchdog) est non-déterministe :
            // retomber sur l'oracle ici puis revenir au vectorisé à la page suivante MÉLANGERAIT les deux espaces
            // d'id -> gap/dup. On échoue la page (le client re-tente -> reste sur le vectorisé, séquence cohérente).
            // Le fallback légitime = formes JAMAIS routables (curseur oracle dès la page 1) via les `Ok(None)` plus bas.
            Err(e) => return Err(format!("hot keyset (fail-closed, cohérence espace-id): {e}")),
        }
    };
    let hot_count = rows.len() as i64;
    // COLD complément : pur-froid -> N lignes sous le curseur ; sinon (hot épuisé) -> les N-hot premières du froid.
    let cold_limit = if pure_cold { n } else { (n - hot_count).max(0) };
    let cold_cursor = if pure_cold { cursor } else { None };
    let (cold_cols, cold_rows) = if cold_limit > 0 {
        match crate::cold_store::cold_keyset_page(db_path, conf, env, from, to, boundary, soql, true, cold_cursor, cold_limit as usize, preds)? {
            Some(x) => x,
            None => return Ok(None), // non routable -> fallback COMPLET (jamais une page partielle)
        }
    } else {
        (Vec::new(), Vec::new())
    };
    // COLONNES : hot prioritaire (homogène par construction). Si le cold rend des lignes ET diverge du hot ->
    // fallback (jamais une page hot∪cold aux colonnes incohérentes).
    let columns: Vec<Value> = match &hot_cols {
        Some(hc) => {
            if !cold_rows.is_empty() {
                let cc: Vec<Value> = cold_cols.iter().map(|s| json!(s)).collect();
                if &cc != hc {
                    return Ok(None);
                }
            }
            hc.clone()
        }
        None => cold_cols.iter().map(|s| json!(s)).collect(),
    };
    for r in cold_rows {
        rows.push(Value::Array(r));
    }
    // has_more = rendu == N (pas de `truncated` cap-artefact : le parcours est COMPLET) ; next_cursor = dernière ligne.
    let mut v = json!({ "columns": columns, "rows": rows, "stats": { "truncated": false } });
    keyset_finalize(&mut v, n);
    Ok(Some(v))
}

// Requête analytique (P3) : SQL ou soql, en LECTURE SEULE (spawn_blocking).
// SQL BRUT = ADMIN : `au` sert à réserver le champ `sql` BRUT (is_soql=false) à l'admin ;
// le chemin SOQL/search reste OUVERT à TOUS les rôles (viewer inclus).
pub(crate) async fn query(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    let _mt = crate::search_timer(); // #51 DAY-2 OPS : latence recherche (p50/p95) enregistrée à la sortie (Drop)
    // FIX perf (métrique honnête) : chrono à l'ENTRÉE -> couvre TOUT (attente du permit sémaphore +
    // COUNT pagination + page), là où stats.elapsed_ms ne mesure QUE l'exécution SQL de la page. Exposé
    // en stats.server_ms (+ stats.sem_wait_ms = attente du permit). elapsed_ms conservé (compat).
    let t_start = Instant::now();
    let from = body.i64_field("from", 0);
    let to = body.i64_field("to", 0);
    // CHANGEMENT 1 : budget PAR REQUÊTE. interactive:true -> budget INTERACTIF (60 s) ; sinon AUTO (5 s,
    // inchangé : panneaux/tuiles protégés). CHANGEMENT 2 : qid client optionnel -> annulable via /api/cancel.
    let interactive = body.bool_field("interactive", false);
    let budget_ms: u64 = if interactive { query_budget_interactive_ms() } else { query_budget_ms() };
    let qid_owned: Option<String> = body.get("qid").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    // KEYSET (#28) — le client OPTE dans la pagination par CURSEUR avec `keyset:true`. Le browse Explore raw
    // l'utilise pour parcourir l'INTÉGRALITÉ du match-set (millions de lignes auditd-7d) sans le cap 10 000 qui
    // CACHAIT des événements. N'a d'effet que sur le chemin SOQL (la compilation cursor_id est SOQL-only) : un
    // `sql` brut admin retombe sur la pagination offset habituelle. Off (défaut) -> chemins offset/count intacts.
    let keyset = body.bool_field("keyset", false);
    // KEYSET APPLICABILITÉ (fix #-panels « no such column: ts/id ») : un pipeline projetant `| table`/`| fields`
    // retire la clé de tri (ts,id) -> keyset impossible. On DÉGRADE vers l'offset AVANT toute compilation, pour
    // que la base compile en mode NON-keyset (soql_to_sql_masked_x -> `| sort` interne préservé, byte-identique
    // au pré-keyset) et que `do_keyset` reste faux. `search` brut nu -> keyset intact (parcours complet). Point
    // UNIQUE : ce shadow gouverne la route rollup (l.~260), le choix de compilation (l.~288) ET `do_keyset` (l.~351).
    let keyset = keyset
        && body.get("soql").and_then(|v| v.as_str()).map(|s| !soql_projects_away_keyset(s)).unwrap_or(true);
    // rollup_meta = Some((approx, truncated, note)) si la requête a été ROUTÉE vers un rollup (sinon raw).
    let mut rollup_meta: Option<(bool, bool, Option<String>)> = None;
    // #18 P3 — UNION hot∪cold : `Some(B)` (frontière jour) si le tier cold est ON ET que la fenêtre atteint
    // SOUS `B` (territoire cold). None (feature off / cold off / fenêtre entièrement HOT / SQL brut) -> chemin
    // HOT byte-identique. Posé dans la branche SOQL ci-dessous (sous gate compile+runtime).
    #[allow(unused_mut)]
    let mut cold_boundary: Option<i64> = None;
    // #18 P4a — SOQL post-exclusion capturé pour le ROUTEUR VECTORISÉ (pur-froid + vectorisable). Posé UNIQUEMENT
    // quand masques VIDES et hors keyset (gate #3) ; None sinon -> le routeur n'est jamais tenté (fallback
    // = chemin actuel cold_union_query inchangé). Mode 0 / sans feature : variable absente.
    #[cfg(feature = "cold_tier")]
    #[allow(unused_mut)]
    let mut cold_vec_soql: Option<String> = None;
    // #28 PHASE B — les prédicats d'égalité sur les dims CIM universelles (pour l'ÉLAGAGE cold seal-résident,
    // min/max + bloom) sont extraits du SQL COMPILÉ juste avant l'appel `cold_union_query` (cf. le bloc UNION
    // ci-dessous) — pas ici : lire la SORTIE du compilateur garantit la PARITÉ (la valeur extraite ne peut
    // diverger de ce que la requête filtre) et RÉTABLIT l'élagage sur `host=web1 source in (a,b)`.
    let (sql, from_soql) = if let Some(soql) = body.get("soql").and_then(|v| v.as_str()) {
        // AFFICHAGE SEUL : substitue d'abord les placeholders d'exclusion self/opérateur (mirror
        // compile_panel_sql) -> /api/query débruite comme les panneaux ; no-op si absents. JAMAIS sur la
        // détection (rule_sql ne substitue pas ; cf invariant excl_v55_*).
        let soql = apply_excl_placeholders(soql.trim(), true);
        // FILTRE ENVIRONNEMENT (#2d) : propagé au rollup-route ET au compilo (raw event). None en mode 0.
        let env = au.env_filter();
        // FIELD FILTERS (#45) : masques EFFECTIFS pour le rôle/tenant/env de l'appelant. VIDE (mode 0 / aucune
        // règle) -> compilation byte-identique + rollup-route intact. NON VIDE -> on DÉSACTIVE le rollup-route
        // (les tables event_rollup portent src_ip/host EN CLAIR -> les servir court-circuiterait le masque) et
        // on compile via le chemin masqué (masque émis DANS le SQL, avant agrégation).
        let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
        // #18 P4a — capture le SOQL post-exclusion pour le routeur vectorisé quand masques VIDES et hors keyset
        // (le routeur ne reproduit ni HASH/MASK ni le browse par curseur). Non vide -> le routeur sera tenté sur
        // le chemin cold non paginé ; échec de routage -> fallback cold_union_query (aucune régression).
        #[cfg(feature = "cold_tier")]
        {
            // ①a — capture AUSSI en keyset : le browse cold par curseur (chemin keyset) route vers la
            // matérialisation keyset colonnaire (`cold_keyset_page`). Le chemin vectorisé NON-keyset reste gaté
            // `limit.is_none()` ET n'est atteint QUE hors keyset (les requêtes keyset early-return avant lui) ->
            // élargir la capture à keyset est sûr (aucun chevauchement de route). Masque non vide -> capture None
            // -> le keyset retombe sur `cold_union_query` (fallback capé inchangé).
            if masks.is_empty() {
                cold_vec_soql = Some(soql.to_string());
            }
        }
        // #18 P3 — DÉCLENCHEUR UNION cold : gate COMPILE (`cold_tier`) + RUNTIME (`PLUME_COLD_TIER`). La fenêtre
        // atteint SOUS la frontière jour `B` (dérivée de la MÊME `cold_hot_cutoff` que l'aging) -> on DÉSACTIVE
        // le rollup-route (les rollups sont purgés à retention_days ; complétude rollup-gap P1.5 = brut hot∪cold)
        // et on exécutera le SQL compilé sur l'UNION masquée. `from<B` couvre AUSSI `from==0` (fenêtre non bornée
        // -> inclut le cold). Feature/flag OFF -> `cold_boundary` reste None -> chemin HOT byte-identique.
        #[cfg(feature = "cold_tier")]
        {
            let conf = load_config();
            if crate::cold_store::cold_tier_runtime_on(&conf) {
                let rc = req_db(&st, &au);
                let b = {
                    let c = rc.lock();
                    let rd = retention_effective(&c, &conf, "retention_days");
                    crate::cold_store::cold_query_boundary(&c, &conf, now(), rd)
                };
                if from < b {
                    cold_boundary = Some(b);
                }
            }
        }
        // ROLLUP-ROUTE (masque VIDE requis — un masque/deny actif DÉSACTIVE toute route, hot comme cold, et
        // force le chemin masqué/authorizer). #28 Phase A : quand la fenêtre atteint SOUS `B` (cold_boundary
        // Some), on tente le rollup COLD+HOT (union event_rollup ∪ cold_rollup EN BASE, ZÉRO Parquet) ; succès
        // -> on EFFACE cold_boundary pour servir via le pool normal ; échec (motif non `count by` / dim non
        // rollée) -> cold_boundary CONSERVÉ -> chemin brut cold_union_query (correct, plus lent). Fenêtre
        // entièrement HOT (cold_boundary None) -> rollup HOT habituel, inchangé.
        // KEYSET (#28) : le browse par curseur porte sur des LIGNES BRUTES (ts,id) ; un rollup pré-agrégé n'a NI
        // `id` NI ligne individuelle -> on DÉSACTIVE toute route rollup (hot comme cold) quand `keyset` est demandé
        // et on compile la base brute AVEC `id` (via `soql_to_sql_masked_keyset_x`). Sans keyset : logique intacte.
        // WATERMARK rollup RÉEL (event_rollup_wm) : borne le corps du MERGE multi-dim au réellement-finalisé
        // (anti sous-comptage silencieux d'events ingérés en retard, cf. rollup_route::plan_merge). Absent -> MIN
        // -> tout raw (exact). Lecture indexée (PK meta), coût négligeable ; sans effet sur ROUTE A/B (single-dim).
        let rollup_wm = { let rc = req_db(&st, &au); let c = rc.lock(); event_rollup_wm(&c) };
        let rr = if masks.is_empty() && !keyset {
            #[cfg(feature = "cold_tier")]
            {
                match cold_boundary {
                    Some(b) => {
                        let c = try_cold_rollup_route(&soql, from, to, env, b, rollup_wm);
                        if c.is_some() {
                            cold_boundary = None;
                        }
                        c
                    }
                    None => try_rollup_route(&soql, from, to, env, rollup_wm),
                }
            }
            #[cfg(not(feature = "cold_tier"))]
            {
                try_rollup_route(&soql, from, to, env, rollup_wm)
            }
        } else {
            None
        };
        if let Some(rr) = rr {
            rollup_meta = Some((rr.approx, rr.truncated, rr.note));
            (rr.sql, true)
        } else {
            // KEYSET : compile AVEC la clé de tri `id` en fin de projection (cursor_id=true) ; sinon compile masqué
            // habituel (cursor_id=false, byte-identique mode 0). Les DEUX passent par le MÊME choke-point store
            // (masques #45 + authorizer read-pool inchangés -> aucune fuite via le chemin keyset).
            let compiled = if keyset {
                soql_to_sql_masked_keyset_x(&soql, from, to, env, &masks)
            } else {
                soql_to_sql_masked_x(&soql, from, to, env, &masks)
            };
            match compiled {
                Ok(s) => (s, true),
                Err(e) => return bad_req(e),
            }
        }
    } else {
        // SQL BRUT = ADMIN — le champ `sql` BRUT (is_soql=false) lit l'INTÉGRALITÉ de la base
        // (tout `SELECT … FROM …`, y compris user.hash / token.token_hash) : RÉSERVÉ ADMIN, exactement comme
        // les règles (validate_detection_content) et les panneaux (panel_create/update). Le chemin SOQL/search
        // (branche `if` supra) reste OUVERT à TOUS les rôles — c'est le langage de lecture prévu du viewer.
        // Fail-closed via raw_sql_allowed : is_soql=false + rôle non-admin -> 403 (message clair, pas d'exécution).
        if !raw_sql_allowed(false, &au.role) {
            return forbidden("SQL brut réservé à l'administrateur (utilisez SOQL)");
        }
        let raw = apply_excl_placeholders(body.str_field("sql").trim(), false);
        (raw.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()), false)
    };
    if sql.is_empty() {
        return bad_req("requête vide");
    }
    // backpressure : acquire_owned ATTEND un permit (borne les déchiffrements concurrents à
    // N -> anti-OOM, les waiters ne déchiffrent pas) ; il ne rejette jamais sous charge. UN seul acquire
    // par handler (pas de ré-acquisition imbriquée -> pas de deadlock) ; le permit couvre AUSSI le COUNT de
    // pagination ; relâché en fin de handler. Seule erreur possible = sémaphore fermé (shutdown) -> on sert
    // vide proprement (identique à panel_data + /api/search, pas de 503 « saturation » trompeur).
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({ "columns": [], "rows": [] })).into_response(),
    };
    let sem_wait_ms = dur_ms(t_start.elapsed()); // temps passé À ATTENDRE un permit (hors exécution)
    let sql_for_resp = sql.clone();
    let db_path = req_db_path(&st, &au); // #2a-2b : requête interactive routée vers la base du tenant courant
    // PAGINATION SERVEUR : si `limit` fourni ET pas de LIMIT déjà dans le SQL (raw search), on renvoie
    // UNE page (LIMIT/OFFSET) + le total (COUNT) -> le navigateur ne tient jamais qu'une page (scale 1M+).
    let limit = body.get("limit").and_then(|v| v.as_i64()).filter(|&n| n > 0 && n <= 10000);
    let offset = body.i64_field("offset", 0).max(0);
    // KEYSET (#28) — COMPTAGE TOTAL asynchrone SANS PLAFOND : le SPA le demande EN PARALLÈLE de la 1re page keyset
    // pour afficher « N résultats · page X / N » + le pager numéroté. `COUNT(*) FROM (SELECT 1 FROM (sql))` -> compte
    // index-assisté quand le filtre est indexé (idx_event_src_ts), borné par le budget interactif + annulable (qid).
    // Masques/authorizer inchangés (un COUNT compte des LIGNES, ne lit aucun champ masqué). -1 si le watchdog
    // interrompt (le SPA rend « ? »). AUCUN plafond -> aucun événement caché (contraste avec le COUNT capé de l'offset).
    if body.bool_field("count_only", false) {
        let count_sql = format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}))");
        let dbp = db_path.clone();
        let qidc = qid_owned.clone();
        let total = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &count_sql, budget_ms, qidc.as_deref()))
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|v| v.get("rows").and_then(|r| r.get(0)).and_then(|r0| r0.get(0)).and_then(|x| x.as_i64()))
            .unwrap_or(-1);
        return Json(json!({ "count_only": true, "total": total })).into_response();
    }
    // KEYSET (#28) — chemin browse par CURSEUR (parcours intégral, ZÉRO plafond de comptage). N'est actif que
    // sur le chemin SOQL (`from_soql` : la clé de tri `id` n'existe que via la compilation cursor_id). `cursor`
    // OPTIONNEL continue une page précédente : `{ts:<i64>, id:<i64>}`. SÉCURITÉ : `ts`/`id` sont parsés en i64
    // STRICT (`as_i64()` -> None si non entier) puis formatés dans le SQL -> injection IMPOSSIBLE (jamais de
    // texte non fiable interpolé). Curseur mal formé / absent -> première page (pas d'erreur).
    let do_keyset = keyset && from_soql;
    let cursor: Option<(i64, i64)> = if do_keyset {
        body.get("cursor").and_then(|c| Some((c.get("ts")?.as_i64()?, c.get("id")?.as_i64()?)))
    } else {
        None
    };
    // KEYSET — taille de page par défaut si le client n'a pas fourni `limit` (il l'envoie normalement = pageSize).
    let keyset_lim = limit.unwrap_or(100);
    // KEYSET (#28) — CHEMIN COLD hot∪cold par curseur. cold_tier OFF en prod : le HOT ci-dessous est prioritaire.
    // On applique le MÊME wrap keyset (`keyset_page_sql`) sur l'union hydratée + le MÊME masquage/authorizer que
    // le hot (via `cold_union_query`). Pas de COUNT (le curseur pilote le parcours). CAVEAT documenté : si
    // l'hydratation cold PLAFONNE (meta.truncated), on le surface et on garde `has_more` -> jamais présenté complet.
    #[cfg(feature = "cold_tier")]
    if do_keyset {
        if let Some(boundary) = cold_boundary {
            let conf = load_config();
            let env_s = au.env_filter().map(|s| s.to_string());
            let preds = crate::cold_store::extract_cold_dim_preds(&sql);
            // ①a — CHEMIN KEYSET VECTORISÉ (hot-puis-cold SÉQUENTIEL, SANS cap). Gaté `PLUME_COLD_VECTORIZED=1`,
            // masques vides (`cold_vec_soql` Some) et navigation par curseur (`offset==0` : le saut-à-la-page
            // OFFSET reste sur le fallback capé). Insight frontière : hot `ts>=boundary` puis cold `ts<boundary`
            // NE S'INTERLEAVENT PAS en `ts DESC` -> on remplit la page depuis le HOT (keyset SQLite existant,
            // borné `ts>=boundary`), et si le hot s'épuise avant N on COMPLÈTE avec le COLD keyset colonnaire.
            // `None` (forme non vectorisable / hydrat. impossible) -> FALLBACK `cold_union_query` ci-dessous.
            if offset == 0 && crate::cfg(&conf, "PLUME_COLD_VECTORIZED", "") == "1" {
                if let Some(rsoql) = cold_vec_soql.clone() {
                    let dbp = db_path.clone();
                    let confc = conf.clone();
                    let envc = env_s.clone();
                    let sqlc = sql.clone();
                    let predsc = preds.clone();
                    let qidc = qid_owned.clone();
                    let cur = cursor;
                    let res = tokio::task::spawn_blocking(move || {
                        cold_keyset_vectorized_page(&dbp, &confc, envc.as_deref(), &sqlc, &rsoql, from, to, boundary, cur, keyset_lim, budget_ms, qidc.as_deref(), &predsc)
                    })
                    .await;
                    match res {
                        Ok(Ok(Some(mut v))) => {
                            v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                            v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                            v["compiled_sql"] = json!(sql_for_resp);
                            // TRANSPARENCE : servi par le browse keyset colonnaire hot∪cold (COMPLET, sans cap).
                            v["stats"]["cold"] = json!({ "served_from": "hot+cold-vectorized-keyset", "boundary_ts": boundary });
                            return Json(v).into_response();
                        }
                        Ok(Ok(None)) => { /* non routable -> FALLBACK cold_union_query ci-dessous */ }
                        // Err = corruption froid OU erreur hot transitoire : côté SERVEUR, fail-closed
                        // et RETRIABLE (5xx, pas 4xx) -> le client re-tente et reste sur le chemin vectorisé.
                        Ok(Err(e)) => return server_err(e),
                        Err(_) => return server_err("exécution échouée"),
                    }
                }
            }
            let page_sql = keyset_page_sql(&sql, cursor, offset, keyset_lim);
            let dbp = db_path.clone();
            let qid = qid_owned.clone();
            let res = tokio::task::spawn_blocking(move || {
                crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &page_sql, None, budget_ms, qid.as_deref(), &preds)
            })
            .await;
            return match res {
                Ok(Ok((mut v, _total, meta))) => {
                    // truncated cold OR-é AVANT keyset_finalize -> `has_more` en tient compte (jamais un union tronqué
                    // présenté comme dernière page). Puis on annote la couverture cold (transparence).
                    if meta.truncated { v["stats"]["truncated"] = json!(true); }
                    keyset_finalize(&mut v, keyset_lim);
                    v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                    v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                    v["compiled_sql"] = json!(sql_for_resp);
                    v["stats"]["cold"] = json!({
                        "served_from": "hot+cold",
                        "boundary_ts": boundary,
                        "rows_hydrated": meta.rows_hydrated,
                        "files_read": meta.files_read,
                        "files_pruned": meta.files_pruned,
                        "truncated": meta.truncated,
                    });
                    Json(v).into_response()
                }
                Ok(Err(e)) => bad_req(e),
                Err(_) => server_err("exécution échouée"),
            };
        }
    }
    // KEYSET (#28) — CHEMIN HOT (prod). Wrap `SELECT * FROM ({sql}) [WHERE (ts,id) < curseur] ORDER BY ts DESC,
    // id DESC LIMIT lim`. `{sql}` est le SQL DÉJÀ compilé/masqué/autorisé (avec `id` projeté) -> le wrap PRÉSERVE
    // masques (#45), authorizer DENY (user.hash/token_hash au prepare) et scope tenant/env : `SELECT *` d'une
    // sous-requête masquée reste masqué (`id` n'est pas un champ masqué). MÊME budget/qid/permit que le hot offset.
    if do_keyset {
        let page_sql = keyset_page_sql(&sql, cursor, offset, keyset_lim);
        let dbp = db_path.clone();
        let qid = qid_owned.clone();
        let res = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &page_sql, budget_ms, qid.as_deref())).await;
        return match res {
            Ok(inner) => {
                autoindex_mark_slow_if(req_db_path(&st, &au).as_str(), &inner); // Phase 3 : chaleur lente (no-op si OFF)
                match inner {
                    Ok(mut v) => {
                        keyset_finalize(&mut v, keyset_lim);
                        v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                        v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                        v["compiled_sql"] = json!(sql_for_resp);
                        apply_rollup_stats(&mut v, &rollup_meta); // rollup_meta = None ici (keyset désactive la route) -> served_from=raw
                        Json(v).into_response()
                    }
                    Err(e) => bad_req(e),
                }
            }
            Err(_) => server_err("exécution échouée"),
        };
    }
    // #18 P3 — CHEMIN UNION hot∪cold. Early-return DÉDIÉ (le chemin HOT ci-dessous reste byte-identique). On
    // construit la connexion d'union UNE FOIS (une seule hydratation) et on exécute page + COUNT dans UN SEUL
    // spawn_blocking (la Connection ne traverse jamais un .await). Masquage (#45) + authorizer DENY appliqués aux
    // lignes cold via le MÊME SQL compilé + le MÊME authorizer (cf. cold_store::open_cold_union). `truncated`
    // (plafond cold atteint) est SURFACÉ (jamais un cold∪hot incomplet présenté comme complet).
    #[cfg(feature = "cold_tier")]
    if let Some(boundary) = cold_boundary {
        // #18 P4a — ROUTEUR VECTORISÉ (premier câblage runtime). Tenté UNIQUEMENT sur le chemin NON paginé
        // (limit None : dashboards/agrégats), pour une requête pur-froid ET vectorisable (masques vides). Succès
        // -> servi par les kernels (vitesse) ; None -> FALLBACK au chemin actuel cold_union_query CI-DESSOUS
        // (INCHANGÉ). Invariant : résultat routé == résultat cold_union_query (prouvé par le harnais de parité).
        // #28 P3.5 — égalités de dims extraites du SQL COMPILÉ (post-masquage #45), le MÊME que celui exécuté par
        // l'oracle `cold_union_query` ci-dessous -> les DEUX chemins élaguent le MÊME ensemble de fichiers (cohérence
        // du gate cap). Calculé UNE FOIS ici et partagé (vectorisé + union).
        let cold_dim_preds = crate::cold_store::extract_cold_dim_preds(&sql);
        if limit.is_none() {
            if let Some(rsoql) = cold_vec_soql.clone() {
                let conf = load_config();
                let env_s = au.env_filter().map(|s| s.to_string());
                let dbp = db_path.clone();
                let preds = cold_dim_preds.clone();
                let qidv = qid_owned.clone();
                // #18 P4a vs P4b — ROUTAGE selon la FENÊTRE : PUR-FROID (`0 < to < boundary`) -> kernels seuls
                // (`cold_vectorized_try`) ; CHEVAUCHANTE (`from < boundary <= to`, ou `to<=0` non borné haut =
                // atteint le hot) -> MERGE hot∪cold (`cold_vectorized_merge_try` : froid vectorisé + hot SQLite
                // fusionnés). Une SEULE des deux est appelée (compteur de route propre). None (l'une ou l'autre)
                // -> FALLBACK au chemin actuel cold_union_query CI-DESSOUS (INCHANGÉ). Invariant des deux :
                // résultat routé == cold_union_query (harnais de parité p4a_* / p4b_*).
                let pure_cold = to > 0 && to < boundary;
                let res = tokio::task::spawn_blocking(move || {
                    if pure_cold {
                        crate::cold_store::cold_vectorized_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, &preds)
                    } else {
                        crate::cold_store::cold_vectorized_merge_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, qidv.as_deref(), &preds)
                    }
                })
                .await;
                match res {
                    Ok(Ok(Some(mut v))) => {
                        let mode = if pure_cold { "cold-vectorized" } else { "cold-vectorized-merge" };
                        v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                        v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                        v["compiled_sql"] = json!(sql_for_resp);
                        v["stats"]["served_from"] = json!(mode);
                        // TRANSPARENCE : servi par le moteur colonnaire (pur-froid) ou le merge hot∪cold vectorisé.
                        v["stats"]["cold"] = json!({ "served_from": mode, "boundary_ts": boundary });
                        return Json(v).into_response();
                    }
                    Ok(Ok(None)) => { /* non vectorisable / non routable -> fallback cold_union_query ci-dessous */ }
                    Ok(Err(e)) => return bad_req(e), // corruption cold -> fail-closed (comme l'oracle)
                    Err(_) => return server_err("exécution échouée"),
                }
            }
        }
        let conf = load_config();
        let env_s = au.env_filter().map(|s| s.to_string());
        let (page_sql, count_sql) = match limit {
            Some(lim) => (
                format!("SELECT * FROM ({sql}) LIMIT {lim} OFFSET {offset}"),
                // COUNT BORNÉ (perf) : MÊME plafond que le chemin hot (cf. PAGINATION_COUNT_CAP) -> le COUNT sur
                // l'union hydratée hot∪cold s'arrête à CAP+1 lignes au lieu de compter tout le match-set.
                Some(format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}) LIMIT {})", PAGINATION_COUNT_CAP + 1)),
            ),
            None => (sql.clone(), None),
        };
        let dbp = db_path.clone();
        let qid = qid_owned.clone();
        // #28 PHASE B/P3.5 — RÉUTILISE les égalités de dims déjà extraites du SQL COMPILÉ (`sql`, post-masquage
        // #45), le MÊME jeu que le chemin vectorisé ci-dessus -> parité par construction + gate cap cohérent.
        let preds = cold_dim_preds;
        let res = tokio::task::spawn_blocking(move || {
            crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &page_sql, count_sql.as_deref(), budget_ms, qid.as_deref(), &preds)
        })
        .await;
        return match res {
            Ok(Ok((mut v, total, meta))) => {
                v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                v["compiled_sql"] = json!(sql_for_resp);
                // TRANSPARENCE + INCOMPLÉTUDE : couverture cold + drapeau. Truncated cold -> on OR-e aussi le
                // `stats.truncated` global (même posture que le row-cap hot) : aucun consommateur ne peut prendre
                // un cold∪hot tronqué pour complet.
                v["stats"]["cold"] = json!({
                    "served_from": "hot+cold",
                    "boundary_ts": boundary,
                    "rows_hydrated": meta.rows_hydrated,
                    "files_read": meta.files_read,
                    "files_pruned": meta.files_pruned,
                    "truncated": meta.truncated,
                });
                if meta.truncated {
                    v["stats"]["truncated"] = json!(true);
                }
                if let Some(lim) = limit {
                    // COUNT BORNÉ : raw = min(vrai_total, CAP+1). > CAP -> capé (CAP + total_capped) ; sinon exact.
                    let raw_total = total.unwrap_or(-1);
                    let total_capped = raw_total > PAGINATION_COUNT_CAP;
                    v["total"] = json!(if total_capped { PAGINATION_COUNT_CAP } else { raw_total });
                    if total_capped { v["total_capped"] = json!(true); }
                    v["offset"] = json!(offset);
                    v["limit"] = json!(lim);
                }
                Json(v).into_response()
            }
            Ok(Err(e)) => bad_req(e),
            Err(_) => server_err("exécution échouée"),
        };
    }
    if let Some(lim) = limit {
        // pagination par WRAP en sous-requête : marche AUSSI quand {sql} a déjà un LIMIT (`| head`) ->
        // l'inner cape, l'outer pagine dedans. AVANT : `if !contains(" limit ")` SAUTAIT la pagination
        // pour ces requêtes -> offset ignoré (chaque page = mêmes lignes) + pas de `total` -> pager cassé.
        let page_sql = format!("SELECT * FROM ({sql}) LIMIT {lim} OFFSET {offset}");
        // COUNT BORNÉ (perf) : plafonné à PAGINATION_COUNT_CAP+1 lignes -> exact sous le plafond, capé au-dessus
        // (cf. PAGINATION_COUNT_CAP). Le SELECT 1 s'aplatit -> index-only via idx_event_src_ts, s'arrête au cap.
        let count_sql = format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}) LIMIT {})", PAGINATION_COUNT_CAP + 1);
        let dbp = db_path.clone();
        // FIX perf : COUNT total et page lancés CONCURREMMENT (tokio::join!) -> latence ≈ max(count, page)
        // au lieu de count + page (avant : await séquentiels). Sémantique inchangée ; le permit du
        // sémaphore couvre toujours les deux (relâché en fin de handler).
        // budget par requête (CHANGEMENT 1) + qid pour l'annulation (CHANGEMENT 2) : page ET count sont
        // enregistrés sous le qid -> /api/cancel interrompt les deux (sinon le join! attendrait le count).
        let qid1 = qid_owned.clone();
        let qid2 = qid_owned.clone();
        let count_fut = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &count_sql, budget_ms, qid1.as_deref()));
        let page_fut = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &page_sql, budget_ms, qid2.as_deref()));
        let (count_res, page) = tokio::join!(count_fut, page_fut);
        // total best-effort : si le COUNT dépasse le watchdog (requête énorme), -1 -> UI ◀ ▶ sans numéros.
        let raw_total = count_res
            .ok().and_then(|r| r.ok())
            .and_then(|v| v.get("rows").and_then(|r| r.get(0)).and_then(|r0| r0.get(0)).and_then(|x| x.as_i64()))
            .unwrap_or(-1);
        // COUNT BORNÉ : raw_total = min(vrai_total, CAP+1). > CAP -> capé (on renvoie CAP + total_capped) ; sinon
        // EXACT (petits résultats : dernière page + numéros justes). -1 (watchdog) N'est jamais > CAP -> intact.
        let total_capped = raw_total > PAGINATION_COUNT_CAP;
        let total = if total_capped { PAGINATION_COUNT_CAP } else { raw_total };
        return match page {
            Ok(inner) => {
                if from_soql {
                    autoindex_mark_slow_if(req_db_path(&st, &au).as_str(), &inner); // Phase 3 : marque la chaleur lente (no-op si OFF)
                }
                match inner {
                    Ok(mut v) => {
                        v["total"] = json!(total);
                        if total_capped { v["total_capped"] = json!(true); }  // le SPA rend « … sur 10 000+ »
                        v["offset"] = json!(offset);
                        v["limit"] = json!(lim);
                        v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                        v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                        if from_soql {
                            v["compiled_sql"] = json!(sql_for_resp);
                            apply_rollup_stats(&mut v, &rollup_meta); // served_from/approx/truncated (transparence)
                        }
                        Json(v).into_response()
                    }
                    Err(e) => bad_req(e),
                }
            }
            Err(_) => server_err("exécution échouée"),
        };
    }
    let qid_c = qid_owned.clone();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &sql, budget_ms, qid_c.as_deref())).await;
    match res {
        Ok(inner) => {
            // PHASE 3 : si la requête venait de soql, marque LENTS les champs json touchés ce cycle
            // (instrumentation cheap, no-op si auto-index OFF).
            if from_soql {
                autoindex_mark_slow_if(req_db_path(&st, &au).as_str(), &inner);
            }
            match inner {
                Ok(mut v) => {
                    v["stats"]["server_ms"] = json!(dur_ms(t_start.elapsed()));
                    v["stats"]["sem_wait_ms"] = json!(sem_wait_ms);
                    if from_soql {
                        v["compiled_sql"] = json!(sql_for_resp);
                        apply_rollup_stats(&mut v, &rollup_meta); // served_from/approx/truncated (transparence)
                    }
                    Json(v).into_response()
                }
                Err(e) => bad_req(e),
            }
        }
        Err(_) => server_err("exécution échouée"),
    }
}

/// CHANGEMENT 2 — annulation serveur (bouton STOP). Body `{"qid":"..."}` : pose le drapeau `cancelled`
/// puis appelle `.interrupt()` sur TOUTES les requêtes en vol de ce qid (page + count de pagination) ->
/// la requête en cours s'arrête et renvoie « annulé par l'utilisateur » (pas un 500). Idempotent (qid
/// inconnu/déjà fini -> cancelled:0). Même garde d'auth que /api/query (viewer) via readonly_post.
pub(crate) async fn cancel(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let qid = b.trimmed("qid");
    if qid.is_empty() {
        return bad_req("qid requis");
    }
    // MT-KEY : n'annule QUE les requêtes en vol de CE db_path portant ce qid (jamais celles d'une autre base).
    let key = (req_db_path(&st, &au), qid.clone());
    let mut n = 0u32;
    if let Some(reg) = QUERY_CANCEL.get() {
        { let map = reg.lock();
            if let Some(vec) = map.get(&key) {
                for e in vec {
                    e.cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                    e.interrupt.interrupt();
                    n += 1;
                }
            }
        }
    }
    Json(json!({ "cancelled": n, "qid": qid })).into_response()
}

// ================================================================================================
// EXPORT (CSV / JSON) — P0 UI. INVARIANT DE SÉCURITÉ : ne fait RIEN d'autre que /api/query, en changeant
// UNIQUEMENT le format de sortie. Même compilation (SOQL ouvert à tous ; champ `sql` BRUT réservé admin via
// raw_sql_allowed), même exécuteur run_query_ex -> donc MÊME authorizer read-pool qui DENY user.hash /
// token.token_hash / connector.secret au prepare() (non contournable, même en SQL brut admin), MÊME budget/
// watchdog, MÊME plafond de lignes. Un export ne peut donc PAS voir une colonne que /api/query ne verrait
// pas, ni contourner le gate admin, ni produire un dump brut non caviardé. Aucun accès à st.db (sans
// authorizer) : tout passe par req_db_path + run_query_ex (read pool). Mode 0 / data-plane inchangés.
// ================================================================================================

/// Plafond de lignes d'un export (borne la taille du fichier). Réglable via PLUME_EXPORT_MAX, borné dur à
/// 100k (= plafond dur de run_query_ex). run_query_ex applique DE TOUTE FAÇON son propre max_rows
/// (PLUME_QUERY_MAX) -> l'export ne dépasse jamais le plafond de lecture existant (pas d'exfiltration massive).
pub(crate) fn export_max_rows() -> i64 {
    std::env::var("PLUME_EXPORT_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0 && n <= 100_000)
        .unwrap_or(50_000)
}

/// Seuil de lignes au-delà duquel un EXPORT est audité (exfiltration potentielle).
/// Réglable via PLUME_AUDIT_BULK_ROWS (défaut 10 000). L'/api/query interactif est paginé (≤ 10k/page) -> le
/// vecteur d'exfil de masse est l'export ; c'est lui qu'on audite.
pub(crate) fn bulk_read_threshold() -> usize {
    std::env::var("PLUME_AUDIT_BULK_ROWS").ok().and_then(|s| s.parse().ok()).filter(|&n| n > 0).unwrap_or(10_000)
}
/// Émet un event source=plume-audit action=bulk_read SI (et seulement si) `rows >= seuil` -> mode-0-INERTE
/// (une lecture normale ne l'atteint jamais). Best-effort ; ne porte JAMAIS de donnée de résultat (juste le
/// compte + le principal). La règle SEC4 « lecture/export de masse » alerte dessus.
pub(crate) fn audit_bulk_read(st: &AppState, au: &AuthUser, kind: &str, rows: usize) {
    if rows < bulk_read_threshold() { return; }
    let ts = now();
    let msg = format!("{kind} de masse : {rows} lignes par '{}' (rôle {})", au.name, au.role);
    let fields = json!({ "action": "bulk_read", "kind": kind, "principal": au.name, "role": au.role, "rows": rows }).to_string();
    let conn = st.db.lock();
    let _ = conn.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,'plume-audit','audit',3,?2,'plume-daemon',?3,'daemon')",
        params![ts, msg, fields],
    );
}

/// Échappe une cellule CSV (RFC 4180) + neutralisation d'injection de formule (OWASP CSV injection) : une
/// cellule TEXTE débutant par `= + @` ou un caractère de contrôle (\t \r) est préfixée d'une apostrophe ->
/// le tableur ne l'interprète PAS comme une formule. Les nombres/booléens ne sont jamais neutralisés.
pub(crate) fn csv_cell(v: &Value) -> String {
    let raw = match v {
        Value::Null => return String::new(),
        Value::Bool(b) => return b.to_string(),
        Value::Number(n) => return n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let needs_guard = raw
        .as_bytes()
        .first()
        .is_some_and(|&c| matches!(c, b'=' | b'+' | b'@' | b'\t' | b'\r'));
    let guarded = if needs_guard { format!("'{raw}") } else { raw };
    if guarded.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Sérialise un résultat run_query_ex ({columns, rows}) en CSV (en-tête = colonnes ; CRLF ; RFC 4180).
pub(crate) fn result_to_csv(v: &Value) -> String {
    let empty: Vec<Value> = Vec::new();
    let cols = v.get("columns").and_then(|c| c.as_array()).unwrap_or(&empty);
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);
    let mut out = String::new();
    let header: Vec<String> = cols.iter().map(csv_cell).collect();
    out.push_str(&header.join(","));
    out.push_str("\r\n");
    for row in rows {
        if let Some(arr) = row.as_array() {
            let line: Vec<String> = arr.iter().map(csv_cell).collect();
            out.push_str(&line.join(","));
            out.push_str("\r\n");
        }
    }
    out
}

/// Sérialise un résultat en JSON « records » ([{col: val, ...}, ...]) — le format le plus consommable par
/// un tiers. Colonnes homonymes : la dernière l'emporte (rare en SOQL/table). Valeurs déjà caviardées par
/// run_query_ex (l'authorizer a refusé les colonnes secrètes au prepare()).
pub(crate) fn result_to_json_records(v: &Value) -> Value {
    let cols: Vec<String> = v
        .get("columns")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let empty: Vec<Value> = Vec::new();
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);
    let recs: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            if let Some(arr) = row.as_array() {
                for (i, c) in cols.iter().enumerate() {
                    obj.insert(c.clone(), arr.get(i).cloned().unwrap_or(Value::Null));
                }
            }
            Value::Object(obj)
        })
        .collect();
    Value::Array(recs)
}

/// Nom de fichier SÛR (anti-injection d'en-tête Content-Disposition) : ne conserve que [A-Za-z0-9._-],
/// borné à 48 caractères, défaut « export ». Empêche toute CRLF/guillemet dans l'en-tête.
pub(crate) fn safe_export_name(raw: Option<&str>) -> String {
    let s: String = raw
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(48)
        .collect();
    if s.is_empty() { "export".to_string() } else { s }
}

/// EXPORT CSV/JSON — même gating et même exécuteur que /api/query (cf. bloc EXPORT supra). Body :
/// `{ format:"csv"|"json", soql?|sql?, from?, to?, limit?, name? }`. Enregistré en `readonly_post`
/// (POST de LECTURE) -> viewer autorisé pour SOQL ; `sql` brut refusé au non-admin (raw_sql_allowed).
/// Réponse = fichier en pièce jointe (Content-Disposition: attachment) + X-Plume-Truncated si le plafond
/// de lignes a été atteint.
pub(crate) async fn export(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    let from = body.i64_field("from", 0);
    let to = body.i64_field("to", 0);
    let format = body.get("format").and_then(|v| v.as_str()).unwrap_or("csv").to_ascii_lowercase();
    if format != "csv" && format != "json" {
        return bad_req("format invalide (csv|json)");
    }
    // #18 P3 — comme /api/query : union hot∪cold quand la fenêtre atteint sous la frontière jour (sinon None).
    #[allow(unused_mut)]
    let mut cold_boundary: Option<i64> = None;
    // #28 PHASE B — MÊME élagage dimensionnel cold que /api/query : les prédicats sont extraits du SQL COMPILÉ
    // juste avant `cold_union_query` (parité par construction), pas ici.
    // --- COMPILATION STRICTEMENT IDENTIQUE À /api/query (choke-point unique de redaction/RBAC) ---
    let (sql, _from_soql) = if let Some(soql) = body.get("soql").and_then(|v| v.as_str()) {
        let soql = apply_excl_placeholders(soql.trim(), true);
        let env = au.env_filter();
        // FIELD FILTERS (#45) : export = MÊME compilation masquée que /api/query (choke-point unique). Masques
        // VIDES -> byte-identique + rollup-route intact ; sinon rollup désactivé (src_ip/host en clair) + compile
        // masqué -> l'export CSV/JSON hérite AUTOMATIQUEMENT du masque (jamais de dump brut non caviardé).
        let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
        // #18 P3 — MÊME déclencheur union que /api/query : une fenêtre atteignant sous `B` DÉSACTIVE le rollup-route
        // (complétude rollup-gap) et exporte l'union hot∪cold masquée -> un export sur longue histoire n'omet JAMAIS
        // en SILENCE les lignes cold. Feature/flag OFF -> None -> chemin HOT byte-identique.
        #[cfg(feature = "cold_tier")]
        {
            let conf = load_config();
            if crate::cold_store::cold_tier_runtime_on(&conf) {
                let rc = req_db(&st, &au);
                let b = {
                    let c = rc.lock();
                    let rd = retention_effective(&c, &conf, "retention_days");
                    crate::cold_store::cold_query_boundary(&c, &conf, now(), rd)
                };
                if from < b {
                    cold_boundary = Some(b);
                }
            }
        }
        // #28 Phase A — MÊME logique que /api/query : rollup COLD+HOT (ZÉRO Parquet) quand la fenêtre atteint
        // sous `B` et qu'aucun masque n'est actif ; succès -> cold_boundary effacé (pool normal) ; sinon chemin
        // brut cold_union_query. Un masque/deny actif -> aucune route -> compile masqué + authorizer (parité).
        // WATERMARK rollup RÉEL (event_rollup_wm) : voir /api/query — borne le corps du MERGE au finalisé.
        let rollup_wm = { let rc = req_db(&st, &au); let c = rc.lock(); event_rollup_wm(&c) };
        let rr = if masks.is_empty() {
            #[cfg(feature = "cold_tier")]
            {
                match cold_boundary {
                    Some(b) => {
                        let c = try_cold_rollup_route(&soql, from, to, env, b, rollup_wm);
                        if c.is_some() {
                            cold_boundary = None;
                        }
                        c
                    }
                    None => try_rollup_route(&soql, from, to, env, rollup_wm),
                }
            }
            #[cfg(not(feature = "cold_tier"))]
            {
                try_rollup_route(&soql, from, to, env, rollup_wm)
            }
        } else {
            None
        };
        if let Some(rr) = rr {
            (rr.sql, true)
        } else {
            match soql_to_sql_masked_x(&soql, from, to, env, &masks) {
                Ok(s) => (s, true),
                Err(e) => return bad_req(e),
            }
        }
    } else {
        // FAILLE A (miroir /api/query) : le champ `sql` BRUT lit toute la base -> RÉSERVÉ ADMIN. L'authorizer
        // read-pool DENY quand même les colonnes secrètes, même pour un admin (défense en profondeur).
        if !raw_sql_allowed(false, &au.role) {
            return forbidden("SQL brut réservé à l'administrateur (utilisez SOQL)");
        }
        let raw = apply_excl_placeholders(body.str_field("sql").trim(), false);
        (raw.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()), false)
    };
    if sql.is_empty() {
        return bad_req("requête vide");
    }
    // borne d'export : wrap LIMIT (marche même si {sql} a déjà un LIMIT — l'inner cape). run_query_ex applique
    // EN PLUS son propre plafond (max_rows) -> jamais au-delà du plafond de lecture existant.
    let limit = body
        .get("limit")
        .and_then(|v| v.as_i64())
        .filter(|&n| n > 0)
        .unwrap_or_else(export_max_rows)
        .min(export_max_rows());
    // backpressure : MÊME sémaphore que /api/query (borne les déchiffrements concurrents ; anti-OOM).
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    let db_path = req_db_path(&st, &au); // #2a : base du tenant courant (jamais st.db, jamais une autre base)
    let page_sql = format!("SELECT * FROM ({sql}) LIMIT {limit}");
    let budget = query_budget_interactive_ms(); // export = action délibérée -> budget interactif (comme /api/query interactive)
    // #18 P3 — INCOMPLÉTUDE : un export cold-tronqué DOIT le signaler (X-Plume-Truncated) -> jamais un CSV/JSON
    // partiel présenté comme complet. `cold_extra_truncated` OR-e la troncature cold au flag `stats.truncated`.
    #[allow(unused_mut)]
    let mut cold_extra_truncated = false;
    #[cfg(feature = "cold_tier")]
    let v = if let Some(boundary) = cold_boundary {
        let conf = load_config();
        let env_s = au.env_filter().map(|s| s.to_string());
        let dbp = db_path.clone();
        let ps = page_sql.clone();
        // #28 PHASE B — extrait du SQL COMPILÉ (`sql`, post-masquage #45), le MÊME qui s'exécute sur l'union.
        let preds = crate::cold_store::extract_cold_dim_preds(&sql);
        let res = tokio::task::spawn_blocking(move || {
            crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &ps, None, budget, None, &preds)
        })
        .await;
        match res {
            Ok(Ok((v, _total, meta))) => {
                cold_extra_truncated = meta.truncated;
                v
            }
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    } else {
        let dbp = db_path.clone();
        let ps = page_sql.clone();
        match tokio::task::spawn_blocking(move || run_query_ex(&dbp, &ps, budget, None)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    };
    #[cfg(not(feature = "cold_tier"))]
    let v = {
        let res = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &page_sql, budget, None)).await;
        match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    };
    // AUDIT : audite l'export SI le volume dépasse le seuil (exfiltration potentielle).
    let nrows = v.get("rows").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0);
    audit_bulk_read(&st, &au, "export", nrows);
    let truncated = v.get("stats").and_then(|s| s.get("truncated")).and_then(|t| t.as_bool()).unwrap_or(false) || cold_extra_truncated;
    let (ct, ext, body_str): (&'static str, &str, String) = if format == "csv" {
        ("text/csv; charset=utf-8", "csv", result_to_csv(&v))
    } else {
        ("application/json; charset=utf-8", "json", serde_json::to_string(&result_to_json_records(&v)).unwrap_or_else(|_| "[]".into()))
    };
    let fname = format!("plume-{}-{}.{}", safe_export_name(body.get("name").and_then(|v| v.as_str())), now(), ext);
    let disp = format!("attachment; filename=\"{fname}\"");
    let mut resp = (StatusCode::OK, body_str).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static(ct));
    if let Ok(hv) = axum::http::HeaderValue::from_str(&disp) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    h.insert(
        axum::http::HeaderName::from_static("x-plume-truncated"),
        axum::http::HeaderValue::from_static(if truncated { "1" } else { "0" }),
    );
    resp
}
