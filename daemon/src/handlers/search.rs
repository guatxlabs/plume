//! Handler `/api/search` — recherche interactive (FTS + filtres structurés, masques #45,
//! garde-oracle, watchdog read-pool). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Prédicat d'égalité `champ:valeur` de la BARRE, y compris l'ALIAS DE LECTURE CIM.
///
/// EXTRAITE DU HANDLER POUR ÊTRE TESTABLE, et ce n'est pas de la cosmétique : tant que cette décision
/// vivait en ligne dans un handler `async`, aucun test ne pouvait l'atteindre — une revue adverse a
/// neutralisé la branche d'alias et la suite est restée VERTE à 757. Une garde qu'aucun test ne défend
/// sera supprimée au premier nettoyage, par quelqu'un de bonne foi qui la croira morte.
///
/// L'alias lui-même (dette de migration, péremption 2027-07-23) : cette barre construit son SQL À LA
/// MAIN, elle NE passe PAS par le compilateur GXQL, donc pas par `cim_read_alias_exec`. Sans lui,
/// `category:exec` ici serait AVEUGLE sur l'historique `process` des collecteurs Windows d'avant le
/// 2026-07-23, alors que la MÊME question posée en GXQL le trouverait — deux réponses pour une question.
pub(crate) fn search_bar_exact_pred(col: &str, v: &str) -> String {
    if col == "category" && v == CIM_EXEC_CANON {
        format!("e.category IN ('{CIM_EXEC_CANON}','{CIM_EXEC_LEGACY}')")
    } else {
        format!("e.{col}='{v}'")
    }
}

/// #18 — COUVERTURE DÉCLARÉE DE LA BARRE DE RECHERCHE.
///
/// LE DÉFAUT QU'ELLE FERME. `/api/search` interroge `event` — la table HOT — et RIEN d'autre. Quand le
/// tier froid est actif, tout ce qui est plus vieux que la frontière `B` a quitté `event` pour du
/// Parquet. Avec une rétention d'un an et une fenêtre chaude de 7 jours, la barre était donc MUETTE sur
/// 358 des 365 jours conservés — et elle rendait `{"results": []}`, c'est-à-dire « rien ne correspond »,
/// alors que la réponse honnête était « je n'ai pas cherché là ». Un mensonge par omission.
///
/// POURQUOI ELLE DÉCLARE AU LIEU DE SERVIR. Servir le froid ici demanderait un index plein-texte sur le
/// colonnaire, qui n'existe pas ; l'imiter par un `LIKE`/regex donnerait une AUTRE sémantique
/// (tokenisation, préfixes, opérateurs booléens de FTS5) — donc un second mensonge, plus difficile à
/// voir. On refuse donc explicitement, on NOMME la cause, et on donne la voie qui, elle, lit le froid :
/// `/api/query` en GXQL. Une erreur vaut mieux qu'une réponse fausse ; un silence ne vaut rien.
///
/// `None` = rien à déclarer (tier froid inactif, aucune donnée froide, ou fenêtre entièrement chaude).
#[cfg(feature = "cold_tier")]
pub(crate) fn search_cold_coverage(conn: &Connection, conf: &HashMap<String, String>, boundary: i64, from: i64) -> Option<Value> {
    if !crate::cold_store::cold_tier_runtime_on(conf) {
        return None;
    }
    // La fenêtre demandée atteint-elle SOUS la frontière ? `from == 0` = non bornée -> oui.
    if from > 0 && from >= boundary {
        return None;
    }
    // Y a-t-il vraiment de l'histoire froide ? Sans seal, la barre couvre tout ce qui existe et une
    // note serait du bruit. Table absente / illisible -> None (jamais d'alarme sur une incertitude).
    let has_cold: bool = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM cold_seal WHERE day < ?1)", params![boundary / 86_400], |r| r.get::<_, i64>(0))
        .map(|n| n == 1)
        .unwrap_or(false);
    if !has_cold {
        return None;
    }
    Some(json!({
        "searched_from": boundary,
        "cold_boundary_ts": boundary,
        "reason": "fts_hot_only",
        "notice": "recherche INCOMPLÈTE : la barre plein-texte n'interroge que l'index FTS5, qui n'existe \
                   que sur la fenêtre chaude — l'historique columnarisé plus ancien n'a PAS été cherché \
                   (ce n'est donc pas « aucun résultat »). Voie EXACTE sur tout l'historique : /api/query \
                   en GXQL, qui lit le tier froid (p. ex. `search message=~<motif>` ou `search \
                   <champ>=<valeur>`)."
    }))
}

pub(crate) async fn search(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let _mt = crate::search_timer(); // #51 DAY-2 OPS : latence recherche (p50/p95) enregistrée à la sortie (Drop)
    let term = q.get("q").cloned().unwrap_or_default();
    let mut limit: i64 = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(st.search_limit_default).clamp(1, st.search_limit_max);
    if term.trim().is_empty() {
        return Json(json!({ "results": [] }));
    }
    // FIELD FILTERS (#45) : masques effectifs de l'appelant. VIDE (mode 0 / admin sans règle) -> aucune garde,
    // /api/search byte-identique. NON VIDE -> (1) refuse tout FILTRE (structuré/regex/joker/plein-texte) qui
    // sonderait un champ masqué (oracle par nombre de lignes) ET le blob `fields` brut (probe des clés JSON) ;
    // (2) caviarde les champs masqués des résultats (plus bas). Réutilisé pour le masquage de sortie.
    let search_db = req_db_path(&st, &au);
    let search_masks = effective_masks(&search_db, &au.role, &au.tenant, au.env_filter());
    // GARDE ORACLE : refuse tout filtre/plein-texte sondant un champ masqué (fonction pure testable). VIDE ->
    // Ok immédiat -> /api/search byte-identique (mode 0). Admin sans règle : jamais restreint.
    if let Err(field) = search_mask_guard(&term, &search_masks, fts_fields_enabled()) {
        let msg = if field == "plein-texte" {
            "recherche plein-texte interdite : un champ indexé (message/source/category ou une clé JSON) est masqué pour votre rôle".to_string()
        } else {
            format!("filtrage interdit sur le champ masqué « {field} » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)")
        };
        return Json(json!({ "results": [], "error": msg }));
    }
    // champs hors-FTS (severity/host/src_ip) -> WHERE structuré ; le reste -> FTS
    let mut fts_terms: Vec<String> = Vec::new();
    let mut where_extra: Vec<String> = Vec::new();
    // Parseur GÉNÉRIQUE : `champ:valeur` / `champ=valeur` sur N'IMPORTE quel champ whitelisté ; valeur =
    // `~motif` (REGEXP), `val*` (joker LIKE) ou exact. `regex=` = raccourci regex sur le message.
    // severity = cas spécial (label/num -> num). Sinon -> recherche plein-texte (FTS). cf field_col().
    for tok in soql_glue_spaced_ops(search_tokens(&term)) {
        // limit:N / max:N -> plafond de résultats dans la requête même (borné 1..5000, anti-flood UI/DoS)
        if let Some(v) = tok.strip_prefix("limit:").or_else(|| tok.strip_prefix("limit=")).or_else(|| tok.strip_prefix("max:")).or_else(|| tok.strip_prefix("max=")) {
            if let Ok(n) = v.parse::<i64>() { limit = n.clamp(1, st.search_limit_max); }
            continue;
        }
        if let Some(v) = tok.strip_prefix("regex=").or_else(|| tok.strip_prefix("regex:")) {
            if !v.is_empty() { where_extra.push(format!("e.message REGEXP '{}'", v.replace('\'', "''"))); }
            continue;
        }
        if let Some(i) = tok.find(|c| c == ':' || c == '=') {
            if let Some(col) = field_col(&tok[..i].to_ascii_lowercase()) {
                let raw = &tok[i + 1..];
                if !raw.is_empty() {
                    if col == "severity" {
                        if let Some(n) = sev_num(raw) { where_extra.push(format!("e.severity={n}")); }
                    } else {
                        let v = raw.replace('\'', "''");
                        if let Some(rx) = v.strip_prefix('~') {            // champ:~motif -> REGEXP
                            where_extra.push(format!("e.{col} REGEXP '{rx}'"));
                        } else if v.contains('*') {                        // champ:val* -> joker (LIKE)
                            where_extra.push(format!("e.{col} LIKE '{}'", v.replace('*', "%")));
                        } else {                                           // champ:val -> exact (ou alias CIM)
                            where_extra.push(search_bar_exact_pred(col, &v));
                        }
                    }
                }
                continue;
            }
        }
        fts_terms.push(tok);
    }
    let q_from = q.get("from").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    if q_from > 0 { where_extra.push(format!("e.ts>={q_from}")); }
    if let Some(t) = q.get("to").and_then(|s| s.parse::<i64>().ok()) {
        if t > 0 { where_extra.push(format!("e.ts<={t}")); }
    }
    // FILTRE ENVIRONNEMENT (#2d) : /api/search construit son SQL à la main (event aliasé `e`) -> injection
    // directe. None (mode 0) -> aucune condition -> résultats tous-env (identique). Valeur validée
    // (env_slug_ok) + échappée (soql_esc) -> anti-injection. Couvre les DEUX branches (FTS et WHERE structuré).
    if let Some(e) = au.env_filter().filter(|e| !e.is_empty()) {
        where_extra.push(format!("e.env_id='{}'", guatx_core::soql::soql_esc(e)));
    }
    // backpressure : acquire_owned ATTEND un permit (borne les déchiffrements concurrents à
    // N -> anti-OOM ; un scan FTS/REGEXP déchiffre des pages). Il ne rejette jamais sous charge -> pas de
    // branche « saturation » : comportement IDENTIQUE à panel_data + /api/query (avant, /api/search
    // renvoyait 200 + error là où les autres « rejetaient » -> incohérent). Seule erreur
    // possible = sémaphore fermé (shutdown) -> on sert vide. Relâché en fin de handler.
    let _permit = match st.query_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return Json(json!({ "results": [] })),
    };
    // FIELD FILTERS (#45) : /api/search NE PASSE PAS par run_query_ex (lignes construites à la main dans
    // map_row) -> on masque APRÈS coup les champs de chaque résultat (message/host/src_ip...) avec le jeu
    // `search_masks` déjà résolu en tête de handler. VIDE -> no-op (mode 0). Une règle DENY sur une COLONNE
    // RÉELLE est EN PLUS bloquée au prepare() par l'authorizer read-pool (SELECT ...e.src_ip... échoue).
    // spawn_blocking : n'occupe pas un worker async pendant le scan. read_with_watchdog : pool read-only
    // (a REGEXP) + watchdog 3s qui interrompt un scan trop long (anti-DoS, cf stress-test). Renvoie Value.
    // #18 — FRONTIÈRE chaud/froid, dérivée EXACTEMENT comme dans /api/query (`cold_query_boundary` sur la
    // même `cold_hot_cutoff` que l'aging) : jamais réinventée ici. Feature/flag OFF -> `None` -> aucune
    // note, aucun coût, /api/search byte-identique (mode 0).
    #[allow(unused_mut)]
    let mut cold_boundary: Option<i64> = None;
    #[cfg(feature = "cold_tier")]
    {
        let conf = load_config();
        if crate::cold_store::cold_tier_runtime_on(&conf) {
            let rc = req_db(&st, &au);
            let c = rc.lock();
            let rd = retention_effective(&c, &conf, "retention_days");
            cold_boundary = Some(crate::cold_store::cold_query_boundary(&c, &conf, now(), rd));
        }
    }
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "results": [] }), move |conn| {
            // #18 — COUVERTURE : ce qui n'a PAS été cherché est dit, jamais tu. Calculée sur la MÊME
            // connexion que la recherche (l'index `cold_seal` vit dans la base du tenant).
            #[allow(unused_mut)]
            let mut coverage: Option<Value> = None;
            #[cfg(feature = "cold_tier")]
            if let Some(b) = cold_boundary {
                coverage = search_cold_coverage(conn, &load_config(), b, q_from);
            }
            let with_coverage = |mut v: Value| -> Value {
                if let Some(c) = coverage.clone() {
                    v["coverage"] = c;
                }
                v
            };
            let map_row = |r: &rusqlite::Row| -> rusqlite::Result<Value> {
                Ok(json!({
                    "ts": r.get::<_, i64>(0)?, "source": r.get::<_, String>(1)?,
                    "severity": r.get::<_, i64>(2)?, "message": r.get::<_, String>(3)?,
                    "host": r.get::<_, Option<String>>(4)?, "src_ip": r.get::<_, Option<String>>(5)?
                }))
            };
            const COLS: &str = "e.ts,e.source,e.severity,e.message,e.host,e.src_ip";
            let out: Vec<Value> = if fts_terms.is_empty() {
                if where_extra.is_empty() {
                    return with_coverage(json!({ "results": [] }));
                }
                let sql = format!("SELECT {COLS} FROM event e WHERE {} ORDER BY e.ts DESC LIMIT ?1", where_extra.join(" AND "));
                let mut stmt = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(_) => return with_coverage(json!({ "results": [] })),
                };
                let rows: Vec<Value> = match stmt.query_map(params![limit], map_row) {
                    // collect en Result : s'ARRÊTE à la 1re erreur (interruption watchdog) au lieu de la
                    // swallow + re-step (ce que faisait .flatten() -> le watchdog ne coupait pas le scan).
                    Ok(r) => match r.collect::<rusqlite::Result<Vec<Value>>>() { Ok(v) => v, Err(_) => return with_coverage(json!({ "results": [] })) },
                    Err(_) => return with_coverage(json!({ "results": [] })),
                };
                rows
            } else {
                let match_q = fts_terms.join(" ");
                let extra = if where_extra.is_empty() { String::new() } else { format!(" AND {}", where_extra.join(" AND ")) };
                // PHASE 1 : si PLUME_FTS_FIELDS=1, on étend le MATCH au flat des valeurs de `fields`
                // (event_fields_fts) en UNION avec event_fts (message/source/category). Un seul ?1
                // réutilisé pour les deux MATCH. Sinon -> requête event_fts seule (comportement actuel,
                // rollback instantané / kill-switch). e.id IN (...) car event_fields_fts est contentless
                // (pas de JOIN direct possible) ; les deux sous-requêtes renvoient des rowid=event.id.
                let sql = if fts_fields_enabled() {
                    format!(
                        "SELECT {COLS} FROM event e WHERE e.id IN (\
                           SELECT rowid FROM event_fts        WHERE event_fts        MATCH ?1 \
                           UNION \
                           SELECT rowid FROM event_fields_fts WHERE event_fields_fts MATCH ?1\
                         ){extra} ORDER BY e.ts DESC LIMIT ?2"
                    )
                } else {
                    format!("SELECT {COLS} FROM event_fts f JOIN event e ON e.id=f.rowid WHERE event_fts MATCH ?1{extra} ORDER BY e.ts DESC LIMIT ?2")
                };
                let mut stmt = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(_) => return with_coverage(json!({ "results": [] })),
                };
                let rows: Vec<Value> = match stmt.query_map(params![match_q, limit], map_row) {
                    // collect en Result : s'ARRÊTE à la 1re erreur (interruption watchdog) au lieu de la
                    // swallow + re-step (ce que faisait .flatten() -> le watchdog ne coupait pas le scan).
                    Ok(r) => match r.collect::<rusqlite::Result<Vec<Value>>>() { Ok(v) => v, Err(_) => return with_coverage(json!({ "results": [] })) },
                    Err(_) => return with_coverage(json!({ "results": [] })),
                };
                rows
            };
            with_coverage(json!({ "results": out }))
        })
    }).await.unwrap_or_else(|_| json!({ "results": [] }));
    // FIELD FILTERS (#45) : caviarde les champs masqués de chaque résultat pour le rôle appelant (no-op si
    // aucun masque -> byte-identique mode 0).
    let mut res = res;
    if !search_masks.is_empty() {
        if let Some(arr) = res.get_mut("results").and_then(|r| r.as_array_mut()) {
            for item in arr.iter_mut() {
                if let Some(obj) = item.as_object_mut() {
                    mask_named_row(&search_db, &search_masks, obj);
                }
            }
        }
    }
    Json(res)
}
