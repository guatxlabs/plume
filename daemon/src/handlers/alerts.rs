//! Triage des alertes : whitelist de colonnes de groupement (`alert_group_col`/`alert_group_expr*`),
//! construction du WHERE (`alert_where`), pagination (`alerts_query_page`/`alert_groups_query_page`),
//! handlers `alerts`/`alert_groups`, et couverture de détection (`scoped_coverage_detections`/
//! `coverage_detections`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// TRIAGE GROUPÉ — WHITELIST STRICTE des colonnes de groupement d'alertes. Renvoie le nom de colonne SQL
/// EXACT (littéral `'static`) ou None si non reconnu. C'est le SEUL point qui autorise un nom de colonne à
/// entrer dans le SQL du groupement/expansion : jamais d'interpolation de texte brut venu du client. `rule`
/// = la règle qui a tiré ('rule.{id}'/'heartbeat.*') ; `mitre` = la technique ATT&CK ; `host` = l'entité ;
/// `dedup` = la clé de déduplication (surtout unitaire — idx_alert_dedup UNIQUE — donc peu pertinente comme
/// axe, mais valide). Défaut appelant = 'rule' (axe de triage principal).
pub(crate) fn alert_group_col(key: &str) -> Option<&'static str> {
    match key {
        "rule" => Some("rule"),
        "mitre" => Some("mitre"),
        "host" => Some("host"),
        "dedup" => Some("dedup"),
        _ => None,
    }
}

/// Expression SQL de la clé de groupe pour `col` (déjà whitelisté). Les colonnes NULLABLES (`host` ajoutée
/// par ALTER v2, `dedup`) sont normalisées `COALESCE(alert.<col>,'')` -> le groupe « sans hôte » (host NULL)
/// et le groupe host='' fusionnent en UNE clé '' qui ROUND-TRIP : la liste groupée l'affiche comme '' et
/// l'EXPANSION (`COALESCE(alert.host,'')=?` avec ?='' ) matche bien les lignes NULL (sinon `host=''` raterait
/// tout NULL). `rule`/`mitre` sont NOT NULL -> `alert.<col>` nu (l'index idx_alert_rule_ts/idx_alert_mitre_ts
/// reste utilisable). `prefix` permet de viser une autre table corrélée (ex. "a2").
pub(crate) fn alert_group_expr_for(col: &str, prefix: &str) -> String {
    if matches!(col, "host" | "dedup") { format!("COALESCE({prefix}.{col},'')") } else { format!("{prefix}.{col}") }
}
pub(crate) fn alert_group_expr(col: &str) -> String { alert_group_expr_for(col, "alert") }

/// WHERE dynamique PARTAGÉ par les trois chemins de lecture d'alertes (liste plate, liste groupée, expansion
/// d'un groupe) : filtre statut (sauf all/any/*) + technique MITRE (idx_alert_mitre_ts) + uncased (backlog non
/// encaissé) + un filtre d'ÉGALITÉ OPTIONNEL sur UNE colonne DÉJÀ whitelistée (`group_col`, résolu via
/// `alert_group_col` AVANT d'arriver ici -> interpolation sûre) = scoping à un groupe. Renvoie (where_clause,
/// bind_vals OWNED) : les valeurs liées sont COPIÉES en `String` -> le Vec survit à l'appel (pas de lifetime
/// gymnastique) ; l'appelant les recoerce en `&dyn ToSql` via `.iter().map(|s| s as &dyn ToSql)` (`&String:
/// ToSql`). Ordre des `?` = ordre des conditions (statut, mitre, group_val) -> mêmes binds COUNT et SELECT.
pub(crate) fn alert_where(all_status: bool, status: &str, mitre: &str, uncased: bool, group_col: Option<&str>, group_val: &str) -> (String, Vec<String>) {
    let mut conds: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if !all_status { conds.push("alert.status=?".to_string()); binds.push(status.to_string()); }
    if !mitre.is_empty() { conds.push("alert.mitre=?".to_string()); binds.push(mitre.to_string()); }
    // ?uncased=1 -> backlog : alertes PAS ENCORE rattachées à un cas (sans param lié, pas de `?`).
    if uncased {
        conds.push("NOT EXISTS (SELECT 1 FROM incident_item ii WHERE ii.ref='alert:'||alert.id)".to_string());
    }
    // Expansion/scoping d'un groupe : `<expr>=?` où `<expr>` = alert_group_expr (COALESCE pour les colonnes
    // nullables -> round-trip du groupe '' avec les lignes NULL). `col` est un littéral whitelisté
    // (alert_group_col), JAMAIS le texte brut du client ; seule la VALEUR (group_val) est liée en `?`.
    if let Some(col) = group_col {
        conds.push(format!("{}=?", alert_group_expr(col)));
        binds.push(group_val.to_string());
    }
    let where_clause = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    (where_clause, binds)
}

/// Page d'alertes (BATCH 1) : construit le WHERE dynamique (statut/mitre/uncased + `group_col`/`group_val`
/// optionnels = expansion d'un groupe), renvoie la fenêtre LIMIT/OFFSET (ordre ts décroissant) + un `total`
/// OPTIONNEL. `want_total` -> COUNT sous le même WHERE (vue « tous statuts » paginée / occurrences d'un
/// groupe) ; le backlog (borné) le laisse à None. Fonction pure sur &Connection -> testable sans AppState.
#[allow(clippy::too_many_arguments)]
pub(crate) fn alerts_query_page(conn: &Connection, all_status: bool, status: &str, mitre: &str, uncased: bool, group_col: Option<&str>, group_val: &str, limit: i64, offset: i64, want_total: bool) -> (Vec<Value>, Option<i64>) {
    // WHERE + binds partagés COUNT/SELECT (mêmes conditions, même ordre) — cf. alert_where (chemin unique).
    let (where_clause, bind_vals) = alert_where(all_status, status, mitre, uncased, group_col, group_val);
    let binds: Vec<&dyn rusqlite::ToSql> = bind_vals.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    // total : COUNT sous le même WHERE (COUNT(*) FROM alert — le WHERE ne touche que `alert.*`, pas besoin du JOIN).
    let total = if want_total {
        let csql = format!("SELECT COUNT(*) FROM alert{where_clause}");
        conn.query_row(&csql, binds.as_slice(), |r| r.get::<_, i64>(0)).ok()
    } else {
        None
    };
    // FIX #4 — LEFT JOIN rule pour exposer `window_s` (la fenêtre d'évaluation EXACTE de la règle) au
    // front, qui centre le drilldown dessus. alert.rule = 'rule.{id}' (cf run_due_rules) -> join sur
    // ('rule.'||r.id). NULL pour les alertes hors règle (heartbeat.*). `ts` est déjà exposé.
    let base = "SELECT alert.id,alert.ts,alert.rule,alert.severity,alert.title,alert.status,\
                COALESCE(alert.detail,''),\
                (SELECT incident_id FROM incident_item WHERE ref='alert:'||alert.id LIMIT 1),\
                COALESCE(alert.mitre,''),r.window_s,\
                COALESCE(alert.acked_at,0),COALESCE(alert.acked_by,'') \
                FROM alert LEFT JOIN rule r ON ('rule.'||r.id)=alert.rule";
    // limit/offset = i64 déjà validés (clamp) -> injection impossible ; interpolés (pas de bind supplémentaire).
    let sql = format!("{base}{where_clause} ORDER BY alert.ts DESC LIMIT {limit} OFFSET {offset}");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return (Vec::new(), total),
    };
    let out: Vec<Value> = match stmt.query_map(binds.as_slice(), |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?,
            "rule": r.get::<_, String>(2)?, "severity": r.get::<_, i64>(3)?,
            "title": r.get::<_, String>(4)?, "status": r.get::<_, String>(5)?,
            "detail": r.get::<_, String>(6)?, "case_id": r.get::<_, Option<i64>>(7)?,
            "mitre": r.get::<_, String>(8)?,
            "window_s": r.get::<_, Option<i64>>(9)?,
            "acked_at": r.get::<_, i64>(10)?, "acked_by": r.get::<_, String>(11)?
        }))
    }) {
        Ok(r) => r.flatten().collect(),
        Err(_) => return (Vec::new(), total),
    };
    (out, total)
}

pub(crate) async fn alerts(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let status = q.get("status").cloned().unwrap_or_else(|| "new".into());
    // FIX #1 — pivot MITRE TOUS STATUTS : ?status=all|any|* -> AUCUN filtre statut (le front demande
    // /alerts?mitre=Txxxx&status=all et voit les N alertes HISTORIQUES d'une technique, pas seulement les
    // 'new'). coverage_detections compte déjà tous statuts ; ce pivot s'aligne dessus. Défaut INCHANGÉ =
    // 'new' (rétro-compat : /alerts sans param se comporte comme avant).
    let all_status = matches!(status.as_str(), "all" | "any" | "*");
    // PURPLE — filtre optionnel par technique MITRE (?mitre=Txxxx[.yyy]) : pivot par technique sans
    // toucher au langage soql. Vide -> comportement actuel. Normalisé (trim+upper) pour matcher
    // l'idx_alert_mitre_ts (mitre en colonne de TÊTE), qui stocke la casse haute. ADDITIF, rétro-compat.
    // (P10.2-d : idx_alert_mitre(mitre) — préfixe strict de ce composite v72 — a été retiré ; le seek
    // `mitre=?` passe désormais par idx_alert_mitre_ts, ce que la casse haute conditionne exactement pareil.)
    let mitre = norm_mitre(q.get("mitre").map(|s| s.as_str()).unwrap_or("")).unwrap_or_default();
    let uncased = q.get("uncased").map(|s| s == "1").unwrap_or(false);
    // TRIAGE GROUPÉ — EXPANSION D'UN GROUPE : `?gkey=rule&gval=rule.38` -> les OCCURRENCES d'un seul groupe,
    // via le MÊME chemin paginé que la liste plate (une seule requête d'occurrences). `gkey` est whitelisté
    // (alert_group_col) -> None si absent/inconnu = liste plate classique (rétro-compat totale). `gval` = la
    // VALEUR de la clé (liée en `?`). Une expansion active -> pagination + total (comme la vue tous statuts),
    // même si le statut n'est pas `all` : l'analyste voit toutes les occurrences du groupe, paginées.
    let group_col = alert_group_col(q.get("gkey").map(|s| s.as_str()).unwrap_or(""));
    let gval = q.get("gval").map(|s| s.as_str()).unwrap_or("");
    let paged = all_status || group_col.is_some();
    // BATCH 1 : pagination + total sur la vue « tous statuts » (historique) ET sur l'expansion d'un groupe.
    // Le backlog (status=new/uncased, non groupé) reste borné à LIMIT 200 sans offset ni total (inchangé).
    let (limit, offset) = if paged {
        let l = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(200).clamp(1, 1000);
        // M6 : offset PLAFONNÉ (anti deep-pagination : un OFFSET énorme force un scan/tri linéaire coûteux).
        let o = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
        (l, o)
    } else {
        (200, 0)
    };
    // M6 : la vue « tous statuts » full-scan + trie toute la table alert -> même régime que /api/query
    // (permit query_sem borne les déchiffrements concurrents ; spawn_blocking n'occupe pas un worker async ;
    // read_with_watchdog = pool read-only + interruption anti-scan-trop-long). idx_alert_ts / idx_alert_mitre_ts
    // (v72) évitent le tri complet. Le backlog borné (LIMIT 200) profite du même chemin sans surcoût.
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(json!({ "alerts": [] })),
    };
    let db_path = req_db_path(&st, &au);
    let gval = gval.to_string();
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "alerts": [] }), move |conn| {
            let (out, total) = alerts_query_page(conn, all_status, &status, &mitre, uncased, group_col, &gval, limit, offset, paged);
            let mut resp = json!({ "alerts": out });
            if let Some(t) = total {
                resp["total"] = json!(t);
            }
            resp
        })
    })
    .await
    .unwrap_or_else(|_| json!({ "alerts": [] }));
    Json(res)
}

/// TRIAGE GROUPÉ — page de GROUPES d'alertes (« 1 groupe = N occurrences »), rend la file gérable au volume
/// (10^4/j). Agrège la table alert par UNE colonne whitelistée (`group_col`, déjà résolu via alert_group_col)
/// sous le MÊME WHERE que la liste plate (statut/mitre/uncased, partagé via alert_where) et renvoie, PAR
/// GROUPE : la clé, le compte, dernier/premier ts, la sévérité MAX, le nombre encore 'new' (open_n), une
/// technique MITRE représentative, et le TITRE + ID d'une occurrence ÉCHANTILLON (la plus récente du groupe,
/// pour l'aperçu repliable). Total = COUNT(DISTINCT group_col) sous le même WHERE (pager serveur). Fonction
/// pure sur &Connection -> testable sans AppState.
///
/// SÉCU/PERF : `group_col` NE PEUT PAS contenir de texte client (whitelist alert_group_col) -> interpolation
/// sûre ; toutes les VALEURS restent liées en `?` (alert_where). La sous-requête corrélée du titre échantillon
/// (`ORDER BY ts DESC LIMIT 1`) s'appuie sur les index (rule,ts)/(host,ts)/(mitre,ts) = un seek par groupe.
/// Elle est volontairement NON re-filtrée par statut (aperçu best-effort : le titre de la dernière alerte du
/// groupe, tous statuts) -> aucun bind supplémentaire, aucune fuite (le titre n'est pas un secret ; l'autorizer
/// SQLite bloque de toute façon user.hash/token.token_hash, absents de `alert`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn alert_groups_query_page(conn: &Connection, group_col: &str, all_status: bool, status: &str, mitre: &str, uncased: bool, limit: i64, offset: i64) -> (Vec<Value>, Option<i64>) {
    let (where_clause, bind_vals) = alert_where(all_status, status, mitre, uncased, None, "");
    let binds: Vec<&dyn rusqlite::ToSql> = bind_vals.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    // Expression de clé (COALESCE pour host/dedup nullables -> round-trip du groupe '' avec les lignes NULL,
    // cohérent avec l'EXPANSION dans alert_where). `col` est whitelisté (alert_group_col) -> interpolation sûre.
    let gexpr = alert_group_expr(group_col);           // ex. alert.rule | COALESCE(alert.host,'')
    let g2expr = alert_group_expr_for(group_col, "a2"); // même expr côté sous-requête corrélée
    // total = nombre de GROUPES distincts sous le même WHERE (borne le pager serveur).
    let csql = format!("SELECT COUNT(DISTINCT {gexpr}) FROM alert{where_clause}");
    let total = conn.query_row(&csql, binds.as_slice(), |r| r.get::<_, i64>(0)).ok();
    // COHÉRENCE D'APERÇU — l'aperçu échantillon est RE-SCOPÉ au MÊME filtre (statut/mitre/uncased)
    // que le groupe. Sinon en scope « Actives » un groupe dont la plus récente TOUS statuts est 'closed'
    // affichait ce titre closed à côté d'un last_ts/n qui, eux, ne reflètent que le set filtré (incohérent).
    // On réplique les prédicats sur a2 -> l'aperçu = la plus récente DANS le set filtré. L'égalité corrélée
    // {g2expr}={gexpr} n'a AUCUN bind ; seuls status/mitre ajoutent un `?` (uncased = NOT EXISTS, sans bind).
    let mut sub_extra = String::new();
    let mut sub_binds: Vec<String> = Vec::new();
    if !all_status { sub_extra.push_str(" AND a2.status=?"); sub_binds.push(status.to_string()); }
    if !mitre.is_empty() { sub_extra.push_str(" AND a2.mitre=?"); sub_binds.push(mitre.to_string()); }
    if uncased { sub_extra.push_str(" AND NOT EXISTS (SELECT 1 FROM incident_item ii WHERE ii.ref='alert:'||a2.id)"); }
    // Binds du SELECT DANS L'ORDRE DU TEXTE SQL : sous-requête sample_title, puis sample_id (elles précèdent le
    // FROM/WHERE), puis le WHERE externe. Chaque sous-requête réplique sub_binds.
    let mut sel_bind_vals: Vec<String> = Vec::with_capacity(sub_binds.len() * 2 + bind_vals.len());
    sel_bind_vals.extend(sub_binds.iter().cloned());
    sel_bind_vals.extend(sub_binds.iter().cloned());
    sel_bind_vals.extend(bind_vals.iter().cloned());
    let sel_binds: Vec<&dyn rusqlite::ToSql> = sel_bind_vals.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    // GROUP BY <expr> ; ORDER BY last_ts DESC (les groupes les plus récents en tête) ; LIMIT/OFFSET = i64
    // clampés -> interpolés (pas de bind). Le titre/id échantillon = dernière occurrence FILTRÉE du groupe.
    let sql = format!(
        "SELECT {gexpr} AS gkey, COUNT(*) AS n, MAX(alert.ts) AS last_ts, MIN(alert.ts) AS first_ts, \
                MAX(alert.severity) AS sev, \
                SUM(CASE WHEN alert.status='new' THEN 1 ELSE 0 END) AS open_n, \
                COALESCE(MAX(alert.mitre),'') AS mitre, \
                (SELECT a2.title FROM alert a2 WHERE {g2expr}={gexpr}{sub_extra} ORDER BY a2.ts DESC LIMIT 1) AS sample_title, \
                (SELECT a2.id    FROM alert a2 WHERE {g2expr}={gexpr}{sub_extra} ORDER BY a2.ts DESC LIMIT 1) AS sample_id \
         FROM alert{where_clause} GROUP BY {gexpr} ORDER BY last_ts DESC LIMIT {limit} OFFSET {offset}"
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return (Vec::new(), total),
    };
    let out: Vec<Value> = match stmt.query_map(sel_binds.as_slice(), |r| {
        Ok(json!({
            "gkey": r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            "n": r.get::<_, i64>(1)?,
            "last_ts": r.get::<_, i64>(2)?,
            "first_ts": r.get::<_, i64>(3)?,
            "severity": r.get::<_, i64>(4)?,
            "open_n": r.get::<_, i64>(5)?,
            "mitre": r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            "sample_title": r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            "sample_id": r.get::<_, Option<i64>>(8)?
        }))
    }) {
        Ok(r) => r.flatten().collect(),
        Err(_) => return (Vec::new(), total),
    };
    (out, total)
}

/// GET /api/alerts/groups?group=rule|mitre|host|dedup&status=&mitre=&uncased=&limit=&offset= — liste GROUPÉE
/// (triage au volume). Non-mutant -> route_min_role case 6 -> MinRole::Read (viewer+), aucune modif de gating.
/// Même régime d'exécution que /api/alerts : permit query_sem (borne les déchiffrements concurrents) +
/// spawn_blocking (n'occupe pas un worker async) + read_with_watchdog (pool read-only + interruption anti-scan).
pub(crate) async fn alert_groups(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    // Colonne de groupement WHITELISTÉE (défaut 'rule' = axe de triage principal). Inconnue -> 'rule'.
    let group_col = alert_group_col(q.get("group").map(|s| s.as_str()).unwrap_or("rule")).unwrap_or("rule");
    let status = q.get("status").cloned().unwrap_or_else(|| "new".into());
    // Miroir de /api/alerts : status=all|any|* -> aucun filtre statut (groupes tous statuts). Défaut = 'new'.
    let all_status = matches!(status.as_str(), "all" | "any" | "*");
    let mitre = norm_mitre(q.get("mitre").map(|s| s.as_str()).unwrap_or("")).unwrap_or_default();
    let uncased = q.get("uncased").map(|s| s == "1").unwrap_or(false);
    let limit = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let offset = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).clamp(0, 100_000);
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(json!({ "groups": [], "group": group_col })),
    };
    let db_path = req_db_path(&st, &au);
    let gc = group_col.to_string();
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "groups": [] }), move |conn| {
            let (groups, total) = alert_groups_query_page(conn, &gc, all_status, &status, &mitre, uncased, limit, offset);
            let mut resp = json!({ "groups": groups, "group": gc });
            if let Some(t) = total {
                resp["total"] = json!(t);
            }
            resp
        })
    })
    .await
    .unwrap_or_else(|_| json!({ "groups": [] }));
    Json(res)
}

/// v75 — détections SCOPÉES à un engagement pour la matrice purple `/api/coverage/detections?engagement=<id>`.
/// BUG corrigé : aucune alerte de PRODUCTION ne porte alert.engagement_id (les alertes sont des agrégats de
/// règle, pas per-IP -> run_due_rules ne propage pas le tag), donc l'ancien filtre `AND engagement_id=?id` ne
/// matchait JAMAIS -> rapport TOUJOURS vide -> l'attaquant scopé lisait 0-détecté / 100 %-manqué alors que la
/// détection avait tiré et est comptée dans la vue globale. On ATTRIBUE une alerte MITRE de la fenêtre [ws,we]
/// à l'engagement soit par son tag direct (forward-compat si un jour l'alerte est taguée), soit par la PRÉSENCE
/// d'au moins un event SCOPÉ (event.engagement_id=id, tagué à l'ingest) dans la même fenêtre — preuve que
/// l'attaquant scopé était actif. INVARIANT SACRÉ intact : on ne fait que RESTREINDRE l'affichage (la table
/// alert reste pleine ; la couverture GLOBALE, branche byte-identique, compte toujours tout). NB : sur-attribuer
/// une détection de la fenêtre est le sens SÛR (l'ancien défaut était le faux 100 %-manqué, dangereux).
pub(crate) fn scoped_coverage_detections(conn: &Connection, id: &str, since: i64, ws: i64, we: i64) -> Vec<Value> {
    let mut stmt = match conn.prepare(
        "SELECT mitre, COUNT(*) AS count, MIN(ts) AS first_ts FROM alert \
         WHERE mitre IS NOT NULL AND mitre<>'' AND ts>=?1 AND ts>=?3 AND ts<=?4 \
           AND (engagement_id=?2 OR EXISTS(SELECT 1 FROM event e WHERE e.engagement_id=?2 AND e.ts>=?3 AND e.ts<=?4)) \
         GROUP BY mitre ORDER BY count DESC, mitre",
    ) { Ok(s) => s, Err(_) => return Vec::new() };
    let rows: Vec<(String, i64, i64)> = match stmt.query_map(params![since, id, ws, we], |r| Ok((
        r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?
    ))) {
        Ok(r) => r.flatten().collect(),
        Err(_) => Vec::new(),
    };
    // MÊME éclatement des tags multi-techniques que la branche globale (cf. explode_detection_rows) :
    // le rapport SCOPÉ ne doit pas dire autre chose que le rapport global sur le même corpus de règles.
    explode_detection_rows(rows)
}

/// PURPLE — éclate les lignes `(tag_mitre, count, first_ts)` agrégées depuis `alert` en TECHNIQUES
/// ATT&CK, **sous-technique PRÉSERVÉE**, et ré-agrège par technique (count SOMMÉ, `first_ts` = MIN —
/// la PREMIÈRE détection).
///
/// POURQUOI : le champ `mitre` d'une règle peut porter PLUSIEURS techniques séparées par espace/
/// virgule/point-virgule — c'est la NORME chez SigmaHQ (plusieurs `attack.` par règle), et
/// `mitre_parents` le documente déjà pour la matrice ATT&CK. Servir la chaîne COMPOSÉE telle quelle
/// sur `/api/coverage/detections` force le consommateur (la boucle purple de Forge) à joindre sur une
/// pseudo-technique qui n'existe dans aucun référentiel : un tag `"T1595.002 T1046"` ne matche alors
/// AUCUNE des deux techniques et le corpus Sigma FABRIQUE de faux « missed ».
///
/// La sous-technique n'est PAS repliée sur sa parente (contrairement à `mitre_parents`, qui sert la
/// grille de couverture) : le consommateur distingue `detected-exact` de `detected-parent-approx`, et
/// cette distinction meurt si on normalise ici.
///
/// ANTI-SILENT-DROP : un tag vendeur/custom hors format `T####` reste servi VERBATIM — une détection
/// qui s'évapore serait pire qu'un tag illisible. Tri de sortie IDENTIQUE au `ORDER BY count DESC,
/// mitre` du SQL (contrat de la réponse inchangé). PUR / testable sans DB.
pub(crate) fn explode_detection_rows(rows: Vec<(String, i64, i64)>) -> Vec<Value> {
    let mut agg: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
    for (tag, count, first_ts) in rows {
        let mut keys = mitre_techniques(&tag);
        if keys.is_empty() {
            let raw = tag.trim();
            if raw.is_empty() { continue; }
            keys.push(raw.to_string());
        }
        for k in keys {
            let e = agg.entry(k).or_insert((0, first_ts));
            e.0 += count;
            if first_ts < e.1 { e.1 = first_ts; }
        }
    }
    let mut out: Vec<(String, i64, i64)> = agg.into_iter().map(|(m, (c, t))| (m, c, t)).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))); // count DESC, mitre ASC
    out.into_iter()
        .map(|(m, c, t)| json!({ "mitre": m, "count": c, "first_ts": t }))
        .collect()
}

/// PURPLE — éclate un tag `mitre` en ses techniques DISTINCTES, **sous-technique PRÉSERVÉE**.
/// Séparateurs espace/virgule/point-virgule (norme SigmaHQ). Format accepté : `T` + chiffres, avec une
/// sous-technique optionnelle `.` + chiffres ; casse normalisée en haut de casse ; token hors format
/// ignoré ; dédupliqué, ordre d'apparition préservé.
///
/// DISTINCT de `mitre_parents`, qui replie CHAQUE technique sur sa PARENTE pour la grille de couverture
/// (`build_attack_matrix`). Ici la sous-technique est conservée : c'est elle que la boucle purple joint
/// pour distinguer une détection EXACTE d'une simple couverture PARENTE. Les deux fonctions coexistent
/// volontairement — `mitre_parents` est laissée INCHANGÉE (ses 4 tests figent son comportement).
/// PUR / testable. Contrat d'éclatement ALIGNÉ sur `console/src/detection.rs::mitre_techniques` côté
/// Forge : les deux extrémités de la jointure doivent découper le tag de la MÊME façon.
pub(crate) fn mitre_techniques(tag: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in tag.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let t = tok.trim().to_ascii_uppercase();
        let Some(rest) = t.strip_prefix('T') else { continue };
        let (base, sub) = match rest.split_once('.') {
            Some((b, s)) => (b, Some(s)),
            None => (rest, None),
        };
        if base.is_empty() || !base.bytes().all(|b| b.is_ascii_digit()) { continue; }
        if let Some(s) = sub {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { continue; }
        }
        if !out.contains(&t) { out.push(t); }
    }
    out
}

/// PURPLE — couverture de détection. Agrège les ALERTES portant un tag MITRE ATT&CK (héritées de la
/// règle qui les a tirées, cf. run_due_rules) par TECHNIQUE : pour chaque technique, le nombre
/// d'alertes et l'horodatage de la 1re détection. C'est la mesure DÉFENSIVE (blue-team) : la console
/// Forge joint cette liste aux techniques tirées (red) pour exposer, à TROIS états, detected-exact /
/// detected-parent-approx / missed + MTTD. Lecture seule (read_with -> pool chiffré), pas d'écriture.
///
/// CONTRAT : la clé `mitre` servie est une TECHNIQUE, jamais un tag composé. Un tag de règle portant
/// plusieurs techniques (`"T1595.002 T1046"`, norme SigmaHQ) est ÉCLATÉ en autant d'entrées, counts
/// sommés et `first_ts` = min (cf. explode_detection_rows) ; la SOUS-technique est PRÉSERVÉE (c'est
/// elle qui permet au consommateur de distinguer une détection exacte d'une couverture parente).
/// Réponse triée par count décroissant (techniques les plus détectées en tête), `mitre` ASC à égalité.
/// Paramètre optionnel `since` (epoch s) borne la fenêtre.
pub(crate) async fn coverage_detections(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let since: i64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    // v75 (MODE ENGAGEMENT) : `?engagement=<id>` -> rapport de couverture SCOPÉ (fondation de la matrice purple
    // scopée). Filtre les alertes par engagement_id ET par la fenêtre [window_start,window_end] de l'engagement.
    // ABSENT (cas normal) -> requête STRICTEMENT identique à aujourd'hui (byte-identique). La détection n'est jamais
    // réduite : on lit toujours la table `alert` (les alertes ont TOUTES été levées ; le scope ne fait que RESTREINDRE
    // l'affichage à ce que le pentest a déclenché).
    let engagement = q.get("engagement").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    // M6 : agrégation (GROUP BY mitre) sur toute la table alert -> même régime que /api/query (query_sem +
    // spawn_blocking + read_with_watchdog). idx_alert_mitre_ts (v72) couvre le filtre mitre<>'' + ts>=?.
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(json!({ "detections": [] })),
    };
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "detections": [] }), move |conn| {
            let row_tuple = |r: &rusqlite::Row| -> rusqlite::Result<(String, i64, i64)> {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            };
            if let Some(id) = &engagement {
                // fenêtre de l'engagement (borne temporelle du rapport scopé).
                let (ws, we): (i64, i64) = match conn.query_row(
                    "SELECT window_start, window_end FROM engagement WHERE id=?1", params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ) { Ok(v) => v, Err(_) => return json!({ "detections": [], "engagement": id }) };
                // Attribution SCOPÉE (via tag alerte OU présence d'events scopés dans la fenêtre) — cf.
                // scoped_coverage_detections. RESTREINT l'affichage, ne réduit JAMAIS la détection.
                let out = scoped_coverage_detections(conn, id, since, ws, we);
                return json!({ "detections": out, "engagement": id, "window_start": ws, "window_end": we });
            }
            let mut stmt = match conn.prepare(
                "SELECT mitre, COUNT(*) AS count, MIN(ts) AS first_ts FROM alert \
                 WHERE mitre IS NOT NULL AND mitre<>'' AND ts>=?1 GROUP BY mitre ORDER BY count DESC, mitre",
            ) {
                Ok(s) => s,
                Err(_) => return json!({ "detections": [] }),
            };
            let rows: Vec<(String, i64, i64)> = match stmt.query_map(params![since], row_tuple) {
                Ok(r) => r.flatten().collect(),
                Err(_) => return json!({ "detections": [] }),
            };
            // ÉCLATEMENT des tags multi-techniques (Sigma) avant de servir : le consommateur purple
            // joint sur des TECHNIQUES, jamais sur une chaîne composée. Cf. explode_detection_rows.
            json!({ "detections": explode_detection_rows(rows) })
        })
    })
    .await
    .unwrap_or_else(|_| json!({ "detections": [] }));
    Json(res)
}

/// #22 (Tier-2 « ATT&CK navigator global ») — Éclate un tag MITRE de règle/alerte en ses techniques PARENTES
/// distinctes. SUPERSET / bring-your-own-vendor : un tag peut porter PLUSIEURS techniques (règles Sigma,
/// imports tiers) séparées par espace/virgule/point-virgule ; chacune est normalisée en sa technique parente
/// `T####` (via guatx_core::attack::parent_technique, les sous-techniques héritent). Un token hors format est
/// ignoré. Dédupliqué : une règle taguée « T1110 T1110.001 » compte UNE fois pour T1110. Pur / testable.
pub(crate) fn mitre_parents(tag: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in tag.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if tok.is_empty() { continue; }
        if let Some(p) = guatx_core::attack::parent_technique(tok) {
            if !out.contains(&p) { out.push(p); }
        }
    }
    out
}

/// #22 — Compose la matrice de couverture ATT&CK à partir des tags des règles ACTIVÉES et des comptes
/// d'alertes par technique. PUR (aucun AppState / DB) donc testable directement. `enabled_rule_tags` = les
/// tags `mitre` des règles enabled=1 (un par règle) ; `alert_counts` = technique parente -> nb d'alertes sur
/// la fenêtre (déjà agrégé depuis la table `alert`, PAS un scan d'events).
///
/// COUVERTURE : une technique est `covered` ssi >=1 règle activée la cible. Les techniques du CATALOG sans
/// aucune règle sont les BLIND-SPOTS (`covered:false`, rule_count:0) — c'est tout l'intérêt d'un « navigator »
/// global : rendre visible ce qu'on NE détecte pas. SUPERSET : une technique taguée hors CATALOG (custom /
/// vendeur) n'est jamais perdue -> repliée dans une pseudo-tactique `unmapped` en fin de matrice.
///
/// Forme : `{ tactics:[{tactic, techniques:[{tid, rule_count, alert_count, covered}], rule_count, alert_count,
/// covered}], totals:{tactics, tactics_covered, techniques, techniques_covered, techniques_uncovered,
/// rules_mapped, alerts} }`.
pub(crate) fn build_attack_matrix(enabled_rule_tags: &[String], alert_counts: &HashMap<String, i64>) -> Value {
    use std::collections::HashMap as Map;
    // rule_count par technique parente (une règle compte 1 par technique DISTINCTE qu'elle cible).
    let mut rule_count: Map<String, i64> = Map::new();
    let mut rules_mapped = 0i64; // nb de règles ayant AU MOINS une technique reconnue.
    for tag in enabled_rule_tags {
        let parents = mitre_parents(tag);
        if !parents.is_empty() { rules_mapped += 1; }
        for p in parents { *rule_count.entry(p).or_insert(0) += 1; }
    }

    // techniques connues du CATALOG (pour détecter les tags hors-catalogue -> pseudo-tactique `unmapped`).
    let known: std::collections::HashSet<&'static str> =
        guatx_core::attack::CATALOG.iter().map(|(tid, _)| *tid).collect();

    let mut tactics_json: Vec<Value> = Vec::new();
    let (mut tot_tech, mut tot_tech_cov, mut tot_tac_cov, mut tot_alerts) = (0i64, 0i64, 0i64, 0i64);

    for tac in guatx_core::attack::TACTICS {
        let mut techs: Vec<Value> = Vec::new();
        let (mut t_rc, mut t_ac, mut t_cov) = (0i64, 0i64, false);
        for tid in guatx_core::attack::techniques_for_tactic(tac) {
            let rc = *rule_count.get(tid).unwrap_or(&0);
            let ac = *alert_counts.get(tid).unwrap_or(&0);
            let covered = rc > 0;
            tot_tech += 1;
            if covered { tot_tech_cov += 1; }
            t_rc += rc; t_ac += ac; t_cov = t_cov || covered;
            techs.push(json!({ "tid": tid, "rule_count": rc, "alert_count": ac, "covered": covered }));
        }
        tot_alerts += t_ac;
        if t_cov { tot_tac_cov += 1; }
        tactics_json.push(json!({
            "tactic": tac, "techniques": techs, "rule_count": t_rc, "alert_count": t_ac, "covered": t_cov
        }));
    }

    // SUPERSET — techniques taguées hors CATALOG : ni perdues, ni faussement « couvrant » une tactique connue.
    // Repliées dans une pseudo-tactique `unmapped` (comptées dans les totaux techniques/couvertes).
    let mut extra: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for k in rule_count.keys() { if !known.contains(k.as_str()) { extra.insert(k.clone()); } }
    for k in alert_counts.keys() { if !known.contains(k.as_str()) { extra.insert(k.clone()); } }
    if !extra.is_empty() {
        let mut techs: Vec<Value> = Vec::new();
        let (mut t_rc, mut t_ac, mut t_cov) = (0i64, 0i64, false);
        for tid in &extra {
            let rc = *rule_count.get(tid).unwrap_or(&0);
            let ac = *alert_counts.get(tid).unwrap_or(&0);
            let covered = rc > 0;
            tot_tech += 1;
            if covered { tot_tech_cov += 1; }
            t_rc += rc; t_ac += ac; t_cov = t_cov || covered;
            techs.push(json!({ "tid": tid, "rule_count": rc, "alert_count": ac, "covered": covered }));
        }
        tot_alerts += t_ac;
        if t_cov { tot_tac_cov += 1; }
        tactics_json.push(json!({
            "tactic": "unmapped", "techniques": techs, "rule_count": t_rc, "alert_count": t_ac, "covered": t_cov
        }));
    }

    json!({
        "tactics": tactics_json,
        "totals": {
            "tactics": tactics_json_len(&tactics_json),
            "tactics_covered": tot_tac_cov,
            "techniques": tot_tech,
            "techniques_covered": tot_tech_cov,
            "techniques_uncovered": tot_tech - tot_tech_cov,
            "rules_mapped": rules_mapped,
            "alerts": tot_alerts
        }
    })
}
#[inline]
fn tactics_json_len(v: &[Value]) -> i64 { v.len() as i64 }

/// #22 — GET `/api/coverage/attack` : matrice de couverture ATT&CK (viewer+, lecture seule). Compose
/// le mapping technique->tactique (guatx_core::attack) avec le comptage des RÈGLES de détection activées
/// (rule.mitre, enabled=1) et des ALERTES récentes par technique (alert.mitre sur fenêtre `?since=<epoch_s>`,
/// agrégées depuis la table `alert` via idx_alert_mitre_ts — JAMAIS un scan de la table event). Surface les
/// techniques NON COUVERTES (blind-spots). ADDITIF / mode-0 byte-identique (nouvel endpoint read-only).
pub(crate) async fn coverage_attack(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let since: i64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    // Même régime de concurrence que coverage_detections (query_sem + spawn_blocking + watchdog).
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return Json(json!({ "tactics": [], "totals": {} })),
    };
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || {
        read_with_watchdog(&db_path, json!({ "tactics": [], "totals": {} }), move |conn| {
            // Règles ACTIVÉES portant un tag MITRE (coverage = règle enabled).
            let mut rule_tags: Vec<String> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT mitre FROM rule WHERE enabled=1 AND mitre IS NOT NULL AND mitre<>''",
            ) {
                if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                    rule_tags = rows.flatten().collect();
                }
            }
            // Alertes par technique sur la fenêtre (table `alert`, indexée ; PAS la table event).
            let mut alert_counts: HashMap<String, i64> = HashMap::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT mitre, COUNT(*) FROM alert WHERE mitre IS NOT NULL AND mitre<>'' AND ts>=?1 GROUP BY mitre",
            ) {
                if let Ok(rows) = stmt.query_map(params![since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
                    let raw: Vec<(String, i64)> = rows.flatten().collect();
                    for (tag, n) in raw {
                        for p in mitre_parents(&tag) { *alert_counts.entry(p).or_insert(0) += n; }
                    }
                }
            }
            build_attack_matrix(&rule_tags, &alert_counts)
        })
    })
    .await
    .unwrap_or_else(|_| json!({ "tactics": [], "totals": {} }));
    Json(res)
}
