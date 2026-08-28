//! Administration UI (#1b) : rétention éditable (`retention_settings_get/put`, `retention_preview`),
//! journal d'intégrité (`ledger_page`/`ledger_get`) et registre d'exclusions unifié
//! (`ExclType`/`ExclEntry`/`daemon_excl_registry`, `suppressions_get/put`, `apply_display_excl_edit`).
//! L'inventaire des sources et leurs métadonnées d'affichage vivent dans `handlers/sources.rs`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ================================ #1b ADMINISTRATION UI (daemon) ================================
// Rétention éditable. Toutes les mutations sont admin-only (path-guard + revérif interne), doublement
// auditées (ledger + event SOC) dans UNE transaction fail-closed, et bornées par des planchers durs.
// Aucun de ces endpoints ne touche l'ingest.

/// GET /api/retention -> valeurs EFFECTIVES courantes (résolveur setting->env/conf->défaut, correctif H2) +
/// bornes (min/max/défaut/unité) pour la validation miroir côté client. Admin only (B9).
pub(crate) async fn retention_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    with_write(&st, &au, |conn| {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".into(), json!(true));
    let mut bounds = serde_json::Map::new();
    for (skey, env_key, def, floor, ceil) in RETENTION_FIELDS {
        obj.insert(skey.to_string(), json!(setting_days(&conn, &conf, skey, env_key, def, floor, ceil)));
        let unit = if skey == "metric_raw_hours" { "hours" } else { "days" };
        bounds.insert(skey.to_string(), json!({ "min": floor, "max": ceil, "default": def, "unit": unit }));
    }
    obj.insert("bounds".into(), Value::Object(bounds));
    Json(Value::Object(obj)).into_response()
    })
}

/// POST|PUT /api/retention {retention_days?,snapshot_days?,alert_days?,metric_days?,metric_raw_hours?} (i64).
/// Chaque champ présent est clampé aux planchers (M6) puis écrit dans `setting`, avec double-audit (ledger +
/// event) DANS UNE TRANSACTION fail-closed (M5). L'« ancienne » valeur auditée = valeur EFFECTIVE résolue (H2).
/// Une baisse (new<current) = sev 3 (destructif) ; hausse/égal = sev 2. No-op (new==current) ignoré (pas d'audit).
pub(crate) async fn retention_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
    }
    let outcome: rusqlite::Result<Vec<(String, i64, i64)>> = (|| {
        let mut changes: Vec<(String, i64, i64)> = Vec::new();
        for (skey, env_key, def, floor, ceil) in RETENTION_FIELDS {
            let Some(v) = b.get(skey).and_then(|x| x.as_i64()) else { continue };
            let cur = setting_days(&conn, &conf, skey, env_key, def, floor, ceil); // valeur EFFECTIVE (H2)
            let n = v.clamp(floor, ceil); // plancher/plafond DURS (M6)
            if n == cur {
                continue; // no-op : ni écriture ni audit
            }
            conn.execute(
                "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
                 ON CONFLICT(scope,key) DO UPDATE SET value=?2,updated=?3,updated_by=?4",
                params![skey, n.to_string(), now(), au.name.as_str()],
            )?;
            let sev = if n < cur { 3 } else { 2 }; // baisse = destructif -> audit bruyant (H3)
            audit_config_change(
                &conn,
                &format!("config.retention.{skey}"),
                &format!("{cur}->{n} par {}", au.name),
                sev,
                &format!("rétention {skey}: {cur}->{n} par {}", au.name),
                &json!({ "key": skey, "old": cur, "new": n, "actor": au.name, "destructive": n < cur }).to_string(),
            )?;
            changes.push((skey.to_string(), cur, n));
        }
        Ok(changes)
    })();
    match outcome {
        Ok(changes) => {
            let _ = conn.execute_batch("COMMIT");
            let applied: serde_json::Map<String, Value> = changes.iter().map(|(k, _, n)| (k.clone(), json!(n))).collect();
            (StatusCode::OK, Json(json!({ "ok": true, "changed": changes.len(), "applied": applied }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : mutation NON persistée si l'audit échoue
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}

/// GET /api/retention/preview?key=<champ>&value=<n> -> aperçu NON destructif du volume purgeable si `key`
/// passait à `value`. Budget 2 Go : events via event_rollup (SUM(n), jamais `event` ni event_dim_rollup) ;
/// snapshot/alert/metric via COUNT index-borné. `destructive`=true si new<current (résolu H2). Tous les champs
/// (H3). Admin only (B9). Le count events est au bucket horaire -> approx=true (afficher « ~N »).
pub(crate) async fn retention_preview(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let key = q.get("key").map(|s| s.as_str()).unwrap_or("");
    let Some((skey, env_key, def, floor, ceil)) = RETENTION_FIELDS.iter().copied().find(|f| f.0 == key) else {
        return (StatusCode::BAD_REQUEST, "clé de rétention inconnue").into_response();
    };
    let new_val = q.get("value").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(def).clamp(floor, ceil);
    let unit_secs = if skey == "metric_raw_hours" { 3600 } else { 86400 };
    let conf = load_config();
    let n = now();
    crate::req_conn!(st, au, conn);
    let cur = setting_days(&conn, &conf, skey, env_key, def, floor, ceil); // MÊME résolveur que l'application (H2)
    let cutoff = n - new_val * unit_secs; // tout ce qui est < cutoff serait purgé au prochain tick
    let (deleted, oldest, kind, approx): (i64, Option<i64>, &str, bool) = match skey {
        "retention_days" => {
            // event_rollup UNIQUEMENT (jamais event_dim_rollup : surcompte par dimension), idx bucket-borné.
            let (s, o) = conn
                .query_row("SELECT COALESCE(SUM(n),0), MIN(bucket) FROM event_rollup WHERE bucket < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "events", true)
        }
        "snapshot_days" => {
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM snapshot WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "snapshots", false)
        }
        "alert_days" => {
            // reflète le filtre status<>'new' de retention_run : les alertes OUVERTES ne sont JAMAIS purgées.
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM alert WHERE status<>'new' AND ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "alerts_closed", false)
        }
        "metric_days" => {
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM metric_rollup WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "metric_rollups", false)
        }
        "metric_raw_hours" => {
            // raw metrics rollupées AVANT purge -> destructif « doux » (agrégat conservé), mais aperçu quand même (H3).
            let (s, o) = conn
                .query_row("SELECT COUNT(*), MIN(ts) FROM metric WHERE ts < ?1", params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap_or((0i64, None));
            (s, o, "metrics_raw", false)
        }
        _ => (0, None, "", false),
    };
    Json(json!({
        "ok": true,
        "key": skey,
        "unit": if skey == "metric_raw_hours" { "hours" } else { "days" },
        "current": cur,
        "new": new_val,
        "destructive": new_val < cur,
        "deleted": deleted,
        "deleted_kind": kind,
        "oldest": oldest,
        "approx": approx,
    }))
    .into_response()
}

// =================================================================================================
// `P11.16-d` — LE JOURNAL D'AUDIT SE LIT PAR FENÊTRE DE TEMPS, PAR CLÉ, ET SANS RECOMPTER LA TABLE
// -------------------------------------------------------------------------------------------------
// CE QUI ÉTAIT ÉCRIT, ET CE QUE ÇA COÛTAIT. La route n'acceptait que `limit` et `offset` : il n'y
// avait AUCUNE borne de temps, donc rien à régler — une capacité absente, pas un réglage mal placé.
// Chaque affichage de page émettait `SELECT COUNT(*) FROM ledger`, un comptage INTÉGRAL de la table,
// pour rendre un total dont le pager n'a besoin qu'une fois. Et la fenêtre était atteinte par
// DÉCALAGE : une page lointaine coûtait le parcours des pages précédentes. Le journal d'intégrité est
// précisément ce qu'on ne purge pas — les trois coûts croissent donc sans borne, pour toujours.
//
// CE QUI CHANGE, ET LA VALEUR QUI LE PROUVE. La grandeur mesurée est le nombre de LIGNES TRAVERSÉES,
// compté par SQLite lui-même (`SQLITE_STMTSTATUS_FULLSCAN_STEP`) : déterministe, indépendant de la
// machine, et c'est celle qui décide — une ligne traversée est une page lue et, sous SQLCipher,
// déchiffrée. Relevé le 2026-08-25 sur la fixture des tests :
//   * LE TOTAL est BORNÉ. `SELECT COUNT(*) FROM (SELECT 1 FROM ledger … LIMIT CAP+1)` s'ARRÊTE au
//     plafond — exactement le motif de `handlers/query.rs`, pour la même raison. MESURÉ : 10 000 lignes
//     traversées sur un journal de 10 500 comme sur un journal de 21 000, quand le même comptage privé
//     de sa borne en traverse 10 499 puis 20 999. Le coût cesse de suivre la taille du journal. Au-delà
//     du plafond le total n'est pas INVENTÉ : il est rendu plafonné ET `total_capped:true` le DIT, la
//     vue passant alors à un pager non numéroté dont le Suivant reste fiable. Un chiffre coûteux n'est
//     pas remplacé par un chiffre faux présenté comme exact. Et il n'est plus demandé À CHAQUE PAGE : un
//     total ne bouge pas au fil d'un parcours, donc la vue le demande sur la PREMIÈRE page d'une fenêtre
//     et le garde (`count=0` ensuite). Sur un journal à peine plus gros que le plafond, la borne seule
//     n'aurait presque rien économisé — c'est ce second geste qui ramène le comptage à UNE fois.
//     (UN COMPTEUR A MENTI, ET C'EST ÉCRIT PARCE QUE ÇA COMPTE : en PAS DE MACHINE VIRTUELLE, la forme
//     bornée en coûte PLUS — 90 024 contre 42 011 et 84 011 — parce que la borne empêche l'aplatissement
//     de la sous-requête, donc chaque ligne coûte plus d'interprétation pendant qu'il y a moitié moins
//     de lignes à lire. Et `SELECT COUNT(*) FROM ledger`, la forme d'origine, coûte NEUF pas quel que
//     soit le volume : SQLite la sert par un comptage de B-tree sans boucle VDBE, donc ce compteur-là
//     est aveugle à son coût. Le compteur retenu est nommé avec ce qu'il mesure.)
//   * LA PAGE se prend PAR CLÉ (`LedgerPlan`), sur le modèle de `PagePlan`/`page_sql`/`keyset_finalize`
//     déjà éprouvé ici même (#28), et avec le MÊME contrat de continuation (`has_more`+`next_cursor`).
//     MESURÉ : atteindre la 40e page par clé coûte ce que coûte la 2e ; par décalage, vingt fois plus.
//   * LA FENÊTRE DE TEMPS existe (`window_days`), elle est réglable, et la vue la DIT.
//
// LA CLÉ EST `id`, PAS `(ts,id)`, ET CE N'EST PAS UN RACCOURCI. L'ordre du journal d'intégrité EST
// l'ordre de sa chaîne de hash : `ledger_append` chaîne sur la dernière ligne `ORDER BY id DESC`, et
// `verify_ledger_conn` recalcule la chaîne `ORDER BY id`. `ledger_export_get` pagine DÉJÀ par `from_id`.
// Reprendre le wrap `(ts,id)` de `page_sql` RÉORDONNERAIT le journal le jour où l'horloge recule — cette
// correction n'a pas le droit de toucher à ce que le journal contient, à son ordre, ni à sa chaîne.
// Ce qui est repris est donc la FORME (un plan fermé, un seul fabricant de page, un curseur, un contrat
// de continuation honnête), pas le littéral SQL d'un autre flux.
//
// CE QUE CETTE CORRECTION NE BORNE PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU. `ledger(ts)` n'est PAS indexé
// (`id INTEGER PRIMARY KEY` est la seule clé, cf. migrate v7). La fenêtre est donc un FILTRE EXACT
// appliqué au fil du balayage descendant de la clé primaire : tant que la fenêtre couvre les entrées
// les plus récentes — ce qu'elle fait par construction, sa borne haute étant l'instant présent — chaque
// page ne lit que ses propres lignes. La DERNIÈRE page d'une fenêtre, elle, doit prouver qu'il n'y a
// plus rien sous la borne : SQLite descend alors jusqu'au bas de la table. C'est UN balayage par
// parcours de fenêtre, contre UN comptage intégral PAR PAGE auparavant. Le fermer demanderait un index
// sur `ledger(ts)`, c'est-à-dire une migration de schéma — hors de ce correctif, et à mettre en regard
// du poids des index déjà porté par la base.
// =================================================================================================

/// Plafond de réglage de la fenêtre, en jours — le MÊME que celui de la rétention et de la purge
/// (`RETENTION_FIELDS`, `PURGE_WINDOW_MAX_DAYS`) : au-delà, une valeur n'est plus une fenêtre mais une
/// faute de frappe. `window_days=0` (ou paramètre absent) = AUCUNE borne.
pub(crate) const LEDGER_WINDOW_MAX_DAYS: i64 = 3650;

/// `P11.16-d` — PLAFOND DU SAUT à une page arbitraire, DÉRIVÉ du plafond de comptage : le `total` rendu
/// ne dépasse jamais `PAGINATION_COUNT_CAP`, donc aucune page NUMÉROTÉE ne peut se trouver au-delà. Un
/// décalage plus grand ne vient pas du pager, et il coûterait exactement le balayage que la clé évite.
/// Au-delà, la route REFUSE en nommant le plafond : elle ne rend pas une page vide, qui se lirait comme
/// une fin de journal — et sur CETTE vue, une ligne manquante ne se remarque pas.
pub(crate) const LEDGER_JUMP_MAX: i64 = PAGINATION_COUNT_CAP;

/// CE QUE LA ROUTE A COMPRIS DE LA DEMANDE — une seule valeur, pour que le test interroge EXACTEMENT ce
/// que le handler exécute (le handler ne fait plus que traduire la requête HTTP en `LedgerAsk`).
pub(crate) struct LedgerAsk {
    /// Taille de page, clampée [1,1000] par le handler.
    pub(crate) limit: i64,
    /// Borne basse de temps, INCLUSE. `i64::MIN` = aucune borne (tout l'historique).
    pub(crate) since: i64,
    /// Fenêtre demandée, en jours (0 = aucune borne). RENDUE au client pour qu'il puisse la DIRE.
    pub(crate) window_days: i64,
    /// Curseur de continuation : `id` de la DERNIÈRE ligne rendue -> la page suivante est `id < cursor`.
    pub(crate) cursor: Option<i64>,
    /// Saut à une page arbitraire DANS l'ordre du journal (clic sur un numéro). 0 = première page.
    pub(crate) offset: i64,
    /// COMPTER, ou pas. Le total ne change pas d'une page à l'autre d'un même parcours : le recompter à
    /// chaque page fait relire jusqu'au plafond pour un chiffre déjà connu. La vue le demande sur la
    /// PREMIÈRE page d'une fenêtre et le garde ; `false` -> `total:null`, et le client sait qu'il doit
    /// se servir de celui qu'il a. Défaut `true` : un appelant qui ne dit rien reçoit ce qu'il recevait.
    pub(crate) count: bool,
}

/// PLAN DE PAGE du journal — la forme de page à fabriquer, sur le modèle fermé de `PagePlan`
/// (`handlers/query.rs`) : ajouter une variante OBLIGE à la traiter dans `ledger_page_sql`, et aucun
/// appelant ne peut composer sa propre clause de page.
pub(crate) enum LedgerPlan {
    /// CURSEUR (Suivant/Précédent séquentiel) : O(page), quelle que soit la profondeur.
    Cursor(i64),
    /// SAUT à une page arbitraire : l'OFFSET est le seul moyen d'atteindre la page k sans parcourir les
    /// k-1 précédentes. Choix ASSUMÉ, borné par `LEDGER_JUMP_MAX` : la page atterrie rend son curseur,
    /// donc le Suivant repart par clé.
    Jump(i64),
    /// PREMIÈRE page.
    First,
}

/// Traduit (curseur, décalage) en plan — la décision est ici, pas chez l'appelant. Le curseur PRIME.
pub(crate) fn ledger_plan(cursor: Option<i64>, offset: i64) -> LedgerPlan {
    match cursor {
        Some(c) => LedgerPlan::Cursor(c),
        None if offset > 0 => LedgerPlan::Jump(offset),
        None => LedgerPlan::First,
    }
}

/// LE SEUL fabricant du COMPTAGE du journal — écrit une fois pour que le test mesure CE QUI EST ÉMIS et
/// non une copie. Le `SELECT 1` ne demande aucune colonne grasse et le `LIMIT CAP+1` ARRÊTE le balayage au
/// plafond : au-dessous le total est EXACT, au-dessus il est plafonné ET annoncé (`total_capped`). Même
/// motif, même raison et même plafond que le `total` de `/api/query` (`PAGINATION_COUNT_CAP`).
///
/// UNE PHRASE HÉRITÉE EST ICI CORRIGÉE : la documentation de `PAGINATION_COUNT_CAP` explique que « SQLite
/// aplatit la sous-requête ». MESURÉ le 2026-08-25 : le `LIMIT` l'EN EMPÊCHE — la sous-requête est jouée en
/// co-routine, ce qui coûte DAVANTAGE de pas de machine virtuelle par ligne. Cela n'enlève rien à la
/// propriété qui décide, et c'est elle qui est éprouvée : le nombre de LIGNES TRAVERSÉES est plafonné,
/// donc le nombre de pages lues et déchiffrées aussi.
pub(crate) fn ledger_total_sql() -> String {
    format!("SELECT COUNT(*) FROM (SELECT 1 FROM ledger WHERE ts>=?1 LIMIT {})", PAGINATION_COUNT_CAP + 1)
}

/// LE SEUL fabricant de page du journal d'audit. `cursor`/`offset` sont des `i64` parsés stricts en amont
/// et formatés directement -> injection impossible (même raisonnement que `page_sql`). La borne de temps
/// part en PARAMÈTRE LIÉ (`?1`) et la taille de page aussi (`?2`). Projection et ordre INCHANGÉS par
/// rapport à la version d'origine : `id,ts,kind,detail,hash`, `ORDER BY id DESC`.
pub(crate) fn ledger_page_sql(plan: &LedgerPlan) -> String {
    const TETE: &str = "SELECT id,ts,kind,detail,hash FROM ledger WHERE ts>=?1";
    match plan {
        LedgerPlan::Cursor(c) => format!("{TETE} AND id<{c} ORDER BY id DESC LIMIT ?2"),
        LedgerPlan::Jump(o) => format!("{TETE} ORDER BY id DESC LIMIT ?2 OFFSET {o}"),
        LedgerPlan::First => format!("{TETE} ORDER BY id DESC LIMIT ?2"),
    }
}

/// Page du journal d'intégrité. Fonction PURE sur `&Connection` -> testable sans AppState.
///
/// Rend `{ok, entries, total, total_capped, window_days, since, oldest_ts, older_outside_window,
/// has_more, next_cursor, limit}` — `total`/`total_capped` valant `null` quand `count` est faux (« non
/// compté », ce qu'un `0` ne saurait pas dire). `entries` : MÊMES colonnes, MÊME ordre (`id` décroissant)
/// qu'avant — la fenêtre de temps FILTRE, elle ne réordonne rien et ne touche pas à la chaîne de hash.
pub(crate) fn ledger_page(conn: &Connection, ask: &LedgerAsk) -> Value {
    // (1) TOTAL BORNÉ : le balayage s'arrête à `CAP+1` lignes au lieu de lire toute la table. Sous le
    //     plafond le total est EXACT (pager numéroté juste) ; au plafond il est rendu plafonné AVEC
    //     `total_capped`, jamais présenté comme exact.
    //     DEMANDÉ SEULEMENT QUAND IL PEUT AVOIR CHANGÉ : hors de la première page d'un parcours, le total
    //     est déjà connu du client, et le relire coûterait le plafond POUR RIEN. `null` dit « non compté »,
    //     ce qu'un `0` ne saurait pas dire.
    let (total, total_capped) = if ask.count {
        let raw: i64 = conn.query_row(&ledger_total_sql(), params![ask.since], |r| r.get(0)).unwrap_or(0);
        let capped = raw > PAGINATION_COUNT_CAP;
        (json!(if capped { PAGINATION_COUNT_CAP } else { raw }), json!(capped))
    } else {
        (Value::Null, Value::Null)
    };

    // (2) LA PLUS ANCIENNE ENTRÉE STOCKÉE — première ligne de la clé primaire, coût constant. C'est ce
    //     qui permet à la vue de DIRE que la fenêtre mord (des entrées existent hors du cadre) au lieu
    //     de laisser croire que le journal s'arrête là.
    let oldest_ts: Option<i64> = conn.query_row("SELECT ts FROM ledger ORDER BY id LIMIT 1", [], |r| r.get(0)).ok();

    // (3) LA PAGE, PAR CLÉ.
    let sql = ledger_page_sql(&ledger_plan(ask.cursor, ask.offset));
    let entries: Vec<Value> = match conn.prepare(&sql) {
        Ok(mut stmt) => stmt
            .query_map(params![ask.since, ask.limit], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "ts": r.get::<_, i64>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "detail": r.get::<_, Option<String>>(3)?,
                    "hash": r.get::<_, String>(4)?,
                }))
            })
            .map(|it| it.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // (4) CONTRAT DE CONTINUATION, identique à `keyset_finalize` : EXACTEMENT `limit` lignes -> il reste
    //     probablement des lignes, on fournit le curseur ; MOINS -> dernière page (`next_cursor:null`).
    //     `has_more` reste HONNÊTE : jamais vrai sans curseur exploitable (sinon la vue bouclerait à vide).
    let next_cursor = if entries.len() as i64 == ask.limit {
        entries.last().and_then(|e| e.get("id").cloned()).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    json!({
        "ok": true,
        "entries": entries,
        "total": total,
        "total_capped": total_capped,
        "window_days": ask.window_days,
        // Borne basse EFFECTIVE, ou `null` quand il n'y a pas de borne (jamais `i64::MIN`, qui se lirait
        // comme une date absurde côté client).
        "since": if ask.window_days > 0 { json!(ask.since) } else { Value::Null },
        "oldest_ts": oldest_ts,
        "older_outside_window": oldest_ts.map(|t| t < ask.since).unwrap_or(false),
        "has_more": !next_cursor.is_null(),
        "next_cursor": next_cursor,
        "limit": ask.limit,
    })
}

/// GET /api/ledger?limit=<n>&window_days=<j>&cursor=<id>&offset=<n>&count=<0|1> -> page du journal
/// d'intégrité (audit tamper-evident), ordre `id` décroissant. Rend l'audit RÉELLEMENT consultable in-UI
/// (correctif H1 : le ledger n'avait qu'un `verify` CLI). Admin only (B9).
///
/// LECTURE SEULE — ET LE CODE LE FAIT MAINTENANT. L'en-tête disait « lecture seule » pendant que le
/// corps prenait le MUTEX D'ÉCRITURE (`with_write`), c'est-à-dire la connexion par laquelle passe
/// l'ingestion. Le comptage intégral servi sur ce verrou entrait donc en concurrence avec elle. La route
/// passe au pool read-only + `query_sem` + `spawn_blocking` + watchdog, EXACTEMENT comme `/api/query`
/// et comme `cases_list` — dont le commentaire porte déjà ce même correctif (« M6 : SORT du mutex
/// d'ÉCRITURE »), preuve que le geste était connu et que cette route était restée en arrière.
///
/// `count=0` : ne recompte pas le total (le client garde celui de la première page de son parcours) ->
/// `total:null` + `total_capped:null`, ce qu'un `0` ne saurait pas dire. ABSENT -> on compte, comme avant.
///
/// `window_days` : 1..`LEDGER_WINDOW_MAX_DAYS`, `0` ou ABSENT = aucune borne. LE DÉFAUT DE LA ROUTE EST
/// « AUCUNE BORNE », ET CE N'EST PAS UN OUBLI : un appelant qui cherche le DERNIER changement audité — le
/// bandeau de la vue Rétention (`web/retention.js`) — doit le trouver même s'il date d'avant n'importe
/// quelle fenêtre choisie ; un défaut borné côté route lui ferait afficher « aucun changement audité »
/// pour un changement qui existe. Le défaut est donc une propriété de la VUE, et il vit à UN seul endroit :
/// `FENETRE_DEFAUT` dans `web/audit.js`, où la vue le NOMME au-dessus du tableau. L'écrire aussi ici en
/// ferait un second compteur, qui pourrirait.
///
/// Un décalage au-delà de `LEDGER_JUMP_MAX`, une fenêtre non numérique, un permis ou une connexion de
/// lecture indisponibles -> REFUS explicite. Jamais une page vide : sur cette vue, un vide se lit comme
/// un fait, et une ligne manquante ne se remarque pas.
pub(crate) async fn ledger_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(100).clamp(1, 1000);
    let offset: i64 = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).max(0);
    if offset > LEDGER_JUMP_MAX {
        return bad_req(format!(
            "saut refusé : décalage {offset} au-delà du plafond de {LEDGER_JUMP_MAX} entrées. Le journal se \
             parcourt par clé (page suivante / précédente), ou se resserre par sa fenêtre de temps."
        ));
    }
    let cursor: Option<i64> = q.get("cursor").and_then(|s| s.trim().parse::<i64>().ok()).filter(|c| *c > 0);
    let window_days: i64 = match q.get("window_days").map(|s| s.trim()) {
        None | Some("") => 0,
        Some(s) => match s.parse::<i64>() {
            Ok(0) => 0,
            Ok(n) if n > 0 => n.min(LEDGER_WINDOW_MAX_DAYS),
            _ => {
                return bad_req(format!(
                    "fenêtre de temps invalide : un nombre de jours entre 1 et {LEDGER_WINDOW_MAX_DAYS} est \
                     attendu, ou 0 pour tout l'historique."
                ))
            }
        },
    };
    let since = if window_days > 0 { now() - window_days * 86_400 } else { i64::MIN };
    // `count=0` -> ne recompte pas (le client garde le total de la première page de son parcours).
    let count = q.get("count").map(|s| !matches!(s.trim(), "0" | "false" | "no")).unwrap_or(true);
    let ask = LedgerAsk { limit, since, window_days, cursor, offset, count };
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => {
            return server_err(
                "journal d'audit : aucun permis de lecture disponible. Aucune page n'est rendue — une page \
                 vide se lirait comme un journal vide.",
            )
        }
    };
    let db_path = req_db_path(&st, &au);
    let res = tokio::task::spawn_blocking(move || read_with_watchdog(&db_path, Value::Null, move |conn| ledger_page(conn, &ask)))
        .await
        .unwrap_or(Value::Null);
    if res.is_null() {
        return server_err(
            "journal d'audit illisible (connexion de lecture indisponible). Aucune page n'est rendue — une \
             page vide se lirait comme un journal vide.",
        );
    }
    Json(res).into_response()
}

// Inventaire des sources + métadonnées d'affichage : `handlers/sources.rs` (P11.3-a).

// =================================================================================================
// CHANTIER « whitelists → webui » — REGISTRE UNIQUE des suppressions/whitelists/filtres du DAEMON.
//
// AVANT : chaque exclusion vivait en CONSTANTE MAGIQUE dispersée (EXCL_CLAUSES, sources connues,
// RETENTION_FIELDS, PROTECTED_IP_MATCHERS, HOT_FIELDS, FTS_FIELDS_ON, generic_sources) —
// certaines invisibles = l'ANGLE MORT redouté (une suppression cachée). MAINTENANT : chacune est DÉCLARÉE
// ici comme DONNÉE {name, scope, type, value, source} et lue LIVE (aucune valeur dupliquée : le registre
// est une DÉCLARATION au-dessus des MÊMES sources de vérité que le runtime -> byte-identique par construction).
//
// Le registre alimente le panneau read-only (GET /api/suppressions) et rend la config INSPECTABLE
// (principe open-source / vendor-agnostic : déclaré/documenté, pas hardcodé magique).
//
// INVARIANT STRUCTUREL : seul le type `display-only` PROUVÉ (operator/self — jamais substitué dans
// `rule_sql`, garantie v55) porte `editable=true` ; `collection-reducing` et `host` sont TOUJOURS
// mirror-only (surfacer un filtre ≠ le rendre pilotable). Centraliser la VISIBILITÉ ≠ centraliser le CONTRÔLE.
// =================================================================================================

/// TYPE d'une suppression (test de l'angle mort) — détermine la politique d'édition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExclType {
    /// de-bruite un PANNEAU seul — jamais retiré du stockage `event` ni de la détection (`rule_sql`).
    DisplayOnly,
    /// réduit ce qui est INGÉRÉ/STOCKÉ (filtre collecteur, purge) — un changement PEUT ouvrir un angle mort.
    CollectionReducing,
    /// état firewall/enforcement/détecteur à la frontière hôte (nft, origin-fw, never-ban…).
    Host,
}
impl ExclType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ExclType::DisplayOnly => "display-only",
            ExclType::CollectionReducing => "collection-reducing",
            ExclType::Host => "host",
        }
    }
}

/// Une suppression/whitelist/filtre DÉCLARÉ comme donnée. `value`/`detail` sont résolus LIVE. `editable`
/// = true UNIQUEMENT pour operator/self (display-only prouvé) ; `edit_key` = clé passée à `suppressions_put`.
pub(crate) struct ExclEntry {
    pub(crate) name: &'static str,
    pub(crate) label: &'static str,
    pub(crate) scope: &'static str,
    pub(crate) etype: ExclType,
    pub(crate) value: String,
    pub(crate) detail: Value,
    pub(crate) source: &'static str,
    pub(crate) editable: bool,
    pub(crate) edit_key: &'static str,
}
impl ExclEntry {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "label": self.label,
            "scope": self.scope,
            "type": self.etype.as_str(),
            "value": self.value,
            "detail": self.detail,
            "source": self.source,
            "editable": self.editable,
            "edit_key": self.edit_key,
            "guarantee": "collecte/règles NON modifiées",
        })
    }
}

/// Construit le REGISTRE des exclusions DAEMON (A1..A9), valeurs LUES LIVE. Aucun état dupliqué : chaque
/// entrée lit la même source de vérité que le runtime -> le registre PROUVE ce qui est réellement en vigueur.
pub(crate) fn daemon_excl_registry(conn: &Connection, conf: &HashMap<String, String>) -> Vec<ExclEntry> {
    let mut out: Vec<ExclEntry> = Vec::new();
    // A1/A2 — exclusions d'AFFICHAGE opérateur/self (display-only, ÉDITABLES). value = CSV résolu (override
    // setting sinon env) ; detail = clauses RÉELLEMENT substituées à la compilation des panneaux (jamais dans
    // les règles de détection, v55). `P4.10-a` — CE QUE `detail` NOMME EST UNE SURFACE, JAMAIS UN SYMBOLE :
    // ce registre est SERVI à l'exploitant et se dit PREUVE de ce qui est en vigueur ; un nom de fonction y
    // devient faux au premier renommage, sans que rien ne le signale — c'est arrivé le 2026-08-28.
    // SEULE catégorie editable de tout le registre.
    let op_csv = excl_display_csv(conn, conf, EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT);
    let self_csv = excl_display_csv(conn, conf, EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT);
    let e = ExclClauses::resolve(conn, conf);
    out.push(ExclEntry {
        name: "operator_excl",
        label: "Exclusion opérateur (__OPERATOR_EXCL__)",
        scope: "panneaux menace externe (web top-clients/4xx, Cloudflare 25-29, banpass)",
        etype: ExclType::DisplayOnly,
        value: op_csv,
        detail: json!({ "field": "src_ip", "sql": e.op_sql, "soql": e.op_soql, "substituted_in": "la compilation des panneaux", "never_in": "les règles de détection" }),
        source: "ExclClauses / PLUME_OPERATOR_IPS (override setting excl_operator_ips)",
        editable: true,
        edit_key: "operator",
    });
    out.push(ExclEntry {
        name: "self_excl",
        label: "Exclusion self/vhost (__SELF_EXCL__)",
        scope: "mêmes panneaux menace externe (vhost self)",
        etype: ExclType::DisplayOnly,
        value: self_csv,
        detail: json!({ "field": "vhost", "sql": e.self_sql, "soql": e.self_soql, "substituted_in": "la compilation des panneaux", "never_in": "les règles de détection" }),
        source: "ExclClauses / PLUME_SELF_HOSTS (override setting excl_self_hosts)",
        editable: true,
        edit_key: "self",
    });
    // A3 — sources ATTENDUES PAR CONSTRUCTION (flag d'affichage « inattendu » + sévérité B8 ; ZÉRO effet
    // ingest/collecte). DÉRIVÉES (fichiers livrés, sondes, dimensions de rollup — cf. handlers/sources.rs),
    // plus les connecteurs configurés, qui dépendent de la base et ne sont donc pas listés ici.
    let attendues = sources_attendues_sans_base();
    out.push(ExclEntry {
        name: "sources_attendues_par_construction",
        label: "Sources attendues par construction (flag « inattendu »)",
        scope: "inventaire /api/sources + sévérité B8",
        etype: ExclType::DisplayOnly,
        value: attendues.join(","),
        detail: json!({ "count": attendues.len(), "items": attendues }),
        source: "SOURCES_LIVREES + COLLECTORS + dim_rollup_specs / raison_attendue_par_construction",
        editable: false,
        edit_key: "",
    });
    // A4 — planchers de RÉTENTION (collection-reducing : lifecycle des données). Valeur effective + planchers DURS.
    let ret: Vec<Value> = RETENTION_FIELDS
        .iter()
        .map(|&(k, env_key, d, floor, ceil)| json!({ "key": k, "effective": retention_effective(conn, conf, k), "floor": floor, "ceil": ceil, "default": d, "env": env_key }))
        .collect();
    out.push(ExclEntry {
        name: "retention_floors",
        label: "Rétention / purge (planchers)",
        scope: "purge retention_run (lifecycle des données)",
        etype: ExclType::CollectionReducing,
        value: format!("{} champs", RETENTION_FIELDS.len()),
        detail: json!({ "fields": ret, "note": "éditable ailleurs via /api/retention (plancher DUR anti-effacement) — surfacé ici en lecture" }),
        source: "const RETENTION_FIELDS / retention_run",
        editable: false,
        edit_key: "",
    });
    // A5 — never-ban (HOST/enforcement). PIÈGE §4 : partage l'env PLUME_OPERATOR_IPS mais N'EST PAS éditable ici.
    let nb: Vec<Value> = protected_ip_matchers().iter().map(|(v, p)| json!({ "match": v, "prefix": p })).collect();
    out.push(ExclEntry {
        name: "protected_ip_matchers",
        label: "IP protégées (never-ban)",
        scope: "responder / enforcement ban",
        etype: ExclType::Host,
        value: format!("{} matchers configurés + loopback/RFC1918/ULA (built-in)", nb.len()),
        detail: json!({ "configured": nb, "builtin": "loopback/link-local/RFC1918/ULA", "note": "HOST/enforcement — partage PLUME_OPERATOR_IPS mais JAMAIS pilotable d'ici (§4 : surfacer≠piloter)" }),
        source: "PROTECTED_IP_MATCHERS / ip_is_protected",
        editable: false,
        edit_key: "",
    });
    // A6 — HOT_FIELDS (whitelist d'index-expression : PERF ; un champ hors liste reste STOCKÉ et requêtable).
    out.push(ExclEntry {
        name: "hot_fields",
        label: "Champs chauds indexés (HOT_FIELDS)",
        scope: "index expression (perf)",
        etype: ExclType::DisplayOnly,
        value: HOT_FIELDS.join(","),
        detail: json!({ "items": HOT_FIELDS, "note": "perf uniquement — un champ hors liste reste STOCKÉ et requêtable" }),
        // P7.15-a — LA PROVENANCE ANNONCÉE ÉTAIT À MOITIÉ FAUSSE : elle citait une fonction de test
        // d'indexation à l'EXÉCUTION qui n'était JAMAIS APPELÉE (elle a depuis été retirée avec le
        // mécanisme adaptatif mort). L'opérateur croyait lire un état ; il lit une CONSTANTE. Une
        // provenance fausse est pire qu'une provenance absente : elle fait cesser de chercher.
        // Aujourd'hui c'est EXACT et EXHAUSTIF : cette liste figée est le SEUL mécanisme qui indexe
        // un champ JSON — tout champ absent d'ici est scanné, aucun ne sera jamais promu à chaud.
        source: "const HOT_FIELDS (liste FIGÉE à la compilation ; SEUL mécanisme d'indexation des champs JSON)",
        editable: false,
        edit_key: "",
    });
    // A8 — FTS_FIELDS (portée du search libre : commodité ; aucun effet collecte/détection).
    out.push(ExclEntry {
        name: "fts_fields",
        label: "Recherche plein-texte des champs (FTS_FIELDS)",
        scope: "search libre",
        etype: ExclType::DisplayOnly,
        value: if fts_fields_enabled() { "on".into() } else { "off".into() },
        detail: json!({ "enabled": fts_fields_enabled(), "env": "PLUME_FTS_FIELDS", "note": "commodité de recherche — aucun effet collecte/détection" }),
        source: "FTS_FIELDS_ON / PLUME_FTS_FIELDS",
        editable: false,
        edit_key: "",
    });
    // A9 — extracteur générique (collection-ENRICHISSANTE = opposé d'une suppression ; garde-fou jamais * / auditd).
    out.push(ExclEntry {
        name: "generic_extract",
        label: "Extracteur générique (opt-in par source)",
        scope: "extraction de champs (enrichit, ne supprime pas)",
        etype: ExclType::DisplayOnly,
        value: generic_sources().join(","),
        detail: json!({ "sources": generic_sources(), "env": "PLUME_GENERIC_EXTRACT", "guard": "jamais '*' ni 'auditd'", "note": "ENRICHIT la collecte (opposé d'une suppression)" }),
        source: "generic_sources / PLUME_GENERIC_EXTRACT",
        editable: false,
        edit_key: "",
    });
    out
}

/// ALLOW-LIST des clés de `fields` surfacées pour un auto-report de config collecteur (défense en
/// profondeur). Le panneau ré-émet ces `fields` VERBATIM au DOM admin ; un collecteur (futur, ou COMPROMIS /
/// un report FORGÉ) qui glisserait un champ inattendu (token, URL-avec-creds) ne doit JAMAIS voir cette valeur
/// echo-ée dans la console. On ne surface QUE les descripteurs de filtre CONNUS (l'union des clés de niveau 1
/// émises par collectors/*: type/collector/filters/note/enforcement/detector/max/source/carve_out) ; toute clé
/// hors liste est DROPPÉE. `fields` non-objet -> objet vide. Structurellement incapable d'échoyer un secret.
pub(crate) fn suppression_fields_allowlist(f: &Value) -> Value {
    const SURFACED: &[&str] = &["type", "collector", "filters", "note", "enforcement", "detector", "max", "source", "carve_out"];
    let mut out = serde_json::Map::new();
    if let Some(obj) = f.as_object() {
        for k in SURFACED {
            if let Some(v) = obj.get(*k) {
                out.insert((*k).to_string(), v.clone());
            }
        }
    }
    Value::Object(out)
}

/// GET /api/suppressions — PANNEAU read-only agrégeant TOUTES les suppressions/whitelists/filtres, quel que
/// soit leur périmètre : (1) registre DAEMON A1..A9 (lu live) ; (2) filtres des COLLECTEURS hôte, auto-reportés
/// via un event `category='config'` par source (B/C) ; (3) état FIREWALL (snapshot kind=firewall). Chaque
/// entrée porte son TYPE + « collecte/règles NON modifiées ». Admin only. LECTURE PURE : rien ici ne pilote
/// un filtre (invariant : centraliser la VISIBILITÉ ≠ centraliser le CONTRÔLE — un seul panneau, zéro angle mort).
/// Lit la base PLATEFORME (`st.db`) et non `req_db` : ce panneau est une vue OPÉRATEUR (registre daemon,
/// collecteurs hôte CENTRAUX ingérés dans la base `default`, état firewall — aucune donnée tenant) ; l'exclusion
/// display operator/self y est PLATEFORME-globale (même périmètre que le cache process-global EXCL_CLAUSES et
/// le refresh du boot). Mode 0 -> `st.db` == `req_db` -> byte-identique. Corrige la fuite/incohérence #3.
pub(crate) async fn suppressions_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let conf = load_config();
    let __rc = st.db.clone();
    let conn = __rc.lock();
    // (1) DAEMON — registre déclaratif A1..A9.
    let daemon: Vec<Value> = daemon_excl_registry(&conn, &conf).iter().map(|e| e.to_json()).collect();
    // (2) COLLECTEURS HÔTE — dernier event category='config' PAR source (auto-report). idx_event_category seek
    // (borné : ces events sont dédupliqués par empreinte de config côté collecteur). On EXCLUT les audits
    // DAEMON (origin='daemon' : plume-config/…). READ-ONLY absolu : un collecteur ne peut pas se rendre éditable.
    // CONTESTE (anti-empoisonnement) : nb d'hôtes DISTINCTS ayant auto-reporté la config d'UNE même source
    // (fenêtre 14 j). >1 = un hôte usurpe une source qui appartient à un autre (ex: collecteur mail légitime +
    // hôte compromis prétendant source='mail') -> l'entrée est marquée `contested` : le conflit d'hôtes DEVIENT
    // VISIBLE, le panneau ne peut plus être empoisonné en silence. Bornée par source (cardinalité collecteurs).
    let mut host_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT source, COUNT(DISTINCT host) FROM event \
         WHERE category='config' AND origin<>'daemon' AND ts > ?1 GROUP BY source",
    ) {
        if let Ok(rows) = s.query_map(params![now() - 14 * 86400], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
            for (src, n) in rows.flatten() { host_counts.insert(src, n); }
        }
    }
    let mut collectors: Vec<Value> = Vec::new();
    if let Ok(mut s) = conn.prepare(
        "SELECT e.source, e.ts, e.host, e.fields, e.message, e.origin FROM event e \
         JOIN (SELECT source, MAX(ts) mts FROM event WHERE category='config' AND origin<>'daemon' GROUP BY source) j \
           ON e.source=j.source AND e.ts=j.mts \
         WHERE e.category='config' AND e.origin<>'daemon' ORDER BY e.source",
    ) {
        if let Ok(rows) = s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        }) {
            for (src, ts, host, fields, msg, origin) in rows.flatten() {
                let raw: Value = fields.as_deref().and_then(|x| serde_json::from_str(x).ok()).unwrap_or(Value::Null);
                // le TYPE est DÉCLARÉ par le collecteur (champ `type` de ses fields) mais `editable` est
                // TOUJOURS false ici (structurel) : la frontière hôte garde le CONTRÔLE, le panneau la VISIBILITÉ.
                let etype = raw.get("type").and_then(|v| v.as_str()).unwrap_or("collection-reducing").to_string();
                // ALLOW-LIST : ne ré-émettre QUE les clés de descripteur connues (jamais un champ inattendu).
                let f = suppression_fields_allowlist(&raw);
                // PROVENANCE SERVEUR (origin) — `attested` seulement si le report vient d'un token
                // AGENT lié (host non-forgeable). Un report `unverified` (host auto-déclaré) NE peut plus se
                // faire passer pour la vérité terrain en silence.
                // ⚠️ `contested` (>1 hôte pour la même source) N'EST PAS un signal d'usurpation sur un PARC :
                // c'est le cas NORMAL dès que deux machines font tourner le même collecteur. Le lire comme une
                // suspicion ferait chercher une attaque là où il n'y a qu'une flotte. Ce qui compte est le
                // DÉNOMINATEUR (`hosts_total`), pas le drapeau.
                let attested = origin == "agent";
                let contested = host_counts.get(&src).copied().unwrap_or(1) > 1;
                let age_s = (now() - ts).max(0);
                collectors.push(json!({
                    "source": src, "ts": ts, "host": host, "message": msg,
                    "type": etype, "fields": f, "editable": false,
                    "attested": attested, "contested": contested, "age_s": age_s,
                    // LE DÉNOMINATEUR, pas seulement le drapeau. `contested` seul répond « oui/non » à
                    // une question que l'exploitant ne se pose pas ; ce qu'il lui faut est « la ligne
                    // affichée est celle d'UN hôte sur N ». Sans ce nombre, un parc de 50 machines
                    // rendait UNE ligne qui se lisait comme l'état du parc — exactement la faute
                    // mesurée et corrigée pour le pare-feu vingt lignes plus bas (« 1 hôte rendu pour
                    // 50 »). Le drapeau restait vrai, mais un booléen ne dit pas l'ampleur.
                    "hosts_total": host_counts.get(&src).copied().unwrap_or(1),
                    "provenance": if attested { "agent (host lié au token)" } else { "auto-déclaré (non attesté)" },
                    "guarantee": "collecte/règles NON modifiées",
                }));
            }
        }
    }
    // (3) ÉTAT HÔTE/FIREWALL — dernier instantané kind=firewall, surfacé RO (nft sets / origin-fw / etc.),
    // PAR MACHINE. Ce site faisait `ORDER BY ts DESC LIMIT 1` : l'état d'UNE machine s'affichait comme
    // l'état du parc (mesuré : 1 hôte rendu pour 50). C'est la même faute que le `contested` déjà posé
    // sur les auto-reports collecteurs ci-dessus — plusieurs machines revendiquant la même chose DOIT
    // devenir visible. `firewall` reste la plus fraîche (mono-hôte -> réponse inchangée) ; `firewall_hosts`
    // porte la ventilation et `firewall_n_hosts` le dénominateur.
    let fw_par_hote = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
    let fw_json: Vec<Value> = fw_par_hote
        .iter()
        .map(|(h, ts, _, data)| json!({
            "ts": ts,
            "data": serde_json::from_str::<Value>(data).unwrap_or(Value::Null),
            "host": h,
        }))
        .collect();
    let firewall = fw_json.first().cloned();
    Json(json!({
        "ok": true,
        "generated": now(),
        "daemon": daemon,
        "collectors": collectors,
        "firewall": firewall,
        "firewall_hosts": fw_json,
        "firewall_n_hosts": fw_json.len(),
        "legend": {
            "display-only": "de-bruite un PANNEAU seul — jamais retiré du stockage ni de la détection (rule_sql). Operator/self = ÉDITABLE+audité.",
            "collection-reducing": "réduit ce qui est INGÉRÉ/STOCKÉ — READ-ONLY ici, contrôle à la frontière hôte.",
            "host": "état firewall/enforcement à la frontière hôte — READ-ONLY, visibilité seule.",
            "provenance": "auto-report collecteur : `attested`=host lié à un token agent (non-forgeable) ; sinon host auto-déclaré (non attesté). `contested`=plusieurs hôtes revendiquent la même source. Le `type` est DÉCLARÉ par le collecteur — un report non attesté/contesté/périmé NE fait PAS foi.",
        },
    }))
    .into_response()
}

/// POST|PUT /api/suppressions {action, value?} — édite l'UNIQUE exclusion display-only PROUVÉE (operator/self).
/// Enum FERMÉ : set_operator_excl(csv) | clear_operator_excl | set_self_excl(csv) | clear_self_excl. RIEN
/// d'autre n'est éditable — une action collection-reducing/host = 400 (le contrôle reste à la frontière). Admin
/// only + double-audit fail-closed (ledger + event plume-config) sev 3 (modifier une exclusion d'AFFICHAGE = un
/// de-bruitage auditable dans la durée, comme B8). GARANTIE angle mort : l'override n'alimente QUE
/// la compilation des panneaux (jamais les règles de détection ni le bannissement) -> il NE PEUT créer aucun angle mort de collecte/détection.
/// Recompile le cache d'exclusion (hot-reload) -> effet immédiat sur les panneaux.
/// Cœur TESTABLE de l'édition d'une exclusion display-only : valide l'action (ENUM FERMÉ operator/self),
/// écrit/efface le `setting`, audite (ledger + event plume-config sev 3) DANS UNE TRANSACTION fail-closed,
/// renvoie (edit_key, old_csv, new_csv). Toute autre action (collection-reducing/host, ou inconnue) -> 400 :
/// le registre est read-only par conception, SEULE cette exclusion display-only est pilotable. N'appelle PAS
/// `excl_clauses_refresh` (le hot-reload du cache reste à l'appelant, hors transaction).
pub(crate) fn apply_display_excl_edit(
    conn: &Connection,
    conf: &HashMap<String, String>,
    action: &str,
    value: &str,
    actor: &str,
) -> Result<(&'static str, String, String), (StatusCode, String)> {
    let (setting_key, env_key, default, field, is_clear) = match action {
        "set_operator_excl" => (EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT, "operator", false),
        "clear_operator_excl" => (EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT, "operator", true),
        "set_self_excl" => (EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT, "self", false),
        "clear_self_excl" => (EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT, "self", true),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "action inconnue — seules les exclusions d'AFFICHAGE operator/self sont éditables (collection-reducing/host = read-only par conception)".to_string(),
            ))
        }
    };
    // valeur CSV bornée (display-only ; validée à la compilation par parse_excl_item -> une entrée non
    // interprétable devient no-op, jamais du SQL invalide ni un angle mort). Ici on borne juste la taille.
    let value: String = if is_clear { String::new() } else { value.chars().take(2000).collect() };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible".to_string()));
    }
    let outcome: rusqlite::Result<(String, String)> = (|| {
        let ts = now();
        let old = excl_display_csv(conn, conf, setting_key, env_key, default);
        if is_clear {
            conn.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![setting_key])?;
        } else {
            conn.execute(
                "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
                 ON CONFLICT(scope,key) DO UPDATE SET value=?2,updated=?3,updated_by=?4",
                params![setting_key, value, ts, actor],
            )?;
        }
        let new = excl_display_csv(conn, conf, setting_key, env_key, default);
        // sev 3 (B8-like) : de-bruitage d'affichage AUDITÉ (ledger + event plume-config SOC-visible dans la durée).
        audit_config_change(
            conn,
            &format!("config.suppression.{field}"),
            &format!("exclusion affichage {field}: [{old}]->[{new}] par {actor}"),
            3,
            &format!("exclusion d'affichage {field} (display-only): [{old}]->[{new}] par {actor} — panneaux uniquement, collecte/détection inchangées"),
            &json!({ "field": field, "old": old, "new": new, "actor": actor, "type": "display-only", "effect": "la compilation des panneaux SEULEMENT (jamais les règles de détection, jamais le bannissement)" }).to_string(),
        )?;
        Ok((old, new))
    })();
    match outcome {
        Ok((old, new)) => {
            let _ = conn.execute_batch("COMMIT");
            Ok((field, old, new))
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification): {e}")))
        }
    }
}

pub(crate) async fn suppressions_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let action = b.str_field("action");
    let value = b.str_field("value");
    let conf = load_config();
    // PORTÉE : l'exclusion d'affichage operator/self est PLATEFORME-globale (mêmes IP/vhosts de bruit de
    // l'opérateur/du self quel que soit le tenant) et pilote le cache PROCESS-global EXCL_CLAUSES rafraîchi
    // depuis `st.db` au boot. On écrit + rafraîchit donc sur `st.db` (base plateforme), JAMAIS sur la base
    // du tenant courant : sinon (multi-tenant) l'override écrit dans une base tenant fuit dans le cache global
    // de TOUS les tenants puis est PERDU au reboot (le boot ne relit que st.db). Mode 0 -> st.db == req_db ->
    // byte-identique. Reste STRICTEMENT display-only + audité (aucun impact collecte/détection/never-ban).
    let __rc = st.db.clone();
    let conn = __rc.lock();
    match apply_display_excl_edit(&conn, &conf, action, value, au.name.as_str()) {
        Ok((field, old, new)) => {
            // hot-reload du cache d'exclusion DEPUIS la base éditée -> effet immédiat sur les panneaux.
            excl_clauses_refresh(&conn, &conf);
            (StatusCode::OK, Json(json!({ "ok": true, "field": field, "old": old, "new": new }))).into_response()
        }
        Err((code, msg)) => (code, msg).into_response(),
    }
}
