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

/// Page du journal d'intégrité (BATCH 1) : `total` = COUNT total du ledger + `entries` = fenêtre
/// LIMIT/OFFSET (ordre id décroissant). Fonction pure sur &Connection -> testable sans AppState.
pub(crate) fn ledger_page(conn: &Connection, limit: i64, offset: i64) -> (Vec<Value>, i64) {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap_or(0);
    let entries: Vec<Value> = match conn.prepare("SELECT id,ts,kind,detail,hash FROM ledger ORDER BY id DESC LIMIT ?1 OFFSET ?2") {
        Ok(mut stmt) => stmt
            .query_map(params![limit, offset], |r| {
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
    (entries, total)
}

/// GET /api/ledger?limit=<n>&offset=<n> -> page du journal d'intégrité (audit tamper-evident), ordre
/// décroissant + `total`. Rend l'audit config RÉELLEMENT consultable in-UI (correctif H1 : le ledger n'avait
/// qu'un `verify` CLI). Lecture seule, admin only (B9). limit clampé [1,1000] ; offset absent -> 0 (rétro-compat).
pub(crate) async fn ledger_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !au.is_admin() {
        return (StatusCode::FORBIDDEN, "réservé à l'administrateur").into_response();
    }
    let limit: i64 = q.get("limit").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(100).clamp(1, 1000);
    let offset: i64 = q.get("offset").and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0).max(0);
    with_write(&st, &au, |conn| {
    let (entries, total) = ledger_page(&conn, limit, offset);
    Json(json!({ "ok": true, "entries": entries, "total": total })).into_response()
    })
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
    // setting sinon env) ; detail = clauses RÉELLEMENT substituées dans compile_panel_sql (jamais rule_sql, v55).
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
        detail: json!({ "field": "src_ip", "sql": e.op_sql, "soql": e.op_soql, "substituted_in": "compile_panel_sql", "never_in": "rule_sql (v55)" }),
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
        detail: json!({ "field": "vhost", "sql": e.self_sql, "soql": e.self_soql, "substituted_in": "compile_panel_sql", "never_in": "rule_sql (v55)" }),
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
/// compile_panel_sql (jamais rule_sql ni never-ban) -> il NE PEUT créer aucun angle mort de collecte/détection.
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
            &json!({ "field": field, "old": old, "new": new, "actor": actor, "type": "display-only", "effect": "compile_panel_sql only (never rule_sql / never-ban)" }).to_string(),
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
