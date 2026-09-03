//! Ergonomie des dashboards (#54) — SUR-ENSEMBLE Grafana/Splunk, ADDITIF & INERTE en mode 0 :
//!   - `library_panel` : panneaux RÉUTILISABLES (édités une fois, référencés par N dashboards ; la
//!     résolution de la définition EXÉCUTÉE vit dans le coffre `panneau_resolu.rs`, et c'est elle que
//!     la porte « SQL brut = admin » emprunte — P7.13-a) ;
//!   - `playlist` : listes ORDONNÉES de dashboards qui défilent (NOC wall-board) ;
//!   - `dashboard_snapshot` : capture POINT-IN-TIME des données rendues, partageable en LECTURE SEULE via
//!     un token CSPRNG. Deux garanties DISTINCTES, et ce bandeau n'en annonçait qu'une seule en les
//!     mélangeant (« hérite #45 + RBAC ») alors que la seconde était ABSENTE :
//!       1. CHAMPS — la capture passe par le CHEMIN GXQL MASQUÉ (effective_masks du rôle du créateur)
//!          -> un snapshot ne fige jamais un CHAMP hors de la portée du créateur (#45) ;
//!       2. PANNEAUX — la capture reçoit désormais la PORTÉE DE LECTURE du créateur (`PorteeLecture`,
//!          paramètre OBLIGATOIRE) -> un panneau PRIVÉ d'un autre propriétaire n'y entre pas. Mesuré
//!          le 2026-08-03 sur `3256e4d` AVANT ce correctif : `dash_get` -> `panels: []` et `panel_data`
//!          -> 403 pour ce tiers, mais `snapshot_create` -> 200 avec la ligne privée figée dedans.
//! CRUD = editor+ (route_min_role section 7) ; lecture d'un snapshot par token = viewer+ (Read, section 6).
use crate::*;

// ---------- helpers communs ----------
/// Le compte peut-il modifier CET objet (library_panel / playlist) ? admin: toujours ; sinon: propriétaire,
/// partagé, ou ownership vide (legacy). Miroir de `dash_editable`/`view_*`. `table` allowlistée (jamais du body).
/// P7.13-a : le PRÉDICAT lui-même n'est plus réécrit ici — c'est `panneau_resolu::lisible_par`, le MÊME que
/// celui qui filtre l'inventaire (`library_panels_list`) et que celui qui autorise un RATTACHEMENT. Trois
/// surfaces, une seule expression : elles ne peuvent plus diverger.
fn ergo_editable(conn: &Connection, au: &AuthUser, table: &str, id: i64) -> bool {
    if au.is_admin() {
        return true;
    }
    let sql = match table {
        "library_panel" => "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM library_panel WHERE id=?1",
        "playlist" => "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM playlist WHERE id=?1",
        _ => return false,
    };
    match conn.query_row(sql, params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
        Ok((owner, vis)) => panneau_resolu::lisible_par(&owner, &vis, au),
        Err(_) => false,
    }
}

fn vis_of(b: &Value) -> &'static str {
    if b.get("visibility").and_then(|v| v.as_str()) == Some("private") { "private" } else { "shared" }
}

// =====================================================================================
// LIBRARY PANELS
// =====================================================================================
pub(crate) async fn library_panels_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) — portée par `ident`, dont
    // `is_admin()` est la première branche.
    // `P11.20-n` — `ident` porte l'identité jusqu'au coffre : le drapeau `editable` et le filtre
    // `lisible_par` rendent la MÊME décision, écrite une seule fois.
    let ident = au.clone();
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "library_panels": [], "me": &me, "role": &role })), |conn| {
        let mut stmt = match conn.prepare(
            "SELECT id,name,title,query,is_soql,viz,COALESCE(drill,''),COALESCE(owner,''),COALESCE(visibility,'shared'),\
                    (SELECT COUNT(*) FROM panel p WHERE p.library_panel_id=library_panel.id) \
             FROM library_panel ORDER BY name,id",
        ) {
            Ok(s) => s,
            Err(_) => return Json(json!({ "library_panels": [], "me": &me, "role": &role })),
        };
        // P7.13-a — LE MÊME PRÉDICAT que celui qui autorise un RATTACHEMENT (`panneau_resolu::lisible_par`).
        // Il était auparavant écrit une 2e fois en SQL ici ; c'est cette duplication qui rendait crédible
        // « l'editor ne voit pas cette définition » alors que le rattachement, lui, ne regardait rien.
        // Le filtre passe en Rust (la table des définitions réutilisables est petite : dizaines de lignes).
        let out: Vec<Value> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)? != 0, r.get::<_, String>(5)?, r.get::<_, String>(6)?, r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?, r.get::<_, i64>(9)?,
                ))
            })
            .map(|rows| {
                rows.flatten()
                    .filter(|(_, _, _, _, _, _, _, owner, vis, _)| panneau_resolu::lisible_par(owner, vis, &au))
                    .map(|(id, name, title, query, is_soql, viz, drill, owner, vis, used_by)| {
                        // `P11.20-n` — le drapeau dit ce que la porte fera : `ergo_editable`, dont
                        // le corps EST `lisible_par`. Une seule phrase pour la porte et pour la vue.
                        let owns = panneau_resolu::lisible_par(&owner, &vis, &ident);
                        json!({
                            "id": id, "name": name, "title": title, "query": query, "is_soql": is_soql, "viz": viz,
                            "drill": drill, "owner": owner, "visibility": vis, "used_by": used_by, "editable": owns
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Json(json!({ "library_panels": out, "me": &me, "role": &role }))
    })
}

pub(crate) async fn library_panel_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Panneau réutilisable").to_string();
    let title = b.get("title").and_then(|v| v.as_str()).unwrap_or("Panneau").to_string();
    let query = b.str_field("query").to_string();
    let is_soql = if b.bool_field("is_soql", true) { 1 } else { 0 };
    let viz = b.get("viz").and_then(|v| v.as_str()).unwrap_or("table").to_string();
    let drill = b.str_field("drill").to_string();
    let visibility = vis_of(&b);
    // SQL BRUT (is_soql=0) = lecture arbitraire de toute la base à chaque refresh -> RÉSERVÉ ADMIN (miroir panel_create).
    if !raw_sql_allowed(is_soql == 1, &au.role) {
        return forbidden("SQL brut réservé à l'administrateur (utilisez GXQL)");
    }
    crate::req_conn!(st, au, conn);
    let _ = conn.execute(
        "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
        params![name, title, query, is_soql, viz, drill, au.name, visibility, now()],
    );
    Json(json!({ "id": conn.last_insert_rowid() })).into_response()
}

pub(crate) async fn library_panel_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    // is_soql EFFECTIF (corps si fourni, sinon base) -> un editor ne peut NI basculer en SQL brut NI éditer un
    // panneau déjà en SQL brut (miroir panel_update, anti-contournement fail-closed).
    let cur_soql: bool = match conn.query_row("SELECT COALESCE(is_soql,1) FROM library_panel WHERE id=?1", params![id], |r| r.get::<_, i64>(0).map(|n| n != 0)) {
        Ok(x) => x,
        Err(_) => return StatusCode::NOT_FOUND,
    };
    if !ergo_editable(&conn, &au, "library_panel", id) {
        return StatusCode::FORBIDDEN;
    }
    let eff_soql = b.get("is_soql").and_then(|v| v.as_bool()).unwrap_or(cur_soql);
    if !raw_sql_allowed(eff_soql, &au.role) {
        return StatusCode::FORBIDDEN;
    }
    for (k, col) in [("name", "name"), ("title", "title"), ("query", "query"), ("viz", "viz"), ("drill", "drill")] {
        if let Some(v) = b.get(k).and_then(|v| v.as_str()) {
            let _ = conn.execute(&format!("UPDATE library_panel SET {col}=?1 WHERE id=?2"), params![v, id]);
        }
    }
    if let Some(v) = b.get("is_soql").and_then(|v| v.as_bool()) {
        let _ = conn.execute("UPDATE library_panel SET is_soql=?1 WHERE id=?2", params![v as i64, id]);
    }
    if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
        let vv = if v == "private" { "private" } else { "shared" };
        let _ = conn.execute("UPDATE library_panel SET visibility=?1 WHERE id=?2", params![vv, id]);
    }
    let _ = conn.execute("UPDATE library_panel SET updated=?1 WHERE id=?2", params![now(), id]);
    // Édition d'une bibliothèque -> purge le cache des panneaux qui la référencent (leur requête a pu changer).
    panneau_avoue::cache_invalider_bibliotheque(&conn, id);
    StatusCode::NO_CONTENT
}

pub(crate) async fn library_panel_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM library_panel WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return StatusCode::NOT_FOUND;
    }
    if !ergo_editable(&conn, &au, "library_panel", id) {
        return StatusCode::FORBIDDEN;
    }
    // On DÉTACHE les panneaux référents (ils redeviennent autonomes avec leur query locale) — pas de perte.
    let _ = conn.execute("UPDATE panel SET library_panel_id=NULL WHERE library_panel_id=?1", params![id]);
    let _ = conn.execute("DELETE FROM library_panel WHERE id=?1", params![id]);
    StatusCode::NO_CONTENT
}

// =====================================================================================
// PLAYLISTS (rotation de dashboards)
// =====================================================================================
/// Normalise `items` (JSON) en liste ORDONNÉE d'ids de dashboards (ignore le non-entier). Sérialisé en TEXT.
pub(crate) fn playlist_items_json(b: &Value) -> Option<String> {
    let arr = b.get("items")?.as_array()?;
    let ids: Vec<i64> = arr.iter().filter_map(|v| v.as_i64()).collect();
    Some(serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()))
}

pub(crate) async fn playlists_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) -> bind `?1` visibilité.
    // `P11.20-n` — l'ownership de la closure passe par `ident` et le coffre ; `?2<>''` refuse
    // l'appariement d'une identité SANS NOM à une colonne `owner` vide.
    let adm = if au.is_admin() { "admin" } else { "" };
    let ident = au.clone();
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "playlists": [], "me": &me, "role": &role })), |conn| {
        let mut stmt = match conn.prepare(
            "SELECT id,name,interval_s,items,COALESCE(owner,''),COALESCE(visibility,'shared') FROM playlist \
             WHERE ?1='admin' OR COALESCE(visibility,'shared')='shared' OR (?2<>'' AND owner=?2) \
             ORDER BY name,id",
        ) {
            Ok(s) => s,
            Err(_) => return Json(json!({ "playlists": [], "me": &me, "role": &role })),
        };
        let out: Vec<Value> = stmt
            .query_map(params![adm, me], |r| {
                let owner: String = r.get(4)?;
                let vis: String = r.get(5)?;
                let items_raw: String = r.get(3)?;
                let items: Value = serde_json::from_str(&items_raw).unwrap_or_else(|_| json!([]));
                // `P11.20-n` — le drapeau dit ce que la porte fera : `ergo_editable` = `lisible_par`.
                let owns = panneau_resolu::lisible_par(&owner, &vis, &ident);
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "interval_s": r.get::<_, i64>(2)?,
                    "items": items, "owner": owner, "visibility": vis, "editable": owns
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default();
        Json(json!({ "playlists": out, "me": &me, "role": &role }))
    })
}

pub(crate) async fn playlist_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Playlist").to_string();
    let interval_s = b.i64_field("interval_s", 30).clamp(3, 3600);
    let items = playlist_items_json(&b).unwrap_or_else(|| "[]".into());
    let visibility = vis_of(&b);
    crate::req_conn!(st, au, conn);
    let _ = conn.execute(
        "INSERT INTO playlist(name,interval_s,items,owner,visibility,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
        params![name, interval_s, items, au.name, visibility, now()],
    );
    Json(json!({ "id": conn.last_insert_rowid() })).into_response()
}

pub(crate) async fn playlist_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM playlist WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return StatusCode::NOT_FOUND;
    }
    if !ergo_editable(&conn, &au, "playlist", id) {
        return StatusCode::FORBIDDEN;
    }
    if let Some(v) = b.get("name").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE playlist SET name=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("interval_s").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE playlist SET interval_s=?1 WHERE id=?2", params![v.clamp(3, 3600), id]);
    }
    if let Some(items) = playlist_items_json(&b) {
        let _ = conn.execute("UPDATE playlist SET items=?1 WHERE id=?2", params![items, id]);
    }
    if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
        let vv = if v == "private" { "private" } else { "shared" };
        let _ = conn.execute("UPDATE playlist SET visibility=?1 WHERE id=?2", params![vv, id]);
    }
    let _ = conn.execute("UPDATE playlist SET updated=?1 WHERE id=?2", params![now(), id]);
    StatusCode::NO_CONTENT
}

pub(crate) async fn playlist_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM playlist WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return StatusCode::NOT_FOUND;
    }
    if !ergo_editable(&conn, &au, "playlist", id) {
        return StatusCode::FORBIDDEN;
    }
    let _ = conn.execute("DELETE FROM playlist WHERE id=?1", params![id]);
    StatusCode::NO_CONTENT
}

// =====================================================================================
// DASHBOARD SNAPSHOTS (capture point-in-time partageable, LECTURE SEULE)
// =====================================================================================
/// Jeton de partage CSPRNG (32 octets d'entropie noyau -> 64 hex). Non devinable ; sert de capability du partage
/// read-only. FAIL-CLOSED : `None` si l'entropie noyau est indisponible -> le
/// partage ÉCHOUE, plus jamais un fallback `Sha256(now|pid|time)` DEVINABLE (parité avec `token_rand_hex`).
pub(crate) fn gen_snapshot_token() -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut buf).ok()?;
    Some(hex_encode(&buf))
}

/// CAPTURE (pure, testable sans AppState) : résout TOUS les panneaux d'un dashboard en données rendues, via
/// le CHEMIN GXQL MASQUÉ (mêmes garanties que panel_data_masked_live). `masks` = jeu EFFECTIF du rôle du
/// créateur (effective_masks) : VIDE -> compilation NON masquée (identique au rendu live d'un rôle non masqué).
/// Non vide -> GXQL masqué dans le SQL (soql_to_sql_masked_x) + masquage POST-requête du SQL brut opaque
/// (mask_query_result). Le snapshot ne peut donc JAMAIS contenir un champ hors de la portée du créateur.
/// Résout aussi les LIBRARY PANELS — par le coffre `panneau_resolu` (P7.13-a), donc par la MÊME
/// expression que `panel_access` et `dash_get`. Renvoie {dashboard_id, name, captured_at, panels:[…]}.
///
/// `conf` EST UN PARAMÈTRE, ET C'EST UNE CORRECTION DE PLACEMENT MESURÉE (`P10.5-i`). Cette fonction est
/// appelée À L'INTÉRIEUR du `req_conn!` de `snapshot_create`, c'est-à-dire sous le MUTEX WRITER du
/// tenant. Le `load_config()` qu'elle faisait elle-même y ajoutait un `std::fs::read_to_string` NON
/// mémoïsé (`main.rs`) — un accès DISQUE tenu sous le verrou qui bloque l'ingestion, contre la
/// discipline que `dashboards.rs` énonce en toutes lettres (« HORS LOCK : lecture config … AVANT de
/// prendre le lock writer ») et que ce même lot invoque pour justifier son geste là-bas. L'appelant le
/// fait donc AVANT de prendre le verrou, une seule fois, et le passe.
pub(crate) fn capture_dashboard_data(
    db_path: &str, conn: &Connection, conf: &HashMap<String, String>, dashboard_id: i64, dash_name: &str, from: i64, to: i64,
    env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet, portee: &PorteeLecture,
) -> Value {
    let mut panels_out: Vec<Value> = Vec::new();
    let rows: Vec<(String, String, bool, String, String, String)> = {
        let mut stmt = match conn.prepare(&format!(
            "SELECT {t},{q},{s},{v},{d},COALESCE(p.visibility,'shared') FROM {j} WHERE p.dashboard_id=?1 ORDER BY p.position,p.id",
            t = panneau_resolu::COL_TITRE, q = panneau_resolu::COL_QUERY, s = panneau_resolu::COL_IS_SOQL,
            v = panneau_resolu::COL_VIZ, d = panneau_resolu::COL_DRILL, j = panneau_resolu::JOINTURE,
        )) {
            Ok(s) => s,
            Err(_) => return json!({ "dashboard_id": dashboard_id, "name": dash_name, "captured_at": now(), "panels": [] }),
        };
        stmt.query_map(params![dashboard_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default()
    };
    // P7.13-a — LA MÊME PORTÉE DE LECTURE QUE `dash_get`/`panel_access` : un panneau PRIVÉ d'un autre
    // propriétaire n'entre PAS dans la capture. MESURÉ AVANT (2026-08-03, `3256e4d`) : sur un dashboard
    // PARTAGÉ d'alice portant un panneau privé, un editor tiers avait `dash_get` -> `panels: []` et
    // `panel_data` -> 403, mais `snapshot_create` -> 200 avec la ligne privée FIGÉE dans le snapshot,
    // ensuite partageable par jeton. L'en-tête de ce module affirmait « hérite #45 + RBAC ».
    let rows: Vec<_> = rows.into_iter().filter(|(_, _, _, _, _, pvis)| portee.voit(pvis)).collect();
    for (title, query, is_soql, viz, _drill, _pvis) in rows {
        // `P10.5-i` — TROIS SITES DE COMPILATION deviennent DEUX BRANCHES, et c'est un déplacement pur :
        // le coffre non masqué traite déjà `is_soql=0` par la MÊME substitution appliquée au MÊME
        // `apply_excl_placeholders`, et le coffre masqué reproduit le corps de `panel_data_masked_live`.
        // Le troisième site (masques NON vides + `is_soql=1`) produisait un `String` nu : sans cette
        // réduction, la MOITIÉ des instantanés — ceux d'un appelant à masques actifs — sortirait sans aveu.
        let compiled = if masks.is_empty() {
            panneau_avoue::compile_panneau_avoue(&query, is_soql, from, to, env)
        } else {
            panneau_avoue::compile_panneau_avoue_masque(&query, is_soql, from, to, env, masks)
        };
        let pc = match compiled {
            Ok(pc) => pc,
            Err(e) => { panels_out.push(json!({ "title": title, "viz": viz, "error": e })); continue; }
        };
        // SQL brut opaque : masquage POST-requête par nom de colonne (le masque ne s'injecte pas).
        let post_mask = !is_soql && !masks.is_empty();
        match panneau_avoue::executer(db_path, conf, pc, from) {
            Ok(mut v) => {
                if post_mask {
                    mask_query_result(db_path, masks, &mut v);
                }
                panels_out.push(json!({
                    "title": title, "viz": viz,
                    "columns": v.get("columns").cloned().unwrap_or_else(|| json!([])),
                    "rows": v.get("rows").cloned().unwrap_or_else(|| json!([])),
                    // L'INSTANTANÉ EST L'ARTEFACT QUI VOYAGE : partageable par jeton, relu des semaines
                    // plus tard, hors de tout contexte de fenêtre. Sans cette ligne, l'aveu s'arrêterait
                    // ici — et c'est la garde dérivée du routeur (règle sur `data.panels[*]`) qui la tient.
                    "stats": v.get("stats").cloned().unwrap_or_else(|| json!({})),
                }));
            }
            Err(e) => panels_out.push(json!({ "title": title, "viz": viz, "error": e })),
        }
    }
    json!({ "dashboard_id": dashboard_id, "name": dash_name, "captured_at": now(), "panels": panels_out })
}

pub(crate) async fn snapshot_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let dashboard_id = b.i64_field("dashboard_id", 0);
    let from = b.i64_field("from", 0);
    let to = b.i64_field("to", 0);
    let env = au.env_filter();
    // La capture lit la BASE COURANTE du tenant ET le registre de masques -> même db_path partout.
    let db_path = req_db_path(&st, &au);
    // 1) Le créateur peut-il VOIR ce dashboard ? (mêmes règles que dash_get : admin / partagé / propriétaire.)
    let (name, owner, vis): (String, String, String) = {
        crate::req_conn!(st, au, conn);
        match conn.query_row(
            "SELECT name,COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
            params![dashboard_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ) {
            Ok(x) => x,
            Err(_) => return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response(),
        }
    };
    // `P11.20-n` — MÊME phrase que `dash_get` : un dashboard SANS propriétaire n'est plus « à nous ».
    if !panneau_resolu::lisible_par(&owner, &vis, &au) {
        return forbidden("dashboard privé");
    }
    let snap_name = b.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| name.clone());
    // 2) CAPTURE via le chemin MASQUÉ (jeu effectif du rôle du CRÉATEUR) — jamais de données hors de sa portée.
    let masks = effective_masks(&db_path, &au.role, &au.tenant, env);
    // P7.13-a — la capture reçoit la PORTÉE DE LECTURE du créateur (même décision que `dash_get`) : un
    // panneau privé d'un autre propriétaire n'y entre pas. Le paramètre est OBLIGATOIRE (E0061) : un
    // futur appelant ne peut pas l'oublier, ce qui était exactement la faute mesurée ici.
    let portee = PorteeLecture::du_dashboard(&au, &owner);
    // HORS LOCK, ET UNE SEULE FOIS (`P10.5-i`) : `load_config()` fait un accès DISQUE non mémoïsé.
    // Le prendre SOUS le mutex writer bloquerait l'ingestion du tenant le temps d'une lecture de fichier.
    let conf = load_config();
    let data = {
        crate::req_conn!(st, au, conn);
        capture_dashboard_data(&db_path, &conn, &conf, dashboard_id, &name, from, to, env, &masks, &portee)
    };
    let payload = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
    let token = match gen_snapshot_token() {
        Some(t) => t,
        None => return server_err("entropie noyau indisponible — création du partage refusée (jamais de jeton faible)"),
    };
    {
        crate::req_conn!(st, au, conn);
        let _ = conn.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) \
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![dashboard_id, snap_name, token, payload, now(), au.name, au.role],
        );
        Json(json!({ "id": conn.last_insert_rowid(), "token": token })).into_response()
    }
}

pub(crate) async fn snapshots_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) -> bind `?1` visibilité + ownership.
    let adm = if au.is_admin() { "admin" } else { "" };
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "snapshots": [], "me": &me, "role": &role })), |conn| {
        // MÉTADONNÉES seulement (jamais le blob `data` en liste). L'admin voit tout ; sinon ses propres captures.
        let mut stmt = match conn.prepare(
            "SELECT id,dashboard_id,name,token,created,COALESCE(created_by,''),COALESCE(role_at_capture,'') FROM dashboard_snapshot \
             WHERE ?1='admin' OR COALESCE(created_by,'')=?2 ORDER BY created DESC,id DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Json(json!({ "snapshots": [], "me": &me, "role": &role })),
        };
        let out: Vec<Value> = stmt
            .query_map(params![adm, me], |r| {
                let created_by: String = r.get(5)?;
                let owns = adm == "admin" || created_by == me;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "dashboard_id": r.get::<_, i64>(1)?, "name": r.get::<_, String>(2)?,
                    "token": r.get::<_, String>(3)?, "created": r.get::<_, i64>(4)?, "created_by": created_by,
                    "role_at_capture": r.get::<_, String>(6)?, "editable": owns
                }))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default();
        Json(json!({ "snapshots": out, "me": &me, "role": &role }))
    })
}

/// Lecture d'un snapshot PAR TOKEN (read-only, token-scoped). Renvoie les données DÉJÀ figées & masquées à la
/// capture -> aucune re-exécution GXQL, aucune fuite : ce que le créateur a vu, rien de plus. viewer+ (Read).
pub(crate) async fn snapshot_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(token): Path<String>) -> Response {
    // token allowlisté (hex 64) : anti-injection & anti-probe (aucun match si format inattendu).
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::NOT_FOUND, "snapshot introuvable").into_response();
    }
    crate::req_conn!(st, au, conn);
    match conn.query_row(
        "SELECT name,dashboard_id,data,created,COALESCE(created_by,''),COALESCE(role_at_capture,'') FROM dashboard_snapshot WHERE token=?1",
        params![token],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?)),
    ) {
        Ok((name, did, data, created, by, role)) => {
            let parsed: Value = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
            Json(json!({
                "name": name, "dashboard_id": did, "created": created, "created_by": by,
                "role_at_capture": role, "readonly": true, "data": parsed
            }))
            .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "snapshot introuvable").into_response(),
    }
}

pub(crate) async fn snapshot_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.query_row("SELECT COALESCE(created_by,'') FROM dashboard_snapshot WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(by) => {
            if !au.is_admin() && by != au.name {
                return StatusCode::FORBIDDEN;
            }
        }
        Err(_) => return StatusCode::NOT_FOUND,
    }
    let _ = conn.execute("DELETE FROM dashboard_snapshot WHERE id=?1", params![id]);
    StatusCode::NO_CONTENT
}
