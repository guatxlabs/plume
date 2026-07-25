//! Dashboards & panneaux (P3) : contrôle d'accès (`dash_editable`/`panel_access`), CRUD dashboards/
//! panneaux/vues, et le cache SWR des panneaux (clés de plage `cache_range_key`/`query_fingerprint`,
//! exclusions opérateur/self `ExclClauses`/`EXCL_CLAUSES`/`apply_excl_placeholders`, compilation
//! `compile_panel_sql`, rafraîchissement `enqueue_panel_refresh`/`serve_swr`, handler `panel_data`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- dashboards (P3) ----------
// Le compte peut-il modifier ce dashboard (et ses panneaux) ?
// admin : toujours ; sinon : propriétaire, dashboard partagé, ou ownership hérité (legacy/vide).
pub(crate) fn dash_editable(conn: &Connection, au: &AuthUser, dash_id: i64) -> bool {
    if au.is_admin() {
        return true;
    }
    match conn.query_row(
        "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
        params![dash_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        Ok((owner, vis)) => owner == au.name || owner.is_empty() || vis == "shared",
        Err(_) => false,
    }
}

// Le compte peut-il VOIR ce panneau, et avec quelle exécution ? -> (query, is_soql, window_s, owns)
pub(crate) fn panel_access(conn: &Connection, au: &AuthUser, panel_id: i64) -> Option<(String, bool, i64, bool)> {
    // LIBRARY PANELS (#54) : si le panneau RÉFÉRENCE une définition réutilisable (panel.library_panel_id),
    // la requête EXÉCUTÉE et son is_soql viennent de `library_panel` (résolus à la lecture -> éditer la
    // bibliothèque met à jour partout). LEFT JOIN + COALESCE : library_panel_id NULL (tout l'existant) ->
    // retombe sur p.query/p.is_soql -> RÉSULTAT byte-identique au mode 0. La fenêtre/visibilité restent au panneau.
    let (did, query, issoql, window, pvis): (i64, String, i64, i64, String) = conn
        .query_row(
            "SELECT p.dashboard_id,COALESCE(lp.query,p.query),COALESCE(lp.is_soql,p.is_soql),p.window_s,COALESCE(p.visibility,'shared') \
             FROM panel p LEFT JOIN library_panel lp ON lp.id=p.library_panel_id WHERE p.id=?1",
            params![panel_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .ok()?;
    let (downer, dvis): (String, String) = conn
        .query_row(
            "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
            params![did],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()?;
    let accessible = au.is_admin() || dvis == "shared" || downer == au.name || downer.is_empty();
    if !accessible {
        return None;
    }
    let owns = au.is_admin() || downer == au.name || downer.is_empty();
    if pvis == "private" && !owns {
        return None; // panneau privé d'un autre
    }
    Some((query, issoql != 0, window, owns))
}

pub(crate) async fn dash_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    // filtre optionnel par vue : ?view=<id> ou ?view=none (dashboards sans vue)
    let extra = match q.get("view").map(|s| s.as_str()) {
        Some("none") => " AND d.view_id IS NULL".to_string(),
        Some(v) => match v.parse::<i64>() {
            Ok(n) => format!(" AND d.view_id={n}"),
            Err(_) => String::new(),
        },
        None => String::new(),
    };
    let sql = format!(
        "SELECT d.id,d.name,COALESCE(d.owner,''),COALESCE(d.visibility,'shared'),d.view_id,
                (SELECT COUNT(*) FROM panel p WHERE p.dashboard_id=d.id),
                COALESCE(d.cols,2),COALESCE(d.height,0),COALESCE(d.collapsed,0),COALESCE(d.position,d.id)
         FROM dashboard d
         WHERE (?1='admin' OR COALESCE(d.visibility,'shared')='shared' OR d.owner=?2 OR COALESCE(d.owner,'')=''){extra}
         ORDER BY COALESCE(d.position,d.id), d.id"
    );
    let (me, role) = (au.name.clone(), au.role.clone());
    // #64 : AUTORITÉ ADMIN EFFECTIVE (rôle composable base=admin inclus) via `is_admin()` -> `adm` sert de bind
    // SQL `?1` (visibilité) ET de test d'ownership dans la closure. Byte-identique en mode 0 (rôle de base admin
    // -> "admin", sinon ""). `role` reste la valeur brute renvoyée pour l'affichage.
    let adm = if au.is_admin() { "admin" } else { "" };
    read_with(req_db_path(&st, &au).as_str(), Json(json!({ "dashboards": [], "me": &me, "role": &role })), |conn| {
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Json(json!({ "dashboards": [], "me": &me, "role": &role })),
        };
        let out: Vec<Value> = match stmt.query_map(params![adm, me], |r| {
            let owner: String = r.get(2)?;
            let owns = adm == "admin" || owner.is_empty() || owner == me;
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                "owner": owner, "visibility": r.get::<_, String>(3)?,
                "view_id": r.get::<_, Option<i64>>(4)?, "panels": r.get::<_, i64>(5)?,
                "cols": r.get::<_, i64>(6)?, "height": r.get::<_, i64>(7)?,
                "collapsed": r.get::<_, i64>(8)? != 0, "position": r.get::<_, i64>(9)?,
                "editable": owns
            }))
        }) {
            Ok(r) => r.flatten().collect(),
            Err(_) => return Json(json!({ "dashboards": [], "me": &me, "role": &role })),
        };
        Json(json!({ "dashboards": out, "me": &me, "role": &role }))
    })
}

pub(crate) async fn dash_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Sans titre").to_string();
    let vis = match b.get("visibility").and_then(|v| v.as_str()) {
        Some("shared") => "shared",
        _ => "private",
    };
    let view_id = b.get("view_id").and_then(|v| v.as_i64());
    crate::req_conn!(st, au, conn);
    let _ = conn.execute(
        "INSERT INTO dashboard(name,created,owner,visibility,view_id) VALUES(?1,?2,?3,?4,?5)",
        params![name, now(), au.name, vis, view_id],
    );
    Json(json!({ "id": conn.last_insert_rowid() }))
}

pub(crate) async fn dash_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    let exists: bool = conn.query_row("SELECT 1 FROM dashboard WHERE id=?1", params![id], |_| Ok(())).is_ok();
    if !exists {
        return StatusCode::NOT_FOUND;
    }
    if !dash_editable(&conn, &au, id) {
        return StatusCode::FORBIDDEN;
    }
    if let Some(name) = b.get("name").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE dashboard SET name=?1 WHERE id=?2", params![name, id]);
    }
    if let Some(vis) = b.get("visibility").and_then(|v| v.as_str()) {
        let vis = if vis == "shared" { "shared" } else { "private" };
        let _ = conn.execute("UPDATE dashboard SET visibility=?1 WHERE id=?2", params![vis, id]);
    }
    if let Some(vv) = b.get("view_id") {
        if vv.is_null() {
            let _ = conn.execute("UPDATE dashboard SET view_id=NULL WHERE id=?1", params![id]);
        } else if let Some(n) = vv.as_i64() {
            let _ = conn.execute("UPDATE dashboard SET view_id=?1 WHERE id=?2", params![n, id]);
        }
    }
    // layout dans la vue (grille) : largeur en colonnes, hauteur px, ordre, replié
    if let Some(v) = b.get("cols").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE dashboard SET cols=?1 WHERE id=?2", params![v.clamp(1, 4), id]);
    }
    if let Some(v) = b.get("height").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE dashboard SET height=?1 WHERE id=?2", params![v.max(0), id]);
    }
    if let Some(v) = b.get("collapsed").and_then(|v| v.as_bool()) {
        let _ = conn.execute("UPDATE dashboard SET collapsed=?1 WHERE id=?2", params![v as i64, id]);
    }
    if let Some(v) = b.get("position").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE dashboard SET position=?1 WHERE id=?2", params![v, id]);
    }
    StatusCode::NO_CONTENT
}

pub(crate) async fn dash_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let meta: Option<(String, String, String, Option<i64>)> = conn
        .query_row(
            "SELECT name,COALESCE(owner,''),COALESCE(visibility,'shared'),view_id FROM dashboard WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    let Some((name, owner, vis, view_id)) = meta else {
        return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response();
    };
    if !au.is_admin() && vis != "shared" && !owner.is_empty() && owner != au.name {
        return (StatusCode::FORBIDDEN, "dashboard privé").into_response();
    }
    let owns = au.is_admin() || owner.is_empty() || owner == au.name;
    // LIBRARY PANELS (#54) : titre/requête/is_soql/viz/drill AFFICHÉS sont résolus depuis `library_panel`
    // quand le panneau la référence (LEFT JOIN + COALESCE). library_panel_id NULL (tout l'existant) ->
    // COALESCE retombe sur les colonnes du panneau -> JSON byte-identique au mode 0 (+ `library_panel_id`:null).
    let mut stmt = conn
        .prepare("SELECT p.id,COALESCE(lp.title,p.title),COALESCE(lp.query,p.query),COALESCE(lp.is_soql,p.is_soql),COALESCE(lp.viz,p.viz),p.position,p.window_s,COALESCE(p.visibility,'shared'),COALESCE(p.query_private,0),COALESCE(p.cols,1),COALESCE(p.height,0),COALESCE(lp.drill,p.drill,''),p.library_panel_id \
                  FROM panel p LEFT JOIN library_panel lp ON lp.id=p.library_panel_id WHERE p.dashboard_id=?1 ORDER BY p.position,p.id")
        .unwrap();
    let panels: Vec<Value> = stmt
        .query_map(params![id], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0,
                r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?, r.get::<_, i64>(8)? != 0,
                r.get::<_, i64>(9)?, r.get::<_, i64>(10)?, r.get::<_, String>(11)?, r.get::<_, Option<i64>>(12)?,
            ))
        })
        .unwrap()
        .flatten()
        .filter(|(_, _, _, _, _, _, _, pvis, _, _, _, _, _)| owns || pvis.as_str() == "shared") // panneau privé -> proprio seulement
        .map(|(pid, title, query, is_soql, viz, position, window_s, pvis, qpriv, cols, height, drill, lib_id)| {
            let hide = qpriv && !owns; // requête privée masquée (et son drill)
            let qtext = if hide { String::new() } else { query };
            let dtext = if hide { String::new() } else { drill };
            json!({
                "id": pid, "title": title, "query": qtext, "is_soql": is_soql, "viz": viz,
                "position": position, "window_s": window_s, "visibility": pvis, "query_private": qpriv,
                "cols": cols, "height": height, "drill": dtext, "library_panel_id": lib_id
            })
        })
        .collect();
    Json(json!({
        "id": id, "name": name, "owner": owner, "visibility": vis, "view_id": view_id, "editable": owns,
        "panels": panels
    }))
    .into_response()
}

pub(crate) async fn dash_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.query_row("SELECT COALESCE(owner,'') FROM dashboard WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(owner) => {
            if !au.is_admin() && !owner.is_empty() && owner != au.name {
                return StatusCode::FORBIDDEN;
            }
        }
        Err(_) => return StatusCode::NOT_FOUND,
    }
    let _ = conn.execute("DELETE FROM panel WHERE dashboard_id=?1", params![id]);
    let _ = conn.execute("DELETE FROM dashboard WHERE id=?1", params![id]);
    StatusCode::NO_CONTENT
}

pub(crate) async fn panel_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let did = b.i64_field("dashboard_id", 0);
    let title = b.get("title").and_then(|v| v.as_str()).unwrap_or("Panneau").to_string();
    let query = b.str_field("query").to_string();
    let is_soql = if b.bool_field("is_soql", true) { 1 } else { 0 };
    let viz = b.get("viz").and_then(|v| v.as_str()).unwrap_or("table").to_string();
    let window_s = b.i64_field("window_s", 0);
    let visibility = if b.get("visibility").and_then(|v| v.as_str()) == Some("private") { "private" } else { "shared" };
    let query_private = if b.bool_field("query_private", false) { 1 } else { 0 };
    let cols = b.i64_field("cols", 1).clamp(1, 4);
    let height = b.i64_field("height", 0).max(0);
    let drill = b.str_field("drill").to_string();
    // LIBRARY PANELS (#54) : référence optionnelle à une définition réutilisable. 0/absent -> panneau autonome.
    let library_panel_id = b.get("library_panel_id").and_then(|v| v.as_i64()).filter(|&n| n > 0);
    crate::req_conn!(st, au, conn);
    if !dash_editable(&conn, &au, did) {
        return (StatusCode::FORBIDDEN, "dashboard non modifiable").into_response();
    }
    // SQL BRUT = ADMIN — un panneau en SQL BRUT (is_soql=false) exécute du SQL arbitraire
    // read-only sur TOUTE la base à chaque refresh (panel_data) : RÉSERVÉ ADMIN, comme les règles et
    // /api/query. Le SOQL (is_soql=true) reste ouvert à l'editor. Fail-closed via raw_sql_allowed.
    if !raw_sql_allowed(is_soql == 1, &au.role) {
        return (StatusCode::FORBIDDEN, "SQL brut réservé à l'administrateur (utilisez SOQL)").into_response();
    }
    let _ = conn.execute(
        "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,window_s,visibility,query_private,cols,height,drill,library_panel_id,position) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,(SELECT COALESCE(MAX(position),-1)+1 FROM panel WHERE dashboard_id=?1))",
        params![did, title, query, is_soql, viz, window_s, visibility, query_private, cols, height, drill, library_panel_id],
    );
    Json(json!({ "id": conn.last_insert_rowid() })).into_response()
}

pub(crate) async fn panel_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    // État courant : dashboard (droit d'édition) + is_soql (garde SQL brut EFFECTIVE, anti-contournement).
    let (did, cur_soql) = match conn.query_row(
        "SELECT dashboard_id, COALESCE(is_soql,1) FROM panel WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? != 0)),
    ) {
        Ok(x) => x,
        Err(_) => return StatusCode::NOT_FOUND,
    };
    if !dash_editable(&conn, &au, did) {
        return StatusCode::FORBIDDEN;
    }
    // SQL BRUT = ADMIN — is_soql EFFECTIF après PATCH (corps si fourni, sinon base), miroir exact
    // de rule_update : un editor ne peut NI basculer un panneau en SQL brut, NI éditer un panneau déjà en SQL
    // brut. Le SQL brut (is_soql=false) = lecture arbitraire de toute la base -> RÉSERVÉ ADMIN. Le SOQL reste
    // ouvert. Fail-closed via raw_sql_allowed.
    let eff_soql = b.get("is_soql").and_then(|v| v.as_bool()).unwrap_or(cur_soql);
    if !raw_sql_allowed(eff_soql, &au.role) {
        return StatusCode::FORBIDDEN;
    }
    if let Some(viz) = b.get("viz").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE panel SET viz=?1 WHERE id=?2", params![viz, id]);
    }
    if let Some(title) = b.get("title").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE panel SET title=?1 WHERE id=?2", params![title, id]);
    }
    if let Some(v) = b.get("query").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE panel SET query=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("is_soql").and_then(|v| v.as_bool()) {
        let _ = conn.execute("UPDATE panel SET is_soql=?1 WHERE id=?2", params![v as i64, id]);
    }
    if let Some(v) = b.get("window_s").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE panel SET window_s=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
        let vv = if v == "private" { "private" } else { "shared" };
        let _ = conn.execute("UPDATE panel SET visibility=?1 WHERE id=?2", params![vv, id]);
    }
    if let Some(v) = b.get("query_private").and_then(|v| v.as_bool()) {
        let _ = conn.execute("UPDATE panel SET query_private=?1 WHERE id=?2", params![v as i64, id]);
    }
    if let Some(v) = b.get("cols").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE panel SET cols=?1 WHERE id=?2", params![v.clamp(1, 4), id]);
    }
    if let Some(v) = b.get("height").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE panel SET height=?1 WHERE id=?2", params![v.max(0), id]);
    }
    if let Some(v) = b.get("drill").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE panel SET drill=?1 WHERE id=?2", params![v, id]);
    }
    if let Some(v) = b.get("position").and_then(|v| v.as_i64()) {
        let _ = conn.execute("UPDATE panel SET position=?1 WHERE id=?2", params![v, id]);
    }
    // LIBRARY PANELS (#54) : (dé)référencer une définition réutilisable. 0/null -> panneau autonome (détache).
    if let Some(vv) = b.get("library_panel_id") {
        if vv.is_null() || vv.as_i64() == Some(0) {
            let _ = conn.execute("UPDATE panel SET library_panel_id=NULL WHERE id=?1", params![id]);
        } else if let Some(n) = vv.as_i64() {
            let _ = conn.execute("UPDATE panel SET library_panel_id=?1 WHERE id=?2", params![n, id]);
        }
    }
    // INVALIDATION : invalide le cache du panneau à chaque update. On purge sans condition (le coût est nul :
    // 1 ligne max) -> aucun payload périmé servi après changement de requête/viz/fenêtre/visibilité. La
    // garde query_fp (v36) couvre déjà le cas requête, ceci couvre aussi viz/window/visibilité d'un coup.
    let _ = conn.execute("DELETE FROM panel_cache WHERE panel_id=?1", params![id]);
    StatusCode::NO_CONTENT
}

pub(crate) async fn panel_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.query_row("SELECT dashboard_id FROM panel WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(d) if dash_editable(&conn, &au, d) => {}
        Ok(_) => return StatusCode::FORBIDDEN,
        Err(_) => return StatusCode::NOT_FOUND,
    }
    let _ = conn.execute("DELETE FROM panel WHERE id=?1", params![id]);
    // INVALIDATION : purge le cache du panneau supprimé -> un futur panneau réutilisant ce rowid (panel_id)
    // ne servira jamais le payload de l'ancien (fuite inter-owners/visibilités). La garde query_fp (v36)
    // est une 2e barrière, mais on supprime explicitement la ligne ici.
    let _ = conn.execute("DELETE FROM panel_cache WHERE panel_id=?1", params![id]);
    StatusCode::NO_CONTENT
}

// Exécute la requête d'un panneau CÔTÉ SERVEUR (read-only) -> permet la requête « privée »
// (le client n'a jamais le texte) et l'accès en lecture aux rôles sans droit de requête libre.
/// Granularité du bucket de rollup (s) : les bornes de la clé de cache sont quantifiées dessus.
pub(crate) const CACHE_BUCKET_S: i64 = 3600;
/// Nombre max de plages (range_key) cachées PAR panneau : le cache est désormais
/// multi-emplacement (PK composite panel_id+range_key) ; ce cap évince les plus vieilles plages
/// (par computed_at) après chaque insert -> anti-explosion si un user zoome sur N plages distinctes.
pub(crate) const CACHE_MAX_RANGES_PER_PANEL: i64 = 8;
/// Clé de fenêtre du cache. PROBLÈME corrigé : la PWA n'envoie JAMAIS from=0/to=0 ; pour la
/// fenêtre par défaut (24 h glissantes) elle envoie `from = now-86400` (timestamp GLISSANT) et `to = 0`
/// (= maintenant). Cléer sur ces timestamps bruts -> la clé bouge à chaque seconde -> cache toujours MISS.
/// FIX : on clé sur la DURÉE de fenêtre (quantifiée au bucket), pas sur des bornes glissantes :
///   - to==0 (fenêtre « jusqu'à maintenant ») -> dur = now - from, clé = « w=<dur quantifiée> ».
///     Tous les refresh dans la même fenêtre par défaut produisent la MÊME clé -> HIT (jusqu'au TTL).
///   - bornes absolues (zoom/range custom) -> on quantifie from/to au bucket -> clé « a=<f>-<t> » stable
///     d'un refresh à l'autre tant qu'on reste dans le même bucket.
/// `now_s` = horloge courante (passée pour testabilité). Taille du cache bornée par panneau via le cap
/// CACHE_MAX_RANGES_PER_PANEL (éviction des plus vieilles plages, cf. panel_data).
pub(crate) fn cache_range_key(from: i64, to: i64, now_s: i64) -> String {
    let q = |t: i64| (t / CACHE_BUCKET_S) * CACHE_BUCKET_S; // quantifie au bucket
    if to == 0 {
        // fenêtre « jusqu'à maintenant » : on clé sur la DURÉE (glissante mais stable), quantifiée.
        let dur = (now_s - from).max(0);
        let qd = ((dur + CACHE_BUCKET_S / 2) / CACHE_BUCKET_S).max(0) * CACHE_BUCKET_S; // arrondi au bucket
        format!("w={qd}")
    } else {
        format!("a={}-{}", q(from), q(to))
    }
}

/// FILTRE ENVIRONNEMENT (#2d) : préfixe la clé de plage du cache panneau par l'environnement demandé ->
/// une même fenêtre servie pour env=staging n'écrase JAMAIS le payload env=prod (cache SÉPARÉ par env).
/// None (mode 0 / __all__) -> clé INCHANGÉE (byte-identique à cache_range_key) -> comportement identique.
pub(crate) fn env_range_key(env: Option<&str>, base: &str) -> String {
    match env.filter(|e| !e.is_empty()) {
        Some(e) => format!("e={e}|{base}"),
        None => base.to_string(),
    }
}

/// Empreinte (fingerprint) de la requête d'un panneau : sha256(is_soql|query). Stockée avec le payload
/// caché -> on ne sert le cache QUE si la requête courante a la MÊME empreinte (un
/// panel_update qui change la requête/viz, ou un rowid panel réutilisé après delete, n'expose jamais le
/// payload périmé/étranger). Court (12 hex) : la collision n'a aucune conséquence de sécurité (le
/// payload reste celui d'une requête identique), juste un anti-fuite défensif.
pub(crate) fn query_fingerprint(query: &str, is_soql: bool) -> String {
    sha256_hex(format!("{}|{}", is_soql as u8, query.trim()).as_bytes())[..12].to_string()
}

/// Réglages de SERVICE des panneaux, lus en UN SEUL accès disque (load_config) HORS du lock writer
/// (load_config() fait un accès DISQUE -> jamais appelé en tenant le Mutex sur le chemin chaud).
/// Renvoie :
///   - `ttl_global` : TTL global du cache (PLUME_PANEL_CACHE_TTL, défaut 60s ; 0 = cache désactivé) ;
///   - `live_ms` : seuil de CLASSIFICATION ADAPTATIVE (PHASE 3d, PLUME_PANEL_LIVE_MS, défaut 100). Un
///     panneau dont le coût mesuré (stats.elapsed_ms) est < seuil est servi LIVE (frais) ; >= seuil -> SWR.
/// À calculer avant de prendre le lock, puis passer à panel_cache_ttl().
pub(crate) fn panel_serve_cfg() -> (i64, i64) {
    let conf = load_config();
    let ttl_global = cfg(&conf, "PLUME_PANEL_CACHE_TTL", "60").parse().unwrap_or(60);
    let live_ms = cfg(&conf, "PLUME_PANEL_LIVE_MS", "100").parse().unwrap_or(100);
    (ttl_global, live_ms)
}

/// PHASE 3d — coût mesuré (stats.elapsed_ms) de la requête d'un panneau. Clé = panel_id (1 ligne/panneau)
/// LIÉ au query_fp courant -> la classe vaut GLOBALEMENT (panel_data est appelé par panel_id), où que le
/// panneau soit rendu (n'importe quel dashboard/vue), PAS par vue. Renvoie None si aucun coût pour ce
/// couple (panneau NOUVEAU ou requête modifiée) -> l'appelant exécute en LIVE (mesuré) et se classe seul.
/// Le filtre query_fp empêche de réutiliser le coût d'une ANCIENNE requête après un panel_update (anti-fuite,
/// cohérent avec panel_cache.query_fp).
pub(crate) fn read_panel_cost(conn: &Connection, panel_id: i64, q_fp: &str) -> Option<f64> {
    conn.query_row(
        "SELECT cost_ms FROM panel_cost WHERE panel_id=?1 AND query_fp=?2",
        params![panel_id, q_fp],
        |r| r.get::<_, f64>(0),
    )
    .ok()
}

/// PHASE 3d — mémorise le coût mesuré d'un panneau (INSERT OR REPLACE -> 1 seule ligne/panneau). Appelé
/// après CHAQUE exécution (LIVE à la demande ET refresh de fond) -> AUTO-RECLASSEMENT : un panneau cheap
/// qui ralentit (coût >= seuil) bascule SWR au prochain accès, et inversement s'il redevient rapide. Stocke
/// le query_fp courant (le coût ne vaut que pour CETTE requête ; un panel_update le rend « inconnu »).
pub(crate) fn record_panel_cost(conn: &Connection, panel_id: i64, q_fp: &str, cost_ms: f64, now_s: i64) {
    let _ = conn.execute(
        "INSERT OR REPLACE INTO panel_cost(panel_id,query_fp,cost_ms,measured_at) VALUES(?1,?2,?3,?4)",
        params![panel_id, q_fp, cost_ms, now_s],
    );
}

/// Extrait le coût SQL mesuré (stats.elapsed_ms) d'un résultat run_query, s'il est présent.
pub(crate) fn measured_cost_ms(v: &Value) -> Option<f64> {
    v.get("stats").and_then(|s| s.get("elapsed_ms")).and_then(|e| e.as_f64())
}

/// TTL effectif du cache d'un panneau : panel.panel_cache_ttl_s (si défini) sinon `ttl_global` (déjà lu
/// hors lock). 0 (global ou par panneau) = cache désactivé pour ce panneau. NE lit PLUS la config disque
/// `ttl_global` est fourni par l'appelant (lu avant de prendre le lock).
pub(crate) fn panel_cache_ttl(conn: &Connection, panel_id: i64, ttl_global: i64) -> i64 {
    let per: Option<i64> = conn
        .query_row("SELECT panel_cache_ttl_s FROM panel WHERE id=?1", params![panel_id], |r| r.get::<_, Option<i64>>(0))
        .ok()
        .flatten();
    per.unwrap_or(ttl_global)
}

// =====================================================================================
// DEBRUITAGE « self / opérateur » des vues ORIENTÉES MENACE EXTERNE (configurable, cache boot).
//
// PROBLÈME : le navigateur de l'opérateur sur le dashboard SOC (le vhost de l'UI) peut générer un
// volume massif de challenges edge + de 4xx web = bruit pur.
// Ce trafic SELF/OPÉRATEUR remonte EN TÊTE des panneaux « attaquants / scan / recon » et
// SUR-DÉCLENCHE les règles (« attaquant actif non banni », CF scan/flood/recon…) alors que ce
// n'est PAS une menace. On l'EXCLUT donc des vues « externe/menace », et UNIQUEMENT de celles-là
// (jamais des vues où l'activité opérateur EST le signal voulu : audit kubectl/dataaccess,
// auth/sudo, validation purple-team).
//
// CONFIGURABLE (aucune IP en dur ; DÉFAUT VIDE = build générique, valeur réelle par déploiement) :
//   PLUME_OPERATOR_IPS (CSV) — IP/préfixes de l'opérateur. Défaut VIDE (à fournir par votre
//       déploiement, via un secret/variable d'env). Un item en NOTATION CIDR (« base/N ») ou suffixé « * » ->
//       match de PRÉFIXE (NOT LIKE 'préf%') ; sinon égalité exacte (!=). Un /32 IPv6
//       « 2001:db8::/32 » -> préfixe « 2001:db8: » (RFC 5737/3849 = exemples doc).
//   PLUME_SELF_HOSTS (CSV) — vhosts de l'UI SOC elle-même. Défaut VIDE (à fournir par votre
//       déploiement, ex. « plume.example.com »).
//
// MÉCANIQUE : placeholders `__OPERATOR_EXCL__` (par src_ip) et `__SELF_EXCL__` (par vhost),
// substitués comme `__FROM__` à la compilation (compile_panel_sql / rule_sql), dans la BONNE
// cible : clause SQL booléenne pour le SQL natif (is_soql=0, ex. `src_ip != '203.0.113.7' AND
// src_ip NOT LIKE '2001:db8:%'`) OU termes de recherche soql (is_soql=1, ex.
// `src_ip!=203.0.113.7 src_ip!=2001:db8:*`). Liste vide -> no-op (`1=1` en SQL
// natif, terme vide en soql) = exclusion entièrement désactivable.
// =====================================================================================
// DÉFAUTS VIDES (build générique, aucune donnée perso bakée). La VRAIE valeur est fournie PAR
// DÉPLOIEMENT : PLUME_OPERATOR_IPS et PLUME_SELF_HOSTS (secret / variable d'env de VOTRE
// déploiement, ex. « plume.example.com »). Défaut vide -> exclusion no-op (dashboard
// neuf non filtré) tant qu'aucune IP/vhost n'est configuré : sûr et générique pour un client neuf.
pub(crate) const PLUME_OPERATOR_IPS_DEFAULT: &str = "";
pub(crate) const PLUME_SELF_HOSTS_DEFAULT: &str = "";

/// (valeur_à_matcher, préfixe?) pour un item de liste d'exclusion. None si item vide.
pub(crate) fn parse_excl_item(raw: &str) -> Option<(String, bool)> {
    let item = raw.trim();
    if item.is_empty() {
        return None;
    }
    // suffixe '*' explicite -> préfixe
    if let Some(p) = item.strip_suffix('*') {
        let p = p.trim();
        return if p.is_empty() { None } else { Some((p.to_string(), true)) };
    }
    // notation CIDR « base/N » -> préfixe (égalité exacte si /32 IPv4 ou /128 IPv6).
    if let Some((base, masklen)) = item.split_once('/') {
        let base = base.trim();
        let n: u32 = masklen.trim().parse().unwrap_or(0);
        if base.contains(':') {
            // IPv6 : un /64 (le défaut) -> les hextets de poids fort + ':' (préfixe NOT LIKE).
            if n >= 128 {
                return Some((base.trim_end_matches(':').to_string(), false)); // hôte exact
            }
            return Some((format!("{}:", base.trim_end_matches(':')), true));
        }
        // IPv4 : préfixe par octets (N/8). /32 (ou plus) -> exact.
        let octets = (n / 8) as usize;
        if octets >= 4 {
            return Some((base.to_string(), false));
        }
        let pref: Vec<&str> = base.split('.').take(octets).collect();
        if pref.is_empty() {
            return Some((base.to_string(), false));
        }
        return Some((format!("{}.", pref.join(".")), true));
    }
    // sinon : égalité exacte
    Some((item.to_string(), false))
}

/// Clauses d'exclusion compilées (SQL natif + termes soql) pour `src_ip` (opérateur) et `vhost`
/// (self). Générées UNE fois depuis la conf, mises en cache au boot (lues sur le chemin chaud
/// sans load_config).
pub(crate) struct ExclClauses {
    pub(crate) op_sql: String,
    pub(crate) op_soql: String,
    pub(crate) self_sql: String,
    pub(crate) self_soql: String,
}
impl ExclClauses {
    /// (clause SQL native, termes soql) pour un champ donné et une liste CSV.
    pub(crate) fn build(field: &str, csv: &str) -> (String, String) {
        // champ réel (src_ip) vs champ JSON (vhost) : la clause SQL native doit json_extract un
        // champ hors-colonne pour rester valide même si elle est un jour utilisée en is_soql=0.
        let sql_field: String = if EVENT_COLS.contains(&field) {
            field.to_string()
        } else {
            format!("json_extract(fields,'$.{field}')")
        };
        let mut sqls: Vec<String> = Vec::new();
        let mut soqls: Vec<String> = Vec::new();
        for item in csv.split(',') {
            if let Some((val, is_prefix)) = parse_excl_item(item) {
                let esc = val.replace('\'', "''");
                if is_prefix {
                    sqls.push(format!("{sql_field} NOT LIKE '{esc}%'"));
                    soqls.push(format!("{field}!={val}*")); // soql `field!=val*` -> NOT LIKE
                } else {
                    sqls.push(format!("{sql_field} != '{esc}'"));
                    soqls.push(format!("{field}!={val}")); // soql `field!=val` -> <>
                }
            }
        }
        let sql = if sqls.is_empty() { "1=1".to_string() } else { sqls.join(" AND ") };
        (sql, soqls.join(" "))
    }
    pub(crate) fn from_config(conf: &HashMap<String, String>) -> Self {
        let (op_sql, op_soql) =
            Self::build("src_ip", &cfg(conf, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT));
        let (self_sql, self_soql) =
            Self::build("vhost", &cfg(conf, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT));
        ExclClauses { op_sql, op_soql, self_sql, self_soql }
    }
    /// Variante RÉSOLUE (chantier « whitelists → webui ») : la valeur d'AFFICHAGE opérateur/self peut être
    /// SURCHARGÉE par un `setting` éditable+audité (`excl_display_csv`). MÊME chaîne que `setting_days` : la
    /// BDD gagne, sinon repli sur l'env PLUME_* (défaut vide). BYTE-IDENTIQUE à `from_config` quand AUCUNE
    /// ligne `setting` n'existe (cas prod par défaut : la vraie valeur vient du Secret via l'env, pas d'override).
    /// GARANTIE display-only (§4) : le CSV résolu ici n'alimente QUE ces clauses de PANNEAUX (compile_panel_sql) ;
    /// il n'est JAMAIS lu par `protected_ip_matchers` (never-ban HOST) ni par `rule_sql` (détection).
    pub(crate) fn resolve(conn: &Connection, conf: &HashMap<String, String>) -> Self {
        let (op_sql, op_soql) = Self::build(
            "src_ip",
            &excl_display_csv(conn, conf, EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT),
        );
        let (self_sql, self_soql) = Self::build(
            "vhost",
            &excl_display_csv(conn, conf, EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT),
        );
        ExclClauses { op_sql, op_soql, self_sql, self_soql }
    }
}
/// Clés `setting` (scope='global') portant l'override d'AFFICHAGE éditable des exclusions opérateur/self.
/// DÉLIBÉRÉMENT DISTINCTES des env `PLUME_OPERATOR_IPS`/`PLUME_SELF_HOSTS` : ces env alimentent AUSSI la
/// denylist never-ban HOST (`protected_ip_matchers`) ; l'override webui ne doit JAMAIS piloter l'enforcement
/// (invariant sacré : surfacer ≠ piloter — piège §4). Un override ne touche donc QUE le débruitage des panneaux.
pub(crate) const EXCL_OP_SETTING: &str = "excl_operator_ips";
pub(crate) const EXCL_SELF_SETTING: &str = "excl_self_hosts";
/// Résout le CSV COURANT d'une exclusion d'AFFICHAGE : `setting` override (l'admin l'emporte, hot-reload)
/// sinon env PLUME_* (défaut vide). Repli byte-identique quand aucune ligne `setting` n'existe (ni table).
pub(crate) fn excl_display_csv(conn: &Connection, conf: &HashMap<String, String>, setting_key: &str, env_key: &str, default: &str) -> String {
    conn.query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![setting_key], |r| r.get::<_, String>(0))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| cfg(conf, env_key, default))
}
pub(crate) static EXCL_CLAUSES: std::sync::OnceLock<parking_lot::RwLock<ExclClauses>> = std::sync::OnceLock::new();
/// Cache process-global des clauses d'exclusion (RwLock : RAFRAÎCHISSABLE après une édition webui audité).
/// Initialisé au boot depuis conf+setting ; lazy (défauts env) sinon. Lu sur le chemin chaud (apply_excl_*).
pub(crate) fn excl_clauses_cell() -> &'static parking_lot::RwLock<ExclClauses> {
    EXCL_CLAUSES.get_or_init(|| parking_lot::RwLock::new(ExclClauses::from_config(&load_config())))
}
/// Recompile le cache d'exclusion depuis la BDD (`setting` override) + conf. Appelé AU BOOT et après chaque
/// édition audité de l'exclusion opérateur/self (hot-reload). JAMAIS sur le chemin chaud de requête.
pub(crate) fn excl_clauses_refresh(conn: &Connection, conf: &HashMap<String, String>) {
    let fresh = ExclClauses::resolve(conn, conf);
    { let mut w = excl_clauses_cell().write();
        *w = fresh;
    }
}
/// Substitue `__OPERATOR_EXCL__` / `__SELF_EXCL__` dans la cible adaptée (SQL natif vs termes
/// soql). Fast-path : aucun placeholder -> chaîne renvoyée telle quelle (quasi-totalité des
/// requêtes). Pas de load_config sur le chemin chaud (clauses lues via le cache RwLock).
pub(crate) fn apply_excl_placeholders(query: &str, is_soql: bool) -> String {
    if !query.contains("__OPERATOR_EXCL__") && !query.contains("__SELF_EXCL__") {
        return query.to_string();
    }
    let g = excl_clauses_cell().read();
    let (op, slf) = if is_soql {
        (g.op_soql.as_str(), g.self_soql.as_str())
    } else {
        (g.op_sql.as_str(), g.self_sql.as_str())
    };
    query.replace("__OPERATOR_EXCL__", op).replace("__SELF_EXCL__", slf)
}

/// Compile la requête d'un panneau en SQL exécutable : SOQL -> soql_to_sql, sinon substitution
/// __FROM__/__TO__ (Phase 3b — factorisé entre panel_data, le fallback live et cache_refresh_all_panels).
/// Substitue d'abord les placeholders d'exclusion self/opérateur (no-op si absents).
/// `env` (#2d) : filtre par environnement propagé au chemin SOQL des panneaux (rollup-route + compilo).
/// None (mode 0) -> aucun filtre -> SQL inchangé. NB : les panneaux is_soql=0 (SQL brut sur les rollups,
/// ex. seeds Vue d'ensemble) ne sont PAS auto-filtrés ici (SQL opaque) -> ils restent tous-env (les
/// rollups portent env_id v67, mais l'injection dans un SQL arbitraire exigerait un parseur : différé).
pub(crate) fn compile_panel_sql(query: &str, is_soql: bool, from: i64, to: i64, env: Option<&str>) -> Result<String, String> {
    let query = apply_excl_placeholders(query.trim(), is_soql);
    if is_soql {
        // Router les PANNEAUX vers le rollup comme /api/query : « … | stats count by source »
        // lit event_rollup (qq ms) au lieu de scanner event (timeout 5 s -> cache figé/périmé).
        // WATERMARK : `compile_panel_sql` est PUR (aucune Connection tenant) -> on passe `i64::MAX` = corps
        // rollup non borné par le watermark, comportement PANNEAU inchangé (les dashboards sont servis via
        // cache SWR = éventuellement-cohérents). Le fix anti sous-comptage (borne au watermark réel) s'applique
        // aux chemins interactifs AUTORITATIFS (/api/query, /api/datamodels) qui surfacent `approx:false`.
        if let Some(rr) = try_rollup_route(&query, from, to, env, i64::MAX) {
            return Ok(rr.sql);
        }
        soql_to_sql_x(&query, from, to, env)
    } else {
        Ok(query.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()))
    }
}

/// PHASE 3b — refresh ASYNCHRONE (SWR) d'un panneau. Déclenché par panel_data quand le cache est périmé
/// ou absent. Ne bloque JAMAIS le chemin requête :
///   - anti-stampede : un seul refresh EN VOL par clé (panel_id, range_key) via st.panel_refresh_inflight ;
///   - borné : `refresh_sem.try_acquire_owned()` (PAS await) — sémaphore SÉPARÉ du query_sem interactif
///     (CHANGEMENT 1) : un refresh NE VOLE JAMAIS de permis à /api/query ni /api/search. Si refresh_sem
///     est saturé, on abandonne ce refresh (le cache périmé reste servi) ;
///   - run_query en spawn_blocking, puis INSERT OR REPLACE panel_cache (même logique que le tick).
pub(crate) fn enqueue_panel_refresh(st: &AppState, au: &AuthUser, id: i64, range_key: String, q_fp: String, sql: String, ttl_global: i64) {
    let key = (id, range_key.clone());
    {
        // insertion atomique dans le set in-flight : si déjà présent, un refresh est en vol -> on sort.
        let mut g = st.panel_refresh_inflight.lock();
        if !g.insert(key.clone()) {
            return;
        }
    }
    let db = req_db(st, au);            // #2a-2b : cache/refresh du panneau sur la base du tenant COURANT
    let db_path = req_db_path(st, au);
    let refresh_sem = st.refresh_sem.clone(); // CHANGEMENT 1 : sémaphore refresh SÉPARÉ (jamais query_sem)
    let inflight = st.panel_refresh_inflight.clone();
    tokio::spawn(async move {
        // try_acquire_owned (PAS await) : si aucun permit libre, on renonce — le cache périmé reste servi.
        if let Ok(_permit) = refresh_sem.try_acquire_owned() {
            let now_s = now();
            if let Ok(Ok(v)) = tokio::task::spawn_blocking(move || run_query(&db_path, &sql)).await {
                let cost_ms = measured_cost_ms(&v); // PHASE 3d : mesure du refresh -> classe le panneau
                if let Ok(payload) = serde_json::to_string(&v) {
                    { let conn = db.lock();
                        // PHASE 3d : mémorise le coût (auto-reclassement) même si le cache est off ensuite.
                        if let Some(c) = cost_ms {
                            record_panel_cost(&conn, id, &q_fp, c, now_s);
                        }
                        if panel_cache_ttl(&conn, id, ttl_global) > 0 {
                            let _ = conn.execute(
                                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)",
                                params![id, range_key, q_fp, now_s, payload],
                            );
                            // cap anti-explosion : ne garde que les K plages les plus récentes (par computed_at).
                            let _ = conn.execute(
                                "DELETE FROM panel_cache WHERE panel_id=?1 AND range_key NOT IN \
                                 (SELECT range_key FROM panel_cache WHERE panel_id=?1 ORDER BY computed_at DESC LIMIT ?2)",
                                params![id, CACHE_MAX_RANGES_PER_PANEL],
                            );
                        }
                    }
                }
            }
        }
        // retrait du set in-flight (succès, abandon ou erreur) -> un futur refresh pourra repartir.
        { let mut g = inflight.lock();
            g.remove(&key);
        }
    });
}

/// PHASE 3d — sert un panneau en SWR (stale-while-revalidate), logique EXACTE de 3c : HIT cache (frais OU
/// périmé) -> service IMMÉDIAT + refresh ASYNC borné (refresh_sem, JAMAIS query_sem) si périmé ; MISS ->
/// enqueue refresh + JSON VALIDE « warming » non bloquant. Utilisé par (a) le chemin LOURD (coût >= seuil)
/// et (b) le FALLBACK du chemin CHEAP/LIVE quand la lane refresh_sem est saturée (jamais de blocage).
/// Pré-conditions (vérifiées par l'appelant) : cacheable && ttl>0.
pub(crate) fn serve_swr(
    st: &AppState, au: &AuthUser, id: i64, query: &str, is_soql: bool, from: i64, to: i64,
    range_key: &str, q_fp: &str, ttl: i64, ttl_global: i64, now_s: i64, env: Option<&str>,
) -> Response {
    let cached = {
        // lecture cache SANS prédicat de fraîcheur : on récupère payload + computed_at quel que soit l'âge.
        let __rc = req_db(st, au);
        let conn = __rc.lock();
        conn.query_row(
            "SELECT payload, computed_at FROM panel_cache WHERE panel_id=?1 AND range_key=?2 AND query_fp=?3",
            params![id, range_key, q_fp],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .ok()
    };
    match cached {
        Some((payload, computed_at)) => {
            // HIT (frais OU périmé) -> service IMMÉDIAT. Si périmé : refresh async (hors query_sem).
            let v = serde_json::from_str::<Value>(&payload)
                .unwrap_or_else(|_| json!({ "columns": [], "rows": [] }));
            if now_s - computed_at > ttl {
                if let Ok(sql) = compile_panel_sql(query, is_soql, from, to, env) {
                    enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), sql, ttl_global);
                }
            }
            Json(v).into_response()
        }
        None => {
            // MISS total (jamais réchauffé) -> refresh async + JSON VALIDE non bloquant « warming ».
            if let Ok(sql) = compile_panel_sql(query, is_soql, from, to, env) {
                enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), sql, ttl_global);
            }
            Json(json!({ "columns": [], "rows": [], "warming": true })).into_response()
        }
    }
}

pub(crate) async fn panel_data(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> Response {
    let from: i64 = q.get("from").and_then(|s| s.parse().ok()).unwrap_or(0);
    let to: i64 = q.get("to").and_then(|s| s.parse().ok()).unwrap_or(0);
    let info = {
        crate::req_conn!(st, au, conn);
        panel_access(&conn, &au, id)
    };
    let Some((query, is_soql, _window, _owns)) = info else {
        return forbidden("panneau inaccessible");
    };
    // PHASE 3d — CLASSIFICATION ADAPTATIVE PAR PANNEAU (par COÛT MESURÉ, PAS par vue). panel_data est appelé
    // par panel_id -> le coût stocké (clé panel_id+query_fp) classe le panneau GLOBALEMENT, où qu'il soit
    // rendu. INVARIANT 3c CONSERVÉ : ni le LIVE ni le refresh ne prennent JAMAIS un permit query_sem
    // (réservé à /api/query + /api/search) -> sem_wait interactif ~0.
    //   - LOURD (coût CONNU >= PLUME_PANEL_LIVE_MS) OU INCONNU (jamais mesuré) -> SWR (3c) : sert panel_cache
    //     + refresh async si périmé ; à froid (MISS) renvoie un payload `warming` non bloquant + mesure async.
    //     (FIX #5c : un panneau inconnu ne part PLUS en LIVE synchrone -> plus de time-out proxy à froid.)
    //   - CHEAP CONFIRMÉ (coût MESURÉ < seuil) -> LIVE : requête à la demande sur la lane refresh_sem
    //     (try_acquire borné, zéro attente) -> toujours frais (un indicateur mono-valeur bascule à l'instant) ;
    //     lane saturée -> fallback cache (SWR) -> ne BLOQUE JAMAIS. Mesure + mémorise le coût à CHAQUE
    //     exécution -> auto-reclassement (un cheap qui ralentit passe SWR, et inversement).
    // range_key est clé sur la DURÉE de fenêtre (cf. cache_range_key) ; q_fp lie au COUPLE (requête, is_soql).
    let now_s = now();
    // FILTRE ENVIRONNEMENT (#2d) : env demandé (None en mode 0) -> injecté dans le SQL (compile_panel_sql)
    // ET dans la clé de plage du cache (env_range_key) -> payloads par-env SÉPARÉS, jamais de collision.
    let env = au.env_filter();
    // FIELD FILTERS (#45) : le panel_cache est clé par (panel_id, range) SANS le rôle -> un blob mis en cache
    // NE PEUT PAS servir des vues différentes selon le rôle. Si l'appelant a des masques ACTIFS, on NE TOUCHE
    // donc PAS le cache (ni lecture ni écriture) : compilation masquée + exécution LIVE hors cache. VIDE
    // (mode 0 / admin sans règle) -> chemin cache/SWR historique STRICTEMENT INCHANGÉ (byte-identique).
    let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
    if !masks.is_empty() {
        return panel_data_masked_live(&st, &au, &query, is_soql, from, to, env, &masks).await;
    }
    let q_fp = query_fingerprint(&query, is_soql);
    let cacheable = to == 0 || (from > 0 && to > from); // fenêtre glissante OU plage absolue bornée
    let range_key = env_range_key(env, &cache_range_key(from, to, now_s));
    // HORS LOCK : lecture config (accès disque load_config) AVANT de prendre le lock writer (1 seul accès).
    let (ttl_global, live_threshold) = panel_serve_cfg();
    // TTL effectif + coût mesuré stocké (par panneau) — 1 prise de lock.
    let (ttl, cost) = {
        crate::req_conn!(st, au, conn);
        (panel_cache_ttl(&conn, id, ttl_global), read_panel_cost(&conn, id, &q_fp))
    };
    // LOURD = coût CONNU et >= seuil.
    let heavy = matches!(cost, Some(c) if c >= live_threshold as f64);
    // FIX #5c — coût INCONNU (jamais mesuré) : on NE PRÉSUME PLUS « cheap ». Un panneau jamais mesuré peut
    // être LOURD (source brute volumineuse) -> un LIVE SYNCHRONE à froid risque de dépasser le timeout du
    // proxy = corps vide « réponse vide ». On le sert donc en SWR/WARMING (renvoie {columns:[],rows:[],
    // warming:true} + mesure ASYNC) tant qu'il est cacheable : le coût mesuré au 1er refresh le CLASSE
    // ensuite (CHEAP confirmé -> LIVE instantané ; LOURD -> reste en SWR). Un panneau lourd à froid ne
    // time-out donc JAMAIS de façon synchrone. (Le front gère le flag `warming` + re-poll.)
    let unknown = cost.is_none();

    // ---- LOURD (connu) ou INCONNU (1re fois) : SWR (3c). Sert le cache + refresh async ; ne lance JAMAIS
    //      de live synchrone. ----
    if (heavy || unknown) && cacheable && ttl > 0 {
        return serve_swr(&st, &au, id, &query, is_soql, from, to, &range_key, &q_fp, ttl, ttl_global, now_s, env);
    }

    // ---- CHEAP / INCONNU (et le cas résiduel LOURD non-cacheable / cache off) : LIVE MESURÉ. ----
    // La requête tourne à la demande -> toujours frais. Lane refresh_sem UNIQUEMENT (jamais query_sem).
    // try_acquire_owned (borné, zéro attente) : si la lane est saturée, on NE BLOQUE PAS -> fallback cache.
    let sql = match compile_panel_sql(&query, is_soql, from, to, env) {
        Ok(s) => s,
        Err(e) => return bad_req(e),
    };
    match st.refresh_sem.clone().try_acquire_owned() {
        Ok(permit) => {
            let db_path = req_db_path(&st, &au);
            let res = tokio::task::spawn_blocking(move || run_query(&db_path, &sql)).await;
            drop(permit); // relâche la lane refresh dès la requête finie (avant l'écriture coût/cache)
            match res {
                Ok(Ok(v)) => {
                    // MESURE : coût SQL de CETTE exécution -> mémorisé par panneau (auto-reclassement).
                    let cost_ms = measured_cost_ms(&v);
                    {
                        crate::req_conn!(st, au, conn);
                        if let Some(c) = cost_ms {
                            record_panel_cost(&conn, id, &q_fp, c, now_s);
                        }
                        // peuple aussi panel_cache -> un futur fallback (lane saturée) sert du frais récent.
                        if cacheable && ttl > 0 {
                            if let Ok(payload) = serde_json::to_string(&v) {
                                let _ = conn.execute(
                                    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)",
                                    params![id, range_key, q_fp, now_s, payload],
                                );
                                let _ = conn.execute(
                                    "DELETE FROM panel_cache WHERE panel_id=?1 AND range_key NOT IN \
                                     (SELECT range_key FROM panel_cache WHERE panel_id=?1 ORDER BY computed_at DESC LIMIT ?2)",
                                    params![id, CACHE_MAX_RANGES_PER_PANEL],
                                );
                            }
                        }
                    }
                    Json(v).into_response()
                }
                Ok(Err(e)) => bad_req(e),
                Err(_) => server_err("exécution échouée"),
            }
        }
        Err(_) => {
            // lane refresh SATURÉE -> NE JAMAIS BLOQUER. Fallback cache (SWR) si dispo.
            if cacheable && ttl > 0 {
                serve_swr(&st, &au, id, &query, is_soql, from, to, &range_key, &q_fp, ttl, ttl_global, now_s, env)
            } else {
                // cache off ET lane saturée (rare) : dernier recours -> live SANS permit (jamais query_sem),
                // identique à l'ancien fallback 3c. Chemin dégradé exceptionnel (pas de mesure ici).
                let db_path = req_db_path(&st, &au);
                match tokio::task::spawn_blocking(move || run_query(&db_path, &sql)).await {
                    Ok(Ok(v)) => Json(v).into_response(),
                    Ok(Err(e)) => bad_req(e),
                    Err(_) => server_err("exécution échouée"),
                }
            }
        }
    }
}

/// FIELD FILTERS (#45) — chemin panneau pour un appelant AVEC masques actifs : HORS cache (le panel_cache est
/// rôle-agnostique). Panneaux SOQL -> compilation MASQUÉE (masque émis dans le SQL, avant agrégation ; rollup
/// désactivé car event_rollup porte src_ip/host en clair). Panneaux SQL BRUT (is_soql=0, opaques : impossible
/// d'injecter le masque) -> exécution puis MASQUAGE POST-REQUÊTE par nom de colonne (défense : caviarde une
/// colonne projetée directement, ex `SELECT src_ip …`). Toujours LIVE (jamais mis en cache) -> aucune fuite
/// inter-rôles via le cache partagé.
async fn panel_data_masked_live(
    st: &AppState, au: &AuthUser, query: &str, is_soql: bool, from: i64, to: i64, env: Option<&str>,
    masks: &guatx_core::soql::FieldMaskSet,
) -> Response {
    let q2 = apply_excl_placeholders(query.trim(), is_soql);
    let sql = if is_soql {
        // rollup-route DÉSACTIVÉ (masques actifs) -> compile masqué.
        match soql_to_sql_masked_x(&q2, from, to, env, masks) {
            Ok(s) => s,
            Err(e) => return bad_req(e),
        }
    } else {
        q2.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string())
    };
    let db_path = req_db_path(st, au);
    // Jamais query_sem (réservé /api/query + /api/search). refresh_sem si dispo, sinon exécution directe
    // (chemin masqué rare ; ne bloque pas les lanes interactives).
    let post_mask = !is_soql; // SOQL déjà masqué dans le SQL ; SQL brut -> masquage post-requête (idempotence).
    let dbp2 = db_path.clone();
    let run = tokio::task::spawn_blocking(move || run_query(&dbp2, &sql)).await;
    match run {
        Ok(Ok(mut v)) => {
            if post_mask {
                mask_query_result(&db_path, masks, &mut v);
            }
            Json(v).into_response()
        }
        Ok(Err(e)) => bad_req(e),
        Err(_) => server_err("exécution échouée"),
    }
}

// ---------- vues (ensembles de dashboards) ----------
pub(crate) async fn views_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = conn
        .prepare(
            "SELECT id,name,COALESCE(owner,''),visibility,
                    (SELECT COUNT(*) FROM dashboard d WHERE d.view_id=view.id)
             FROM view
             WHERE ?1='admin' OR visibility='shared' OR owner=?2
             ORDER BY id",
        )
        .unwrap();
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) bindée en `?1` de visibilité.
    let adm = if au.is_admin() { "admin" } else { "" };
    let rows = stmt
        .query_map(params![adm, au.name], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                "owner": r.get::<_, String>(2)?, "visibility": r.get::<_, String>(3)?,
                "dashboards": r.get::<_, i64>(4)?
            }))
        })
        .unwrap();
    Json(json!({ "views": rows.flatten().collect::<Vec<_>>(), "me": au.name, "role": au.role }))
}

pub(crate) async fn view_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Vue").to_string();
    let vis = if b.get("visibility").and_then(|v| v.as_str()) == Some("shared") { "shared" } else { "private" };
    crate::req_conn!(st, au, conn);
    let _ = conn.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![name, au.name, vis]);
    Json(json!({ "id": conn.last_insert_rowid() }))
}

pub(crate) async fn view_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.query_row("SELECT COALESCE(owner,'') FROM view WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(owner) => {
            if !au.is_admin() && !owner.is_empty() && owner != au.name {
                return StatusCode::FORBIDDEN;
            }
        }
        Err(_) => return StatusCode::NOT_FOUND,
    }
    let _ = conn.execute("UPDATE dashboard SET view_id=NULL WHERE view_id=?1", params![id]); // on délie, on ne supprime pas les dashboards
    let _ = conn.execute("DELETE FROM view WHERE id=?1", params![id]);
    StatusCode::NO_CONTENT
}

pub(crate) async fn view_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    match conn.query_row("SELECT COALESCE(owner,'') FROM view WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
        Ok(owner) => {
            if !au.is_admin() && !owner.is_empty() && owner != au.name {
                return StatusCode::FORBIDDEN;
            }
        }
        Err(_) => return StatusCode::NOT_FOUND,
    }
    if let Some(name) = b.get("name").and_then(|v| v.as_str()) {
        let _ = conn.execute("UPDATE view SET name=?1 WHERE id=?2", params![name, id]);
    }
    if let Some(vis) = b.get("visibility").and_then(|v| v.as_str()) {
        let vis = if vis == "shared" { "shared" } else { "private" };
        let _ = conn.execute("UPDATE view SET visibility=?1 WHERE id=?2", params![vis, id]);
    }
    StatusCode::NO_CONTENT
}
