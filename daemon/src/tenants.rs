//! Cycle de vie des tenants (onboarding/destruction) & handlers HTTP de gestion : génération de clé
//! (`tenant_generate_key`), provisionnement/destruction (`tenant_provision`/`tenant_destroy`/
//! `seed_tenant_content`) et les routes `my_tenants`/`tenants_list`/`tenant_create`/`tenant_suspend`/
//! `tenant_unsuspend`/`tenant_set_suspended`/`tenant_delete` + grants (`grants_list`/`grant_set`/
//! `grant_delete`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Nombre d'octets d'une clé SQLCipher de tenant (-> 2x en hex). 256 bits, la taille attendue par
/// `PRAGMA key` sous forme hexadécimale.
pub(crate) const TENANT_KEY_BYTES: usize = 32;

/// Clé SQLCipher d'un tenant : 256 bits tirés du CSPRNG de l'OS via le PRODUCTEUR UNIQUE `os_entropy`
/// (`/dev/urandom`, puis `getrandom(2)` sans descripteur de fichier) -> hex 64 chars. `None` si l'hôte
/// n'offre AUCUNE source d'entropie : l'appelant REFUSE de créer le tenant.
///
/// MÊME DOCTRINE QUE LE SECRET D'INSTALLATION, et pour la même raison. Le « filet anti-panique » qui
/// vivait ici hachait `now() | pid | adresse de pile | SystemTime::now()` : qui connaît la minute de
/// création d'un tenant énumère l'espace restant, et cette clé chiffre TOUTE la base du tenant, pour
/// toute la durée de rétention de la donnée. Un avertissement au journal ne referme pas cela — il se
/// lit une fois, la clé reste faible aussi longtemps que la donnée vit.
///
/// CE QUE LE REPLI COUVRAIT est SERVI, pas perdu : le cas réel visé (`/dev` non monté — chroot,
/// conteneur minimal) est exactement celui que la SECONDE source d'`os_entropy` traite, `getrandom(2)`
/// n'ayant besoin d'aucun descripteur. Les trois modes de déploiement revendiqués (systemd hôte-natif,
/// Docker, k3s) sont Linux, où cet appel existe depuis 3.17. Reste le noyau SANS CSPRNG : il n'y a pas
/// de bonne réponse à ce cas, et surtout pas une clé fabriquée à partir d'une horloge.
#[allow(dead_code)]
pub(crate) fn tenant_generate_key() -> Option<String> {
    tenant_key_from_entropy(os_entropy::<TENANT_KEY_BYTES>())
}

/// Formate la clé de tenant À PARTIR DE la matière aléatoire fournie — la clé EST cette matière, rien
/// d'autre. `None` en entrée -> `None` en sortie : il n'existe AUCUNE troisième voie, donc aucun repli
/// dérivé d'une horloge, d'un pid ou d'un compteur. Cœur PUR : c'est lui qui rend la mutation
/// « entropie indisponible » mesurable sans démonter l'hôte.
pub(crate) fn tenant_key_from_entropy(raw: Option<[u8; TENANT_KEY_BYTES]>) -> Option<String> {
    raw.map(|b| hex_encode(&b))
}

/// ONBOARDING : crée l'entrée control-plane `tenant` (id, name, key_ref, db_path) PUIS la base tenant vide
/// CHIFFRÉE avec SA clé (schéma + migrations + seed minimal). FAIL-CLOSED : si `key_ref` ne résout pas
/// (ex. vault: injoignable), RIEN n'est créé. Enregistre la clé (registre read-pool) -> frontière crypto
/// immédiatement effective. La clé n'apparaît JAMAIS dans un message d'erreur/log.
#[allow(dead_code)]
pub(crate) fn tenant_provision(mgr: &TenantDbManager, id: &str, name: &str, db_path: &str, key_ref: &str) -> Result<(), String> {
    let cp = mgr.control.as_ref().ok_or("multi-tenant désactivé (mode 0) : provisioning indisponible")?;
    if !tenant_slug_ok(id) {
        return Err("slug tenant invalide (alphanumérique + '_'/'-', ≤ 64)".into());
    }
    // 1) Résout la clé AVANT toute création (fail-closed : jamais de tenant à moitié provisionné).
    let key = resolve_tenant_key(key_ref).map_err(|e| format!("key_ref non résoluble : {e}"))?;
    // 2) Entrée catalogue — refuse d'écraser un tenant existant (pas de perte silencieuse).
    {
        let conn = cp.conn.lock();
        let exists = conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(())).is_ok();
        if exists {
            return Err(format!("tenant '{id}' existe déjà"));
        }
        conn.execute(
            "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,?3,?4,?5,0)",
            params![id, name, key_ref, db_path, now()],
        ).map_err(|e| format!("insert tenant : {e}"))?;
    }
    // 3) Base tenant vide CHIFFRÉE avec SA clé (le FICHIER est le tenant). Parent créé au besoin.
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // FAIL-CLOSED (même doctrine que la résolution de clé en 1) : la PORTE applique la garde
    // anti-downgrade puis `prepare_schema` (schéma, migrations, présence des objets ET des colonnes).
    // On REFUSE de déclarer le tenant prêt plutôt que de le seeder sur un schéma qui n'est pas celui
    // attendu. Les PRAGMA de la base tenant sont posés dans le prélude, donc AVANT le contrat (ordre
    // historique préservé : ils précédaient déjà `prepare_schema`).
    let conn = PreparedDb::open_keyed_with_prelude(db_path, key.as_deref(), |c| {
        let _ = c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
    })
    .map_err(|e| match e {
        DbOpenError::Ouverture(e) => format!("création base tenant : {e}"),
        autre => format!("base tenant : {autre} — tenant NON provisionné"),
    })?;
    // D7 (#2c) : contenu de détection COMPLET par tenant (dashboards + règles + playbooks builtin) — une
    // base tenant neuve démarre exactement comme une install fraîche (cf. run()). Les seeds conf/déploiement
    // (overlays config.d, notifier d'env, données de démo) sont DÉLIBÉRÉMENT exclus (spécifiques au site).
    seed_tenant_content(&conn);
    // 4) Enregistre la clé du tenant pour le read-pool (frontière crypto effective sans attendre un resolve).
    register_db_key(db_path, key);
    Ok(())
}

/// DESTRUCTION CRYPTO (RGPD) : OUBLIE la clé (supprime l'entrée control-plane `tenant` + ses grants/tokens
/// + purge les caches de clé) et SUPPRIME le fichier chiffré (+ WAL/SHM). Après cela, la donnée est
/// cryptographiquement irrécupérable. Évince aussi le writer mémoïsé. Le tenant `default` est protégé.
#[allow(dead_code)]
pub(crate) fn tenant_destroy(mgr: &TenantDbManager, id: &str) -> Result<(), String> {
    let cp = mgr.control.as_ref().ok_or("multi-tenant désactivé (mode 0) : destruction indisponible")?;
    if id == "default" {
        return Err("refus : le tenant 'default' ne peut pas être détruit".into());
    }
    let (db_path, key_ref) = {
        let conn = cp.conn.lock();
        let row = conn.query_row(
            "SELECT db_path, key_ref FROM tenant WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ).ok();
        let (p, kr) = row.ok_or_else(|| format!("tenant '{id}' inconnu"))?;
        // Oublie la clé + les identités liées (le key_ref disparaît -> plus aucune référence à la clé).
        let _ = conn.execute("DELETE FROM token WHERE tenant_id=?1", params![id]);
        let _ = conn.execute("DELETE FROM \"grant\" WHERE tenant_id=?1", params![id]);
        let _ = conn.execute("DELETE FROM tenant WHERE id=?1", params![id]);
        (p, kr)
    };
    // Évince le writer chaud + purge les caches de clé (registre read-pool + cache Vault).
    mgr.writers.lock().remove(id);
    unregister_db_key(&db_path);
    if let Some(vp) = key_ref.strip_prefix("vault:") {
        vault_key_cache_forget(vp);
    }
    // Supprime le fichier chiffré + journaux (destruction crypto : sans la clé, le contenu est illisible).
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(format!("{db_path}-wal"));
    let _ = std::fs::remove_file(format!("{db_path}-shm"));
    Ok(())
}

/// D7 (#2c) — SEED COMPLET du contenu de détection d'une base tenant NEUVE : dashboards + règles + playbooks
/// builtin, DANS LE MÊME ORDRE que run() sur une install fraîche. N'inclut PAS les seeds spécifiques au
/// déploiement/site (overlays config.d, notifier d'environnement, données de démo `seed_demo`) : ceux-ci
/// dépendent de la conf de l'hôte et n'ont pas de sens « par défaut » pour un tenant client. Idempotent
/// (chaque seed est gardé par son flag `meta.seeded_*`), donc sûr à ré-exécuter.
pub(crate) fn seed_tenant_content(conn: &Connection) {
    seed_default_dashboard(conn);
    seed_example_rules(conn);
    seed_purple_rules(conn);
    seed_detection_rules(conn);
    seed_runbooks(conn);   // #3 incidents Phase 1 : runbooks managés keyés MITRE (flag dédié `seeded_runbooks`)
    seed_ti_alert_rules(conn);   // #23 activation : alerte match IOC (managé, inerte sans IOC)
    seed_risk_rules(conn);       // #24 activation : règles RBA mode risque (managé)
    seed_example_playbooks(conn);
    seed_ssh_cve_playbook(conn);
    seed_k8s_rules(conn);
    seed_obs_dashboard(conn);
    seed_obs_rules(conn);
    seed_sts_rules(conn);
    seed_velero_rule(conn);
    seed_malware_rule(conn);
    seed_slab_rule(conn);
    seed_security_dashboard(conn);
    seed_egress_dashboard(conn);
    seed_web_dashboard(conn);
    seed_mail_dashboard(conn);
    seed_dataaccess_dashboard(conn);
    seed_dataacl_dashboard(conn);
    seed_sca_dashboard(conn);    // #57 : posture SCA/CIS (BYO-agent endpoint)
    seed_vuln_dashboard(conn);   // #57 : vulnérabilités CVE endpoint
    seed_kube_rbac_dashboard(conn);
    seed_minio_dashboard(conn);
    seed_vault_dashboard(conn);
    seed_rollup_dashboard(conn);
    ensure_rollup_srcip_host_panels(conn);
    seed_banpass_dashboard(conn);
    seed_egress_rules(conn);
}

/// GET /api/my-tenants — liste les tenants accessibles à l'utilisateur (pour le switcher UI). Tout user
/// authentifié (mode 1). Mode 0 : `[{id:"default", role:<rôle courant>}]` (inerte, aucun control-plane).
/// Super-admin : TOUS les tenants (rôle = son grant s'il en a un, sinon "operator" = accès cross-tenant) ;
/// sinon : ses grants matérialisés (table `grant`). Le tenant COURANT (au.tenant) est toujours présent.
pub(crate) async fn my_tenants(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    if !st.multi_tenant {
        return Json(json!([{ "id": "default", "role": au.role }]));
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!([{ "id": "default", "role": au.role }]));
    };
    let mut out: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    {
        let conn = cp.conn.lock();
        if au.is_superadmin {
            // Super-admin : tous les tenants (non-supprimés). Rôle = son grant si membre, sinon "operator".
            if let Ok(mut stmt) = conn.prepare(
                "SELECT t.id, t.name, t.suspended, COALESCE(g.role,'operator') \
                 FROM tenant t LEFT JOIN \"grant\" g ON g.tenant_id=t.id \
                   AND g.user_id=(SELECT id FROM platform_user WHERE name=?1) ORDER BY t.id",
            ) {
                if let Ok(rows) = stmt.query_map(params![au.name], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
                }) {
                    for (id, name, susp, role) in rows.flatten() {
                        seen.insert(id.clone());
                        out.push(json!({ "id": id, "name": name, "role": role, "suspended": susp != 0 }));
                    }
                }
            }
        } else if let Ok(mut stmt) = conn.prepare(
            "SELECT t.id, t.name, t.suspended, g.role FROM \"grant\" g JOIN tenant t ON t.id=g.tenant_id \
             WHERE g.user_id=(SELECT id FROM platform_user WHERE name=?1) ORDER BY t.id",
        ) {
            if let Ok(rows) = stmt.query_map(params![au.name], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
            }) {
                for (id, name, susp, role) in rows.flatten() {
                    seen.insert(id.clone());
                    out.push(json!({ "id": id, "name": name, "role": role, "suspended": susp != 0 }));
                }
            }
        }
    }
    // Le tenant COURANT est toujours listé (couvre les grants SSO-live non matérialisés dans `grant`).
    if !au.tenant.is_empty() && !seen.contains(&au.tenant) {
        out.push(json!({ "id": au.tenant, "role": au.role }));
    }
    Json(json!(out))
}

/// GET /api/tenants — liste TOUS les tenants (SUPER-ADMIN only, re-check serveur). Mode 0 : `{tenants:[]}`.
pub(crate) async fn tenants_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !st.multi_tenant {
        return Json(json!({ "tenants": [] })).into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!({ "tenants": [] })).into_response();
    };
    let conn = cp.conn.lock();
    let mut stmt = match conn.prepare(
        "SELECT t.id, t.name, t.suspended, t.created, t.db_path, \
                (SELECT COUNT(*) FROM \"grant\" g WHERE g.tenant_id=t.id) \
         FROM tenant t ORDER BY t.id",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("control-plane indisponible: {e}")).into_response(),
    };
    let tenants: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "suspended": r.get::<_, i64>(2)? != 0,
                "created": r.get::<_, Option<i64>>(3)?,
                "db_path": r.get::<_, String>(4)?,
                "nb_users": r.get::<_, i64>(5)?,
            }))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "tenants": tenants })).into_response()
}

/// POST /api/tenants — ONBOARDING d'un tenant (SUPER-ADMIN only). Body : {id, name, key_ref?, admin?}.
/// Génère une clé fraîche (`tenant_generate_key`, stockée `literal:` dans le control-plane chiffré) si aucun
/// `key_ref` explicite (ex. `vault:chemin` pré-approvisionné) n'est fourni. `tenant_provision` crée l'entrée
/// control-plane + la base chiffrée + seed COMPLET (D7). Refuse un slug invalide / `default` / existant.
/// Optionnellement pose le 1er grant admin. Audit : control_ledger `tenant.create` + event tenant.
pub(crate) async fn tenant_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if st.tenants.control.is_none() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    }
    let id = b.trimmed("id");
    let name = b.trimmed("name");
    if !tenant_slug_ok(&id) {
        return (StatusCode::BAD_REQUEST, "slug invalide (alphanumérique + '_'/'-', ≤ 64)").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' est réservé").into_response();
    }
    let name = if name.is_empty() { id.clone() } else { name };
    // key_ref explicite (ex. vault:...) sinon clé fraîche générée, stockée en literal: dans le control-plane
    // (lui-même chiffré at-rest par PLUME_CONTROL_KEY). tenant_provision est FAIL-CLOSED si key_ref ne résout pas.
    // Et la GÉNÉRATION l'est aussi : sans entropie de l'OS, AUCUN tenant n'est créé — plutôt aucun tenant
    // qu'un tenant dont la base entière est chiffrée par une clé énumérable. L'exploitant garde la voie
    // explicite (`key_ref` pré-approvisionné : `env:`, `literal:`, `vault:`), qui ne dépend pas de l'entropie locale.
    let key_ref = match b.get("key_ref").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(explicite) => explicite,
        None => match tenant_generate_key() {
            Some(k) => format!("literal:{k}"),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "aucune source d'entropie (ni /dev/urandom ni getrandom) : tenant NON créé. Aucune clé \
                     dérivée d'une horloge ou d'un pid n'est émise. Répare l'entropie de l'hôte, ou fournis \
                     un `key_ref` pré-approvisionné.",
                )
                    .into_response()
            }
        },
    };
    let db_path = tenant_db_path(&st, &id);
    // Provisioning HORS de l'exécuteur async (schéma + seeds = plusieurs ms). TenantDbManager est Clone (Arc).
    let mgr = st.tenants.clone();
    let (pid, pname, pdb, pkey) = (id.clone(), name.clone(), db_path.clone(), key_ref.clone());
    let provision = tokio::task::spawn_blocking(move || tenant_provision(&mgr, &pid, &pname, &pdb, &pkey))
        .await
        .unwrap_or_else(|e| Err(format!("tâche de provisioning interrompue: {e}")));
    if let Err(e) = provision {
        // "existe déjà" -> 409 ; sinon échec de provisioning (clé/FS) -> 400 (fail-closed, rien créé).
        let code = if e.contains("existe déjà") { StatusCode::CONFLICT } else { StatusCode::BAD_REQUEST };
        return (code, e).into_response();
    }
    // 1er grant admin OPTIONNEL : matérialise le platform_user + grant admin sur le nouveau tenant.
    let mut first_admin: Option<String> = None;
    if let Some(admin) = b.get("admin").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if platform_user_name_ok(admin) {
            if let Some(cp) = st.tenants.control.as_ref() {
                if let Some(uid) = ensure_platform_user(cp, admin) {
                    let conn = cp.conn.lock();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')",
                        params![uid, id],
                    );
                    first_admin = Some(admin.to_string());
                }
            }
        }
    }
    control_ledger_append(
        &st,
        "tenant.create",
        &au.name,
        &id,
        &json!({ "name": name, "db_path": db_path, "first_admin": first_admin }).to_string(),
    );
    audit_tenant_event(
        &st,
        &id,
        "tenant.create",
        2,
        &format!("tenant '{id}' provisionné par l'opérateur plateforme '{}'", au.name),
        json!({ "operator": au.name, "name": name, "first_admin": first_admin }),
    );
    (StatusCode::CREATED, Json(json!({ "ok": true, "id": id, "name": name, "first_admin": first_admin }))).into_response()
}

/// POST /api/tenants/:id/suspend | /unsuspend — bascule le flag `suspended` (SUPER-ADMIN only). Un tenant
/// suspendu = plus d'accès (guard fail-closed) + jobs de fond SKIP. `default` protégé. Audit.
pub(crate) async fn tenant_suspend(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    tenant_set_suspended(&st, &au, &id, true).await
}

pub(crate) async fn tenant_unsuspend(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    tenant_set_suspended(&st, &au, &id, false).await
}

pub(crate) async fn tenant_set_suspended(st: &AppState, au: &AuthUser, id: &str, suspend: bool) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' ne peut pas être suspendu").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    // Existence + audit AVANT de basculer (à la suspension, la base doit encore être résoluble pour l'event).
    let exists = {
        let conn = cp.conn.lock();
        conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(())).is_ok()
    };
    if !exists {
        return (StatusCode::NOT_FOUND, "tenant inconnu").into_response();
    }
    let (kind, sev, verb) = if suspend {
        ("tenant.suspend", 3, "suspendu")
    } else {
        ("tenant.unsuspend", 2, "réactivé")
    };
    if suspend {
        // event tant que la base est encore active (après flip, handle_for pourra ne plus résoudre).
        audit_tenant_event(st, id, kind, sev, &format!("tenant '{id}' {verb} par '{}'", au.name), json!({ "operator": au.name }));
    }
    {
        let conn = cp.conn.lock();
        let _ = conn.execute("UPDATE tenant SET suspended=?1 WHERE id=?2", params![i64::from(suspend), id]);
    }
    if !suspend {
        // event APRÈS réactivation (la base redevient résoluble).
        audit_tenant_event(st, id, kind, sev, &format!("tenant '{id}' {verb} par '{}'", au.name), json!({ "operator": au.name }));
    }
    control_ledger_append(st, kind, &au.name, id, &json!({ "operator": au.name }).to_string());
    Json(json!({ "ok": true, "id": id, "suspended": suspend })).into_response()
}

/// DELETE /api/tenants/:id — DESTRUCTION CRYPTO (SUPER-ADMIN only, DESTRUCTIF). Exige une confirmation forte
/// (body {confirm:<name>} == nom du tenant). `default` INTERDIT (protégé aussi par tenant_destroy). Audit
/// control_ledger `tenant.destroy` (niveau break-glass). La base tenant disparaissant, pas d'event tenant.
pub(crate) async fn tenant_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !au.is_superadmin {
        return (StatusCode::FORBIDDEN, "réservé au super-admin plateforme").into_response();
    }
    if id == "default" {
        return (StatusCode::BAD_REQUEST, "le tenant 'default' ne peut pas être détruit").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    let name: Option<String> = {
        let conn = cp.conn.lock();
        conn.query_row("SELECT name FROM tenant WHERE id=?1", params![id], |r| r.get::<_, String>(0)).ok()
    };
    let Some(name) = name else {
        return (StatusCode::NOT_FOUND, "tenant inconnu").into_response();
    };
    // CONFIRMATION FORTE : body {confirm} DOIT égaler EXACTEMENT le nom du tenant (anti-suppression accidentelle).
    let confirm = b.str_field("confirm");
    if confirm != name {
        return (StatusCode::BAD_REQUEST, "confirmation invalide : `confirm` doit égaler EXACTEMENT le nom du tenant").into_response();
    }
    // Audit AVANT destruction (la base + son ledger disparaissent) — niveau break-glass (opération destructive).
    control_ledger_append(
        &st,
        "tenant.destroy",
        &au.name,
        &id,
        &json!({ "operator": au.name, "name": name, "level": "break-glass", "destructive": true }).to_string(),
    );
    let mgr = st.tenants.clone();
    let tid = id.clone();
    let destroy = tokio::task::spawn_blocking(move || tenant_destroy(&mgr, &tid))
        .await
        .unwrap_or_else(|e| Err(format!("tâche de destruction interrompue: {e}")));
    match destroy {
        Ok(()) => Json(json!({ "ok": true, "id": id, "destroyed": true })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// GET /api/tenants/:id/grants — liste (user -> role) du tenant. SUPER-ADMIN (tout tenant) OU admin de CE
/// tenant (re-check serveur `can_manage_grants`).
pub(crate) async fn grants_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    if !st.multi_tenant {
        return Json(json!({ "grants": [] })).into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return Json(json!({ "grants": [] })).into_response();
    };
    let conn = cp.conn.lock();
    let mut stmt = match conn.prepare(
        "SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id \
         WHERE g.tenant_id=?1 ORDER BY p.name",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("control-plane indisponible: {e}")).into_response(),
    };
    let grants: Vec<Value> = stmt
        .query_map(params![id], |r| Ok(json!({ "user": r.get::<_, String>(0)?, "role": r.get::<_, String>(1)? })))
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "tenant": id, "grants": grants })).into_response()
}

/// POST /api/tenants/:id/grants — pose/màj un grant {user, role}. SUPER-ADMIN (tout tenant) OU admin de CE
/// tenant. `role` ∈ {admin, editor, viewer} (enum FERMÉ -> aucune escalade superadmin). Anti-lockout : un
/// non-superadmin ne peut pas retirer/rétrograder le DERNIER admin du tenant. Audit control_ledger + event.
pub(crate) async fn grant_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    let user = b.trimmed("user");
    let role = b.trimmed("role");
    if !platform_user_name_ok(&user) {
        return (StatusCode::BAD_REQUEST, "nom d'utilisateur invalide (alphanumérique, . _ - uniquement)").into_response();
    }
    if !valid_grant_role(&role) {
        return (StatusCode::BAD_REQUEST, "rôle invalide (admin | editor | viewer)").into_response();
    }
    // Le tenant doit exister (jamais un grant sur un tenant fantôme).
    {
        let conn = cp.conn.lock();
        if conn.query_row("SELECT 1 FROM tenant WHERE id=?1", params![id], |_| Ok(())).is_err() {
            return (StatusCode::NOT_FOUND, "tenant inconnu").into_response();
        }
    }
    // ANTI-LOCKOUT (non-superadmin, #64 effective-base-aware) : rétrograder le dernier admin EFFECTIF vers un
    // rôle SANS autorité admin laisserait 0 admin. Le NOUVEAU rôle garde-t-il l'autorité admin ? -> pas une
    // rétrogradation (ré-assigner un rôle composable base=admin reste admin). L'ANCIEN grant est-il effective-admin
    // (littéral OU custom base=admin) ? Sinon rien à protéger.
    if !au.is_superadmin && effective_base_role(&role) != "admin" {
        let was_admin = {
            let conn = cp.conn.lock();
            conn.query_row(
                "SELECT g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id \
                 WHERE g.tenant_id=?1 AND p.name=?2",
                params![id, user],
                |r| r.get::<_, String>(0),
            )
            .map(|r| effective_base_role(&r) == "admin")
            .unwrap_or(false)
        };
        if was_admin && tenant_admin_grant_count(cp, &id) <= 1 {
            return (StatusCode::BAD_REQUEST, "dernier administrateur du tenant — rétrogradation refusée").into_response();
        }
    }
    let Some(uid) = ensure_platform_user(cp, &user) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "échec de matérialisation du compte plateforme").into_response();
    };
    {
        let conn = cp.conn.lock();
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)",
            params![uid, id, role],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("échec du grant: {e}")).into_response();
        }
    }
    control_ledger_append(&st, "grant.set", &au.name, &id, &json!({ "user": user, "role": role, "by": au.name }).to_string());
    audit_tenant_event(
        &st,
        &id,
        "grant.set",
        2,
        &format!("grant {role} accordé à '{user}' par '{}'", au.name),
        json!({ "user": user, "role": role, "by": au.name }),
    );
    Json(json!({ "ok": true, "tenant": id, "user": user, "role": role })).into_response()
}

/// DELETE /api/tenants/:id/grants/:user — retire un grant. SUPER-ADMIN (tout tenant) OU admin de CE tenant.
/// Anti-lockout : un non-superadmin ne peut pas retirer le DERNIER admin. Audit control_ledger + event.
pub(crate) async fn grant_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, user)): Path<(String, String)>) -> Response {
    if !st.multi_tenant {
        return (StatusCode::NOT_FOUND, "multi-tenant désactivé (mode 0)").into_response();
    }
    if !can_manage_grants(&au, &id) {
        return (StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant").into_response();
    }
    let Some(cp) = st.tenants.control.as_ref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "control-plane indisponible").into_response();
    };
    // Le grant existe-t-il, et est-ce le rôle admin ? (existence + anti-lockout).
    let existing_role: Option<String> = {
        let conn = cp.conn.lock();
        conn.query_row(
            "SELECT g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id \
             WHERE g.tenant_id=?1 AND p.name=?2",
            params![id, user],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    let Some(existing_role) = existing_role else {
        return (StatusCode::NOT_FOUND, "grant inconnu").into_response();
    };
    // #64 : autorité admin EFFECTIVE (littéral OU rôle composable base=admin) -> cohérent avec l'anti-lockout
    // de scim.rs/grant demote ; retirer le dernier `gov-admin` d'un tenant serait sinon un lockout DoS.
    if !au.is_superadmin && effective_base_role(&existing_role) == "admin" && tenant_admin_grant_count(cp, &id) <= 1 {
        return (StatusCode::BAD_REQUEST, "dernier administrateur du tenant — retrait refusé").into_response();
    }
    {
        let conn = cp.conn.lock();
        let _ = conn.execute(
            "DELETE FROM \"grant\" WHERE tenant_id=?1 AND user_id=(SELECT id FROM platform_user WHERE name=?2)",
            params![id, user],
        );
    }
    control_ledger_append(&st, "grant.remove", &au.name, &id, &json!({ "user": user, "by": au.name }).to_string());
    audit_tenant_event(
        &st,
        &id,
        "grant.remove",
        2,
        &format!("grant de '{user}' retiré par '{}'", au.name),
        json!({ "user": user, "by": au.name }),
    );
    StatusCode::NO_CONTENT.into_response()
}
