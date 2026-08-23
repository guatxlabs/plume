//! Câblage du serveur & amorçage : en-têtes de sécurité + HSTS (`security_headers`/`TLS_ON`), rate-limit
//! par IP/global (`rate_limit`), PRAGMA d'ouverture (`tune`), conversion panic->JSON (`panic_to_json_response`)
//! et surtout `run()` — construction du routeur Axum (middlewares + routes), boot (config/DB/control-plane/
//! TLS) et les boucles de fond (`thread::spawn`). `main()` (dispatch CLI) reste dans main.rs. Extrait de
//! main.rs (refactor split #25 — byte-identique).
use crate::*;

// ── SOUS-MODULES (`P7.18-a`) ──────────────────────────────────────────────────────────────────────
// Ce fichier était le plus gros de la production, très au-delà du seuil de mille lignes que la règle
// de modularité fixe à une façade. Les blocs AUTONOMES en sont extraits par DÉPLACEMENT PUR ; la
// façade garde le boot (`boot_config`, `open_and_migrate_db`, `run`) et les couches HTTP, et
// RÉ-EXPORTE la surface des sous-modules sous les chemins d'origine (`crate::server::X`) — aucun
// appelant ne change de chemin. Les sous-modules consomment la façade par `use super::*` (idiome du
// dépôt, cf. `cold_store/mod.rs` et `backup/mod.rs`).
mod groupes_de_routes; // LA TABLE DE ROUTAGE : les sous-routeurs par domaine + leur composition
pub(crate) use groupes_de_routes::build_router;
mod sauvegarde_planifiee; // ORDONNANCEUR DE SAUVEGARDE NATIF : réglage, destination, cycle, posture
pub(crate) use sauvegarde_planifiee::{scheduled_backup_cycle, spawn_backup_scheduler};
mod travaux_sur_la_base; // TRAVAUX SUR LA BASE PRIMAIRE : vacuum, ANALYZE, index, FTS, pré-chauffage
use travaux_sur_la_base::*; // les `spawn_*` que le lancement des travaux de fond appelle sans les qualifier
pub(crate) use travaux_sur_la_base::spawn_autovacuum_loop;

/// TLS natif actif (PLUME_TLS_CERT + PLUME_TLS_KEY posés au boot) -> le listener sert en HTTPS et
/// security_headers émet HSTS. OFF par défaut (HTTP en clair, comportement k3s/Traefik INCHANGÉ).
/// Lu sur le chemin chaud (security_headers) sans relire la config -> atomic mis en cache au boot.
pub(crate) static TLS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// En-têtes de sécurité HTTP sur toutes les réponses.
pub(crate) async fn security_headers(req: Request, next: Next) -> Response {
    // #51 DAY-2 OPS — compteur HTTP process-global bumpé dans une couche DÉJÀ traversée par TOUTES les
    // requêtes (aucune nouvelle couche, aucune State) : invisible du client, coût ~1 ns -> mode 0 identique.
    HTTP_REQUESTS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = req.uri().path().to_string();   // capturé avant next.run (req consommé ensuite)
    let mut res = next.run(req).await;
    if res.status().is_server_error() {
        HTTP_5XX_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(axum::http::HeaderName::from_static(k), axum::http::HeaderValue::from_static(v));
    };
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "permissions-policy", "geolocation=(), microphone=(), camera=()");
    set(h, "content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    // HSTS UNIQUEMENT quand le TLS natif est actif (item 1). En HTTP (défaut k3s : TLS au proxy), NE PAS
    // émettre HSTS sur le 80 d'origine -> on ne casse pas un déploiement HTTP. Émis ssi PLUME_TLS_CERT/KEY.
    if TLS_ON.load(std::sync::atomic::Ordering::Relaxed) {
        set(h, "strict-transport-security", "max-age=31536000; includeSubDomains");
    }
    // Cache-Control par chemin (défense en profondeur, v118). Politique PURE & testable : cf. cache_control_for.
    if let Some(cc) = cache_control_for(&path) {
        set(h, "cache-control", cc);
    }
    res
}

/// v118 — politique `Cache-Control` par chemin (défense en profondeur). PURE & testable (assert direct).
/// - `/api/*`  -> `no-store` : ferme la fenêtre bfcache/bouton-retour POST-LOGOUT. Les réponses `/api` sont
///   sensibles et PROPRES À L'UTILISATEUR ; `no-store` interdit au navigateur de les MÉMORISER ou de les
///   RESTAURER depuis le history/back-forward cache. Défense en profondeur SELF-ONLY (n'affecte que le même
///   navigateur du même utilisateur ; issue de l'audit d'auth). NOUVEAU en v118 : v117 ne posait AUCUN
///   Cache-Control sur `/api`.
/// - `/loki/*` -> `None` (AUCUN Cache-Control) : INCHANGÉ v117. API de requête compat-Loki ; on N'applique PAS
///   `no-store` pour ne pas perturber une éventuelle sémantique range/streaming (scoping prudent -> `/api` only).
/// - reste (shell : index.html/app.js/sw.js/style.css…) -> `no-cache` : INCHANGÉ v117. Le navigateur ET
///   Cloudflare REVALIDENT (ETag de ServeDir) au lieu de servir une version périmée après un déploiement ;
///   sw.js DOIT être revalidé sinon le service worker ne se met jamais à jour.
pub(crate) fn cache_control_for(path: &str) -> Option<&'static str> {
    if path.starts_with("/api/") {
        Some("no-store")   // v118 — nouveau
    } else if path.starts_with("/loki/") {
        None               // inchangé v117 (pas de Cache-Control ; no-store NON appliqué à /loki)
    } else {
        Some("no-cache")   // inchangé v117 (shell revalidé)
    }
}

/// Rate-limit global (fenêtre 10s) — anti-flood / défense en profondeur anti-bruteforce.
pub(crate) async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    const WIN: Duration = Duration::from_secs(10);
    let now = Instant::now();
    // Garde-fou GLOBAL conservé (filet ultime anti-saturation), relevé pour ne pas pénaliser plusieurs
    // IP légitimes simultanées maintenant que le tri fin se fait PAR IP. k3s = 1 IP Traefik -> jamais
    // atteint avant le per-IP (transparent).
    {
        let mut g = st.rl.lock();
        if now.duration_since(g.0) > WIN {
            *g = (now, 0);
        }
        g.1 += 1;
        if g.1 > st.rl_global_max {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limit (global)").into_response();
        }
    }
    // Plafond PAR IP source (item 4) — résout le self-DoS : une IP qui sature ne renvoie plus 429 à
    // TOUTES les autres (opérateur inclus). Routes d'auth (/api/setup,/api/password) = budget plus
    // strict que le polling UI. Sans IP (tests / serve sans connect-info) -> on saute le per-IP.
    let ip = client_ip(&req);
    if !ip.is_empty() {
        // Budget d'auth STRICT (anti-bruteforce + anti-DoS) : setup/password/login + les routes fédérées
        // PRÉ-AUTH #44 (login OIDC start/callback, bind LDAP, 2e facteur MFA). Ces dernières déclenchent du
        // réseau bloquant (spawn_blocking) et sont joignables sans identité -> même budget serré que le login.
        let p = req.uri().path();
        let auth_route = matches!(p, "/api/setup" | "/api/password" | "/api/login" | "/api/login/mfa" | "/api/auth/ldap")
            || p.starts_with("/api/auth/oidc/")
            || p.starts_with("/api/auth/saml/");
        let cap = if auth_route { st.rl_auth_max } else { st.rl_ip_max };
        let mut m = st.rl_ip.lock();
        if m.len() > 8192 {
            m.retain(|_, (t, _)| now.duration_since(*t) <= WIN);
        }
        let e = m.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) > WIN {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > cap {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limit (ip)").into_response();
        }
    }
    next.run(req).await
}

/// Réglages SQLite (perf + sûreté en WAL) — cf. plan données. NORMAL reste sûr de la corruption en WAL.
pub(crate) fn tune(conn: &Connection) {
    // Le budget mémoire vient de `sqlite_plafond` (un seul auteur) : un `GROUP BY` lancé sur la
    // connexion d'ÉCRITURE a exactement le même trieur que sur une connexion de lecture.
    // LA POLITIQUE DE JOURNAL vient de `wal_empreinte` (un seul auteur) : le seuil d'auto-checkpoint ET
    // la borne du RÉSIDU en sont DÉRIVÉS l'un de l'autre, donc les écrire ici séparément les laisserait
    // diverger. Le fragment vient APRÈS `journal_mode=WAL` : `journal_size_limit` ne borne le WAL qu'en
    // mode WAL (hors WAL il borne le journal de rollback, qui n'est pas le sujet).
    let _ = conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL;\
         PRAGMA synchronous=NORMAL;\
         PRAGMA busy_timeout=5000;\
         {}\
         {}\
         PRAGMA foreign_keys=ON;",
        sqlite_plafond::pragmas_memoire(),
        wal_empreinte::pragmas_journal(wal_empreinte::page_size_de(conn))
    ));
}

// Responder de CatchPanicLayer : transforme tout panic d'un handler/middleware en réponse
// 500 JSON propre `{"error":"erreur interne"}` (au lieu d'un corps VIDE -> le front affichait
// « Unexpected end of JSON input »). On extrait le message du payload (String / &str) à seule
// fin de log côté serveur ; le corps renvoyé au client reste générique (pas de fuite interne).
pub(crate) fn panic_to_json_response(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let msg = if let Some(s) = err.downcast_ref::<String>() {
        s.as_str()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s
    } else {
        "panic"
    };
    eprintln!("[panic] handler paniqué -> 500 JSON : {msg}");
    server_err("erreur interne")
}

// ---------- runtime ----------
// ---------- boot path (extrait de run() en sous-fonctions pures, ordre préservé — refactor #25) ----------
/// Bundle de configuration de démarrage, lu une fois par `boot_config()` puis destructuré dans `run()`
/// (les liaisons locales restent byte-identiques). Aucun changement de comportement.
struct BootConfig {
    conf: HashMap<String, String>,
    db_path: String,
    spool: String,
    addr: String,
    user: String,
    pass: String,
    webdir: String,
    host: String,
    host_strict: bool,
    sso_secret: String,
    public_demo: bool,
    metrics_token: String,
    sso_group_admin: String,
    sso_group_editor: String,
    sso_group_superadmin: String,
    sso_header_user: String,
    sso_header_groups: String,
    tls_cert: String,
    tls_key: String,
    tls_on: bool,
    lock_threshold: u32,
    lock_base_s: u64,
    lock_max_s: u64,
    rl_ip_max: u32,
    rl_auth_max: u32,
    rl_global_max: u32,
    session_ttl_s: i64,
    session_secret: Vec<u8>,
    ingest_min_free_mb: u64,
    ingest_max_events: usize,
    search_limit_default: i64,
    search_limit_max: i64,
    query_sem: Arc<tokio::sync::Semaphore>,
    refresh_sem: Arc<tokio::sync::Semaphore>,
    bound: Arc<std::sync::atomic::AtomicBool>,
}

/// Lit toute la configuration de démarrage (PLUME_*) + effets de bord d'amorçage inchangés
/// (START_TS/TLS_ON, logs host_strict/public_demo). Ordre identique à l'ancien préambule de run().
fn boot_config() -> BootConfig {
    // #51 DAY-2 OPS : horodatage de démarrage (process_start_time_seconds / uptime) posé une fois.
    START_TS.store(now(), std::sync::atomic::Ordering::Relaxed);
    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    let spool = cfg(&conf, "PLUME_SPOOL", "/var/lib/plume/spool");
    let addr = cfg(&conf, "PLUME_ADDR", "127.0.0.1:7000");
    // Défaut GÉNÉRIQUE « admin » (aucun username perso baké). Le déploiement fournit la VRAIE valeur via
    // le Secret plume-auth (PLUME_USER).
    let user = cfg(&conf, "PLUME_USER", "admin");
    // SECRET-PROVIDER PHASE 1 (v118) — hash admin lu depuis `PLUME_PASS_HASH_FILE` (mount RO) si posé, sinon
    // repli env `PLUME_PASS_HASH` (v116/v117). Lecteur SETUP-SAFE (`cfg_secret_optional`, PAS `cfg_secret`) :
    // fichier ABSENT/VIDE -> "" -> MODE SETUP légitime (mount k8s `optional: true` sur cluster non-bootstrappé) ;
    // fichier PRÉSENT mais illisible/non-UTF8 -> fail-closed exit(78) (ne retombe JAMAIS en setup = pas de
    // re-bootstrap d'auth). SSO/ntfy restent sur `cfg_secret` strict (leur absence n'est PAS légitime).
    let pass = cfg_secret_optional(&conf, "PLUME_PASS_HASH");
    let webdir = cfg(&conf, "PLUME_WEB", "/usr/local/share/plume/web");
    let host = cfg(&conf, "PLUME_HOST", "plume.localhost");
    // DURCISSEMENT STANDALONE — allowlist Host stricte (config-gated). DÉFAUT 0 = inchangé (loopback OK).
    let host_strict = cfg(&conf, "PLUME_HOST_STRICT", "0") == "1";
    if host_strict { eprintln!("[host] PLUME_HOST_STRICT=1 : allowlist Host restreinte aux FQDN de PLUME_HOST ({host}) — loopback NON auto-accepté"); }
    // SECRET-PROVIDER PHASE 1 — secret trusted-header SSO lu depuis `PLUME_SSO_HEADER_SECRET_FILE` (mount RO)
    // si posé, sinon repli env `PLUME_SSO_HEADER_SECRET` (v116). Fail-closed si le fichier configuré manque/vide
    // (ne PAS retomber en silence sur env absent -> SSO ne doit jamais s'ouvrir par défaut de secret manquant).
    let sso_secret = cfg_secret(&conf, "PLUME_SSO_HEADER_SECRET");
    let public_demo = cfg(&conf, "PLUME_PUBLIC_DEMO", "0") == "1";   // démo publique : anon read-only (opt-in)
    // #51 DAY-2 OPS — jeton de scrape /metrics (Bearer). Vide (défaut) -> /metrics exige viewer+ (jamais anonyme).
    let metrics_token = cfg(&conf, "PLUME_METRICS_TOKEN", "");
    if public_demo { eprintln!("[demo] PLUME_PUBLIC_DEMO=1 : accès ANONYME en LECTURE SEULE (viewer) — NE PAS utiliser en prod"); }
    let sso_group_admin = cfg(&conf, "PLUME_SSO_GROUP_ADMIN", "plume-admin");
    let sso_group_editor = cfg(&conf, "PLUME_SSO_GROUP_EDITOR", "plume-editor");
    let sso_group_superadmin = cfg(&conf, "PLUME_SSO_GROUP_SUPERADMIN", "admins");
    // VENDOR-AGNOSTIC (C1) — noms des en-têtes trusted-header. Défauts = les noms Authentik historiques
    // -> comportement GUATX byte-identique. Un client fronting Plume avec un autre forward-auth pose ses
    // propres noms. Normalisés en minuscules (les clés HeaderMap axum sont insensibles à la casse mais
    // stockées en minuscules ; `HeaderMap::get` est case-insensitive, on garde une valeur propre).
    let sso_header_user = cfg(&conf, "PLUME_SSO_HEADER_USER", "x-authentik-username").to_ascii_lowercase();
    let sso_header_groups = cfg(&conf, "PLUME_SSO_HEADER_GROUPS", "x-authentik-groups").to_ascii_lowercase();
    // DURCISSEMENT STANDALONE (item 1) — TLS natif CONFIG-GATED : HTTPS rustls ssi PLUME_TLS_CERT +
    // PLUME_TLS_KEY (chemins PEM) sont posés. Vides (DÉFAUT) -> HTTP en clair comme aujourd'hui : k3s
    // derrière Traefik (TLS au proxy) reste INCHANGÉ. HSTS n'est émis QUE quand ce TLS est actif.
    let tls_cert = cfg(&conf, "PLUME_TLS_CERT", "");
    let tls_key = cfg(&conf, "PLUME_TLS_KEY", "");
    let tls_on = !tls_cert.trim().is_empty() && !tls_key.trim().is_empty();
    TLS_ON.store(tls_on, std::sync::atomic::Ordering::Relaxed);
    // DURCISSEMENT STANDALONE (item 2) — anti-brute-force : lockout par (compte Basic, IP) à backoff
    // exponentiel + AUTO-INGEST SIEM. Défauts GÉNÉREUX/transparents (le légitime ne fait pas d'échecs).
    // PLUME_AUTH_LOCK_THRESHOLD=0 désactive le lockout (les échecs restent loggés). 10 / 30s / 900s.
    let lock_threshold: u32 = cfg(&conf, "PLUME_AUTH_LOCK_THRESHOLD", "10").parse().unwrap_or(10);
    let lock_base_s: u64 = cfg(&conf, "PLUME_AUTH_LOCK_BASE_S", "30").parse().unwrap_or(30).max(1);
    let lock_max_s: u64 = cfg(&conf, "PLUME_AUTH_LOCK_MAX_S", "900").parse().unwrap_or(900).max(1);
    // DURCISSEMENT STANDALONE (item 4) — rate-limit PAR IP (anti self-DoS) + garde-fou global. k3s = 1 IP
    // Traefik -> rl_ip_max (= ancien plafond global 1200/10s) s'applique à cette IP = même borne qu'avant.
    let rl_ip_max: u32 = cfg(&conf, "PLUME_RL_IP_MAX", "1200").parse().unwrap_or(1200).max(1);
    let rl_auth_max: u32 = cfg(&conf, "PLUME_RL_AUTH_MAX", "120").parse().unwrap_or(120).max(1);
    let rl_global_max: u32 = cfg(&conf, "PLUME_RL_GLOBAL_MAX", "6000").parse().unwrap_or(6000).max(1);
    // FORM-LOGIN (cookie de session signé HMAC) : TTL configurable (défaut 12h) + secret de signature
    // (env PLUME_SESSION_SECRET, sinon clé persistée 0600). JAMAIS de secret en dur. ADDITIF (Basic/SSO/
    // Bearer inchangés). `load_session_secret` lit/génère la clé ; `session_secret` (Vec) shadow rien.
    let session_ttl_s: i64 = cfg(&conf, "PLUME_SESSION_TTL_S", "43200").parse().unwrap_or(43200).max(60);
    let session_secret = load_session_secret(&conf);
    // L1 — GARDE DISQUE/CARDINALITÉ À L'INGEST. Seuils volontairement TRÈS au-dessus d'un batch légitime
    // (512 Mo libres, 50 000 events/req) : ne coupent QU'un flux pathologique / un disque saturé, jamais la
    // collecte réelle. PLUME_INGEST_MIN_FREE_MB=0 désactive le garde disque ; PLUME_INGEST_MAX_EVENTS borné >=1.
    let ingest_min_free_mb: u64 = cfg(&conf, "PLUME_INGEST_MIN_FREE_MB", "512").parse().unwrap_or(512);
    let ingest_max_events: usize = cfg(&conf, "PLUME_INGEST_MAX_EVENTS", &INGEST_MAX_EVENTS_DEFAUT.to_string())
        .parse().unwrap_or(INGEST_MAX_EVENTS_DEFAUT).max(1);
    let search_limit_default: i64 = cfg(&conf, "PLUME_SEARCH_LIMIT", "100").parse().unwrap_or(100).max(1);
    let search_limit_max: i64 = cfg(&conf, "PLUME_SEARCH_MAX", "5000").parse().unwrap_or(5000).max(1);
    // sémaphore de concurrence de l'INTERACTIF (/api/query / /api/search) : au moins 1.
    let query_concurrency: usize = cfg(&conf, "PLUME_QUERY_CONCURRENCY", "3").parse().unwrap_or(3).max(1);
    let query_sem = Arc::new(tokio::sync::Semaphore::new(query_concurrency));
    // P7.8-a : la BORNE est publiée (jamais modifiée ici). « 3 permis détenus » ne dit rien sans
    // « sur 3 » : `plume_query_permits_held` ne se lit que contre `plume_query_permits_limit`.
    semaphore_interactif::poser_borne(query_concurrency);
    // CHANGEMENT 1 — sémaphore SÉPARÉ du refresh ASYNC des panneaux (SWR + cache_refresh_all_panels) :
    // le refresh ne partage PLUS la borne de l'interactif -> sem_wait interactif ~0 même sous rafale de
    // rafraîchissement (14 panneaux). Taille via PLUME_PANEL_REFRESH_CONCURRENCY (défaut 2), au moins 1.
    let refresh_concurrency: usize = cfg(&conf, "PLUME_PANEL_REFRESH_CONCURRENCY", "2").parse().unwrap_or(2).max(1);
    let refresh_sem = Arc::new(tokio::sync::Semaphore::new(refresh_concurrency));
    // #32 — DRAPEAU « listener bind :7000 fait ». Le ANALYZE complet (tâche de fond, ~3 min, prend le lock
    // writer) ne démarre QU'APRÈS que le port écoute réellement (readiness tcpSocket passe). Remplace le
    // sleep(20s) « au jugé » par un vrai gate structurel : sur un boot où le bind traîne (déploiement de
    // migration), le ANALYZE NE peut plus fenêtrer AVANT le bind -> plus de mini-panne « connection refused ».
    // Sain par défaut : sur un boot normal le bind est immédiat -> le gate lève tout de suite (timing inchangé).
    let bound = Arc::new(std::sync::atomic::AtomicBool::new(false));
    BootConfig {
        conf,
        db_path,
        spool,
        addr,
        user,
        pass,
        webdir,
        host,
        host_strict,
        sso_secret,
        public_demo,
        metrics_token,
        sso_group_admin,
        sso_group_editor,
        sso_group_superadmin,
        sso_header_user,
        sso_header_groups,
        tls_cert,
        tls_key,
        tls_on,
        lock_threshold,
        lock_base_s,
        lock_max_s,
        rl_ip_max,
        rl_auth_max,
        rl_global_max,
        session_ttl_s,
        session_secret,
        ingest_min_free_mb,
        ingest_max_events,
        search_limit_default,
        search_limit_max,
        query_sem,
        refresh_sem,
        bound,
    }
}

/// Crée les répertoires, ouvre/chiffre la base, applique le schéma + migrations, puis TOUS les seed_*
/// et rechargements (overlays/parsers/processors/field-filters/knowledge). Séquence byte-identique.
/// RÉSIDU DE RENOMMAGE HISTORIQUE — rename LEGACY one-shot IN-DAEMON : les déploiements docker/hôte se
/// self-healent sans étape d'init externe. Si `db_path` s'appelle `plume.db`, n'existe PAS, et
/// qu'une base LEGACY `soc.db` est dans le MÊME dossier, on la renomme (+ WAL/SHM) : aucune perte (rename atomique
/// même fs), JAMAIS de clobber (skip si la cible existe), no-op sur PVC neuf / base déjà en plume.db / autre nom.
/// PUR (agit sur le FS, aucun état global) -> testable. Rend le défaut `plume.db` sûr dans les 3 modes.
pub(crate) fn rename_legacy_db(db_path: &str) {
    let target = std::path::Path::new(db_path);
    if target.file_name().and_then(|n| n.to_str()) != Some("plume.db") || target.exists() {
        return;
    }
    let Some(dir) = target.parent() else { return };
    if !dir.join("soc.db").exists() {
        return;
    }
    for ext in ["", "-wal", "-shm"] {
        let (from, to) = (dir.join(format!("soc.db{ext}")), dir.join(format!("plume.db{ext}")));
        if from.exists() && !to.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    eprintln!("[boot] rename legacy soc.db -> plume.db (résidu soc->plume, portable docker/host)");
}

fn open_and_migrate_db(db_path: String, spool: String, conf: HashMap<String, String>) -> Connection {
    // Crée le spool + le dossier parent de la DB s'ils manquent (conteneur/PVC vierge : rien ne les
    // pré-crée, contrairement à l'install hôte via bootstrap -> sinon /api/ingest échoue en écriture).
    let _ = std::fs::create_dir_all(&spool);
    {
        // spool en 0750 (pas world-readable) : cohérent avec le durcissement 0600 des fichiers de spool.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o750));
    }
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    rename_legacy_db(&db_path); // ④ : self-heal legacy soc.db -> plume.db (portable docker/host), AVANT ouverture

    // P8.7-b ② — LA BASCULE EST DITE AVANT D'AGIR. Sur un hôte systemd, une clé écrite dans
    // `/etc/plume/soc.conf` était IGNORÉE par la voie qui ouvre la base : elle ne chiffrait que le
    // tier froid. Elle chiffre désormais les deux moitiés — et la ligne suivante peut donc RÉÉCRIRE
    // une base existante. On le dit d'abord, avec le verdict de la base et ce qu'il faut prévoir.
    // Silencieux quand rien ne change (Docker/k3s : tout est en `env:` -> aucune annonce).
    annoncer_bascule_at_rest(&conf, &db_path);
    ensure_encrypted(&conf, &db_path);   // SQLCipher : chiffre la base en clair existante si PLUME_DB_KEY posé (idempotent, backup auto)
    // LA PORTE (`db_open`) : ouverture, garde ANTI-DOWNGRADE, `tune` (prélude), puis contrat de schéma —
    // dans CET ordre, qui est celui d'avant, ligne pour ligne. Le daemon n'est plus le seul chemin à
    // l'appliquer : c'est la porte qui le fait, pour tout ce qui obtient une connexion d'écriture.
    //
    // v105 (CHANGE 1) — GARDE ANTI-DOWNGRADE, AVANT toute écriture (schema.sql/migrate/tune). Si la base est
    // estampillée PLUS HAUT que ce binaire (rollback d'image sur une base déjà migrée par un plus récent),
    // on REFUSE d'ouvrir : arrêt PROPRE (exit 1, aucune écriture -> aucun risque de corruption), pas un panic.
    //
    // REFUS DE SERVIR SUR UN SCHÉMA QUI N'EST PAS CELUI ATTENDU (symétrique de la garde anti-downgrade
    // ci-dessus). `prepare_schema` applique db/schema.sql, déroule les migrations, PUIS vérifie que les
    // objets attendus sont bien là (une base peut porter la version SANS ses objets : cf. sa doc).
    // Continuer signifierait servir avec des tables absentes — et une table absente n'est pas une panne
    // visible, c'est une FONCTION SILENCIEUSEMENT ABSENTE (`net_ban` manquante -> le ban natif HTTP, un
    // contrôle de sécurité, devient un passthrough).
    //
    // CHOIX ASSUMÉ : arrêt propre en code 1, AVANT `reconcile_index_state`, les `seed_*` et le bind.
    // Ce que ce refus couvre EXACTEMENT, et ce qu'il ne couvre pas : `prepare_schema` juge l'ÉTAT FINAL.
    // Une contention TRANSITOIRE d'écriture (le sidecar backup tient le verrou) fait échouer
    // `db/schema.sql`, mais sur une base DÉJÀ au schéma attendu cet échec est SANS EFFET et le démarrage
    // continue (mesuré : `write_contention_on_an_up_to_date_database_is_not_a_refusal`). Si la base
    // n'est PAS à jour, la contention empêche vraiment la migration : refus, et là le redémarrage suffit
    // dès que le verrou est rendu. Pour un élément de schéma manquant, en revanche, le redémarrage NE
    // répare RIEN (le message le dit) : c'est une intervention opérateur. On préfère l'indisponibilité
    // bruyante à la sécurité silencieusement absente.
    let conn = match PreparedDb::open_with_prelude(&db_path, tune) {
        Ok(c) => c.into_connection(),
        Err(DbOpenError::PlusRecenteQueCeBinaire(v)) => {
            eprintln!(
                "[schema] REFUS D'OUVERTURE : base en schema_version={v} > CODE_SCHEMA_MAX={} — ce binaire est \
                 TROP ANCIEN pour cette base (probable rollback d'image sur une base déjà migrée par un binaire \
                 plus récent). Aucune écriture effectuée. Déployer un binaire >= schéma v{v}, ou restaurer une \
                 sauvegarde compatible. Arrêt propre.",
                CODE_SCHEMA_MAX
            );
            std::process::exit(1);
        }
        Err(DbOpenError::Ouverture(e)) => panic!("open db: {e}"),
        Err(DbOpenError::Contrat(e)) => {
            eprintln!(
                "[schema] REFUS DE SERVIR : {e}. Servir dans cet état rendrait des fonctions (dont des \
                 contrôles de sécurité) silencieusement absentes. Aucun seed, aucun bind. Arrêt propre."
            );
            std::process::exit(1);
        }
    };
    // VRAI kill-switch env-driven, idempotent, à CHAQUE boot (après migrate, avant bind).
    // Crée/droppe la vtable+triggers FTS et droppe les index expression selon PLUME_FTS_FIELDS /
    // PLUME_EXPRINDEX. INSTANTANÉ (DDL pur, pas de scan) -> ne retarde pas le bind. Le CREATE INDEX
    // lourd des 7 champs est lancé EN FOND plus bas (anti-crashloop).
    reconcile_index_state(&conn, &conf);
    // P5.7-b — LE FAIT DE DÉPLOIEMENT, DATÉ ET AUDITÉ. Compare le jeu d'unités systemd que CE binaire
    // livre à celui noté sur la base : s'il a changé, un autre build tourne. Le fait est écrit au ledger
    // + `plume-config` AVANT d'ouvrir quoi que ce soit, et il ouvre une fenêtre BORNÉE pendant laquelle un
    // dépôt d'unité au CONTENU livré est reclassé en informationnel (jamais effacé, cf. maj_corroboree.rs).
    // Signature inchangée -> aucune fenêtre ; base neuve -> pose silencieuse. Fail-closed des deux côtés.
    noter_le_build_en_cours(&conn, &db_path);
    seed_default_dashboard(&conn);
    seed_example_rules(&conn);
    seed_purple_rules(&conn);   // règles ATT&CK purple (flag dédié -> arrivent sur DB déjà seedée)
    seed_detection_rules(&conn);   // règles de détection ciblées (portscan/brute-force/cloudflare, flag dédié)
    seed_runbooks(&conn);   // #3 incidents Phase 1 : runbooks managés keyés MITRE (flag dédié `seeded_runbooks`)
    seed_ti_alert_rules(&conn);   // #23 activation : alerte sur match IOC confiance≥80 (managé, inerte tant qu'aucun IOC)
    seed_risk_rules(&conn);       // #24 activation : règles RBA mode risque (brute-force/recon par entité, managé)
    seed_example_playbooks(&conn);
    seed_ssh_cve_playbook(&conn);
    seed_k8s_rules(&conn);
    seed_obs_dashboard(&conn);
    seed_obs_rules(&conn);
    seed_sts_rules(&conn);
    seed_velero_rule(&conn);
    seed_malware_rule(&conn);
    seed_slab_rule(&conn);
    seed_security_dashboard(&conn);
    seed_demo(&conn);   // PLUME_DEMO=1 : peuple une instance fraîche (démo self-serve) ; no-op sinon
    seed_egress_dashboard(&conn);
    seed_web_dashboard(&conn);
    seed_mail_dashboard(&conn);
    seed_dataaccess_dashboard(&conn);
    seed_dataacl_dashboard(&conn);
    seed_sca_dashboard(&conn);    // #57 : posture SCA/CIS (BYO-agent endpoint) — idempotent par nom
    seed_vuln_dashboard(&conn);   // #57 : vulnérabilités CVE endpoint — idempotent par nom
    seed_compliance_dashboards(&conn); // #38 : posture PAR cadre (PCI DSS/HIPAA/NIST 800-53) — idempotent par nom
    seed_kube_rbac_dashboard(&conn);
    seed_minio_dashboard(&conn);
    seed_vault_dashboard(&conn);
    seed_rollup_dashboard(&conn);
    ensure_rollup_srcip_host_panels(&conn);   // filet idempotent (bases existantes)
    seed_banpass_dashboard(&conn);   // v52 : dashboard « Banni / Pass » (anti-join banlist, SWR) — idempotent par nom
    seed_egress_rules(&conn);
    // PERSONNALISATION PHASE 1 — overlays versionnés (config.d) : APRÈS tous les seed_* (un overlay GAGNE
    // sur le builtin du même nom), AVANT parsers_reload (pour que le cache compilé inclue les overlays).
    load_overlays(&conn, &conf);
    parsers_reload(&conn, &db_path);   // charge le registre de parsers (builtin + custom) de CE db_path dans le cache compilé
    dparsers_reload(&conn, &db_path);  // Slice #7 pièce 2 : registre de parseurs DÉCLARATIFS (config.d) de CE db_path
    processors_reload(&conn, &db_path); // #40 : registre du PROCESSEUR D'INGEST (table ingest_rule) de CE db_path (VIDE en mode 0 -> ingest byte-identique)
    field_filters_reload(&conn, &db_path); // #45 : registre des FIELD FILTERS (table field_filter) de CE db_path (VIDE en mode 0 -> lecture byte-identique)
    knowledge_reload(&conn, &db_path); // #46 : registre des KNOWLEDGE OBJECTS (tables knowledge_*) de CE db_path (VIDE en mode 0 -> compilation GXQL byte-identique)
    knowledge_activate(&db_path); // #46 : ACTIVE ce db_path (tenant primaire) pour la compilation GXQL db-agnostique (VIDE -> byte-identique)
    seed_env_notifier(&conn, &conf);
    conn
}

/// Lance toutes les boucles de fond (ingest, ordonnanceur de règles, connecteurs, destinations,
/// rétention, rapports, rollups, refresh panneaux, ANALYZE/index en fond) + applique les toggles mis
/// en cache au boot (FTS/engagement/exclusions). MÊME ordre, MÊME cadence qu'avant.
fn spawn_background_jobs(conf: HashMap<String, String>, spool: String, db_path: String, db: Arc<Mutex<Connection>>, tenants: TenantDbManager, refresh_sem: Arc<tokio::sync::Semaphore>, bound: Arc<std::sync::atomic::AtomicBool>) {
    {
        // ROUTING PER-TENANT de l'ingest (R8) : le manager résout la base cible PAR fichier spool (tenant
        // encodé dans le nom). Mode 0 -> toujours (st.db, st.db_path) = comportement identique.
        spawn_ingest_loop(tenants.clone(), spool.clone());
    }

    // planificateur des règles de détection (P4) — #2a-2c : PAR TENANT (mode 0 = 1 itération `default`=st.db).
    {
        spawn_rule_scheduler(tenants.clone());
    }

    // BAN NATIF PLUME (chantier ② Phase 1) — maintenance du store live `net_ban` : charge le cache AU DÉMARRAGE
    // (les bans persistés survivent au reboot) puis, périodiquement, (a) purge les lignes EXPIRÉES et (b) recharge
    // le cache (capte les écritures HORS-PROCESS du responder root). Mode 0 : table vide -> cache vide -> guard
    // passthrough, travail négligeable (tick 15 s sur une table minuscule).
    {
        spawn_netban_maintenance(db.clone());
    }

    // #3a — TICK CONNECTEURS : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si table `connector`
    // vide (état prod actuel) : run_due_connectors sélectionne les connecteurs DUS -> 0 ligne -> no-op strict
    // (aucun réseau, aucune écriture). Thread DÉDIÉ (séparé de l'ingest et des règles) -> un pull réseau lent
    // (10 s) ne retarde jamais l'ingest local ni les rollups. Séquentiel par tenant (for_each_active_tenant,
    // budget 2 Go). FAIL-SAFE : un connecteur cassé log dans connector.last_error et n'arrête pas les autres.
    {
        spawn_connector_tick(tenants.clone());
    }

    // #50 — TICK FORWARDER (OUTPUTS/DESTINATIONS) : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si
    // table `destination` vide (état prod actuel) : run_due_destinations sélectionne les destinations DUES ->
    // 0 ligne -> no-op strict (aucun réseau, aucune écriture, ZÉRO coût sur l'ingest). Thread DÉDIÉ (séparé de
    // l'ingest, des règles ET des connecteurs) -> un sink lent/mort (envoi réseau borné 10 s, lot borné) ne
    // retarde JAMAIS l'ingest local ni les autres tenants. Séquentiel par tenant (budget 2 Go). FAIL-SAFE :
    // une destination cassée log dans destination.last_error (watermark gelé, rejouable) sans arrêter les autres.
    {
        spawn_destination_tick(tenants.clone());
    }

    // rétention + purge + ledger (horaire). #2a-2c : PAR TENANT — chaque
    // NB (constat VÉRIFIÉ le 31/07) : ce commentaire annonçait un « filet » — que `retention_run` rappelait
    // `rollup_events`. C'est FAUX depuis #23 F3, qui a RETIRÉ ce re-run du plus long verrou writer parce que
    // la boucle dédiée (`spawn_rollup_loop`, ~120 s) l'appelle déjà à une cadence bien plus fine (cf.
    // `rollups.rs`, « les re-runs rollup_events / materialize_banned_ip / rollup_risk sont RETIRÉS »). Un
    // commentaire qui promet un filet inexistant est pire qu'aucun : il ferme la question qu'il faudrait poser.
    // tenant lit SES settings de rétention (#1b) depuis SA base (mode 0 = 1 itération `default`=st.db).
    {
        spawn_retention_loop(tenants.clone());
    }

    // #60 — TICK SCHEDULED REPORTS : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si table
    // `scheduled_report` vide : run_due_reports sélectionne 0 ligne -> no-op strict (aucun réseau, aucune
    // écriture). Thread DÉDIÉ (séparé de l'ingest/règles/connecteurs/destinations) -> un notifier lent/mort ne
    // retarde jamais l'ingest ni les autres tenants. Séquentiel par tenant. FAIL-SAFE : chaque rapport isolé
    // (catch_unwind + last_error). Le résultat est MASQUÉ #45 par le run_as du rapport (jamais par un rôle
    // supérieur). Granularité 30 s (le due se calcule sur interval_s du rapport).
    {
        spawn_report_tick(tenants.clone());
    }

    // #59 — RAFRAÎCHISSEMENT PÉRIODIQUE du cache de rôles COMPOSABLES (control-plane). Le cache
    // process (CUSTOM_ROLES) est chargé au boot + sur mutation LOCALE ; sur un déploiement MULTI-RÉPLICA, une
    // mutation faite sur une AUTRE réplica ne serait vue qu'au prochain boot -> fenêtre de staleness (un rôle
    // custom PLUS permissif honoré trop longtemps). Ce ticker borne la fenêtre à ~45 s (même pattern que le
    // scheduler de rétention). Mode 0 (control=None) -> thread INERTE (jamais de reload -> cache VIDE ->
    // tous les chemins RBAC byte-identiques). Cheap (un SELECT sur une petite table control-plane).
    {
        spawn_custom_roles_refresh(tenants.clone());
    }
    // rollup d'events FRÉQUENT -> faible latence sur « Vue d'ensemble (rapide) » + agrégats GROUP-BY plus
    // frais (SOC) : ré-agrège l'heure en cours + la précédente (incrémental/borné, JAMAIS de full-scan).
    // CHANGEMENT 2b : intervalle PLUME_ROLLUP_INTERVAL_S (défaut 120s, au lieu de 300s) pour des agrégats
    // plus frais sur un SOC. Séparé de la rétention horaire (qui purge + signe le ledger).
    {
        // #2a-2c : rollup + banlist + pré-chauffage panneaux PAR TENANT (mode 0 = 1 itération `default`=st.db).
        // intervalles/seuils lus depuis conf AU SITE D'APPEL (jamais de load_config dans le helper) et
        // passes par valeur ; warm_freshness = control-plane present (mode 1). Byte-identique.
        let rollup_interval: u64 = cfg(&conf, "PLUME_ROLLUP_INTERVAL_S", "120").parse().unwrap_or(120).max(1);
        let disk_warn_pct: u8 = cfg(&conf, "PLUME_DISK_WARN_PCT", "80").parse().unwrap_or(80);
        spawn_rollup_loop(tenants.clone(), rollup_interval, disk_warn_pct, tenants.control.is_some());
    }
    // PHASE 3b — boucle de refresh des panneaux DÉDIÉE (courte), DÉCORRÉLÉE du tick rollup : maintient
    // le cache SWR frais (computed_at avance) à intervalle PLUME_PANEL_REFRESH_S. CHANGEMENT 2a : défaut
    // 10s (au lieu de 20s) -> tuiles SOC quasi temps-réel. Bornée par refresh_sem.try_acquire (CHANGEMENT
    // 1 : sémaphore SÉPARÉ) -> ne prend AUCUN permit query_sem, ne bloque/affame jamais l'interactif.
    {
        // #2a-2c : boucle de refresh des panneaux DÉDIÉE, PAR TENANT (mode 0 = 1 itération `default`=st.db).
        let refresh_s: u64 = cfg(&conf, "PLUME_PANEL_REFRESH_S", "10").parse().unwrap_or(10).max(1);
        spawn_panel_refresh_loop(tenants.clone(), refresh_sem.clone(), refresh_s);
    }
    // OPS NATIVE #1 — SCHEDULER DE BACKUP IN-DAEMON (host-natif, Docker ET k3s : `deploy/k3s.yaml` pose
    // `PLUME_BACKUP_INTERVAL` dans son unique conteneur, il n'y a plus de sidecar shell). GATÉ sur
    // PLUME_BACKUP_INTERVAL (secondes ; 0/absent = DÉSACTIVÉ -> AUCUN thread spawné -> comportement
    // byte-identique). Sur host/Docker : monte un volume, pose la var -> self-backup. Chaque cycle qui publie
    // une archive émet les signaux SOC de posture qu'elle implique : sans destinataire d'escrow, la posture
    // symétrique (P8.25-a) ; exercice de restauration dû, l'exercice (P8.26-a).
    {
        annoncer_bascule_sauvegarde(&conf);
        spawn_backup_scheduler(conf.clone(), db_path.clone());
    }
    // OPS NATIVE #2 — AUTO-VACUUM INCRÉMENTAL IN-DAEMON (best-effort, NON-BLOQUANT). GATÉ sur
    // PLUME_AUTOVACUUM_INTERVAL (0/absent = DÉSACTIVÉ -> AUCUN thread -> byte-identique). INOPÉRANT (warn
    // honnête, jamais de VACUUM plein bloquant) si la base n'est pas en auto_vacuum=INCREMENTAL.
    {
        spawn_autovacuum_loop(conf.clone(), db.clone());
    }
    // P10.9-a — L'OBSERVATOIRE D'USAGE DES INDEX. Réglé ICI, depuis la configuration RÉSOLUE, et non
    // par une lecture d'environnement nue : sinon la clé écrite dans le fichier de configuration d'un
    // déploiement host-natif n'aurait aucun effet. `PLUME_INDEX_USAGE_SAMPLE_N=0` (défaut) -> aucun
    // plan lu, aucune série publiée, `/metrics` inchangé octet pour octet.
    {
        index_usage::configurer(&conf);
    }
    // LA SÉRIE DU BUDGET (P10.2-a suite) — la ventilation par poste, ÉCRITE DANS LE TEMPS au lieu
    // d'être relevée à la main. Tick lent (défaut horaire = la résolution de `metric_rollup`), parcours
    // `dbstat` sur le POOL DE LECTURE (jamais le mutex writer), publication dans `metric` -> lue par la
    // commande SOQL `metric`, qui UNIONNE `metric` et `metric_rollup` (90 j). Coût MESURÉ sur une base
    // réelle le 2026-08-09 : une vingtaine de secondes par Gio parcouru, soit moins de 1 % d'un cœur au
    // tick horaire sur une base de l'ordre du Gio, et borné à
    // 5 % par `prochain_sommeil` si la base grossit. `PLUME_VENTILATION_INTERVAL_S=0` -> aucun thread.
    {
        ventilation_serie::spawn_boucle(conf.clone(), db_path.clone(), db.clone(), bound.clone());
    }
    // #32 : ANALYZE COMPLET en TÂCHE DE FOND (jamais dans migrate()) -> boot non bloquant.
    // Le boot est désormais STRUCTURELLEMENT : migrate -> bind :7000 -> (fond) ANALYZE. On n'attend plus
    // un sleep « au jugé » (course : si le bind traînait, le ANALYZE fenêtrait quand même) : on ATTEND le
    // drapeau `bound` posé juste après que le listener écoute, PUIS une courte grâce (liveness passée), PUIS
    // le ANALYZE complet une seule fois (gardé par meta 'analyze_full_done'). Le ANALYZE prend le lock
    // writer (~3 min) mais les LECTURES sont servies par le pool read-only (query_exec) -> jamais bloquées ;
    // seules les écritures (ingest) attendent, et le spool les tamponne. Sur base déjà analysée : no-op.
    {
        spawn_analyze_full(db.clone(), bound.clone());
    }

    // PHASE 1 — toggle mis en cache AU BOOT (atomic lu sur le chemin chaud de compilation/recherche
    // sans load_config()). Défaut PRUDENT : FTS-fields OFF. cfg() couvre PLUME_* (canonical).
    FTS_FIELDS_ON.store(cfg(&conf, "PLUME_FTS_FIELDS", "0") == "1", std::sync::atomic::Ordering::Relaxed);
    // v75 — MODE ENGAGEMENT (pentest natif) : drapeau mis en cache AU BOOT (lu sur le chemin chaud ingest/ban
    // sans load_config). Défaut OFF -> tout le sous-système engagement INERTE (byte-identique).
    set_engagement_mode(engagement_enabled_in(&conf));
    // DEBRUITAGE self/opérateur — clauses d'exclusion (`__OPERATOR_EXCL__` / `__SELF_EXCL__`) compilées et
    // MISES EN CACHE AU BOOT (lues sur le chemin chaud de compilation sans load_config). Chantier
    // whitelists→webui : la valeur résout DÉSORMAIS un override `setting` éditable+audité (repli BYTE-IDENTIQUE
    // sur l'env quand aucun override) ; refresh depuis la base principale au boot. Configurable
    // PLUME_OPERATOR_IPS / PLUME_SELF_HOSTS + override setting excl_operator_ips / excl_self_hosts ; vide -> no-op.
    {
        {
            let conn = db.lock();
            excl_clauses_refresh(&conn, &conf);
        }
        let g = excl_clauses_cell().read();
        eprintln!(
            "[exclusion] self/opérateur — op(src_ip)=[{}] self(vhost)=[{}] (PLUME_OPERATOR_IPS / PLUME_SELF_HOSTS, override setting {EXCL_OP_SETTING}/{EXCL_SELF_SETTING})",
            g.op_sql, g.self_sql
        );
    }
    // CREATE des index expression (un par entrée d'EXPR_INDEX_FIELDS) EN FOND après le bind (jamais synchrone : un CREATE
    // INDEX sur 1,24M lignes bloquerait le bind -> liveness k8s -> CrashLoopBackOff). 1 index à la fois,
    // lock writer borné par index. No-op si PLUME_EXPRINDEX!=1 (le DROP est synchrone au boot) ou si
    // déjà créés. Réconcilie réellement le toggle ON à chaque boot (idempotent, IF NOT EXISTS).
    {
        spawn_reconcile_expr_indexes(db.clone());
    }

    // (v47) CREATE de l'index manquant idx_event_category EN FOND après le bind (jamais
    // synchrone : CREATE INDEX sur 2,39M lignes chiffrées bloquerait le bind). One-shot, idempotent.
    {
        spawn_ensure_event_category_index(db.clone());
    }

    // v110 (ALLÈGEMENT INDEX HOT — P5) — DROP EN FOND après le bind des index REDONDANTS idx_event_sev
    // (préfixe de idx_event_sev_srcip) et idx_event_src (préfixe de idx_event_src_ts) sur la base LIVE.
    // REMPLACE l'ancien spawn_ensure_event_source_index (CHANGE 4 v103) qui CRÉAIT idx_event_src, rendu
    // obsolète par le composite (source, ts) de v108. DROP INDEX = cheap (ne déchiffre pas la table) -> sûr en
    // fond. Gardé (source-seul droppé seulement quand idx_event_src_ts présent) -> zéro fenêtre de scan.
    {
        spawn_drop_redundant_event_indexes(db.clone());
    }

    // P10.2-d (ALLÈGEMENT INDEX, SUITE) — DROP EN FOND après le bind des NEUF index redondants que le schéma
    // migré posait encore, sur la base LIVE qui les porte déjà (les `CREATE INDEX` ont été retirés de
    // migrate.rs -> une base neuve ne les crée plus). Huit sont subsumés par l'AUTO-INDEX d'une contrainte
    // UNIQUE/PRIMARY KEY (présent par construction avec la table) -> DROP inconditionnel ; le neuvième
    // (idx_alert_mitre) est subsumé par un index EXPLICITE (idx_alert_mitre_ts, v72) -> DROP gardé par sa
    // présence confirmée, zéro fenêtre sans index de tête sur `mitre`. Même doctrine que v110 : DROP INDEX ne
    // déchiffre pas la table -> sûr en fond (un CREATE ne le serait pas).
    {
        spawn_drop_prefix_subsumed_indexes(db.clone());
    }

    // P6.8-b — DROP EN FOND après le bind des index `idx_ev_auto_*` ORPHELINS du mécanisme d'auto-index
    // adaptatif RETIRÉ. Son mainteneur était le SEUL code qui savait les dropper ; sans ceci ils seraient
    // des orphelins permanents (coût disque + un insert btree par ligne ingérée, que plus personne ne peut
    // retirer). La liste est DEMANDÉE à sqlite_master, jamais écrite en dur. En fond et NON en migration :
    // un bump de schéma rendrait la base illisible par le binaire précédent -> le rollback automatique de
    // la porte de déploiement deviendrait un cul-de-sac. Même doctrine que v110/P10.2-d.
    {
        spawn_drop_orphan_auto_field_indexes(db.clone());
    }

    // v108 (PERF recherche raw haut-volume) — CREATE de l'index COMPOSITE idx_event_src_ts(source,ts) EN FOND
    // après le bind (jamais synchrone : CREATE INDEX sur des millions de lignes chiffrées bloquerait le bind).
    // schema.sql le déclare (bases neuves) mais aucune migration ne le crée -> la base live en manque. Une fois
    // créé, `search source=X earliest=-Nd` range-prune ts (COUNT pagination index-only borné + page bornée) au
    // lieu de déchiffrer toute la table grasse. One-shot, idempotent (IF NOT EXISTS + court-circuit, même nom).
    {
        spawn_ensure_event_src_ts_index(db.clone());
    }

    // P3.7-a (PERF INGEST) — CREATE de l'index PARTIEL idx_event_health_beat(source,ts) WHERE
    // category='health' EN FOND après le bind (même doctrine anti-crashloop). Sans lui, les 8 sondes
    // dead-man's-switch de COLLECTORS remontent la plage de leur source ligne par ligne, sous le verrou
    // d'écriture, toutes les 20 s — coût mesuré `5 x (lignes depuis le dernier battement)`, donc O(N)
    // exactement quand le collecteur surveillé est mort. One-shot, idempotent (IF NOT EXISTS + court-circuit).
    {
        spawn_ensure_event_health_beat_index(db.clone());
    }

    // ANTI FULL-SCAN (rollup_hosts sur metric/snapshot) — CREATE des index ts-leading idx_metric_ts/idx_snapshot_ts
    // EN FOND après le bind (jamais synchrone : CREATE INDEX sur ~2M lignes metric chiffrées bloquerait le bind).
    // Une fois créés, rollup_hosts range-prune la fenêtre chaude/définitive (plus de full-scan+déchiffrement sous
    // le lock writer -> plus de famine ingest) et pipeline_is_fresh fait un MAX(ts) indexé O(1). One-shot, idempotent.
    {
        spawn_ensure_host_rollup_scan_indexes(db.clone());
    }

    // PHASE 1 — BACKFILL de event_fields_fts pour l'historique (1,24M lignes) EN FOND après bind.
    // No-op si PLUME_FTS_FIELDS!=1 ou backfill désactivé. Reprenable par watermark, gardé par meta.
    {
        spawn_fts_backfill(db.clone());
    }

    // #23 — PRÉ-CHAUFFAGE au boot (cold-read fix) : le 1er /api/integrations (~12 s FROID) / /api/overview
    // payait tout le déchiffrement SQLCipher à froid. On exécute UNE fois, APRÈS le bind + la liveness, un petit
    // lot BORNÉ de lectures (intégrations + fraîcheur + qq agrégats overview) sur le READ POOL pour peupler le
    // cache de pages 64 Mio AVANT le 1er clic (et remplir les caches SWR). Best-effort, jamais bloquant.
    {
        spawn_boot_prewarm(conf.clone(), db_path.clone(), bound.clone());
    }
}

// ---------- jobs de fond (refactor split #8) ----------
// Chaque std::thread::spawn de spawn_background_jobs() extrait en un helper spawn_<job>(...) prenant ses
// clones/valeurs PAR VALEUR. INVARIANT : ordre de creation des threads inchange, clone AU SITE D'APPEL
// (jamais dans le helper), intervalles/flags passes en parametres (aucun load_config re-lu), atomics de
// tick conserves DANS les closures, et les statements de boot synchrones (toggles/excl_clauses)
// restent inline dans spawn_background_jobs a leur place exacte.
fn spawn_ingest_loop(mgr: TenantDbManager, spool: String) {
        std::thread::spawn(move || {
            // ING-4 : balayage de démarrage des `.tmp` spool ORPHELINS (récepteur push crashé AVANT le rename ;
            // `ingest_once` les ignore -> fuite permanente sans ce sweep). Âge-gardé (épargne un POST en vol).
            let balayage = sweep_orphan_ingest_tmps(&spool, Duration::from_secs(INGEST_TMP_ORPHAN_MAX_AGE_SECS));
            let phrase = balayage.phrase("[ingest] .tmp spool au démarrage");
            if !phrase.is_empty() { eprintln!("{phrase}"); }
            loop {
                // P4.1-r — le passage rend son bilan (spool illisible, fichiers abandonnés) et la boucle le
                // PUBLIE : un spool qu'on ne sait plus énumérer n'est plus une boucle qui « tourne ».
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                bilan.absorber(ingest_once(&mgr, &spool));
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_INGEST, bilan.mesure());
                std::thread::sleep(Duration::from_secs(5));
            }
        });
}

fn spawn_rule_scheduler(tenants: TenantDbManager) {
        std::thread::spawn(move || loop {
            // P4.1-r — LE BILAN DU TICK : chaque famille rend ce qu'elle a abandonné, ou l'aveu qu'elle n'a
            // pas pu lire sa liste ; le planificateur absorbe tout et PUBLIE avant de marquer son tick. Un
            // tick qui n'a rien évalué ne peut plus passer pour un tick calme sur la surface d'état.
            let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
            for_each_active_tenant(&tenants, |tid, handle, db_path| {
                // CONC-2 : corps PAR TENANT isolé par catch_unwind (symétrie avec les boucles connecteurs/
                // destinations/rapports). Un panic dans l'évaluation d'une règle d'UN tenant est capturé -> les
                // autres tenants continuent ET le fil planificateur SURVIT (sans ce garde, un panic tuerait le
                // thread infini -> détection stoppée SILENCIEUSEMENT). Happy path INCHANGÉ.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut b = crate::bilan_de_tick::BilanDuPlanificateur::default();
                    b.absorber(run_due_rules(handle, db_path));
                    // #48/#53 : règles « avancées » (fenêtre de suppression / throttle-by-field / per-result),
                    // EXCLUES de run_due_rules et traitées à part (comme run_risk_rules). INERTE mode 0 (0 ligne due).
                    b.absorber(run_advanced_rules(handle, db_path));
                    // #24 (RBA) : règles en MODE RISK (risk_score>0, exclues de run_due_rules) -> CONTRIBUENT du
                    // risque par entité au lieu de lever une alerte scalaire. INERTE mode 0 (aucune règle risk).
                    b.absorber(run_risk_rules(handle, db_path));
                    // #37 (DÉTECTION AVANCÉE) : corrélation multi-événements stateful (finding-groups de séquence)
                    // + baselining statistique UEBA (déviation z-score par entité). MÊMES garanties fail-closed que
                    // run_due_rules (erreur/timeout ne fabrique JAMAIS un « tout clair »). INERTE mode 0 (tables
                    // correlation/baseline vides -> 0 ligne due -> retour immédiat, tick byte-identique).
                    b.absorber(run_correlations(handle, db_path));
                    b.absorber(run_baselines(handle, db_path));
                    b.absorber(run_playbooks(handle, db_path));
                    b.absorber(check_heartbeats(handle));
                    dispatch_notifications(handle);
                    escalate_overdue_cases(handle); // #4a — escalade SLA des cases overdue (INERTE si aucun)
                    sla_multilevel_tick(handle); // #39 — breach SLA MULTI-NIVEAU (ack/resolve). EARLY-RETURN si 0 politique (mode 0 : ZÉRO travail)
                    // v75 (MODE ENGAGEMENT) : auto-expiry des engagements + recompilation de l'index scope actif
                    // (tag d'ingest + guard auto-ban). SELF-GATED sur engagement_enabled() -> mode off = 0 travail
                    // (pas de lock, pas de SELECT) = tick byte-identique.
                    expire_due_engagements(handle);
                    if engagement_enabled() {
                        let c = handle.lock();
                        engagement_scope_refresh(db_path, &c);
                    }
                    b
                }));
                match res {
                    Ok(b) => bilan.absorber(b.bilan_de_tick()),
                    Err(_) => {
                        bilan.panique(tid);
                        eprintln!("[detect] panic capturé dans le tick de détection (tenant isolé) — planificateur préservé, on continue");
                    }
                }
            });
            crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_REGLES, bilan.mesure());
            // #51 DAY-2 OPS : marque le tick du scheduler de règles (santé « détection » = ce tick récent).
            SCHED_RULE_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            SCHED_RULE_LAST_TS.store(now(), std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(Duration::from_secs(20));
        });
}

/// BAN NATIF PLUME (chantier ② Phase 1) — thread de maintenance du store live `net_ban`. Charge le cache au
/// boot puis, toutes les 15 s : purge les bans EXPIRÉS de la table + recharge le cache in-mémoire (source de
/// vérité = la table ; capte les écritures du responder root séparé). Sur la base DEFAULT (l'enforcement HTTP
/// est GLOBAL, avant la résolution tenant -> Phase 1 = mono-base ; per-tenant = Phase 2). Fail-safe : base
/// illisible -> cache vidé (fail-open, aucune IP bloquée) au lieu d'un instantané figé.
fn spawn_netban_maintenance(db: Arc<Mutex<Connection>>) {
    std::thread::spawn(move || {
        {
            let c = db.lock();
            netban_reload(&c); // warm-up : bans persistés effectifs dès le bind
        }
        loop {
            std::thread::sleep(Duration::from_secs(15));
            let c = db.lock();
            let _ = c.execute("DELETE FROM net_ban WHERE expires_ts IS NOT NULL AND expires_ts <= ?1", params![now()]);
            netban_reload(&c);
        }
    });
}

fn spawn_connector_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(45)); // après le bind + le 1er rollup
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_connectors(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_CONNECTEURS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(15)); // granularité du scheduler
            }
        });
}

fn spawn_destination_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(50)); // après le bind + le 1er rollup (post-connecteurs)
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_destinations(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_DESTINATIONS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(15)); // granularité du scheduler de sortie
            }
        });
}

fn spawn_retention_loop(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(60));
            loop {
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    // db_path threadé (#18 FIX #2) : le tier cold en dérive une racine DISJOINTE par tenant
                    // (jamais le PLUME_COLD_DIR global partagé). Mode 0 : db_path==PLUME_DB -> racine cold
                    // HISTORIQUE inchangée. Le reste de la rétention IGNORE db_path (comportement identique).
                    retention_run_tenant(handle, db_path);
                });
                std::thread::sleep(Duration::from_secs(3600));
            }
        });
}

fn spawn_report_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(55)); // après le bind + le 1er rollup (post-destinations)
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_reports(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_RAPPORTS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(30)); // granularité du scheduler de rapports
            }
        });
}

fn spawn_custom_roles_refresh(tenants: TenantDbManager) {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(45));
            if let Some(cp) = tenants.control.as_ref() {
                reload_custom_roles(cp);
            }
        });
}

fn spawn_rollup_loop(tenants: TenantDbManager, rollup_interval: u64, disk_warn_pct: u8, warm_freshness: bool) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(90));
            loop {
                // P4.1-r — les incidents de risque sont une DÉTECTION qui tourne dans cette boucle-ci :
                // leur bilan est publié à part, et la surface « détection » le lit avec celui des règles.
                let mut bilan_risque = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    {
                        let c = handle.lock();
                        rollup_events(&c);
                        materialize_banned_ip(&c);   // banlist matérialisée (incrémentale, bornée) -> anti-join cheap
                        // #23 — rafraîchit le CACHE de match threat-intel de CE tenant (keyé db_path). Cheap
                        // (lit la petite table `ioc`, exclut les expirés). Vide en mode 0 -> no-op. Discipline
                        // host_rollup : le match-on-ingest lit ce cache O(1), JAMAIS un SELECT par event.
                        ioc_cache_reload(&c, db_path);
                        // #24 (RBA) : matérialise risk_rollup (agrégat par entité, reconstruit depuis la
                        // petite table risk_event -> DECAY fenêtré) + déclenche les alertes risk-based. Mode 0
                        // (aucun risk_event) -> fast-path retour immédiat. JAMAIS un scan de `event`.
                        bilan_risque.absorber(rollup_risk(&c));
                    }
                    // F5 : l'appel `cache_refresh_all_panels` a été RETIRÉ d'ici (boucle rollup 120 s) — la
                    // boucle DÉDIÉE de refresh (`spawn_panel_refresh_loop`, ~10 s) appelle EXACTEMENT la même
                    // fonction avec les mêmes args (même `handle`/`db_path` par-tenant, même `refresh_sem`) et
                    // dérive son ensemble de panneaux EN INTERNE (SELECT ... FROM panel) -> ensemble IDENTIQUE,
                    // à cadence plus fine. Refresh idempotent (INSERT OR REPLACE, borné par refresh_sem) : rien
                    // ne cesse d'être rafraîchi. Cette boucle n'a donc plus besoin du refresh_sem (retiré de sa
                    // signature) ; seule la boucle de refresh dédiée le porte.
                    if warm_freshness {
                        // pré-chauffage TOUS-ENV (#2d) : clé = db_path (env_range_key(None,..)) ; les vues
                        // par-env sont calculées à la demande dans le handler freshness.
                        let nv = compute_freshness(db_path, None);
                        freshness_map().lock().insert(db_path.to_string(), (Instant::now(), nv));
                    }
                });
                // GARDE-FOU #29 : alerte pré-saturation disque — UNE fois par tick (ressource HÔTE, pas
                // par-tenant ; dedup horaire = 1 warn/heure). Mesure le volume de la base par défaut (même
                // PVC que le spool). INERTE si seuil=0. Émis dans la base par défaut (posture host-wide).
                if disk_warn_pct != 0 {
                    let dir = std::path::Path::new(tenants.default_db_path.as_str())
                        .parent()
                        .filter(|d| !d.as_os_str().is_empty())
                        .map(|d| d.to_string_lossy().into_owned())
                        .unwrap_or_else(|| ".".to_string());
                    { let c = tenants.default_writer.lock();
                        emit_disk_health(&c, &dir, disk_warn_pct, now());
                    }
                }
                // P10.11-a — CE QUE LES REQUÊTES ONT ATTENDU PENDANT CE TICK, et quelle part du tick
                // une passe de vieillissement couvrait. UNE fois par tick (l'accumulateur est de
                // PROCESSUS, pas par-tenant) et dans la base par défaut : exactement la posture
                // host-wide de l'alerte de saturation disque ci-dessus, pour la même raison. Écrire
                // le même accumulateur dans chaque base compterait le même temps d'attente autant de
                // fois qu'il y a de tenants. Onze `INSERT` au plus, verrou tenu pour eux seuls.
                { let c = tenants.default_writer.lock();
                    crate::attente_serie::publier_fenetre(&c, now());
                }
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_RISQUE, bilan_risque.mesure());
                // #51 DAY-2 OPS : marque le tick de rollup (santé « rollups » = ce tick récent).
                SCHED_ROLLUP_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                SCHED_ROLLUP_LAST_TS.store(now(), std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(rollup_interval));
            }
        });
}

fn spawn_panel_refresh_loop(tenants: TenantDbManager, refresh_sem: Arc<tokio::sync::Semaphore>, refresh_s: u64) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(35)); // après le bind + le 1er rollup
            loop {
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    cache_refresh_all_panels(handle, db_path, &refresh_sem);
                });
                std::thread::sleep(Duration::from_secs(refresh_s));
            }
        });
}

pub(crate) async fn run() {
    let BootConfig { conf, db_path, spool, addr, user, pass, webdir, host, host_strict, sso_secret, public_demo, metrics_token, sso_group_admin, sso_group_editor, sso_group_superadmin, sso_header_user, sso_header_groups, tls_cert, tls_key, tls_on, lock_threshold, lock_base_s, lock_max_s, rl_ip_max, rl_auth_max, rl_global_max, session_ttl_s, session_secret, ingest_min_free_mb, ingest_max_events, search_limit_default, search_limit_max, query_sem, refresh_sem, bound } = boot_config();
    let conn = open_and_migrate_db(db_path.clone(), spool.clone(), conf.clone());
    let db = Arc::new(Mutex::new(conn));
    // PLAFOND MÉMOIRE : on RAPPORTE ce que le processus va faire, et on le rappelle (idempotent — l'effet
    // a déjà eu lieu en tête de `main`, seul endroit assez tôt pour que SQLite le voie).
    // APRÈS l'ouverture, délibérément (`S38`) : la mesure que la bannière publie est LUE sur la connexion
    // qui sert, armée par la porte — une sonde nue ne porte pas `temp_store=FILE`, et sous déversement
    // la bannière contredisait le mode à chaque démarrage.
    eprintln!(
        "[plafond] {}",
        sqlite_plafond::banniere(
            sqlite_plafond::deversement_init(&db_path),
            sqlite_plafond::tri_de_la_connexion_qui_sert(&db.lock())
        )
    );
    // TIER FROID : ce que ce binaire SAIT faire, et ce qu'il FAIT. Un composant qui travaille sans le dire
    // est indistinguable d'un composant ABSENT — c'est ce qui a laissé la production croire trois jours à
    // un tier froid que le binaire ne portait plus. APRÈS l'ouverture de la base, délibérément : la fenêtre
    // chaude et la rétention cold sont des SETTINGS clampés, les publier sans les lire serait les inventer.
    eprintln!("[cold] {}", cold_banniere::banniere(cold_banniere::etat(&db.lock(), &conf, &db_path)));
    // JOURNAL D'ÉCRITURE ANTICIPÉE (P10.16-a) : une borne d'espace qu'un exploitant ne peut pas LIRE au
    // démarrage n'est pas opposable — et celle-ci doit surtout dire ce qu'elle ne borne PAS, sinon elle
    // laisserait croire que la crête d'une rafale est tenue alors que seul le RÉSIDU l'est.
    eprintln!("[wal] {}", wal_empreinte::borne_courante().phrase());
    // L2 — EPOCH de session persistant (meta) chargé au boot -> mint/verify_session le mélangent au HMAC.
    // Survit au redémarrage : un logout/reset AVANT un crash reste effectif après relance.
    let session_epoch = Arc::new(std::sync::atomic::AtomicI64::new(load_session_epoch(&db.lock())));
    {
        let c = load_config();
        let conn = db.lock();
        ledger_append(&conn, "daemon.start", "démarrage plume-daemon");
        // v105 (CHANGE 2 / STEP 1 backstop) — CUTOVER VAULT : si le chemin ACTIF de la clé est un Secret
        // non-legacy ET qu'un fichier legacy résiduel coexiste (fenêtre de cutover), les DEUX clés DOIVENT
        // être identiques. Un écart = la clé escrow dans Vault n'a PAS signé la chaîne existante -> fork
        // SILENCIEUX de la tamper-evidence. Refus-de-boot (défendable : ne se déclenche QUE pendant la
        // coexistence transitoire des deux fichiers, jamais en régime permanent). Trace SOC non-purgeable
        // émise AVANT l'arrêt. On teste les résidus legacy plausibles : la valeur `PLUME_LEDGER_KEY` (compat)
        // ET le chemin on-PVC du manifest live (`/data/ledger.key`).
        let active_key_path = ledger_key_active_path(&c);
        let mut legacy_candidates = vec![cfg(&c, "PLUME_LEDGER_KEY", LEDGER_KEY_LEGACY_DEFAULT), "/data/ledger.key".to_string()];
        legacy_candidates.sort();
        legacy_candidates.dedup();
        for legacy in &legacy_candidates {
            if ledger_key_cutover_check(&active_key_path, legacy) == LedgerKeyCutover::Mismatch {
                let _ = emit_ledger_key_mismatch(&conn, now(), &active_key_path, legacy);
                crate::db_open::checkpoint_wal_tronque(&conn, "arret-cle-ledger"); // durcit la trace avant exit
                eprintln!(
                    "[ledger] REFUS DE DÉMARRER : clé ledger Vault active '{active_key_path}' ≠ clé legacy \
                     résiduelle '{legacy}'. Escrow le BON hex (celui qui a signé la chaîne) avant le cutover, \
                     ou retirer le résidu legacy. Arrêt propre."
                );
                std::process::exit(1);
            }
        }
        // SECRET-PROVIDER PHASE 1 (hygiène finale) — retrait SÛR et IDEMPOTENT du résidu legacy
        // /data/ledger.key. On ne le retire QUE si le cutover Vault est PROUVÉ cohérent (verdict `Match` :
        // chemin actif non-legacy + résidu présent + clé Ed25519 IDENTIQUE). On atteint ce point UNIQUEMENT
        // sans Mismatch (la boucle ci-dessus aurait exit) -> `ledger_residue_removable` ne renvoie true que sur
        // Match, JAMAIS sur active-legacy ni sur un résidu divergent : le résidu n'est retiré qu'une fois sa
        // redondance PROUVÉE. Best-effort : un échec d'unlink NE BLOQUE PAS le boot (le résidu inerte ne nuit
        // pas et reste re-vérifié par le backstop). Tracé au ledger (tamper-evident).
        {
            let residue = "/data/ledger.key";
            if ledger_residue_removable(&active_key_path, residue) {
                match std::fs::remove_file(residue) {
                    Ok(()) => {
                        eprintln!("[ledger] résidu legacy '{residue}' retiré (cutover Vault prouvé cohérent : clé identique)");
                        ledger_append(&conn, "ledger.residue_removed", &format!("résidu legacy {residue} retiré (cutover cohérent, clé identique à {active_key_path})"));
                    }
                    Err(e) => eprintln!("[ledger] retrait du résidu '{residue}' échoué ({e}) — boot poursuivi (résidu inerte, re-vérifié au prochain boot)"),
                }
            }
        }
        // v105 (STEP 2) — signe le checkpoint si la clé est disponible ; sinon, sur un chemin Secret non-legacy,
        // émet un signal SOC NON-PURGEABLE de signature dégradée (clé absente/vide -> checkpoints non signés).
        match ledger_key(&c) {
            Some(k) => sign_checkpoint(&conn, &k),
            None => if !ledger_key_path_is_legacy(&active_key_path) {
                let _ = emit_ledger_unsigned(&conn, now(), &active_key_path);
            }
        }
        // v135 (#7) — CORRECTIF FAUX POSITIF : la posture backup N'EST PLUS asserted ICI. Le check de boot v134
        // émettait un signal SOC NON-PURGEABLE « posture backup dégradée » à CHAQUE restart, sans qu'aucun backup
        // ait été produit. Les signaux de posture — symétrique ET exercice de restauration dû — vivent dans
        // les chemins qui PRODUISENT une archive (backup/ : warn + gate fail-closed
        // PLUME_BACKUP_REQUIRE_ASYMMETRIC ; main.rs : la sous-commande `backup` ; `scheduled_backup_cycle`
        // ci-dessous : le cycle natif, après le rename qui publie — P8.25-a, P8.26-a). Ce processus PRODUIT des
        // backups, par `spawn_backup_scheduler`, dans l'unique conteneur du manifeste livré (lu le 2026-08-22
        // dans `deploy/k3s.yaml`) : les signaux partent de ce cycle-là, pas du démarrage.
        // Voir la note de `signal_backup_symmetric_if_needed`.
    }

    // MULTI-TENANT (#2a-2a) — IDENTITÉ & CATALOGUE, INERTE en mode 0. Le control-plane est ouvert/initialisé
    // LAZY UNIQUEMENT si PLUME_MULTI_TENANT=1 (mode 0 -> None : rien n'est créé, comportement identique).
    // PENDING #2a-2b : les handlers data lisent ENCORE st.db -> le mode 1 n'est PAS fonctionnel end-to-end
    // (2 tenants partageraient la base) -> NE PAS activer =1 en prod tant que #2a-2b n'est pas livré.
    let multi_tenant = multi_tenant_enabled(&conf);
    let control = if multi_tenant {
        match init_control_plane(&conf, &db_path) {
            Ok(cp) => {
                eprintln!(
                    "[multi-tenant] PLUME_MULTI_TENANT=1 : control-plane {} initialisé (IDENTITÉ+CATALOGUE) — \
                     data-isolation par tenant PENDING #2a-2b, NE PAS activer en prod",
                    cp.db_path
                );
                // #59 : charge le catalogue de rôles COMPOSABLES depuis le control-plane. Mode 0 (control=None)
                // -> jamais appelé -> cache VIDE -> tous les chemins RBAC byte-identiques.
                reload_custom_roles(&cp);
                Some(cp)
            }
            Err(e) => {
                eprintln!("[multi-tenant] ÉCHEC init control-plane: {e} — mode 1 NON fonctionnel (identité retombe sur la base unique)");
                None
            }
        }
    } else {
        None
    };
    let tenants = TenantDbManager {
        default_db_path: Arc::new(db_path.clone()),
        default_writer: db.clone(),
        control,
        writers: Arc::new(Mutex::new(HashMap::new())),
    };
    spawn_background_jobs(conf.clone(), spool.clone(), db_path.clone(), db.clone(), tenants.clone(), refresh_sem.clone(), bound.clone());

    let admin0: Option<(String, String)> = {
        let c = db.lock();
        // ANTI-FUITE PAR EXPORT — le hash admin n'est PLUS lu depuis meta (il y était exfiltrable en SQL
        // brut admin). Source de vérité = user.hash (protégé par l'authorizer read-pool). set_admin écrit déjà
        // user(name,hash,role='admin') ; la migration v10 a seedé user depuis l'ancien meta.admin_hash. On PURGE
        // la copie héritée en clair au démarrage (idempotent ; ne casse rien puisqu'on lit désormais user.hash).
        let _ = c.execute("DELETE FROM meta WHERE key='admin_hash'", []);
        match c.query_row("SELECT value FROM meta WHERE key='admin_user'", [], |r| r.get::<_, String>(0)) {
            Ok(u) => c
                .query_row("SELECT hash FROM user WHERE name=?1 AND role='admin'", params![u], |r| r.get::<_, String>(0))
                .ok()
                .map(|h| (u, h)),
            Err(_) => None,
        }
    };
    let setup_token = if admin0.is_none() && pass.is_empty() {
        use std::os::unix::fs::PermissionsExt;
        // Le token d'installation ouvre le compte ADMIN à un anonyme : il n'est FABRIQUÉ qu'à partir
        // d'entropie réelle (cf. `setup_token_from_entropy`). Aucune entropie -> aucun token -> `/api/setup`
        // refuse tout (fail-closed) et on le DIT, au lieu de servir un secret énumérable.
        match setup_token_from_entropy(setup_token_entropy()) {
            Some(tok) => {
                let tp = std::path::Path::new(&db_path).with_file_name("setup-token.txt");
                let _ = std::fs::write(&tp, &tok);
                let _ = std::fs::set_permissions(&tp, std::fs::Permissions::from_mode(0o600));
                eprintln!("\n===== SETUP MODE — token d'installation (usage unique) =====\n  {tok}\n  -> ouvre la page, ⚙️ Réglages : colle ce token + définis tes identifiants.\n  (aussi dans : {})\n===========================================================\n", tp.display());
                tok
            }
            None => {
                eprintln!("\n===== SETUP IMPOSSIBLE — aucune source d'entropie (ni /dev/urandom ni getrandom) =====\n  AUCUN token d'installation n'est émis : /api/setup REFUSERA tout appel.\n  Répare l'entropie de l'hôte et redémarre, ou pose PLUME_PASS_HASH (plume-daemon hashpw).\n=====================================================================================\n");
                String::new()
            }
        }
    } else {
        // F4 — plus en mode setup (un admin existe / pass défini) : on efface tout `setup-token.txt`
        // RÉSIDUEL d'un premier boot (inerte car la route setup est gated sur admin0.is_none(), mais c'est
        // un token en clair token-shaped sur /data). shred (écrasement best-effort) + unlink. Idempotent.
        let tp = std::path::Path::new(&db_path).with_file_name("setup-token.txt");
        if tp.exists() {
            shred_file(&tp.to_string_lossy());
            eprintln!("[setup] token d'installation résiduel effacé ({})", tp.display());
        }
        String::new()
    };
    let state = AppState {
        db,
        user: Arc::new(user),
        pass_hash: Arc::new(pass),
        admin: Arc::new(Mutex::new(admin0)),
        setup_token: Arc::new(setup_token),
        host: Arc::new(host.clone()),
        host_strict,
        sso_secret: Arc::new(sso_secret),
        sso_group_admin: Arc::new(sso_group_admin),
        sso_group_editor: Arc::new(sso_group_editor),
        sso_group_superadmin: Arc::new(sso_group_superadmin),
        sso_header_user: Arc::new(sso_header_user),
        sso_header_groups: Arc::new(sso_header_groups),
        public_demo,
        metrics_token: Arc::new(metrics_token),
        search_limit_default,
        search_limit_max,
        db_path: Arc::new(db_path.clone()),
        spool: Arc::new(spool.clone()),
        auth_cache: Arc::new(Mutex::new(HashMap::new())),
        rl: Arc::new(Mutex::new((Instant::now(), 0))),
        query_sem,
        // Sémaphore d'ingest décompression-lourde (OTLP) — SÉPARÉ de l'interactif. Défaut 4, au moins 1.
        ingest_sem: Arc::new(tokio::sync::Semaphore::new(
            cfg(&conf, "PLUME_OTLP_INGEST_CONCURRENCY", "4").parse().unwrap_or(4).max(1),
        )),
        refresh_sem,
        panel_refresh_inflight: Arc::new(Mutex::new(HashSet::new())),
        auth_fails: Arc::new(Mutex::new(HashMap::new())),
        lock_threshold,
        lock_base_s,
        lock_max_s,
        rl_ip: Arc::new(Mutex::new(HashMap::new())),
        rl_ip_max,
        rl_auth_max,
        rl_global_max,
        session_secret: Arc::new(session_secret),
        session_ttl_s,
        session_epoch,
        ingest_min_free_mb,
        ingest_max_events,
        multi_tenant,
        tenants,
    };

    let app = build_router(state, webdir);

    let port: u16 = addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(7000);
    let hostpart = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1");
    // ConnectInfo<SocketAddr> est posé sur CHAQUE listener (HTTP comme HTTPS) -> auth_guard/rate_limit
    // disposent de l'IP source (lockout + rate-limit per-IP). On NE fait PAS confiance à X-Forwarded-For.
    if tls_on {
        // TLS NATIF (item 1) : HTTPS rustls/ring via axum-server. Provider ring installé une fois
        // (aws-lc-rs exigerait cmake/nasm absents). HSTS émis par security_headers (TLS_ON).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = match axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls_cert, &tls_key).await {
            Ok(c) => c,
            Err(e) => panic!("TLS: lecture du cert/clé PEM échouée (PLUME_TLS_CERT={tls_cert} / PLUME_TLS_KEY={tls_key}): {e}"),
        };
        // bind = l'addr configuré (IP:port) ; à défaut d'IP parsable (ex hostname) -> loopback:port.
        let bind: std::net::SocketAddr = addr.parse().unwrap_or_else(|_| (std::net::Ipv4Addr::LOCALHOST, port).into());
        println!("plume-daemon: https://{host}:{port}  (TLS rustls/ring, bind {bind})  db={db_path}");
        bound.store(true, std::sync::atomic::Ordering::Relaxed);
        READY.store(true, std::sync::atomic::Ordering::Relaxed); // #51 DAY-2 : migrations faites + port bindé -> /readyz 200 // #32 : port sur le point d'écouter -> débloque le ANALYZE de fond
        let _ = axum_server::bind_rustls(bind, tls)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    } else if hostpart.is_empty() || hostpart == "127.0.0.1" || hostpart == "localhost" {
        // défaut sécurisé (bare-metal) : localhost v4 + v6 uniquement — HTTP en clair (k3s inchangé)
        let v4 = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("bind 127.0.0.1");
        bound.store(true, std::sync::atomic::Ordering::Relaxed);
        READY.store(true, std::sync::atomic::Ordering::Relaxed); // #51 DAY-2 : migrations faites + port bindé -> /readyz 200 // #32 : listener bindé -> débloque le ANALYZE de fond
        let app6 = app.clone();
        let t4 = tokio::spawn(async move {
            let _ = axum::serve(v4, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
        });
        let t6 = tokio::spawn(async move {
            if let Ok(v6) = tokio::net::TcpListener::bind(("::1", port)).await {
                let _ = axum::serve(v6, app6.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
            }
        });
        println!("plume-daemon: http://{host}:{port}  (bind 127.0.0.1 + ::1)  db={db_path}");
        let _ = tokio::join!(t4, t6);
    } else {
        // bind explicite (container/k8s : 0.0.0.0, [::], IP) — protégé par basic_auth + host_guard (PLUME_HOST)
        let l = tokio::net::TcpListener::bind(addr.as_str()).await.unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        bound.store(true, std::sync::atomic::Ordering::Relaxed);
        READY.store(true, std::sync::atomic::Ordering::Relaxed); // #51 DAY-2 : migrations faites + port bindé -> /readyz 200 // #32 : listener bindé (k8s 0.0.0.0:7000) -> débloque le ANALYZE de fond
        println!("plume-daemon: bind {addr}  (host autorisé: {host})  db={db_path}");
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
    }
}
