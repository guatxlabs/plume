//! Épine dorsale du contexte de requête (multi-tenant) : `AppState` (hub Clone), `AuthUser`, le
//! control-plane (`ControlPlane` + migration/clés/`init_control_plane`/`resolve_tenant_key`), le registre
//! de bases par tenant (`TenantDbManager`), la résolution d'identité (`TokenIdent`/`token_lookup`/
//! `lookup_basic_ident`), le routage DB par requête (`req_db`/`req_db_path`/`for_each_active_tenant`),
//! les marqueurs slug/spool + cibles d'ingest et `resolve_user_tenant`. Extrait de main.rs (refactor
//! split #25 — byte-identique).
use crate::*;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) user: Arc<String>,
    pub(crate) pass_hash: Arc<String>,
    // admin défini via le wizard (stocké en DB) — prioritaire sur la config ; None+pass vide = setup mode
    pub(crate) admin: Arc<Mutex<Option<(String, String)>>>,
    // token d'installation à usage unique (setup mode) ; vide sinon
    pub(crate) setup_token: Arc<String>,
    pub(crate) host: Arc<String>,
    // DURCISSEMENT STANDALONE — allowlist Host STRICTE (PLUME_HOST_STRICT=1) : host_guard n'accepte
    // QUE les FQDN de PLUME_HOST (retire l'auto-allow loopback). Défaut false = comportement actuel
    // (loopback 127.0.0.1/::1/localhost accepté en plus) -> k3s + vérifs ClusterIP inchangés.
    pub(crate) host_strict: bool,
    // SSO délégué (trusted-header derrière le forward-auth Authentik) : secret partagé injecté par
    // Traefik (anti-usurpation du chemin direct/ClusterIP) + mapping groupe->rôle. Vide = désactivé.
    pub(crate) sso_secret: Arc<String>,
    pub(crate) sso_group_admin: Arc<String>,
    pub(crate) sso_group_editor: Arc<String>,
    pub(crate) sso_group_superadmin: Arc<String>,   // groupe superuser (ex admins) -> admin partout (anti-lockout)
    // VENDOR-AGNOSTIC (C1) — NOMS des en-têtes trusted-header lus sur le chemin SSO délégué. Défauts =
    // x-authentik-username / x-authentik-groups (comportement historique GUATX byte-identique). Un client
    // derrière Okta/Keycloak/oauth2-proxy/tout forward-auth pose ses propres noms (PLUME_SSO_HEADER_USER /
    // PLUME_SSO_HEADER_GROUPS). Ces noms ne sont lus QUE sur le chemin déjà authentifié par le secret partagé
    // (x-plume-sso-secret) : changer le NOM ne contourne NI le secret NI l'overwrite du forward-auth.
    pub(crate) sso_header_user: Arc<String>,
    pub(crate) sso_header_groups: Arc<String>,
    // DÉMO PUBLIQUE (PLUME_PUBLIC_DEMO=1, OPT-IN) : accès ANONYME forcé en LECTURE SEULE (rôle viewer).
    // JAMAIS en prod. À combiner avec PLUME_DEMO=1 (données factices) + instance ISOLÉE de la prod.
    pub(crate) public_demo: bool,
    // #51 DAY-2 OPS — jeton de scrape /metrics (PLUME_METRICS_TOKEN). Non vide -> un scraper Prometheus
    // présente `Authorization: Bearer <token>` (comparé constant-time dans auth_guard) et lit /metrics sans
    // compte. Vide (DÉFAUT) -> /metrics EXIGE une auth viewer+ normale (jamais anonyme au monde). N'affecte
    // aucune autre route -> mode 0 byte-identique.
    pub(crate) metrics_token: Arc<String>,
    // Recherche : limite par défaut + plafond (max match) RÉGLABLES (env PLUME_SEARCH_LIMIT / PLUME_SEARCH_MAX).
    pub(crate) search_limit_default: i64,
    pub(crate) search_limit_max: i64,
    pub(crate) db_path: Arc<String>,
    pub(crate) spool: Arc<String>,
    // cache d'auth : header Authorization -> (nom, rôle, instant de validation)
    pub(crate) auth_cache: Arc<Mutex<HashMap<String, (String, String, Instant)>>>,
    // rate-limit global : (début de fenêtre, compteur)
    pub(crate) rl: Arc<Mutex<(Instant, u32)>>,
    // Sémaphore de concurrence de l'INTERACTIF (/api/query / /api/search) UNIQUEMENT : borne le nombre de
    // spawn_blocking simultanés sur le pool read-only chiffré (chaque requête déchiffre des pages -> CPU).
    // Taille via cfg PLUME_QUERY_CONCURRENCY (défaut 3). Le refresh des panneaux N'Y TOUCHE PLUS (cf.
    // refresh_sem) -> l'interactif n'attend jamais derrière un rafraîchissement de tuiles.
    pub(crate) query_sem: Arc<tokio::sync::Semaphore>,
    // Sémaphore de concurrence des récepteurs d'ingest à DÉCOMPRESSION-lourde (OTLP /v1/traces) : borne le
    // nombre de corps décompressés (≤ OTLP_MAX_DECOMPRESS) PARSÉS SIMULTANÉMENT en `serde_json::Value`, pour
    // que N requêtes concurrentes ne MULTIPLIENT pas le pic mémoire par-requête (un arbre Value ≤16 Mio par
    // permit). SÉPARÉ de query_sem (interactif) : l'ingest ne vole/n'affame jamais l'interactif et vice-versa.
    // Saturé -> 503 (le client OTLP rejoue). Taille via PLUME_OTLP_INGEST_CONCURRENCY (défaut 4, au moins 1).
    pub(crate) ingest_sem: Arc<tokio::sync::Semaphore>,
    // CHANGEMENT 1 — sémaphore SÉPARÉ du refresh ASYNC des panneaux (Phase 3b + cache_refresh_all_panels) :
    // le refresh SWR prend des permis ICI (jamais sur query_sem) -> il ne vole PLUS de permis à l'interactif
    // (mesuré : sem_wait interactif ~0 même quand 14 panneaux se rafraîchissent). Taille via
    // PLUME_PANEL_REFRESH_CONCURRENCY (défaut 2). try_acquire (jamais await) : si saturé, le cache périmé
    // reste servi (jamais d'affamage de l'interactif, jamais de blocage du refresh).
    pub(crate) refresh_sem: Arc<tokio::sync::Semaphore>,
    // PHASE 3b — anti-stampede du refresh SWR des panneaux : un seul refresh async EN VOL par clé
    // (panel_id, range_key). Inséré à l'enqueue, retiré en fin de tâche -> jamais de tempête de refresh.
    pub(crate) panel_refresh_inflight: Arc<Mutex<HashSet<(i64, String)>>>,
    // DURCISSEMENT STANDALONE — anti-brute-force (item 2) : compteur d'échecs d'auth Basic par
    // (username, src_ip) -> backoff exponentiel + lockout temporaire + AUTO-INGEST SIEM (source=plume-auth).
    // Borné (TTL court + cap d'entrées). TRANSPARENT au légitime : seul un échec d'identifiants RÉELLEMENT
    // présentés compte, un succès réarme, et le seuil est généreux (un usage normal ne l'atteint jamais).
    pub(crate) auth_fails: Arc<Mutex<HashMap<(String, String), AuthFail>>>,
    pub(crate) lock_threshold: u32,   // PLUME_AUTH_LOCK_THRESHOLD (0 = lockout désactivé), défaut 10
    pub(crate) lock_base_s: u64,      // PLUME_AUTH_LOCK_BASE_S (1re durée de lockout), défaut 30
    pub(crate) lock_max_s: u64,       // PLUME_AUTH_LOCK_MAX_S (plafond du backoff), défaut 900
    // DURCISSEMENT STANDALONE — rate-limit PAR IP source (item 4) : résout le self-DoS du plafond GLOBAL
    // (une IP qui sature ne renvoie plus 429 à TOUTES les autres, opérateur inclus). Routes d'auth =
    // budget plus strict que le polling UI. Borné (purge fenêtre glissante). k3s = 1 IP Traefik -> mêmes
    // bornes qu'avant (transparent).
    pub(crate) rl_ip: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    pub(crate) rl_ip_max: u32,        // PLUME_RL_IP_MAX (req/10s par IP, hors routes d'auth), défaut 1200
    pub(crate) rl_auth_max: u32,      // PLUME_RL_AUTH_MAX (req/10s par IP sur /api/setup|/api/password), défaut 120
    pub(crate) rl_global_max: u32,    // PLUME_RL_GLOBAL_MAX (garde-fou global req/10s), défaut 6000
    // `P4.13-a` (reprise) — BUDGET D'OCTETS DE LA SURFACE PUBLIQUE (cf. `budget_du_shell_public`). Ouvrir le
    // shell à un anonyme a fait passer le prix d'une requête sans identité de 12 octets / 0,21 ms d'UC à
    // 1,9 Mio / ~6,5 ms de `gzip` (MESURÉ) ; les plafonds ci-dessus, eux, avaient été dimensionnés sur
    // l'ancien prix. La borne est en OCTETS et non en requêtes, pour qu'un 304 de revalidation — qui ne
    // porte aucun corps — ne consomme rien : elle ne pèse que sur le client qui omet l'en-tête conditionnel.
    // La clé est l'IP RÉELLE (`real_client_ip`), donc l'analyste et non la grappe derrière un Traefik k3s.
    pub(crate) shell_octets_ip: Arc<Mutex<HashMap<String, (Instant, u64)>>>,
    pub(crate) shell_octets_global: Arc<Mutex<(Instant, u64)>>,
    pub(crate) shell_octets_ip_max: u64,      // PLUME_SHELL_OCTETS_IP_MAX (octets/10 s par IP réelle), défaut 64 Mio
    pub(crate) shell_octets_global_max: u64,  // PLUME_SHELL_OCTETS_GLOBAL_MAX (octets/10 s, tous clients), défaut 256 Mio
    // FORM-LOGIN (4e méthode d'auth, ADDITIVE) : cookie de session signé HMAC posé par /api/login.
    // `session_secret` = clé HMAC (env PLUME_SESSION_SECRET ou clé persistée 0600 ; JAMAIS en dur).
    // `session_ttl_s` = durée de vie du jeton (PLUME_SESSION_TTL_S, défaut 12h). N'altère AUCUN des
    // chemins Basic/SSO/Bearer : ceux-ci restent intacts (le cookie s'AJOUTE, il ne remplace rien).
    pub(crate) session_secret: Arc<Vec<u8>>,
    pub(crate) session_ttl_s: i64,
    // L2 (RÉVOCATION DE SESSION) — EPOCH GLOBAL de session mélangé au HMAC des jetons (mint/verify_session).
    // Chargé de meta (`session_epoch`) au boot, persisté. INCRÉMENTÉ par /api/logout ET par un changement de
    // mot de passe -> TOUS les cookies antérieurs (y compris un cookie EXFILTRÉ) échouent à la vérif HMAC =
    // révocation SERVEUR effective (pas seulement l'effacement navigateur). Le TTL existant est conservé
    // (double borne : temps + epoch). Mode 0/1 identiques (mécanisme d'auth cookie global, pas per-tenant).
    pub(crate) session_epoch: Arc<std::sync::atomic::AtomicI64>,
    // L1 (GARDE DISQUE/CARDINALITÉ À L'INGEST — anti disk-pressure, rejeu de l'incident) — seuils via cfg
    // (env/conf), posés TRÈS au-dessus d'un batch légitime : on ne coupe QU'un flux pathologique / un disque
    // saturé, JAMAIS la collecte réelle. Le refus est EXPLICITE (l'agent réémet plus tard), jamais une
    // troncature silencieuse. Le daemon MESURE le disque, il ne pilote PAS l'hôte.
    pub(crate) ingest_min_free_mb: u64,   // PLUME_INGEST_MIN_FREE_MB (0 = garde disque désactivé), défaut 512
    pub(crate) ingest_max_events: usize,  // PLUME_INGEST_MAX_EVENTS (plafond dur events/req), défaut 50000
    // MULTI-TENANT (#2, D2) — DÉFAUT false (mode 0 SMB inchangé). Cf. multi_tenant_enabled().
    // INERTE en #2a-2a : posé mais consommé par /api/me + le gating des handlers en #2a-2b.
    #[allow(dead_code)]
    pub(crate) multi_tenant: bool,
    // Résolveur tenant -> (db_path, clé) + handle (#2a-2a). Mode 0 : passthrough EXACT (tenant `default` =
    // st.db_path/st.db). INERTE : utilisé UNIQUEMENT par la couche identité ; les handlers data lisent
    // ENCORE st.db (la data-isolation par tenant est PENDING #2a-2b). `tenants.control` = Some seulement
    // en mode 1 (control-plane ouvert) -> sert d'aiguillage aux accesseurs d'identité (token/user).
    pub(crate) tenants: TenantDbManager,
}

// Identité authentifiée, injectée dans les extensions de requête par auth_guard.
#[derive(Clone)]
pub(crate) struct AuthUser {
    pub(crate) name: String,
    pub(crate) role: String, // admin | editor | viewer | agent
    // TENANT COURANT (#2a-2b) : la base vers laquelle req_db/req_db_path routent CETTE requête. Mode 0 :
    // TOUJOURS "default" (= st.db/st.db_path -> comportement STRICTEMENT identique). Mode 1 : agent -> tenant
    // du token ; user -> tenant sélectionné/1er grant (résolu par auth_guard, fail-closed sinon 403).
    pub(crate) tenant: String,
    // SUPER-ADMIN PLATEFORME (#2b/D3) : `platform_user.is_superadmin` (opérateur ESN), résolu par auth_guard.
    // N'est PAS tenant-admin d'office (le rôle per-tenant `role` reste viewer hors grant). Mode 0 : TOUJOURS
    // false (aucun control-plane). Exposé par /api/me (bandeau opérateur côté SPA) ; le marqueur d'accès
    // cross-tenant, lui, est émis STRUCTURELLEMENT dans auth_guard (R9), jamais par un handler.
    pub(crate) is_superadmin: bool,
    // FORM-LOGIN : méthode d'auth retenue (cookie | basic | sso | bearer | demo) + token CSRF attendu
    // (non vide UNIQUEMENT pour l'auth par cookie -> exposé par /api/me au SPA). M2M : "" (pas de CSRF).
    pub(crate) method: String,
    pub(crate) csrf: String,
    // FILTRE ENVIRONNEMENT (#2d) : env demandé par l'en-tête `X-Plume-Env` (axe intra-tenant, v66/v67).
    // `None` = pas de filtre (mode 0 / en-tête absent / `__all__` / valeur invalide) -> READ PATH voit
    // TOUS les environnements = comportement STRICTEMENT identique (invariant absolu). `Some("<env>")` =
    // requêtes raw (event) + agrégats (rollups) filtrés `env_id='<env>'`. Capté par auth_guard, gated
    // sur `st.multi_tenant` (mode 0 -> TOUJOURS None : tout est prod de toute façon).
    pub(crate) env: Option<String>,
}

/// Base SQLCipher SÉPARÉE du control-plane (`plume-control.db`). Ouverte/initialisée LAZY au boot
/// UNIQUEMENT en mode 1 (en mode 0 : `None`, jamais créée). Porte l'identité plateforme et le catalogue :
/// les `hash` d'auth et le registre de tokens vivent ICI, HORS de portée du SQL brut d'un tenant-admin
/// (corrige R6/R7 : un tenant-admin ne peut plus forger d'identité ni se résoudre un token cross-tenant).
#[derive(Clone)]
pub(crate) struct ControlPlane {
    pub(crate) conn: Arc<Mutex<Connection>>,
    pub(crate) db_path: Arc<String>,
}

/// Chemin du control-plane : `PLUME_CONTROL_DB`, défaut = `plume-control.db` À CÔTÉ de PLUME_DB.
pub(crate) fn control_db_path(conf: &HashMap<String, String>, main_db_path: &str) -> String {
    let default = std::path::Path::new(main_db_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join("plume-control.db").to_string_lossy().into_owned())
        .unwrap_or_else(|| "plume-control.db".to_string());
    cfg(conf, "PLUME_CONTROL_DB", &default)
}

/// Clé SQLCipher du control-plane : env `PLUME_CONTROL_KEY` (Vault/ESO), distincte de PLUME_DB_KEY.
/// Vide/absente -> base en clair (dev/rétrocompat). Lue DIRECTEMENT (jamais via cfg() : une clé ne vient
/// pas d'un fichier conf), comme db_key().
pub(crate) fn control_key() -> Option<String> {
    std::env::var("PLUME_CONTROL_KEY").ok().filter(|k| !k.is_empty())
}

/// Schéma du control-plane (CREATE IF NOT EXISTS, idempotent, re-jouable). Cf. spec §B.1, forme #2a-2a :
///  - tenant(id, name, key_ref, db_path, created, suspended)   : catalogue + routing + réf. clé Vault
///  - platform_user(id, name UNIQUE, hash, is_superadmin, created) : identité plateforme (auth)
///  - grant(user_id, tenant_id, role, PK(user_id,tenant_id))   : rôle PAR tenant (RBAC)
///  - token(hash PK, tenant_id, env_id, host, created)         : token agent -> tenant (résolu AVANT
///    d'ouvrir la base tenant : poule/œuf, R6). `grant` est quoté ("grant") par prudence lexicale.
///  - control_ledger(id, ts, kind, actor, tenant, detail, prev_hash, hash) : audit append-only hash-chaîné
///    du control-plane (#2b/D3 : superadmin.read|superadmin.write des accès cross-tenant, tamper-evident).
pub(crate) fn migrate_control(conn: &Connection) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tenant(\
           id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', key_ref TEXT NOT NULL DEFAULT '', \
           db_path TEXT NOT NULL, created INTEGER, suspended INTEGER NOT NULL DEFAULT 0);\
         CREATE TABLE IF NOT EXISTS platform_user(\
           id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, hash TEXT, \
           is_superadmin INTEGER NOT NULL DEFAULT 0, created INTEGER);\
         CREATE TABLE IF NOT EXISTS \"grant\"(\
           user_id TEXT NOT NULL, tenant_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', \
           PRIMARY KEY(user_id, tenant_id));\
         CREATE TABLE IF NOT EXISTS token(\
           hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, env_id TEXT NOT NULL DEFAULT 'prod', \
           host TEXT, created INTEGER);\
         CREATE TABLE IF NOT EXISTS control_ledger(\
           id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT, tenant TEXT, \
           detail TEXT, prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL DEFAULT '');\
         CREATE TABLE IF NOT EXISTS role_def(\
           name TEXT PRIMARY KEY, base_role TEXT NOT NULL DEFAULT 'viewer', \
           deny_perms TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', created INTEGER);\
         CREATE TABLE IF NOT EXISTS scim_token(\
           hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', \
           created INTEGER, last_used INTEGER);",
    );
}

/// Ouvre + initialise (LAZY) le control-plane. Appelé UNIQUEMENT en mode 1. Garantit idempotemment la
/// ligne catalogue du tenant `default` (-> PLUME_DB actuel). Le backfill complet (platform_user +
/// grants depuis la table `user`) est #2a-2b : ici on ne pose QUE le catalogue minimal.
pub(crate) fn init_control_plane(conf: &HashMap<String, String>, main_db_path: &str) -> Result<ControlPlane, String> {
    let path = control_db_path(conf, main_db_path);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // SANS CONTRAT, et le nom le dit : le control-plane n'est PAS une base plume — il ne porte ni
    // `db/schema.sql` ni `meta.schema_version`, son schéma est `migrate_control` ci-dessus. Lui
    // appliquer le contrat des bases tenant le refuserait à chaque boot.
    let conn = open_db_keyed_without_schema_contract(&path, control_key().as_deref()).map_err(|e| e.to_string())?;
    let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
    migrate_control(&conn);
    // Catalogue minimal : le tenant `default` pointe vers la base tenant actuelle. key_ref='env:PLUME_DB_KEY'
    // -> rétrocompat mono (la clé actuelle reste valable). INSERT OR IGNORE = idempotent (re-boot sans effet).
    let _ = conn.execute(
        "INSERT OR IGNORE INTO tenant(id,name,key_ref,db_path,created,suspended) \
         VALUES('default','default','env:PLUME_DB_KEY',?1,?2,0)",
        params![main_db_path, now()],
    );
    Ok(ControlPlane { conn: Arc::new(Mutex::new(conn)), db_path: Arc::new(path) })
}

/// Résout un `tenant.key_ref` -> passphrase SQLCipher effective (#2a-3 : câblage réel de la clé PAR
/// tenant). Retour = `Result<Option<String>, String>` : `Ok(None)` = base EN CLAIR (choix explicite),
/// `Ok(Some(k))` = clé résolue, `Err(msg)` = clé NON résoluble -> FAIL-CLOSED (la base ne s'ouvre PAS,
/// JAMAIS de repli sur une clé par défaut). `msg` ne contient JAMAIS la valeur de la clé.
/// Conventions :
///  - ""            -> `Ok(None)` : base en clair (dev / rétrocompat mono).
///  - "env:NOM"     -> variable d'env NOM. MIROIR EXACT de db_key() : absente/vide -> `Ok(None)` (clair),
///                     non-vide -> `Ok(Some)`. Le tenant `default` = "env:PLUME_DB_KEY" -> comportement
///                     STRICTEMENT identique à db_key() (invariant mode 0 / rétrocompat).
///  - "literal:xxx" -> `Ok(Some(xxx))` : clé directe (onboarding local / tests). Vide -> `Err`.
///  - "vault:CHEMIN"-> lecture KV v2 (data.data.key) via un client Vault HTTP minimal SI PLUME_VAULT_ADDR
///                     + PLUME_VAULT_TOKEN sont posés ; sinon / injoignable / clé absente -> `Err`
///                     (FAIL-CLOSED). Résultat mis en cache par CHEMIN (pas d'appel Vault par requête).
///  - toute autre forme -> `Err` (préfixe inconnu).
pub(crate) fn resolve_tenant_key(key_ref: &str) -> Result<Option<String>, String> {
    // PHASE 2 — dispatch via la grammaire `SecretRef` UNIFIÉE + les providers PURS du cœur, mais avec la
    // POLITIQUE PROPRE au tenant (`Result<Option<String>, String>` : `Ok(None)`=clair, `Ok(Some)`=clé,
    // `Err`=NON résoluble -> fail-closed). Sémantique STRICTEMENT préservée (mode 0 / rétrocompat mono) :
    //   ""            -> `Ok(None)` (clair) ;
    //   env:NOM       -> EnvProvider filter-vide : absente/vide -> `Ok(None)`, non-vide -> `Ok(Some)`
    //                    (MIROIR EXACT de db_key() -> le tenant `default` = "env:PLUME_DB_KEY" reste identique) ;
    //   literal:xxx   -> `Ok(Some)` ; vide -> `Err` ;
    //   vault:CHEMIN  -> HTTP KV-v2 via le client EXISTANT (généralisé `#field`, défaut `key`) — messages
    //                    d'erreur bruts PRÉSERVÉS (pas de ré-emballage) ;
    //   autre préfixe -> `Err` (inconnu).
    use guatx_core::secret::{SecretOutcome, SecretProvider, SecretRef};
    let kr = key_ref.trim();
    if kr.is_empty() {
        return Ok(None);
    }
    let r = SecretRef::parse(kr);
    match r.scheme() {
        "env" => match guatx_core::secret::EnvProvider.get(&r) {
            Ok(SecretOutcome::Present(v)) => Ok(Some(v.into_string())),
            Ok(SecretOutcome::NotFound) => Ok(None), // absente/vide -> base en clair (miroir db_key)
            Err(e) => Err(format!("key_ref env: {e}")), // EnvProvider ne renvoie jamais d'Err (défensif)
        },
        "literal" => match guatx_core::secret::LiteralProvider.get(&r) {
            Ok(SecretOutcome::Present(v)) => Ok(Some(v.into_string())),
            Ok(SecretOutcome::NotFound) => Ok(None), // inatteignable (literal non-vide)
            Err(_) => Err("key_ref 'literal:' vide".into()), // message historique préservé
        },
        // vault: par le client HTTP EXISTANT (message d'erreur BRUT préservé -> pas de VaultProvider ici
        // pour éviter le ré-emballage `Display`). `#field` supporté (défaut `key` = rétrocompat).
        "vault" => {
            let (path, field) = r.vault_path_field();
            resolve_vault_key_field(path, field).map(Some)
        }
        _ => Err(format!(
            "key_ref inconnu '{kr}' (préfixes acceptés : '' | env: | literal: | vault:)"
        )),
    }
}

/// Résout `tenant -> (db_path, clé)` et fournit le handle DB. Le read-pool #2a-1 est déjà keyé par
/// db_path ; on ajoute ici un registre de writers par tenant. INERTE : exposé pour l'identité uniquement,
/// pas encore câblé aux handlers data (#2a-2b).
///  - Mode 0 (`control=None`) : PASSTHROUGH EXACT — un seul tenant `default` = (st.db_path, PLUME_DB_KEY),
///    writer = st.db. Comportement STRICTEMENT identique à aujourd'hui.
///  - Mode 1 (`control=Some`) : lit la table `tenant` du control-plane + résout key_ref -> ouvre/mémoïse.
// INERTE #2a-2a : `control` est lu par les accesseurs d'identité (token/user) ; les autres champs + les
// méthodes (ready/handle_for/ready_db_path) ne seront câblés aux handlers data qu'en #2a-2b -> allow(dead_code).
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct TenantDbManager {
    pub(crate) default_db_path: Arc<String>,
    pub(crate) default_writer: Arc<Mutex<Connection>>,
    pub(crate) control: Option<ControlPlane>,
    pub(crate) writers: Arc<Mutex<HashMap<String, prepared_writer::PreparedWriter>>>,
}

/// LE CACHE DES WRITERS TENANT NE PEUT PAS CONTENIR UNE BASE NON PRÉPARÉE — et ce n'est pas une
/// convention de relecture, c'est le TYPE.
///
/// Ce que la revue a mesuré sur le code précédent : `handle_for` ouvrait une base TENANT en ÉCRITURE
/// au fil de l'eau (`open_db_keyed` puis mise en cache) SANS `prepare_schema`, sans `migrate`, sans
/// aucun contrôle. Une base tenant n'était migrée qu'AU PROVISIONNEMENT (`tenant_provision`) : après
/// une mise à jour de binaire ajoutant une migration, les bases tenant EXISTANTES étaient servies et
/// ÉCRITES sur l'ancien schéma. C'est le « fail-open par l'appelant oublié », un étage plus bas.
///
/// La réparation ne consiste PAS à ajouter un appel de plus (le prochain appelant l'oublierait à son
/// tour), mais à rendre l'appel STRUCTUREL : la carte des writers ne stocke plus un
/// `Arc<Mutex<Connection>>` — que n'importe quel code peut fabriquer — mais un `PreparedWriter`, dont
/// le champ est PRIVÉ au sous-module et dont le seul constructeur est `PreparedWriter::open`, qui
/// n'obtient sa connexion que par la PORTE (`PreparedDb`, cf. `db_open`) : le contrat est appliqué
/// LÀ, une seule fois pour tout le daemon. Insérer une connexion non préparée dans ce cache NE
/// COMPILE PAS. Mesuré : le comportement par `mode1_tenant_writer_applies_the_schema_contract`, la
/// propriété structurelle par la compilation elle-même (aucun autre chemin ne peut produire la valeur
/// que la carte attend).
pub(crate) mod prepared_writer {
    use super::*;

    /// Writer d'une base plume dont le contrat de schéma A ÉTÉ VÉRIFIÉ **et dont les registres
    /// PAR db_path sont CHARGÉS**. Champs privés : hors de ce sous-module, la seule façon d'en obtenir
    /// un est `open` — donc détenir cette valeur EST la preuve des deux propriétés, pour la connexion
    /// comme pour le CHEMIN (qui ne sort d'ici que par `path()`).
    #[derive(Clone)]
    pub(crate) struct PreparedWriter {
        conn: Arc<Mutex<Connection>>,
        path: Arc<String>,
    }

    impl PreparedWriter {
        /// Ouvre `path` avec `key` PAR LA PORTE (garde anti-downgrade + contrat de schéma), HYDRATE les
        /// registres par-db_path de cette base, et n'existe que si tout cela a réussi. `Err` = base NON
        /// servie (fail-closed) : jamais un handle sur un schéma inconnu, jamais un CHEMIN dont les
        /// registres (dont le masquage #45) seraient vides.
        pub(crate) fn open(path: &str, key: Option<&str>) -> Result<Self, String> {
            let conn = PreparedDb::open_keyed(path, key).map_err(|e| e.to_string())?.into_connection();
            // L'HYDRATATION EST ICI, ET NULLE PART AILLEURS : elle est faite sur la connexion AVANT que
            // la valeur n'existe, donc aucun appelant ne peut l'oublier — il n'y a rien à oublier.
            per_db_registries_reload(&conn, path);
            Ok(PreparedWriter { conn: Arc::new(Mutex::new(conn)), path: Arc::new(path.to_string()) })
        }

        /// Le handle, une fois le contrat satisfait.
        pub(crate) fn handle(&self) -> Arc<Mutex<Connection>> {
            self.conn.clone()
        }

        /// Le db_path de CETTE base — clé du read-pool et de tous les caches/registres par-db_path.
        /// Ne peut désigner qu'une base dont `open` a hydraté les registres (c'est tout l'intérêt).
        pub(crate) fn path(&self) -> String {
            self.path.as_ref().clone()
        }
    }
}

/// LE POINT D'HYDRATATION UNIQUE DES REGISTRES **PAR db_path**.
///
/// CE QUE LA REVUE A MESURÉ. Le daemon tient plusieurs registres process-globaux keyés par db_path
/// (masquage/DLP `field_filter` #45 — qui alimente AUSSI l'authorizer SQLite —, processeur d'ingest,
/// parseurs regex + déclaratifs, knowledge objects, index auto). Ils étaient chargés au BIND, pour
/// PLUME_DB, et — pour les field filters — après chaque CRUD. Aucun de ces deux moments ne couvre une
/// base TENANT : après un redémarrage, tout tenant autre que celui de PLUME_DB tournait donc avec un
/// registre de masquage VIDE, et `SELECT src_ip FROM event` rendait la valeur EN CLAIR (mesuré :
/// `203.0.113.7`) alors que l'exploitant avait posé un DENY dans la base de CE tenant.
///
/// POURQUOI CETTE FORME. Ajouter « un appel à `field_filters_reload` dans `handle_for` » aurait fermé le
/// cas mesuré et laissé les cinq autres registres, plus le prochain chemin d'obtention de connexion.
/// Ici l'hydratation est appelée par `PreparedWriter::open`, SEUL constructeur de la valeur que le cache
/// des writers tenant sait stocker et SEULE source d'un db_path tenant servi (cf. `TenantDbManager`) :
/// une connexion ou un chemin tenant dont les registres ne sont pas chargés NE PEUT PAS EXISTER.
/// La COMPOSITION de cette fonction, elle, est tenue par un test qui DÉRIVE la liste des registres du
/// texte du bind (`every_per_db_registry_loaded_at_boot_is_loaded_for_a_tenant_base`) : un registre
/// ajouté demain au boot fait rougir tant qu'il n'est pas ici — personne n'a de liste à maintenir.
///
/// N'INCLUT PAS `knowledge_activate` : ce n'est pas un registre mais l'ÉLECTION du db_path de
/// compilation GXQL (global). L'activer depuis ici laisserait la base d'un tenant détourner la
/// compilation des autres — sa doc l'interdit explicitement, et le motif dérivé (`X_reload(&conn,
/// &db_path)`) ne l'attrape pas.
///
/// MODE 0 : jamais appelée (aucun writer tenant n'est ouvert) -> comportement STRICTEMENT identique.
pub(crate) fn per_db_registries_reload(conn: &Connection, db_path: &str) {
    parsers_reload(conn, db_path);
    dparsers_reload(conn, db_path);
    processors_reload(conn, db_path);
    field_filters_reload(conn, db_path);
    knowledge_reload(conn, db_path);
}

#[allow(dead_code)]
impl TenantDbManager {
    /// LE CATALOGUE, PAS UN CHEMIN SERVABLE. Rend (db_path, clé_effective) du tenant. Mode 0 :
    /// passthrough (PLUME_DB, PLUME_DB_KEY), quel que soit `tenant` (il n'existe qu'un tenant). Mode 1 :
    /// catalogue control-plane ; tenant absent ou suspendu -> None (fail-closed : jamais de repli
    /// silencieux sur une autre base).
    ///
    /// PRIVÉE À CE MODULE (et `pub(crate)` UNIQUEMENT en build de test, comme `open_db` dans db_open.rs) :
    /// le chemin qu'elle rend n'a PAS ses registres par-db_path chargés, donc le SERVIR serait le fail-open
    /// #45. Le seul chemin servable sort de `ready`/`ready_db_path`. Un chemin de production qui
    /// l'appellerait ne COMPILE PAS (`cargo build`, CI) ; les tests, eux, mesurent légitimement le
    /// catalogue nu.
    fn catalog_route(&self, tenant: &str) -> Option<(String, Option<String>)> {
        match &self.control {
            None => Some((self.default_db_path.as_ref().clone(), db_key())),
            Some(cp) => {
                let conn = cp.conn.lock();
                let (db_path, key_ref, suspended) = conn
                    .query_row(
                        "SELECT db_path, key_ref, suspended FROM tenant WHERE id=?1",
                        params![tenant],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)),
                    )
                    .ok()?;
                if suspended != 0 {
                    return None; // tenant suspendu -> pas de handle
                }
                // #2a-3 : résout la clé DU TENANT et l'enregistre (db_path -> clé) pour que read_conn_open
                // ouvre CE fichier avec SA clé (frontière crypto). FAIL-CLOSED : clé non résoluble
                // (ex. vault: injoignable) -> None, la base ne s'ouvre PAS (jamais de clé par défaut).
                match resolve_tenant_key(&key_ref) {
                    Ok(key) => {
                        register_db_key(&db_path, key.clone());
                        Some((db_path, key))
                    }
                    Err(e) => {
                        eprintln!("[multi-tenant] tenant '{tenant}' : clé non résolue -> FAIL-CLOSED, base NON ouverte ({e})");
                        None
                    }
                }
            }
        }
    }

    /// VISIBILITÉ DE TEST du catalogue nu (cf. `catalog_route`) : les tests mesurent légitimement
    /// « ce tenant est-il catalogué / sa clé résout-elle », sans rien servir. Absente du binaire de
    /// production, exactement comme `open_db`/`open_db_keyed` dans db_open.rs.
    #[cfg(test)]
    pub(crate) fn resolve(&self, tenant: &str) -> Option<(String, Option<String>)> {
        self.catalog_route(tenant)
    }

    /// LE TENANT EST-IL DISPONIBLE ? (existe, non suspendu, clé résoluble). C'est TOUT ce dont les
    /// gardes d'entrée (auth_guard, résolution de rôle cross-tenant) ont besoin : elles REFUSENT, elles
    /// ne servent rien. Elles n'obtiennent donc AUCUN chemin — la seule façon d'en obtenir un reste
    /// `ready_db_path`. Effet de bord conservé (identique à l'ancien `resolve` qu'elles appelaient) :
    /// la clé DU tenant est enregistrée au registre du read-pool.
    pub(crate) fn tenant_available(&self, tenant: &str) -> bool {
        self.catalog_route(tenant).is_some()
    }

    /// LE POINT DE PASSAGE UNIQUE VERS UNE BASE TENANT — mode 1 uniquement.
    ///
    /// Tout ce qui sert un tenant (writer, chemin de lecture, cible d'ingest, job de fond) passe ICI, et
    /// n'en ressort qu'avec un `PreparedWriter` : contrat de schéma satisfait ET registres par-db_path
    /// chargés, par construction (cf. `prepared_writer`). Un futur chemin d'obtention devra demander la
    /// même valeur — ou ne pas compiler.
    ///
    /// LE CATALOGUE EST RE-INTERROGÉ À CHAQUE PASSAGE, pas seulement à l'ouverture froide. Mesuré :
    /// l'ancien fast-path « writer déjà en cache » rendait le handle d'un tenant SUSPENDU depuis (la
    /// suspension n'était vue que par les appelants qui pensaient à la vérifier eux-mêmes). Une garde qui
    /// ne tient que pour les tenants jamais utilisés n'est pas une garde. Le coût est une lecture d'une
    /// table minuscule et indexée du control-plane (ce que `auth_guard` fait déjà par requête).
    ///
    /// FAIL-CLOSED à chaque étape : tenant inconnu/suspendu, clé non résoluble, schéma refusé -> `None`.
    /// Le tenant n'est PAS servi (au lieu d'être servi depuis, ou dans, la base d'un autre). La cause est
    /// nommée dans le journal ; elle ne contient jamais la clé.
    fn ready(&self, tenant: &str) -> Option<prepared_writer::PreparedWriter> {
        if self.control.is_none() {
            return None; // mode 0 : inatteignable (tous les appelants court-circuitent AVANT) ; fail-closed si ça change
        }
        let (path, key) = self.catalog_route(tenant)?;
        let cached = self.writers.lock().get(tenant).cloned();
        if let Some(w) = cached {
            if w.path() == path {
                return Some(w);
            }
            // Le catalogue désigne désormais un AUTRE fichier pour ce tenant : le writer chaud pointe la
            // base PRÉCÉDENTE -> on l'évince plutôt que de continuer à servir l'ancien fichier.
            self.writers.lock().remove(tenant);
        }
        let w = match prepared_writer::PreparedWriter::open(&path, key.as_deref()) {
            Ok(w) => w,
            Err(e) => {
                // NB : on ne prétend PAS que « rien n'a été écrit » — `prepare_schema` a pu appliquer
                // db/schema.sql et des étapes de migration avant d'échouer. Ce qui est garanti ici est
                // plus étroit et suffisant : AUCUNE requête ne sera routée vers cette base.
                eprintln!(
                    "[multi-tenant] tenant '{tenant}' : base NON servie — {e}. Aucune requête ne sera \
                     routée vers elle ; déployer un binaire compatible ou réparer la base, puis réessayer"
                );
                return None;
            }
        };
        // `or_insert` et non `insert` : deux requêtes concurrentes sur un tenant froid ouvrent chacune
        // leur connexion (le verrou n'est PAS tenu pendant l'ouverture — la préparation peut migrer, on
        // ne bloque pas les autres tenants pendant ce temps) ; la première arrivée reste, la seconde est
        // relâchée. Aucune connexion déjà distribuée n'est remplacée sous les pieds d'un appelant.
        let mut cache = self.writers.lock();
        Some(cache.entry(tenant.to_string()).or_insert(w).clone())
    }

    /// Handle d'ÉCRITURE (writer) du tenant. Mode 0 : le writer process-global existant (st.db) —
    /// passthrough exact, AUCUNE ligne de ce chemin n'est touchée (c'est `server/mod.rs` qui a déjà passé
    /// ce handle par `prepare_schema` avant le bind). Mode 1 : le writer du `PreparedWriter` (cf. `ready`).
    pub(crate) fn handle_for(&self, tenant: &str) -> Option<Arc<Mutex<Connection>>> {
        if self.control.is_none() {
            return Some(self.default_writer.clone());
        }
        self.ready(tenant).map(|w| w.handle())
    }

    /// db_path SERVABLE du tenant (clé du read-pool et de tous les caches/registres par-db_path) — mode 1.
    /// Il ne peut sortir que d'un `PreparedWriter`, donc les registres de cette base SONT chargés : c'est
    /// ce qui rend impossible de LIRE un tenant avec un masquage vide. `None` = tenant non servable.
    pub(crate) fn ready_db_path(&self, tenant: &str) -> Option<String> {
        self.ready(tenant).map(|w| w.path())
    }
}

/// Identité d'un agent (Bearer token) après résolution : le tenant PORTEUR du token (résolu AVANT
/// d'ouvrir la base tenant — R6), l'environnement, et l'hôte lié. En mode 0 : toujours (default, prod, host).
/// INERTE #2a-2a : `tenant`/`env` seront consommés par l'ingest tenant-scopé (#2a-2b) ; ici seul `host`
/// est projeté par valid_token (signature/callers inchangés) -> allow(dead_code) sur les champs inertes.
#[allow(dead_code)]
pub(crate) struct TokenIdent {
    pub(crate) tenant: String,
    pub(crate) env: String,
    pub(crate) host: String,
}

/// ACCESSEUR IDENTITÉ token (R6). Mode 0 : lit la table `token` de la base UNIQUE EXACTEMENT comme avant
/// (host + UPDATE last_used) -> comportement STRICTEMENT identique ; tenant='default', env='prod'. Mode 1 :
/// lit le control-plane (`token(hash -> tenant_id, env_id, host)`) car token->tenant DOIT précéder
/// l'ouverture d'une base tenant (poule/œuf ; un token ne peut vivre dans la base tenant). Fail-closed :
/// token inconnu -> None (jamais de repli cross-tenant).
pub(crate) fn token_lookup(st: &AppState, tok: &str) -> Option<TokenIdent> {
    if tok.is_empty() {
        return None;
    }
    let h = sha256_hex(tok.as_bytes());
    if let Some(cp) = st.tenants.control.as_ref() {
        // mode 1 : identité agent résolue depuis le control-plane.
        // #52 KIND-CONFUSION : PAS de filtre `kind` ici — le token du control-plane (migrate_control) n'a PAS
        // de colonne `kind`, et un token `kind='datasource'` NE PEUT PAS y exister : `datasource_token_lookup`
        // renvoie None en mode 1 et `token_create` refuse le provisioning UI en multi-tenant -> aucun token
        // datasource dans cette table. Le vecteur de kind-confusion est donc STRICTEMENT mode 0 (base unique
        // avec colonne `kind`), fermé par le filtre de la branche mode 0 ci-dessous.
        let conn = cp.conn.lock();
        let (tenant, env, host) = conn
            .query_row(
                "SELECT tenant_id, env_id, host FROM token WHERE hash=?1",
                params![h],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?)),
            )
            .ok()?;
        return Some(TokenIdent {
            tenant,
            env: env.unwrap_or_else(|| "prod".into()),
            host: host.unwrap_or_default(),
        });
    }
    // mode 0 : base unique, INCHANGÉ (host + UPDATE last_used) SAUF le filtre kind ci-dessous.
    // #52 KIND-CONFUSION FIX (CRITICAL) : un token `kind='datasource'` (read-scoped, remis à une Grafana
    // externe peu fiable) NE DOIT PAS s'authentifier ici — `token_lookup` alimente le seam AGENT Bearer
    // (auth.rs, role='agent' hardcodé) sur TOUT agent_bearer_path (/api/ingest, /api/metrics/prom|write,
    // /loki/api/v1/push, /api/actions/pending|result, /api/engagements/active) ET le seam HEC (ingest/hec.rs
    // /services/collector). Sans ce filtre, le porteur d'un token datasource forgerait des events SOC,
    // injecterait métriques/logs, et — si host-lié — falsifierait l'audit de containment / lirait le scope
    // d'engagement. On EXCLUT donc explicitement kind='datasource' ; `datasource_token_lookup` (kind='datasource'
    // requis) reste le SEUL chemin d'authentification de ce token, borné aux routes de LECTURE datasource.
    let conn = st.db.lock();
    // #39 — EXCLUT AUSSI kind='client' (jeton client-read, remis à un client MSSP peu fiable) : comme le jeton
    // datasource, il ne DOIT PAS s'authentifier sur le seam AGENT (ingest/responder/HEC). Seul
    // `client_token_lookup` (kind='client' requis) l'authentifie, borné aux routes client-read.
    // P-HEC — EXCLUT AUSSI kind='firehose' (clé de livraison AWS Firehose, remise à un stream cloud) : comme
    // datasource/client, elle ne DOIT PAS s'authentifier sur le seam AGENT (ingest/responder/HEC) — sinon un
    // porteur de clé de livraison forgerait des events SOC via /api/ingest ou /services/collector. Seul
    // `firehose_token_lookup` (kind='firehose' requis) l'authentifie, BORNÉ à /api/ingest/firehose (ingest-only,
    // lié à SON connecteur push). Défaut fermé cohérent avec la doctrine kind-isolation (#52/#39).
    // P-HEC (GCP) — EXCLUT AUSSI kind='gcp_pubsub' (clé de livraison Pub/Sub, remise à un abonnement push GCP) :
    // MÊME raison que 'firehose' — sinon un porteur de clé de livraison Pub/Sub forgerait des events SOC via
    // /api/ingest ou /services/collector. Seul `pubsub_token_lookup` (kind='gcp_pubsub' requis) l'authentifie,
    // BORNÉ à /api/ingest/pubsub. Isolation SYMÉTRIQUE : une clé Firehose ne s'authentifie pas sur pubsub et
    // vice-versa (chaque endpoint EXIGE son propre kind), et NI l'une NI l'autre sur le seam agent/HEC/datasource.
    let host: Option<Option<String>> = conn
        .query_row("SELECT host FROM token WHERE token_hash=?1 AND (kind IS NULL OR kind NOT IN ('datasource','client','firehose','gcp_pubsub'))", params![h], |r| r.get::<_, Option<String>>(0))
        .ok();
    match host {
        Some(h_opt) => {
            let _ = conn.execute("UPDATE token SET last_used=?1 WHERE token_hash=?2", params![now(), h]);
            Some(TokenIdent { tenant: "default".into(), env: "prod".into(), host: h_opt.unwrap_or_default() })
        }
        None => None,
    }
}

/// Identité résolue d'un token DATASOURCE (#52) : rôle de LECTURE (viewer|editor, jamais admin/agent) +
/// tenant/env. Read-scoped par construction.
pub(crate) struct DatasourceIdent {
    pub(crate) name: String,
    pub(crate) tenant: String,
    #[allow(dead_code)]
    pub(crate) env: String,
    pub(crate) role: String,
}

/// ACCESSEUR IDENTITÉ token DATASOURCE (#52). MODE 0 UNIQUEMENT (comme le provisioning UI de jetons) : lit la
/// table `token` de la base unique, EXIGE `kind='datasource'`, mappe vers le rôle de LECTURE stocké (colonne
/// `role`, défaut viewer) BORNÉ à viewer|editor (jamais admin/agent -> read-scoped, pas de SQL brut). Met à
/// jour last_used. Mode 1 (control-plane présent) -> None (l'auth datasource passe alors par Basic/SSO).
/// Fail-closed : token inconnu / mauvais kind -> None.
pub(crate) fn datasource_token_lookup(st: &AppState, tok: &str) -> Option<DatasourceIdent> {
    if tok.is_empty() || st.tenants.control.is_some() {
        return None; // mode 1 : pas de token datasource dans le control-plane -> repli Basic/SSO
    }
    let h = sha256_hex(tok.as_bytes());
    let conn = st.db.lock();
    let row = conn
        .query_row(
            "SELECT name, COALESCE(role,'viewer') FROM token WHERE token_hash=?1 AND kind='datasource'",
            params![h],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()?;
    let (name, role_raw) = row;
    // read-scoped : borne DURE à viewer|editor (toute autre valeur -> viewer, le plancher).
    let role = if role_raw == "editor" { "editor" } else { "viewer" }.to_string();
    let _ = conn.execute("UPDATE token SET last_used=?1 WHERE token_hash=?2", params![now(), h]);
    Some(DatasourceIdent { name, tenant: "default".into(), env: "prod".into(), role })
}

/// ACCESSEUR IDENTITÉ jeton CLIENT-READ (#39). MODE 0 UNIQUEMENT (comme datasource) : lit la table `token`,
/// EXIGE `kind='client'`, mappe vers le rôle read-only STRICT `client` (rank 0 -> masqué par toute règle
/// field-filter, cf. role_rank). Met à jour last_used. Mode 1 (control-plane présent) -> None (repli Basic/SSO).
/// Fail-closed : jeton inconnu / mauvais kind -> None. Read-scoped par construction (host jamais lié).
pub(crate) fn client_token_lookup(st: &AppState, tok: &str) -> Option<DatasourceIdent> {
    if tok.is_empty() || st.tenants.control.is_some() {
        return None;
    }
    let h = sha256_hex(tok.as_bytes());
    let conn = st.db.lock();
    let name: String = conn
        .query_row("SELECT name FROM token WHERE token_hash=?1 AND kind='client'", params![h], |r| r.get(0))
        .ok()?;
    let _ = conn.execute("UPDATE token SET last_used=?1 WHERE token_hash=?2", params![now(), h]);
    Some(DatasourceIdent { name, tenant: "default".into(), env: "prod".into(), role: "client".into() })
}

/// Identité résolue d'une clé de livraison AWS Firehose (P-HEC) : le tenant PORTEUR + le connecteur push LIÉ
/// (`connector_id` -> son `field_map`/`env_id`). INGEST-ONLY par construction (le récepteur ne fait qu'écrire
/// le spool). Read-scoped à ZÉRO surface UI/admin/agent.
pub(crate) struct FirehoseIdent {
    pub(crate) tenant: String,
    pub(crate) connector_id: i64,
}

/// Identité résolue d'une clé de livraison GCP Pub/Sub (P-HEC) — MÊME forme que `FirehoseIdent` (tenant +
/// connecteur push lié), séparée pour l'isolation de TYPE (une clé pubsub ne peut être honorée que par le
/// récepteur pubsub). INGEST-ONLY, read-scoped à ZÉRO surface UI/admin/agent.
pub(crate) struct PubsubIdent {
    pub(crate) tenant: String,
    pub(crate) connector_id: i64,
}

/// PRIMITIVE PARTAGÉE (P-HEC) de résolution d'une clé de livraison PUSH -> son `connector_id` lié, pour un `kind`
/// donné ('firehose' | 'gcp_pubsub'). MODE 0 UNIQUEMENT (les clés sont mintées par `/api/connectors/push-source`,
/// mono-tenant). RÉUTILISE la primitive de vérification EXISTANTE : `sha256_hex(clé)` puis SELECT CONSTANT-TIME
/// sur la colonne INDEXÉE `token_hash` (jamais le clair ; la comparaison porte sur le HASH, aucune fuite de timing
/// sur le secret). EXIGE le `kind` demandé (ISOLATION DE KIND : une clé n'authentifie QUE son propre endpoint, et
/// JAMAIS le seam agent/HEC/datasource — cf. le filtre NOT IN de token_lookup) + un `connector_id` LIÉ non nul.
/// Met à jour last_used. Mode 1 (control-plane présent) -> None. Fail-closed : clé inconnue / mauvais kind /
/// binding absent -> None. Utilisée par `firehose_token_lookup` ET `pubsub_token_lookup` (zéro duplication crypto).
fn push_token_connector(st: &AppState, tok: &str, kind: &str) -> Option<i64> {
    if tok.is_empty() || st.tenants.control.is_some() {
        return None; // mode 1 : pas de clé push hors control-plane -> pas d'auth push (cf. push-source mono-tenant)
    }
    let h = sha256_hex(tok.as_bytes());
    let conn = st.db.lock();
    let cid: Option<i64> = conn
        .query_row(
            "SELECT connector_id FROM token WHERE token_hash=?1 AND kind=?2",
            params![h, kind],
            |r| r.get::<_, Option<i64>>(0),
        )
        .ok()?;
    let connector_id = cid?; // binding manquant (colonne NULL) -> fail-closed (jamais de push non lié)
    let _ = conn.execute("UPDATE token SET last_used=?1 WHERE token_hash=?2", params![now(), h]);
    Some(connector_id)
}

/// ACCESSEUR IDENTITÉ clé de livraison FIREHOSE (P-HEC). EXIGE `kind='firehose'`. Cf. `push_token_connector`.
pub(crate) fn firehose_token_lookup(st: &AppState, tok: &str) -> Option<FirehoseIdent> {
    push_token_connector(st, tok, "firehose").map(|connector_id| FirehoseIdent { tenant: "default".into(), connector_id })
}

/// ACCESSEUR IDENTITÉ clé de livraison GCP Pub/Sub (P-HEC). EXIGE `kind='gcp_pubsub'` (ISOLATION SYMÉTRIQUE :
/// une clé Firehose NE s'authentifie PAS ici, ni une clé pubsub sur Firehose). Cf. `push_token_connector`.
pub(crate) fn pubsub_token_lookup(st: &AppState, tok: &str) -> Option<PubsubIdent> {
    push_token_connector(st, tok, "gcp_pubsub").map(|connector_id| PubsubIdent { tenant: "default".into(), connector_id })
}

/// ACCESSEUR IDENTITÉ Basic (R7) : (hash, rôle) d'un compte par nom. Mode 0 : table `user` de la base
/// UNIQUE, INCHANGÉ (SELECT hash, role FROM user WHERE name=?). Mode 1 : `platform_user` du control-plane
/// -> les hash d'auth ont quitté la base tenant (un tenant-admin en SQL brut ne peut plus forger
/// d'identité). Le rôle PER-TENANT (via `grant`) est résolu dans auth_guard (#2a-2b) ; ici on renvoie un
/// rôle plancher (is_superadmin -> admin, sinon viewer). hash NULL (SSO-only) -> None (repli SSO/admin).
pub(crate) fn lookup_basic_ident(st: &AppState, name: &str) -> Option<(String, String)> {
    if let Some(cp) = st.tenants.control.as_ref() {
        let conn = cp.conn.lock();
        return conn
            .query_row(
                "SELECT hash, is_superadmin FROM platform_user WHERE name=?1",
                params![name],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok()
            .and_then(|(hash, sa)| {
                hash.map(|h| (h, if sa != 0 { "admin".to_string() } else { "viewer".to_string() }))
            });
    }
    let c = st.db.lock();
    let ident = c.query_row("SELECT hash, role FROM user WHERE name=?1", params![name], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })
    .ok();
    // HARD-EXPIRY (MODE ENGAGEMENT) — un credential minté (`eng-cred-*`) ne s'authentifie QUE dans la fenêtre
    // [window_start, window_end) d'un engagement dont le grant scoped_cred est ENCORE 'issued'. Double-garde
    // HORLOGE-MURALE indépendante du sweep (comme l'enforcer) : même révocation périodique en retard, la
    // fenêtre BORNE l'auth. GATE = préfixe réservé -> requête SAUTÉE pour un compte normal => byte-identique
    // hors engagement. Grant 'revoked' (fin/expiry) OU compte supprimé -> None. NB : les eng-creds ne sont
    // JAMAIS mis en cache d'auth (cf. authenticate) -> révocation/expiry effective SANS latence de cache.
    if ident.is_some() && name.starts_with(ENG_CRED_PREFIX) && !engagement_cred_within_window(&c, name, now()) {
        return None;
    }
    ident
}

/// BASE CUL-DE-SAC — le repli d'un tenant INDISPONIBLE, en mode 1 uniquement.
///
/// POURQUOI ELLE EXISTE. `req_db` doit rendre un handle — il est appelé par la macro `req_conn!`, dont
/// `grep -rn 'req_conn!(' daemon/src | grep -v '///' | wc -l` compte 178 sites d'APPEL (la commande
/// exclut les lignes de doc, dont celle-ci : citée sans le filtre elle se compterait elle-même et
/// rendrait 179), dont aucun ne sait échouer — et le repli
/// historique était `st.db`, c'est-à-dire LA BASE DU TENANT
/// `default` : un tenant indisponible faisait donc ATTERRIR SES ÉCRITURES DANS UNE AUTRE BASE. Le
/// commentaire de `main.rs` le justifiait par « chemin non atteint en pratique », ce qui n'est plus
/// vrai depuis que `handle_for` peut refuser une base dont le SCHÉMA n'est pas celui attendu.
///
/// CE QU'ELLE EST : une base en mémoire, VIDE, `query_only=ON`, partagée par le processus. Toute
/// écriture y échoue, toute lecture aussi (la table n'existe pas) ; le message exact est celui de
/// SQLite et n'est pas re-cité ici, seul l'échec est vérifié
/// (`mode1_tenant_writer_applies_the_schema_contract`). Le
/// tenant est donc BRUYAMMENT indisponible au lieu d'écrire silencieusement chez quelqu'un d'autre —
/// et ce raisonnement ne dépend PAS de la cause de l'indisponibilité (clé non résoluble, tenant
/// suspendu, schéma refusé, ou la prochaine cause qu'on ajoutera).
fn unavailable_tenant_db() -> Arc<Mutex<Connection>> {
    static CUL_DE_SAC: std::sync::OnceLock<Arc<Mutex<Connection>>> = std::sync::OnceLock::new();
    CUL_DE_SAC
        .get_or_init(|| {
            // une ouverture en mémoire qui échoue = plus de mémoire : le processus est déjà perdu.
            let c = Connection::open_in_memory().expect("base cul-de-sac en mémoire");
            let _ = c.execute_batch("PRAGMA query_only=ON;");
            Arc::new(Mutex::new(c))
        })
        .clone()
}

/// Handle d'écriture de la base du tenant COURANT (par-requête). Mode 0 : st.db (passthrough exact,
/// AUCUNE ligne changée). Mode 1 : la base DU tenant, ou la base cul-de-sac s'il est indisponible.
pub(crate) fn req_db(st: &AppState, au: &AuthUser) -> Arc<Mutex<Connection>> {
    if !st.multi_tenant {
        return st.db.clone();
    }
    st.tenants.handle_for(&au.tenant).unwrap_or_else(unavailable_tenant_db)
}

/// CHEMIN CUL-DE-SAC — le pendant LECTURE de `unavailable_tenant_db`, et il vient du MÊME raisonnement.
///
/// `req_db_path` doit rendre une `String` (110 sites d'appel, dont aucun ne sait échouer) et son repli
/// historique était `st.db_path`, c'est-à-dire LA BASE DU PROCESSUS = celle du tenant `default` : une
/// LECTURE d'un tenant indisponible servait donc les lignes d'un AUTRE tenant. Mesuré : tenant suspendu ->
/// chemin rendu = celui de la base opérateur, et la requête a servi 1 ligne qui n'appartient qu'à elle.
///
/// CE QU'IL EST : un chemin qui ne peut désigner AUCUN fichier, sur AUCUN système, pour AUCUN uid — root
/// compris. `/dev/null` EXISTE mais n'est PAS un répertoire : toute ouverture SOUS lui échoue (ENOTDIR),
/// en lecture comme en écriture, et personne ne peut « créer le répertoire manquant ». Le tenant est donc
/// BRUYAMMENT indisponible (le pool de lecture rend son erreur, `read_with` rend son défaut) au lieu de
/// servir silencieusement la base de quelqu'un d'autre — et ce raisonnement ne dépend PAS de la CAUSE de
/// l'indisponibilité (suspension, clé non résoluble, schéma refusé, ou la prochaine cause qu'on ajoutera).
/// Vérifié par `the_dead_end_path_can_never_designate_a_real_database`.
pub(crate) const UNAVAILABLE_TENANT_DB_PATH: &str = "/dev/null/plume-tenant-indisponible.db";

/// Chemin de la base du tenant COURANT (clé du read-pool + des caches par-db_path). Mode 0 : st.db_path.
/// Mode 1 : le chemin SERVABLE du tenant (registres chargés, cf. `ready_db_path`), sinon le cul-de-sac.
pub(crate) fn req_db_path(st: &AppState, au: &AuthUser) -> String {
    // Mode 0 — ET mode 1 DÉGRADÉ sans control-plane (init échoué : « l'identité retombe sur la base
    // unique », cf. server/mod.rs) : passthrough EXACT, comme `req_db`/`handle_for` au même instant.
    if !st.multi_tenant || st.tenants.control.is_none() {
        return st.db_path.as_ref().clone();
    }
    st.tenants
        .ready_db_path(&au.tenant)
        .unwrap_or_else(|| UNAVAILABLE_TENANT_DB_PATH.to_string())
}

/// DRY (audit qualité — top win) : prologue de verrou d'écriture répété sur tous les sites d'appel
/// (178 aujourd'hui, cf. la commande citée par `unavailable_tenant_db` ci-dessus ; le nombre a bougé
/// depuis le refactor et il n'y a aucune raison de figer ici un compte qui vit). S'EXPANSE SUR
/// PLACE en `let __rc = req_db(&$st, &$au); let $conn = __rc.lock();` — byte-équivalent au boilerplate
/// manuel, ZÉRO changement de comportement (même fn `req_db` résolue au site d'appel, même Arc temporaire
/// `__rc` porteur du guard, même sémantique de garde relâchée en fin de portée appelante). Contrairement
/// à `with_write` (closure, query_exec.rs) qui ne couvre que les corps SANS early-return, cette macro
/// déclarative se substitue au prologue IN-PLACE → traverse `return`/`?` et couvre TOUS les sites.
/// NB (hygiène macro_rules) : le nom du binding `$conn` DOIT venir du site d'appel (un `conn` introduit
/// par la macro serait hygiénique et invisible à l'appelant) ; `__rc` interne reste hygiénique (jamais
/// référencé par l'appelant, aucun risque de collision entre invocations).
#[macro_export]
macro_rules! req_conn {
    ($st:ident, $au:ident, $conn:ident) => {
        let __rc = req_db(&$st, &$au);
        let $conn = __rc.lock();
    };
}

/// #2a-2c — DISPATCH DES JOBS DE FOND PAR TENANT. Exécute `body(tenant_id, handle, db_path)` pour CHAQUE
/// tenant ACTIF, SÉQUENTIELLEMENT (jamais de fan-out concurrent : borne la RAM, budget 2 Go ; le read-pool a
/// un cap GLOBAL #2a-1). Toutes les boucles de jobs de fond (règles, playbooks, rétention, rollups, banlist,
/// pré-chauffage des panneaux, fraîcheur, auto-index) l'utilisent au lieu de taper directement st.db.
///  - MODE 0 (`control=None`) : UNE SEULE itération `("default", default_writer, default_db_path)` — corps
///    des jobs STRICTEMENT identique à aujourd'hui (même base unique, même cadence, une seule passe).
///  - MODE 1 (`control=Some`) : liste les tenants NON-SUSPENDUS du control-plane, et pour CHACUN résout
///    (db_path, clé) + le writer PUIS exécute le corps sur SA base. Le corps reçoit le handle du tenant
///    (writer) + son db_path (clé des caches par-db_path #2a-1). Les tenants sont ainsi évalués/purgés/
///    rollupés isolément — complétude mode 1 (pas un vecteur de fuite).
///  - SKIP FAIL-CLOSED (log warn) : un tenant dont la CLÉ ne résout pas (vault: injoignable, préfixe inconnu)
///    ou dont la base ne s'ouvre pas est SAUTÉ — le job ne tourne JAMAIS sur la base `default` à sa place
///    (jamais de repli cross-tenant ; cohérent avec resolve/ingest fail-closed R8/#2a-3).
pub(crate) fn for_each_active_tenant<F: FnMut(&str, &Arc<Mutex<Connection>>, &str)>(mgr: &TenantDbManager, mut body: F) {
    let cp = match &mgr.control {
        None => {
            // MODE 0 : passthrough EXACT — un seul tenant `default` = (default_writer, default_db_path).
            body("default", &mgr.default_writer, mgr.default_db_path.as_str());
            return;
        }
        Some(cp) => cp,
    };
    // MODE 1 : SNAPSHOT de la liste des tenants actifs (on relâche le lock control AVANT d'exécuter les corps,
    // qui prennent d'autres verrous / ouvrent des bases -> jamais de lock control tenu pendant un job).
    let tenants: Vec<String> = {
        let conn = cp.conn.lock();
        let list = match conn.prepare("SELECT id FROM tenant WHERE suspended=0") {
            Ok(mut stmt) => stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map(|rows| rows.flatten().collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        list
    };
    for tid in tenants {
        // MÊME point de passage que le chemin requête (`ready`) : clé résolue + enregistrée au registre
        // read-pool, contrat de schéma appliqué, registres par-db_path hydratés — sinon SKIP fail-closed
        // (le job ne tourne JAMAIS sur la base `default` à la place d'un tenant).
        let w = match mgr.ready(&tid) {
            Some(w) => w,
            None => {
                eprintln!("[multi-tenant][jobs] tenant '{tid}' : base non servable (tenant suspendu / clé non résolue / schéma refusé) -> SKIP (fail-closed ; job NON exécuté sur la base default)");
                continue;
            }
        };
        body(&tid, &w.handle(), w.path().as_str());
    }
}

/// Slug de tenant SÛR en nom de fichier spool (routing ingest) : alnum + `_`/`-` (jamais `#`, jamais `.`,
/// jamais `/`). Un slug non conforme -> marqueur invalide -> QUARANTAINE à la relecture (fail-closed).
pub(crate) fn tenant_slug_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// Slug d'ENVIRONNEMENT (#2d) valide et SÛR à injecter comme littéral `env_id='<env>'` : même charset
/// borné que `tenant_slug_ok` (alnum + `_`/`-`, jamais d'espace/quote/`.`/`/`) -> anti-injection. Couvre
/// `prod` (défaut), `staging`, et des noms de site alnum. Une valeur non conforme -> filtre IGNORÉ
/// (traité comme « tous les environnements ») plutôt que rejeté : le read path reste fail-open côté lecture.
pub(crate) fn env_slug_ok(s: &str) -> bool {
    tenant_slug_ok(s)
}

/// M8 (refactor T1) — prédicats de FILTRE ENVIRONNEMENT centralisant l'échappement `soql_esc` (surface
/// d'injection en un seul point). Reproduisent EXACTEMENT le motif inline non qualifié `envp`/`wenv` :
/// `env` non vide -> ` AND env_id='<esc>'` / ` WHERE env_id='<esc>'` ; sinon `""`. Byte-identique (même
/// filtre `!e.is_empty()`, même `soql_esc`). NB : le variant COLONNE-QUALIFIÉ (` AND {col}.env_id=…`,
/// dashboard-badges) reste inline — SQL distinct, hors signature.
pub(crate) fn env_and_pred(env: Option<&str>) -> String {
    match env.filter(|e| !e.is_empty()) { Some(e) => format!(" AND env_id='{}'", guatx_core::soql::soql_esc(e)), None => String::new() }
}

pub(crate) fn env_where_pred(env: Option<&str>) -> String {
    match env.filter(|e| !e.is_empty()) { Some(e) => format!(" WHERE env_id='{}'", guatx_core::soql::soql_esc(e)), None => String::new() }
}

impl AuthUser {
    /// FILTRE ENVIRONNEMENT effectif (#2d) pour le READ PATH : `Some("<env>")` -> injecter `env_id='<env>'`
    /// ; `None` -> aucun filtre (tous les environnements). Déjà validé/gaté (mode 0 -> toujours None) par
    /// auth_guard ; cet accesseur est le point d'appel unique côté handlers (query/search/panels/overview/
    /// fraîcheur) pour ne PAS disperser la logique.
    pub(crate) fn env_filter(&self) -> Option<&str> {
        self.env.as_deref()
    }
    /// M6 (refactor T1) — prédicat admin unique. #64 : AUTORITÉ ADMIN EFFECTIVE via `effective_base_role`
    /// (plafond de base d'un rôle composable), PAS un compare littéral. Byte-identique en mode 0 / rôle de base
    /// (`effective_base_role("admin")=="admin"`, editor/viewer/inconnu -> !="admin"). Un rôle COMPOSABLE base=admin
    /// (ex. "gov-admin" = admin MOINS `manage_users`) est reconnu admin ICI (autorité de ROUTE) ; les capacités
    /// RETIRÉES (`deny_perms`) restent soustraites EN AMONT par `rbac_gate`/`role_perm_denied` (path-guard) AVANT
    /// que le handler ne s'exécute -> aucune escalade. Un base viewer/editor/inconnu NE devient JAMAIS admin
    /// (`effective_base_role` plafonne à la base déclarée, ne l'élève jamais).
    pub(crate) fn is_admin(&self) -> bool { effective_base_role(&self.role) == "admin" }
}

/// M6 (refactor T1) — garde admin réutilisable. `Ok(())` si admin, sinon `Err` portant la réponse 403
/// JSON dominante `{"error":"réservé à l'administrateur"}` (message figé, byte-identique aux sites gate
/// qu'elle remplace). Idiome d'appel côté handler (retour `Response`) : `if let Err(r) = require_admin(&au)
/// { return r; }`. Les gates au message/forme DISTINCTS (réservé admin, StatusCode nu, texte brut) restent
/// inline — un helper à message fixe ne peut les couvrir sans changer l'octet émis.
pub(crate) fn require_admin(au: &AuthUser) -> Result<(), Response> {
    if au.is_admin() { Ok(()) } else { Err(forbidden("réservé à l'administrateur")) }
}

/// Garde EDITOR+ (editor OU admin) — HOISTÉE (était dupliquée VERBATIM dans
/// 4 handlers datamodels/knowledge/scheduled_reports/workflow_actions). Sœur de `require_admin`. Idiome :
/// `if let Err(r) = require_editor(&au) { return r; }`. Re-exportée via `pub(crate) use state::*` -> résolue
/// bare dans les handlers en `use crate::*`.
pub(crate) fn require_editor(au: &AuthUser) -> Result<(), Response> {
    if crate::rbac::role_rank(&au.role) >= crate::rbac::role_rank("editor") {
        Ok(())
    } else {
        Err(forbidden("réservé à l'éditeur (editor+)"))
    }
}

/// Un hostname est-il sûr à encoder dans le marqueur `#H#…#H#` du nom de fichier
/// spool ? Alphanumérique + `.-_` (couvre FQDN/hostnames), non vide, borné, PAS de `#` (délimiteur) ni `/`
/// (chemin). Un host non conforme -> pas de marqueur (on retombe sur le host de l'event, comportement actuel).
pub(crate) fn host_marker_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// M2 — MARQUEUR HOST encodé dans le NOM du fichier spool : lie les events d'un AGENT (token Bearer) à
/// l'hôte RÉELLEMENT lié à son token (`au.name` = host du token, cf. auth_guard). Relu par ingest_once/
/// ingest_journal -> ÉCRASE `event.host` de tous les events du fichier. Empêche un agent de forger
/// `host=<hôte d'un AUTRE agent>` et donc de déclencher une réponse (ban) sur l'hôte d'autrui (M2).
/// Émis UNIQUEMENT pour un agent (role='agent') à token LIÉ (host non vide) : les collecteurs centraux
/// Basic (editor/admin) multiplexent LÉGITIMEMENT plusieurs hôtes -> jamais de marqueur -> collecte intacte.
/// Indépendant du multi-tenant (les agents existent en mode 0). Encadré par `#H#…#H#` (délimiteur distinct
/// du marqueur tenant `#T#`, parsing non ambigu).
///
/// P5.2-a : le prédicat « ce jeton est-il une identité de machine ? » n'est plus recopié ici — il est LU
/// à `HoteIngere::lie`, l'unique résolution partagée par toutes les surfaces d'ingestion. Le marqueur
/// n'est plus qu'un ENCODAGE de cette réponse dans un nom de fichier ; il ne peut plus diverger d'elle.
pub(crate) fn spool_host_marker(au: &AuthUser) -> String {
    match HoteIngere::lie(au) {
        Some(h) => format!("#H#{h}#H#"),
        None => String::new(),
    }
}

/// Host LIÉ (marqueur `#H#…#H#`) d'un fichier spool, ou None (collecteur central / agent non lié / mode
/// historique). Sert à ÉCRASER `event.host` à la relecture (M2). Valeur re-validée (host_marker_ok) : un
/// marqueur corrompu est ignoré (fail-open vers le host de l'event, jamais un crash).
pub(crate) fn spool_file_host(name: &str) -> Option<String> {
    let i = name.find("#H#")?;
    let rest = &name[i + 3..];
    let j = rest.find("#H#")?;
    let h = &rest[..j];
    if host_marker_ok(h) { Some(h.to_string()) } else { None }
}

/// Le namespace `plume-*` des sources est RÉSERVÉ aux events de CONTRÔLE que le
/// daemon écrit LUI-MÊME (plume-config / plume-auth / plume-operator-access / plume-tenant-admin, tous insérés
/// EN DIRECT, JAMAIS via un chemin d'ingestion). Toute source ARRIVANT par l'ingest (agent/collecteur :
/// /api/ingest, journal, loki push) qui usurpe ce préfixe est renommée `ext:<source>` — elle ne peut donc ni
/// (a) polluer la vue d'audit (`search source=plume-config`), ni (b), combinée au marqueur `origin`, se faire
/// passer pour une ligne de contrôle non-purgeable. Aucun collecteur légitime n'émet de source `plume-*`
/// -> la COLLECTE LÉGITIME est INTACTE ; seul le namespace de contrôle est protégé. CE « AUCUN » N'EST PLUS UN
/// « (vérifié) » SANS DATE (S29) : `tests::allegations_d_environnement` relit les collecteurs livrés et les deux
/// amorceurs, y cherche les DEUX formes par lesquelles un nom de source y naît (le littéral JSON, le premier
/// argument des fabriques de `lib.sh`), et lit le préfixe ICI plutôt que de le recopier. La raison du silence
/// que cette garde ferme : un collecteur qui usurperait le préfixe verrait tous ses événements renommés SANS
/// erreur ni rejet — son panneau resterait vide, indistinguable d'un capteur qui n'a rien à dire.
/// Fast-path : source normale -> renvoyée telle quelle (allocation identique à avant).
pub(crate) fn ext_ingest_source(source: &str) -> String {
    if source.starts_with("plume-") {
        format!("ext:{source}")
    } else {
        source.to_string()
    }
}

/// Marqueur tenant encodé dans le NOM du fichier spool (relu par ingest_once -> insert vers la BONNE base,
/// R8). Mode 0 ou tenant `default` -> "" (nom STRICTEMENT identique à aujourd'hui). Encadré par `#T#…#T#`
/// (caractères hors slug -> pas d'ambiguïté). Slug non conforme -> marqueur invalide -> quarantaine.
pub(crate) fn spool_tenant_marker(st: &AppState, au: &AuthUser) -> String {
    spool_tenant_marker_for(st, &au.tenant)
}

/// Variante par TENANT NU (P-HEC) — même logique que `spool_tenant_marker` mais sans exiger un `AuthUser`
/// (le récepteur Firehose s'auto-authentifie via `firehose_token_lookup` HORS du choke-point auth_guard et n'a
/// donc pas d'`AuthUser` en extension). `spool_tenant_marker` DÉLÈGUE ici -> comportement byte-identique pour
/// tous les appelants existants (mode 0 / tenant 'default' -> "").
pub(crate) fn spool_tenant_marker_for(st: &AppState, tenant: &str) -> String {
    if !st.multi_tenant || tenant == "default" {
        return String::new();
    }
    if tenant_slug_ok(tenant) {
        format!("#T#{}#T#", tenant)
    } else {
        "#T#!invalid#T#".to_string()
    }
}

/// Tenant PORTEUR d'un fichier spool (marqueur `#T#…#T#`). Absent -> `default` (mode 0, collecteurs hôte
/// centraux, ou fichiers en vol pré-migration -> base opérateur/self, JAMAIS une base client).
pub(crate) fn spool_file_tenant(name: &str) -> String {
    if let Some(i) = name.find("#T#") {
        let rest = &name[i + 3..];
        if let Some(j) = rest.find("#T#") {
            return rest[..j].to_string();
        }
    }
    "default".to_string()
}

/// (writer, db_path) cible de l'ingest pour un tenant. Mode 0 : (st.db, st.db_path) quel que soit `tenant`
/// (passthrough EXACT — mêmes deux valeurs qu'avant). Mode 1 : le MÊME point de passage que le chemin
/// requête et les jobs (`ready`) -> writer et db_path viennent du MÊME `PreparedWriter` (ils ne peuvent
/// plus désigner deux bases différentes), registres hydratés ; tenant inconnu/suspendu/clé non résolue/
/// schéma refusé -> None (fail-closed R8 : quarantaine du fichier spool, jamais un repli vers `default`).
pub(crate) fn resolve_ingest_target(mgr: &TenantDbManager, tenant: &str) -> Option<(Arc<Mutex<Connection>>, String)> {
    if mgr.control.is_none() {
        return Some((mgr.default_writer.clone(), mgr.default_db_path.as_ref().clone()));
    }
    let w = mgr.ready(tenant)?;
    Some((w.handle(), w.path()))
}

/// QUARANTAINE d'un fichier spool NON routable (tenant inconnu/suspendu) : déplacé sous `<spool>/quarantine`
/// -> JAMAIS inséré dans une base client, JAMAIS de repli vers `default`. Best-effort (dernier recours : rm
/// pour ne pas boucler indéfiniment sur un fichier non routable).
pub(crate) fn quarantine_spool_file(spool: &str, path: &std::path::Path, name: &str, reason: &str) {
    let qdir = format!("{spool}/quarantine");
    let _ = std::fs::create_dir_all(&qdir);
    let dst = format!("{qdir}/{name}");
    if std::fs::rename(path, &dst).is_err() {
        let _ = std::fs::remove_file(path);
    }
    eprintln!("[ingest] {reason} -> quarantaine : {name}");
}

/// Résout le tenant COURANT d'un user (mode 1) : sélection explicite (header/param) si l'user y a un grant
/// actif, sinon son 1er grant (ordre stable). None = aucun grant -> fail-closed (403 côté guard). Le rôle
/// per-tenant renvoyé alimentera le RBAC per-tenant (#2b) ; ici auth_guard n'en retient que le tenant.
pub(crate) fn resolve_user_tenant(st: &AppState, user: &str, requested: Option<&str>) -> Option<(String, String)> {
    let cp = st.tenants.control.as_ref()?;
    let conn = cp.conn.lock();
    let uid: String = conn
        .query_row("SELECT id FROM platform_user WHERE name=?1", params![user], |r| r.get(0))
        .ok()?;
    if let Some(t) = requested.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return conn
            .query_row(
                "SELECT g.role FROM \"grant\" g JOIN tenant t ON t.id=g.tenant_id \
                 WHERE g.user_id=?1 AND g.tenant_id=?2 AND t.suspended=0",
                params![uid, t],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .map(|role| (t.to_string(), role));
    }
    conn.query_row(
        "SELECT g.tenant_id, g.role FROM \"grant\" g JOIN tenant t ON t.id=g.tenant_id \
         WHERE g.user_id=?1 AND t.suspended=0 ORDER BY g.tenant_id LIMIT 1",
        params![uid],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
}
