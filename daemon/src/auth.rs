//! Middleware d'authentification & garde-fous : anti-rebinding Host (`host_guard`), le choke-point
//! `auth_guard` (Basic/SSO/Bearer/cookie -> AuthUser + RBAC + résolution tenant), extraction IP/username
//! (`client_ip`/`basic_username`), anti-brute-force (`auth_lock_check`/`auth_record_*` + `AuthFail`/
//! `AUTH_FAIL_*` + auto-ingest SIEM `ingest_auth_event`), tokens agent (`valid_token`/`agent_bearer_path`),
//! mapping SSO (`sso_role`) et l'authentification (`verify_pw`/`authenticate`). Extrait de main.rs
//! (refactor split #25 — byte-identique).
use crate::*;

/// État anti-brute-force d'un couple (username, src_ip). `count` = échecs consécutifs ; `locked_until`
/// = fin du lockout courant (None si non verrouillé) ; `last` = dernier échec (TTL -> réarmement).
#[derive(Clone)]
pub(crate) struct AuthFail {
    pub(crate) count: u32,
    pub(crate) locked_until: Option<Instant>,
    pub(crate) last: Instant,
}

// ====================================================================================================
// L'AUTORITÉ D'UNE REQUÊTE — UNE SEULE SOURCE, LES DEUX FORMES DU PROTOCOLE.
//
// CE QUI ÉTAIT CASSÉ. `host_guard` ne lisait QUE l'en-tête `Host`. Cet en-tête n'existe PAS en HTTP/2 :
// l'autorité y est le pseudo-en-tête `:authority`, que hyper range dans l'URI de la requête, pas dans
// les en-têtes. Le `.unwrap_or(false)` final transformait donc « le client n'a pas nommé d'autorité
// LÀ OÙ JE REGARDE » en « autorité refusée ».
//
// MESURÉ le 2026-08-02, daemon en TLS natif (`PLUME_TLS_CERT`/`PLUME_TLS_KEY`, `PLUME_HOST=plume.test`) :
//   - `openssl s_client -alpn h2,http/1.1` -> « ALPN protocol: h2 ». axum-server annonce h2 EN PREMIER :
//     un navigateur négocie donc h2 SYSTÉMATIQUEMENT sur ce mode de déploiement.
//   - MÊME requête, MÊME autorité `plume.test`, deux versions : `/api/me`, `/api/search`, `/login`, `/`
//     -> **421 « bad host » en HTTP/2**, **401/404 en `--http1.1`** (la garde passe). Seules `/healthz`,
//     `/readyz`, `/metrics` (les 3 exemptions ci-dessous) répondaient en h2 : **242 des 245 routes
//     déclarées étaient injoignables depuis un navigateur**, l'interface web comprise.
//   - Sonde jetable posée DANS le middleware puis retirée (l'arbre est revenu propre) :
//       HTTP/1.1 -> `uri.authority=None`,               `header_host=Some("plume.test:7443")`
//       HTTP/2.0 -> `uri.authority=Some(plume.test:7443)`, `header_host=None`
//     Les deux emplacements sont exactement COMPLÉMENTAIRES — c'est la mesure, pas une lecture de doc.
// Tous nos émetteurs (collecteurs shell, agent Rust, PowerShell) parlent HTTP/1.1 : c'est ce qui a
// masqué le défaut pendant toute la vie du mode TLS natif.
//
// CE QUE LE REMÈDE N'EST PAS. Laisser passer quand l'autorité est absente désarmerait la garde
// (anti-DNS-rebinding) sur TOUTES les requêtes : `None` doit rester un REFUS.
//
// LA FORME DÉRIVÉE. La question n'est pas « faut-il aussi lire l'URI ? » mais « QU'EST-CE QUE
// L'AUTORITÉ D'UNE REQUÊTE ? ». C'est une notion du PROTOCOLE, pas d'un en-tête : HTTP la range dans
// la cible de requête (forme absolue, `:authority` de h2 et h3) ou dans `Host` (forme origine de
// HTTP/1.x), et RFC 9112 §3.2.2 tranche l'ambiguïté — quand la cible porte une autorité, elle FAIT FOI
// et `Host` est ignoré. On en fait donc UN TYPE, dont le SEUL constructeur prend la REQUÊTE ENTIÈRE et
// consulte les deux emplacements. Conséquence — et c'est la garantie à la compilation : le champ est
// PRIVÉ, donc **aucun appelant ne peut fabriquer une `AutoriteDemandee` à partir d'un seul des deux
// emplacements**. Une garde qui n'en verrait qu'un ne compile pas ; elle ne « rend » pas `false` en
// silence. Ajouter demain une version du protocole qui range l'autorité ailleurs est un changement
// D'UN SEUL endroit, et ce n'est pas une garde qu'on aura oublié de mettre à jour.
// ====================================================================================================

/// MODULE-COFFRE. Le champ d'`AutoriteDemandee` est privé À CE MODULE-CI, pas au fichier : même
/// `host_guard`, juste en dessous, ne peut pas fabriquer la valeur — il DOIT passer par le
/// constructeur. Sans cette enveloppe, l'auteur d'une garde future pourrait, DANS `auth.rs`, écrire
/// `AutoriteDemandee(headers.get(HOST)…)` et rouvrir exactement le trou qu'on ferme, sans que rien ne
/// l'arrête. Vérifié par mutation : cette écriture-là ne compile pas (E0603, champ privé).
mod autorite {
    use super::*;

    /// L'AUTORITÉ que le client a DEMANDÉ à joindre — « quel nom d'hôte a-t-il cru appeler ? ».
    ///
    /// Champ PRIVÉ, constructeur UNIQUE : on ne peut pas en fabriquer une depuis le seul en-tête `Host`
    /// (HTTP/1.x) ni depuis la seule URI (HTTP/2, HTTP/3). Voir le bandeau ci-dessus pour la mesure.
    pub(crate) struct AutoriteDemandee(Option<String>);

    impl AutoriteDemandee {
        /// SEUL constructeur. Lit les DEUX emplacements où HTTP range l'autorité, dans l'ordre que fixe
        /// RFC 9112 §3.2.2 : la cible de requête d'abord (forme absolue HTTP/1.x, `:authority` en h2/h3 —
        /// hyper les expose tous deux par `uri().authority()`), l'en-tête `Host` à défaut (forme origine,
        /// le cas du navigateur en HTTP/1.1). Aucune des deux -> `None` = le client n'a nommé AUCUNE
        /// autorité, ce qui reste un REFUS pour les appelants (jamais un laissez-passer).
        pub(crate) fn de_la_requete(req: &Request) -> Self {
            Self(
                req.uri()
                    .authority()
                    .map(|a| a.as_str().to_string())
                    .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(|s| s.to_string())),
            )
        }

        /// L'hôte SEUL : sans le port, et sans les crochets d'une littérale IPv6. `None` = aucune autorité
        /// nommée. Le port n'est retiré que s'il en EST un (suffixe `:<chiffres>`) — sinon `[::1]` sans port
        /// se ferait amputer par son propre dernier `:`. Aucun changement pour une autorité réelle
        /// (`plume.test`, `plume.test:7443`, `[::1]:7443`) ; seules les formes MALFORMÉES (`plume.test:`)
        /// cessent d'être tronquées, donc cessent de matcher l'allowlist : une garde ne s'élargit pas ici.
        pub(crate) fn hote(&self) -> Option<&str> {
            self.0.as_deref().map(|h| {
                let hp = match h.rsplit_once(':') {
                    Some((g, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => g,
                    _ => h,
                };
                hp.trim_start_matches('[').trim_end_matches(']')
            })
        }
    }
}
pub(crate) use autorite::AutoriteDemandee;

// ---------- middlewares ----------
pub(crate) async fn host_guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    // #51 DAY-2 OPS — endpoints d'infra exemptés de l'allowlist Host : les sondes k8s (httpGet) posent
    // `Host: <pod-ip>` (hors PLUME_HOST) et un scraper Prometheus vise l'IP du service -> host_guard les
    // rejetterait (421). /healthz + /readyz ne révèlent rien ; /metrics reste gaté par auth_guard (jeton de
    // scrape OU viewer+) -> pas de risque de DNS-rebinding (le jeton protège). Aucune autre route exemptée.
    let p = req.uri().path();
    if p == "/healthz" || p == "/readyz" || p == "/metrics" {
        return next.run(req).await;
    }
    // P5.3-a : l'autorité vient de la SOURCE UNIQUE (les deux formes du protocole), plus de l'en-tête seul.
    // `None` (aucune autorité nommée) reste un REFUS — le `unwrap_or(false)` d'origine est conservé tel quel.
    let ok = AutoriteDemandee::de_la_requete(&req)
        .hote()
        .map(|hp| {
            // PLUME_HOST peut lister plusieurs hôtes (virgule) : ex "plume.example.com,plume-ingest.example.com"
            // (chemin navigateur + chemin agent mTLS sur un SNI dédié, déclaré dans votre ingress).
            let fqdn_ok = st.host.split(',').any(|x| hp == x.trim());
            // DURCISSEMENT STANDALONE — allowlist Host STRICTE (config-gated, PLUME_HOST_STRICT=1) :
            // restreint l'allowlist EXACTEMENT aux FQDN de PLUME_HOST (retire l'auto-allow loopback).
            // DÉFAUT (PLUME_HOST_STRICT=0) = comportement ACTUEL : loopback (127.0.0.1/::1/localhost)
            // accepté en plus -> k3s + vérifs `Host: 127.0.0.1`/ClusterIP NE cassent PAS. Le mode strict
            // est réservé au déploiement standalone exposé (un seul FQDN public attendu).
            if st.host_strict {
                fqdn_ok
            } else {
                fqdn_ok || hp == "localhost" || hp == "127.0.0.1" || hp == "::1"
            }
        })
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "bad host").into_response()
    }
}

/// Token d'agent (Bearer) : SHA-256 comparé à la table `token`. Met à jour last_used.
/// Retourne Some(host) si valide (host = l'hôte LIÉ au token, "" si non lié), None si invalide.
/// L'hôte sert à scoper le responder : un agent ne peut agir que sur les actions de SON hôte.
/// R6 (#2a-2a) : projection host de `token_lookup` (mode-aware). #2a-2b : auth_guard consomme désormais
/// `token_lookup` DIRECTEMENT (il a besoin du tenant PORTEUR du token, pas seulement du host) -> ce
/// wrapper n'a plus de caller en prod (conservé pour les tests d'identité + comme API host-only stable).
#[allow(dead_code)]
pub(crate) fn valid_token(st: &AppState, tok: &str) -> Option<String> {
    token_lookup(st, tok).map(|t| t.host)
}

// Mappe les groupes SSO (en-tête de groupes du proxy, ex. X-authentik-groups, séparés par | ou ,) ->
// rôle Plume. On accepte UNIQUEMENT les noms de groupes CONFIGURÉS (cfg, défaut plume-*) plus le
// superadmin (anti-lockout) ; aucun alias de nom implicite n'accorde de privilège.
pub(crate) fn sso_role(st: &AppState, groups: &str) -> String {
    let has = |name: &str| groups.split(|c| c == '|' || c == ',').any(|g| g.trim() == name);
    if has(st.sso_group_admin.as_str()) || has(st.sso_group_superadmin.as_str()) { "admin".into() }
    else if has(st.sso_group_editor.as_str()) { "editor".into() }
    else { "viewer".into() }
}

// ---------- anti-brute-force / IP source (durcissement standalone) ----------
pub(crate) const AUTH_FAIL_TTL: Duration = Duration::from_secs(900); // entrée oubliée après 15 min d'inactivité (réarme)

pub(crate) const AUTH_FAIL_CAP: usize = 4096;                        // borne anti-OOM de la map (purge des entrées expirées)

/// IP source du client = pair TCP (ConnectInfo posé par into_make_service_with_connect_info / axum-server).
/// On NE fait PAS confiance à X-Forwarded-For (spoofable en standalone -> contournerait le lockout).
/// "" si indisponible (tests, ou serve sans connect-info) -> les chemins per-IP deviennent no-op.
pub(crate) fn client_ip(req: &Request) -> String {
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default()
}

// ====================================================================================================
// BAN NATIF PLUME (chantier ② — Phase 1) : IP RÉELLE derrière proxy + store live `net_ban` + guard HTTP.
// Bloque TOUTES les routes du daemon pour l'IP réelle d'un attaquant (même CF-proxifié), réversible, TTL,
// pilotable par l'API admin `/api/netban`. Mode-0-safe (set vide + config défaut = passthrough), fail-OPEN
// (jamais de lock-out de l'opérateur sur un bug de store), kill-switch `PLUME_NETBAN_DISABLE=1`.
// ====================================================================================================

/// TTL par défaut d'un `net_ban` POSÉ PAR UNE ACTION `ban_ip` (miroir de la durée CrowdSec `4h` de
/// `action_command`) — réversible avant expiry via `unban_ip` / DELETE `/api/netban`. Une pose MANUELLE via
/// l'API POST sans `ttl_s` est PERMANENTE (expires_ts NULL).
pub(crate) const NETBAN_ACTION_TTL_S: i64 = 4 * 3600;

/// Liste EXACTE des pairs TCP à qui faire confiance comme reverse-proxy (`PLUME_TRUSTED_PROXIES`, IPs
/// séparées par des virgules). Vide (DÉFAUT) -> politique par défaut privé/loopback (cf `proxy_is_trusted`).
/// Lue UNE FOIS (OnceLock) — comme les autres caches de config (protected_ip_matchers, ssrf_*).
static NETBAN_TRUSTED_PROXIES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
fn netban_trusted_proxies() -> &'static Vec<String> {
    NETBAN_TRUSTED_PROXIES.get_or_init(|| {
        let conf = load_config();
        cfg(&conf, "PLUME_TRUSTED_PROXIES", "")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// DURCISSEMENT ANTI-SPOOF — SECRET D'EDGE. `(nom_header_minuscule, secret)` lus une fois. Si `secret` NON VIDE
/// (config `PLUME_EDGE_SECRET`, injecté par VOTRE reverse-proxy — celui qui est LE PAIR TCP de plume, pas un CDN
/// en amont — sur le header `PLUME_EDGE_SECRET_HEADER`, défaut `x-plume-edge`), `real_client_ip` ne fait
/// confiance aux en-têtes d'IP réelle QUE si la requête porte ce secret -> un attaquant atteignant plume EN DIRECT
/// (hors le proxy de confiance) n'a PAS le secret -> ses en-têtes forgés sont ignorés (repli sur le pair). Secret
/// VIDE (DÉFAUT) = INERTE : confiance sur le pair seul (miroir exact de `sso_secret` : défaut vide = inerte).
static NETBAN_EDGE_SECRET: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
fn netban_edge_secret() -> &'static (String, String) {
    NETBAN_EDGE_SECRET.get_or_init(|| {
        let conf = load_config();
        let name = cfg(&conf, "PLUME_EDGE_SECRET_HEADER", "x-plume-edge").trim().to_ascii_lowercase();
        let secret = cfg(&conf, "PLUME_EDGE_SECRET", "").trim().to_string();
        (name, secret)
    })
}

/// Kill-switch d'enforcement (`PLUME_NETBAN_DISABLE=1`) : le guard devient un passthrough PUR. Lu une fois.
static NETBAN_DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
fn netban_disabled() -> bool {
    *NETBAN_DISABLED.get_or_init(|| {
        matches!(
            std::env::var("PLUME_NETBAN_DISABLE").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Un pair TCP `peer` (déjà en String, cf `client_ip`) est-il un PROXY DE CONFIANCE d'où lire l'IP réelle du
/// client dans les en-têtes ? PUR & testable.
///  - Liste EXPLICITE non vide (`PLUME_TRUSTED_PROXIES`) -> confiance EXACTE à ces IPs UNIQUEMENT (le défaut
///    privé/loopback est REMPLACÉ, pas cumulé -> durcissement standalone : un seul reverse-proxy connu).
///  - Liste vide (DÉFAUT) -> confiance à un pair PRIVÉ (RFC1918) / loopback (v4 & v6) / ULA IPv6 (fc00::/7) :
///    Traefik/ingress k3s pose `10.42.x`, un reverse-proxy local pose `127.0.0.1`. JAMAIS un pair PUBLIC
///    (anti-spoof : un attaquant en direct ne doit pas pouvoir se réécrire une fausse IP réelle via XFF).
pub(crate) fn proxy_is_trusted(peer: &str, trusted_list: &[String]) -> bool {
    let peer = peer.trim();
    if peer.is_empty() {
        return false;
    }
    if !trusted_list.is_empty() {
        return trusted_list.iter().any(|t| t.trim() == peer);
    }
    match peer.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00, // ::1 | fc00::/7
        Err(_) => false,
    }
}

/// IP RÉELLE du client pour le ban natif. Si le pair TCP est un PROXY DE CONFIANCE
/// (`proxy_is_trusted`), on lit l'IP réelle dans les en-têtes PAR PRIORITÉ : `CF-Connecting-IP` (posé par un
/// CDN/WAF = client réel) > `X-Real-IP` > hop GAUCHE de `X-Forwarded-For` ; CHACUNE doit parser en `IpAddr`
/// (std::net) sinon on descend / on retombe sur le pair. Si le pair N'EST PAS de confiance (attaquant direct)
/// -> on renvoie le PAIR, JAMAIS un en-tête (anti-spoof). PORTÉE : le gate `net_ban` ; `client_ip()` et ses
/// callers (rate_limit / verrouillage) sont keyés sur le PAIR TCP. Derrière un reverse-proxy, déclarez-le dans
/// `PLUME_TRUSTED_PROXIES` et scellez les en-têtes d'IP réelle avec `PLUME_EDGE_SECRET`.
pub(crate) fn real_client_ip(req: &Request) -> String {
    let (edge_hdr, edge_secret) = netban_edge_secret();
    real_client_ip_ctx(req, netban_trusted_proxies(), edge_hdr, edge_secret)
}

/// Cœur PUR de `real_client_ip` (config injectée) -> testable sans OnceLock. `trusted`=liste proxies exacts (vide
/// = défaut privé/loopback) ; `edge_secret` vide = pas de gate secret (Phase 1).
pub(crate) fn real_client_ip_ctx(req: &Request, trusted: &[String], edge_hdr: &str, edge_secret: &str) -> String {
    let peer = client_ip(req);
    if !proxy_is_trusted(&peer, trusted) {
        return peer; // pair non-proxy : on IGNORE tout en-tête (anti-spoof)
    }
    // DURCISSEMENT ANTI-SPOOF : si un SECRET D'EDGE est configuré (injecté par le reverse-proxy), il DOIT être
    // présent+correct (ct_eq) pour qu'on fasse confiance aux en-têtes d'IP réelle. Absent/faux -> repli sur le pair
    // (un client qui atteint plume hors du proxy n'a pas le secret). Secret VIDE (défaut) -> gate inerte.
    if !edge_secret.is_empty() {
        let presented = req.headers().get(edge_hdr).and_then(|h| h.to_str().ok()).unwrap_or("");
        if !ct_eq(presented.as_bytes(), edge_secret.as_bytes()) {
            return peer; // pas le secret d'edge -> en-têtes non fiables
        }
    }
    let hdr = |name: &str| req.headers().get(name).and_then(|h| h.to_str().ok());
    let valid = |v: &str| v.trim().parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string());
    if let Some(ip) = hdr("cf-connecting-ip").and_then(|v| valid(v)) {
        return ip;
    }
    if let Some(ip) = hdr("x-real-ip").and_then(|v| valid(v)) {
        return ip;
    }
    if let Some(xff) = hdr("x-forwarded-for") {
        if let Some(ip) = xff.split(',').next().and_then(|h| valid(h)) {
            return ip;
        }
    }
    peer // en-têtes absents/malformés -> repli sur le pair
}

/// STORE LIVE en mémoire du ban natif : `ip -> Option<expires_ts>` (None = ban PERMANENT). DISTINCT de la
/// table `banned_ip` (analytique). Rechargé depuis la base à chaque mutation + périodiquement (spawn_netban_
/// maintenance) + au boot. Check O(1) (lecture RwLock seule, ZÉRO accès DB par requête). Global OnceLock —
/// même patron que `field_deny_cols_cell` / `PROCESSORS` (accessible depuis le guard, l'API admin, les jobs).
static NETBAN_CACHE: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Option<i64>>>> =
    std::sync::OnceLock::new();
pub(crate) fn netban_cache() -> &'static parking_lot::RwLock<HashMap<String, Option<i64>>> {
    NETBAN_CACHE.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// PLAFOND DU STORE LIVE, en ENTRÉES (borne anti-OOM, même rôle qu'`AUTH_FAIL_CAP` pour la map d'échecs
/// d'auth). Le cache est une structure de recherche EN MÉMOIRE dont la taille suit le nombre d'IP bannies ;
/// sans borne, un chemin d'auto-ban (opt-in `PLUME_NETBAN_FROM_ACTIONS`) rend la croissance mémoire
/// PILOTABLE PAR L'ATTAQUANT — un botnet suffit à poser une entrée par adresse source.
///
/// BUDGET, dérivé de la structure et non d'une observation : une entrée = la clé texte (45 octets au pire,
/// une IPv6 en forme longue) + son `String` (24) + `Option<i64>` (16) + l'emplacement de la table de hachage
/// et son octet de contrôle, soit ~120 octets ; 50 000 entrées ≈ 6 Mio. Borné, et négligeable devant le
/// budget de conception de 2 Gio — tout en couvrant très largement une banlist manuelle ou automatique
/// légitime (au-delà, le blocage par adresse n'est plus le bon outil : c'est un préfixe ou un pare-feu).
pub(crate) const NETBAN_CACHE_CAP: usize = 50_000;

/// LE PLAFOND EST-IL ATTEINT ? `true` = la base porte plus de bans que le cache n'en charge, donc des bans
/// posés ne sont PAS enforcés. Une borne qui ne se dit pas est indistinguable d'une borne absente : ce
/// témoin est exposé par `/metrics` (`plume_netban_store_tronque`) et par `GET /api/netban` (`tronque`).
static NETBAN_TRONQUE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn netban_store_tronque() -> bool {
    NETBAN_TRONQUE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Charge le store `net_ban` d'une base -> (map `ip -> Option<expires_ts>`, plafond atteint). PUR (prend
/// `conn`, ne touche pas le cache global) -> testable. Agrège tous les env_id d'une même IP : un ban
/// PERMANENT (expires NULL) l'emporte ; sinon on garde l'expiry MAX (bloque le plus longtemps). Une IP est
/// bloquée si AU MOINS un ban actif la vise.
/// TENTE de charger le store (None = ÉCHEC de LECTURE de la table : base verrouillée/corrompue/absente ; distinct
/// d'une table VIDE = Some(map vide)). Sert le fail-STATIC de `netban_reload` : on ne
/// remplace le cache que sur un chargement RÉUSSI -> une erreur DB transitoire au tick ne VIDE PAS les bans actifs.
///
/// BORNÉ PAR CONSTRUCTION, des deux côtés : `LIMIT` borne les lignes LUES (une base gonflée par un autre
/// écrivain ne fait pas travailler ce chargement sans fin) et l'arrêt à `NETBAN_CACHE_CAP` borne la map
/// CONSTRUITE. L'ordre de priorité est celui de l'enforcement, pas celui de l'insertion : les bans
/// PERMANENTS d'abord, puis les échéances les plus lointaines (`ip` en départage, pour que deux
/// chargements de la même base rendent le MÊME instantané). Ce qui tombe au-delà du plafond est le ban le
/// plus proche d'expirer — et sa chute est DITE, jamais silencieuse.
fn netban_try_load(conn: &Connection) -> Option<(HashMap<String, Option<i64>>, bool)> {
    netban_try_load_cap(conn, NETBAN_CACHE_CAP)
}

/// Cœur PUR du chargement, PLAFOND INJECTÉ -> la borne se teste sur quelques lignes au lieu d'en fabriquer
/// cinquante mille (même patron que `real_client_ip_ctx`, dont la config est injectée). La production
/// passe TOUJOURS par `netban_try_load`, qui pose `NETBAN_CACHE_CAP`.
pub(crate) fn netban_try_load_cap(conn: &Connection, cap: usize) -> Option<(HashMap<String, Option<i64>>, bool)> {
    use std::collections::hash_map::Entry;
    // Une ligne ne peut créer qu'UNE entrée : lire `cap + 1` lignes suffit à remplir la map jusqu'au
    // plafond, et la (cap+1)-ième dit qu'il reste de la matière en base.
    let mut stmt = conn
        .prepare(
            "SELECT ip, expires_ts FROM net_ban \
             ORDER BY (expires_ts IS NULL) DESC, expires_ts DESC, ip LIMIT ?1",
        )
        .ok()?;
    let rows = stmt
        .query_map(params![(cap + 1) as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
        })
        .ok()?;
    let mut map: HashMap<String, Option<i64>> = HashMap::new();
    let mut tronque = false;
    for (ip, exp) in rows.flatten() {
        // Le plafond porte sur le NOMBRE D'ENTRÉES de la map, pas sur les lignes lues : une ligne qui
        // enrichit une IP déjà chargée (autre `env_id`) ne consomme rien et passe toujours.
        if map.len() >= cap && !map.contains_key(&ip) {
            tronque = true;
            break;
        }
        match map.entry(ip) {
            Entry::Vacant(e) => {
                e.insert(exp);
            }
            Entry::Occupied(mut e) => {
                let cur = e.get_mut();
                match (*cur, exp) {
                    (None, _) => {}                 // déjà permanent -> reste permanent
                    (Some(_), None) => *cur = None, // nouvelle ligne permanente -> permanent
                    (Some(a), Some(b)) => {
                        if b > a {
                            *cur = Some(b);
                        }
                    }
                }
            }
        }
    }
    Some((map, tronque))
}

/// Charge le store `net_ban` d'une base -> map `ip -> Option<expires_ts>`. PUR + test-facing (map VIDE sur échec).
/// TEST-ONLY : la prod passe par `netban_try_load` (fail-static) ; ce wrapper `unwrap_or_default` ne sert qu'aux
/// tests d'agrégation -> `#[cfg(test)]` (pas de warning never-used en release).
#[cfg(test)]
pub(crate) fn netban_load(conn: &Connection) -> HashMap<String, Option<i64>> {
    netban_try_load(conn).map(|(m, _)| m).unwrap_or_default()
}

/// Recharge le cache global depuis la base (REMPLACE l'instantané). Appelé après chaque mutation + au tick de
/// maintenance. Ce commentaire a décrit l'INVERSE du code pendant un temps — « base illisible -> map VIDE ->
/// fail-open » — alors que le corps est FAIL-STATIC depuis. Un invariant écrit qui ment sur un mécanisme de
/// protection est aussi coûteux que le défaut lui-même : le lecteur cesse de vérifier.
pub(crate) fn netban_reload(conn: &Connection) {
    // FAIL-STATIC : on ne REMPLACE le cache que si le chargement a RÉUSSI. Une erreur
    // de lecture transitoire (base verrouillée) -> `None` -> on GARDE le dernier bon instantané (les bans actifs
    // ne sautent pas). Une table réellement VIDE -> `Some(map vide)` -> remplace normalement (unban légitime).
    if let Some((map, tronque)) = netban_try_load(conn) {
        *netban_cache().write() = map;
        NETBAN_TRONQUE.store(tronque, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Verdict PUR sur un instantané : `ip` est-elle bloquée à l'instant `now_ts` ? None=absente (pass) ;
/// Some(None)=ban permanent (bloqué) ; Some(Some(exp))=bloqué TANT QUE non expiré. Fail-safe : une IP absente
/// n'est JAMAIS bloquée (mode-0 parité). Testable sans base ni cache.
pub(crate) fn netban_snapshot_blocked(map: &HashMap<String, Option<i64>>, ip: &str, now_ts: i64) -> bool {
    if ip.is_empty() {
        return false;
    }
    match map.get(ip) {
        None => false,
        Some(None) => true,
        Some(Some(exp)) => *exp > now_ts,
    }
}

/// L'IP est-elle actuellement bannie (cache global) ? O(1), lecture RwLock seule, ZÉRO DB. FAIL-OPEN : si le
/// cache n'est PAS encore initialisé (boot avant 1er reload / store indispo), renvoie `false` (laisse passer) —
/// on ne verrouille JAMAIS le trafic légitime sur un état de store manquant.
pub(crate) fn net_ban_is_blocked(ip: &str, now_ts: i64) -> bool {
    match NETBAN_CACHE.get() {
        Some(lock) => netban_snapshot_blocked(&lock.read(), ip, now_ts),
        None => false, // cache pas chargé -> fail-open
    }
}

/// Chemins EXEMPTÉS du guard : sondes k8s + scrape Prometheus (comme `host_guard`) ET la VALVE DE RÉCUPÉRATION
/// `/api/netban` — un opérateur dont l'IP réelle a été bannie par erreur DOIT pouvoir
/// se DÉBANNIR EN DIRECT (`DELETE /api/netban/:ip`) sans redémarrage/port-forward. Sûr : `/api/netban` reste gardé
/// EN AVAL par `auth_guard`+RBAC admin-only -> un attaquant banni SANS session admin y prend 401/403 (il ne gagne
/// aucune route utile) ; seul un admin authentifié peut lever son propre ban. Un ban ne doit jamais masquer la
/// supervision ni se rendre irréversible depuis l'UI.
/// EXEMPTION EXACTE, jamais par préfixe ouvert : `/api/netban` et ses sous-chemins, RIEN d'autre. Un
/// `starts_with("/api/netban")` nu exempterait une future `/api/netban-import` — une route qui n'a pas
/// été jugée digne de la valve de récupération y échapperait au gate par la seule ressemblance de son nom.
fn net_ban_exempt_path(p: &str) -> bool {
    p == "/api/netban" || p.starts_with("/api/netban/") || matches!(p, "/healthz" | "/readyz" | "/metrics")
}

/// Upsert d'un ban live (`net_ban`) + refresh du cache in-process. `expires` None = permanent. `env` défaut
/// 'prod'. Ne JAMAIS bannir une IP protégée : les appelants valident en amont (`action_valid`/`ip_is_protected`).
///
/// Rend `false` quand le ban est REFUSÉ parce que le store live est plein (`NETBAN_CACHE_CAP`) : la borne
/// mémoire est tenue À L'ÉCRITURE, sur l'UNIQUE voie de pose, et pas seulement au chargement — sinon la
/// base grossirait indéfiniment pendant que le cache, lui, plafonnerait, et l'écart (des bans posés qui ne
/// bloquent rien) ne se verrait nulle part. RAFRAÎCHIR un ban DÉJÀ posé reste toujours permis : cela ne
/// fait pas croître la map. L'appelant DOIT rendre le refus visible (réponse HTTP, ledger) — un ban qu'on
/// croit posé et qui ne bloque pas est pire que pas de ban.
#[must_use = "un ban REFUSÉ (store plein) doit être rapporté à l'appelant, jamais avalé"]
pub(crate) fn netban_upsert(conn: &Connection, ip: &str, expires: Option<i64>, reason: &str, by: &str, env: &str) -> bool {
    {
        let c = netban_cache().read();
        if c.len() >= NETBAN_CACHE_CAP && !c.contains_key(ip) {
            return false;
        }
    }
    let _ = conn.execute(
        "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(?1,?2,?3,?4,?5,?6) \
         ON CONFLICT(ip,env_id) DO UPDATE SET reason=?2, expires_ts=?4, created_by=?5",
        params![ip, reason, now(), expires, by, env],
    );
    netban_reload(conn);
    true
}

/// Retire un ban live (TOUS les env_id de l'IP -> l'unban est GLOBAL en Phase 1) + refresh du cache.
pub(crate) fn netban_remove(conn: &Connection, ip: &str) {
    let _ = conn.execute("DELETE FROM net_ban WHERE ip=?1", params![ip]);
    netban_reload(conn);
}

/// DÉCISION COMPLÈTE du guard (kill-switch + exempt + IP réelle + cache), ISOLÉE pour test unitaire. Renvoie
/// `true` = BLOQUER (403). FAIL-OPEN par construction : ne renvoie `true` QUE sur un blocage POSITIF (kill-switch
/// off, chemin non exempté, IP réelle non vide, présente & non-expirée dans le cache). Tout le reste -> `false`.
pub(crate) fn net_ban_guard_blocks(req: &Request) -> bool {
    if netban_disabled() {
        return false;
    }
    // ZÉRO-OVERHEAD MODE-0 : cache vide (aucun ban actif — l'état par défaut) ->
    // on court-circuite AVANT de calculer `real_client_ip` (lecture d'en-têtes + parse du pair). Une simple lecture
    // RwLock + is_empty par requête tant qu'aucune IP n'est bannie -> passthrough vraiment sans coût.
    if NETBAN_CACHE.get().map(|l| l.read().is_empty()).unwrap_or(true) {
        return false;
    }
    if net_ban_exempt_path(req.uri().path()) {
        return false;
    }
    let ip = real_client_ip(req);
    !ip.is_empty() && net_ban_is_blocked(&ip, now())
}

/// MIDDLEWARE `net_ban_guard` — slotté APRÈS `rate_limit`, AVANT `host_guard`/`auth_guard` (une IP bannie
/// prend un 403 AVANT toute vérif d'host/auth, sur TOUTES les routes non exemptées, même non authentifiées).
/// Sans État (comme les autres caches globaux) : la décision passe par `net_ban_guard_blocks` (fail-open).
pub(crate) async fn net_ban_guard(req: Request, next: Next) -> Response {
    if net_ban_guard_blocks(&req) {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            "{\"error\":\"IP bannie\"}",
        )
            .into_response();
    }
    next.run(req).await
}

/// Username d'un en-tête `Authorization: Basic` SANS vérifier le mot de passe (clé du lockout).
/// None si l'en-tête n'est pas du Basic décodable.
pub(crate) fn basic_username(authz: &str) -> Option<String> {
    let b64 = authz.strip_prefix("Basic ")?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(raw).ok()?;
    Some(s.split(':').next().unwrap_or("").to_string())
}

/// Ce couple (compte, IP) est-il actuellement en lockout ? Some(retry_secs) si oui. Vérifié AVANT argon2
/// (économie CPU + frein anti-bruteforce). Transparent au légitime : un usage normal n'accumule pas
/// d'échecs donc n'est jamais verrouillé.
pub(crate) fn auth_lock_check(st: &AppState, user: &str, ip: &str) -> Option<u64> {
    if st.lock_threshold == 0 {
        return None;
    }
    let g = st.auth_fails.lock();
    let f = g.get(&(user.to_string(), ip.to_string()))?;
    let until = f.locked_until?;
    let now = Instant::now();
    (now < until).then(|| (until - now).as_secs().max(1))
}

/// Auth RÉUSSIE -> réarme le compteur d'échecs (le légitime efface toute trace d'un attaquant homonyme).
pub(crate) fn auth_record_success(st: &AppState, user: &str, ip: &str) {
    if st.lock_threshold == 0 {
        return;
    }
    let mut g = st.auth_fails.lock();
    g.remove(&(user.to_string(), ip.to_string()));
}

/// Échec d'auth Basic : incrémente (user,ip), pose un lockout à BACKOFF EXPONENTIEL au seuil, et
/// AUTO-INGÈRE un event SIEM (source=plume-auth) -> le SOC se détecte lui-même (règle 37, T1110).
/// Retourne Some(retry_secs) si l'échec déclenche/maintient un lockout. Si lockout désactivé
/// (threshold=0) on LOG quand même l'échec (un SIEM DOIT voir ses propres échecs d'auth).
pub(crate) fn auth_record_failure(st: &AppState, user: &str, ip: &str) -> Option<u64> {
    if st.lock_threshold == 0 {
        ingest_auth_event(st, "failure", user, ip, 0, 3);
        return None;
    }
    let now = Instant::now();
    let (count, locked) = {
        let mut g = st.auth_fails.lock();
        if g.len() > AUTH_FAIL_CAP {
            g.retain(|_, f| f.last.elapsed() < AUTH_FAIL_TTL);
        }
        let e = g.entry((user.to_string(), ip.to_string())).or_insert(AuthFail { count: 0, locked_until: None, last: now });
        if e.last.elapsed() > AUTH_FAIL_TTL {
            // longue inactivité -> on réarme (transparent au légitime qui se trompe une fois de temps en temps)
            e.count = 0;
            e.locked_until = None;
        }
        e.count += 1;
        e.last = now;
        let mut retry = None;
        if e.count >= st.lock_threshold {
            // backoff exponentiel BORNÉ : base * 2^(échecs au-delà du seuil), plafonné à lock_max_s.
            let extra = (e.count - st.lock_threshold).min(20);
            let secs = st.lock_base_s.saturating_mul(1u64 << extra).min(st.lock_max_s);
            e.locked_until = Some(now + Duration::from_secs(secs));
            retry = Some(secs);
        }
        (e.count, retry)
    }; // verrou de la map RELÂCHÉ avant tout lock DB (ingest) -> pas de lock imbriqué.
    ingest_auth_event(st, "failure", user, ip, count, 3);
    if locked.is_some() {
        ingest_auth_event(st, "lockout", user, ip, count, 4); // RAFALE -> alerte sévère
    }
    locked
}

/// AUTO-INGEST SIEM : écrit un event d'auth (source=plume-auth, category=auth, action=failure|lockout)
/// DIRECTEMENT dans la base -> consommé par le moteur de règles (règle 37) ET visible dans l'UI.
/// `src_ip` est posé en COLONNE (pour `stats count by src_ip`) ET dans fields (cohérence). Best-effort.
pub(crate) fn ingest_auth_event(st: &AppState, action: &str, user: &str, ip: &str, count: u32, sev: i64) {
    let ts = now();
    let msg = if action == "lockout" {
        format!("lockout brute-force : compte '{user}' depuis {ip} ({count} échecs)")
    } else {
        format!("échec d'authentification : compte '{user}' depuis {ip}")
    };
    let fields = json!({ "action": action, "username": user, "src_ip": ip, "fails": count }).to_string();
    let ipc: Option<&str> = if ip.is_empty() { None } else { Some(ip) };
    let conn = st.db.lock();
    let _ = conn.execute(
        // origin='daemon' (v72) : event d'auth AUTO-INGÉRÉ par le daemon lui-même (self-detection brute-force).
        // Marqué 'daemon' par cohérence sémantique (écrit en direct, jamais via l'ingest) ; plume-auth n'est PAS
        // dans l'exclusion de rétention -> purgé normalement comme tout event SIEM.
        "INSERT INTO event(ts,source,category,severity,message,host,src_ip,fields,origin) \
         VALUES(?1,'plume-auth','auth',?2,?3,'plume-daemon',?4,?5,'daemon')",
        params![ts, sev, msg, ipc, fields],
    );
}

/// AUTO-INGEST : un déni RBAC sur une route MUTANTE (un principal martèle une route
/// admin/editor qu'il n'a PAS le droit d'appeler = recon / priv-esc) écrit un event source=plume-authz
/// category=authz action=denied -> la règle de self-detection alerte sur les RAFALES par principal. Best-effort, mode-0-
/// INERTE (émis SEULEMENT sur un vrai déni). Ne porte JAMAIS de secret : principal/rôle/route/méthode seulement.
pub(crate) fn ingest_authz_denied(st: &AppState, principal: &str, role: &str, path: &str, method: &str) {
    let ts = now();
    let msg = format!("déni RBAC : '{principal}' (rôle {role}) -> {method} {path}");
    let fields = json!({ "action": "denied", "principal": principal, "role": role, "route": path, "method": method }).to_string();
    let conn = st.db.lock();
    let _ = conn.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,'plume-authz','authz',3,?2,'plume-daemon',?3,'daemon')",
        params![ts, msg, fields],
    );
}

/// Hôtes d'origine de confiance (PLUME_TRUSTED_ORIGINS, CSV) pour la défense CSRF des sessions
/// SSO. Vide par défaut -> repli sur le header Host. Chargé une fois.
static TRUSTED_ORIGINS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
fn trusted_origin_hosts() -> &'static Vec<String> {
    TRUSTED_ORIGINS.get_or_init(|| {
        let conf = load_config();
        cfg(&conf, "PLUME_TRUSTED_ORIGINS", "").split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()
    })
}
/// Extrait l'hôte (sans schéma, userinfo ni port ; gère `[ipv6]`) d'une valeur Origin/Referer/Host.
pub(crate) fn origin_host(v: &str) -> String {
    let v = v.trim().to_ascii_lowercase();
    let after = v.split("://").nth(1).unwrap_or(&v);
    let hostport = after.split(['/', '?', '#']).next().unwrap_or(after);
    let hp = hostport.rsplit('@').next().unwrap_or(hostport);
    if let Some(rest) = hp.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match hp.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => h.to_string(),
        _ => hp.to_string(),
    }
}
/// Défense CSRF des mutations SSO. Une session SSO (trusted-header amont) n'a PAS de plume_session
/// -> aucun token plume à double-soumettre. On applique donc la défense CSRF TOKEN-LESS recommandée (OWASP) :
/// same-origin par Origin/Referer. L'hôte de l'Origin (à défaut Referer) DOIT appartenir à PLUME_TRUSTED_ORIGINS
/// si défini, sinon égaler l'AUTORITÉ DEMANDÉE (déploiement sans proxy la réécrivant). FAIL-CLOSED : ni
/// Origin ni Referer exploitable -> refus (un navigateur émet TOUJOURS l'un des deux sur une mutation cross-site).
///
/// P5.3-a : cette comparaison lisait elle aussi l'en-tête `Host` SEUL. En HTTP/2 (le mode TLS natif annonce
/// `h2` en premier — mesuré) l'en-tête est absent, donc le repli sans `PLUME_TRUSTED_ORIGINS` refusait
/// TOUTE mutation SSO d'un navigateur. Elle consomme désormais la MÊME source d'autorité que `host_guard`.
/// C'est un défaut de DISPONIBILITÉ et non de sécurité (le refus était fail-closed), mais il vient du même
/// trou : c'était le SECOND et DERNIER site du daemon qui lisait `header::HOST` pour décider quelque chose.
pub(crate) fn sso_same_origin_ok(req: &Request) -> bool {
    let host_matches = |h: &str| -> bool {
        let t = trusted_origin_hosts();
        if !t.is_empty() {
            return t.iter().any(|a| a == h);
        }
        AutoriteDemandee::de_la_requete(req)
            .hote()
            .map(|autorite| autorite.eq_ignore_ascii_case(h))
            .unwrap_or(false)
    };
    for hn in [header::ORIGIN, header::REFERER] {
        if let Some(v) = req.headers().get(hn).and_then(|v| v.to_str().ok()) {
            if v.trim().is_empty() { continue; }
            return host_matches(&origin_host(v));
        }
    }
    false // ni Origin ni Referer -> deny (fail-closed)
}

/// SEAM MACHINE — chemins où un token Bearer d'AGENT établit l'identité (rôle 'agent', name = hôte LIÉ au token).
/// Uniquement : ingest/métriques (push), responder (actions pending/result) et — v75 — le PULL de l'enforcer
/// (/api/engagements/active). Extrait en prédicat PUR pour testabilité + parité STRICTE avec la route mTLS
/// (plume-mtls.yaml) et route_min_role (Ingest/Agent). Ajouter un chemin ici n'AUTHENTIFIE que le token ;
/// l'AUTORISATION reste route_min_role + le re-check role=='agent' && host-bound DANS le handler. DÉFAUT FERMÉ :
/// tout chemin absent -> le Bearer n'établit AUCUNE identité -> 401 (jamais d'accès UI/admin via un token agent).
pub(crate) fn agent_bearer_path(path: &str) -> bool {
    matches!(
        path,
        "/api/ingest" | "/api/ingest/minio" | "/api/ingest/journal"
            | "/api/metrics/prom" | "/api/metrics/write" | "/loki/api/v1/push"
            // OTLP (#41) — récepteur OpenTelemetry traces : ingest machine (Bearer -> agent host-bound).
            | "/v1/traces"
            | "/api/actions/pending" | "/api/actions/result"
            | "/api/engagements/active"
    )
}

/// SEAM DATASOURCE (#52) — chemins de LECTURE EXTERNE où un token `datasource` (Bearer, read-scoped) peut
/// établir l'identité (rôle viewer/editor, JAMAIS admin/agent). ADDITIF au seam machine (agent) : un token
/// datasource NE s'authentifie QUE sur ces routes read-only (défaut fermé) ; Basic/SSO/cookie restent des
/// méthodes valides EN PLUS (les routes vivent sous le choke-point auth_guard normal). Le masquage #45 + RBAC
/// s'appliquent quel que soit le porteur (le rôle résolu -> effective_masks). Mode 0 uniquement (cf.
/// datasource_token_lookup) : en mode 1, l'auth datasource passe par Basic/SSO.
pub(crate) fn datasource_bearer_path(path: &str) -> bool {
    matches!(
        path,
        "/api/ds/query"
            | "/api/v1/query"
            | "/api/v1/query_range"
            | "/api/v1/labels"
            | "/api/v1/series"
            | "/loki/api/v1/query_range"
    ) || path.starts_with("/api/v1/label/")
}

/// SEAM CLIENT-READ (#39) — chemins de LECTURE EXTERNE CLIENT (MSSP : un client voit SES cases) où un jeton
/// `kind='client'` (Bearer, read-scoped, rôle résolu `client`) peut établir l'identité. STRICTEMENT read-only
/// (GET), défaut fermé : un jeton client NE s'authentifie QUE sur ces routes. Basic/SSO restent valides EN PLUS
/// (un analyste viewer+ peut aussi lire ces routes). Le masquage #45 + le tenant-scope (req_db_path) s'appliquent
/// quel que soit le porteur. Mode 0 uniquement (cf. client_token_lookup) : en mode 1, l'auth client passe par
/// Basic/SSO (rôle per-tenant `client` via grant).
pub(crate) fn client_bearer_path(path: &str) -> bool {
    path == "/api/client/cases" || path.starts_with("/api/client/cases/")
}

/// RÉSOLUTION D'IDENTITÉ (extrait byte-identique de `auth_guard`, refactor TIER 2). ORDRE D'AUTH ADDITIF :
/// cookie de session -> Basic (argon2/bcrypt) -> SSO trusted-header -> Bearer agent -> démo publique.
/// Ne lit QUE des en-têtes (aucune écriture) -> pur du point de vue observable. Retourne l'identité
/// (nom, rôle PLANCHER), la méthode, la map de grants SSO (mode 1) + flag super-admin SSO, et le tenant
/// PORTEUR d'un éventuel token agent (Bearer). Zéro changement de logique vs l'inline d'origine.
pub(crate) fn resolve_identity(
    st: &AppState,
    req: &Request,
) -> (
    Option<(String, String)>,
    &'static str,
    Option<HashMap<String, String>>,
    bool,
    Option<String>,
) {
    let path = req.uri().path();
    let authz = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    // ORDRE D'AUTH (ADDITIF) : cookie de session OU Basic OU SSO OU Bearer.
    // 1) COOKIE DE SESSION (4e méthode) : jeton signé HMAC posé par /api/login. Vérifié EN PREMIER.
    //    Aucun cookie présenté -> chemin M2M (Basic/SSO/Bearer) STRICTEMENT inchangé.
    let cookie_hdr = req.headers().get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    let session_tok = cookie_value(&cookie_hdr, "plume_session");
    let mut auth_method: &str = "";
    let mut ident: Option<(String, String)> = None;
    // #2a-2b : tenant PORTEUR d'un token agent (résolu AVANT d'ouvrir la base tenant) -> stampé dans AuthUser.
    let mut bearer_tenant: Option<String> = None;
    // #2b : grants SSO (map tenant->rôle) + flag super-admin, calculés en MODE 1 pour résoudre le rôle
    // PER-TENANT après sélection du tenant. Restent None/false en mode 0 (auth_guard mode 0 = sso_role inchangé).
    let mut sso_grant_map: Option<HashMap<String, String>> = None;
    let mut sso_superadmin = false;
    if let Some(tok) = session_tok.as_deref() {
        // L2 : vérif HMAC LIÉE à l'epoch de session courant (révocation serveur : un cookie antérieur à un
        // logout / changement de mdp échoue ici). TTL conservé.
        let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
        if let Some((u, r)) = verify_session(st.session_secret.as_slice(), tok, epoch) {
            if st.multi_tenant {
                // MODE 1 : le rôle du cookie n'est qu'un PLANCHER ; le rôle PER-TENANT est relu LIVE via les
                // grants (resolve_tenant_access) -> comportement inchangé (déjà mitigé).
                ident = Some((u, r));
                auth_method = "cookie";
            } else if let Some(live) = live_role_for(st, &u) {
                // MODE 0 (L2) : NE PAS faire confiance au rôle FIGÉ dans le cookie -> le RE-RÉSOUDRE LIVE. Un
                // rôle changé (editor->viewer) prend effet immédiatement ; un compte supprimé -> pas d'ident.
                ident = Some((u, live));
                auth_method = "cookie";
            }
            // MODE 0 + compte disparu -> `ident` reste None : le cookie ne vaut plus rien (401 plus bas, sauf
            // si des creds Basic valides suivent). L'utilisateur supprimé est déconnecté avant le TTL.
        }
    }
    // 2) Basic (argon2/bcrypt) — repli applicatif inchangé (cache TTL).
    if ident.is_none() {
        ident = authenticate(st, &authz);
        if ident.is_some() {
            auth_method = "basic";
        }
    }
    // SSO délégué (trusted-header) : derrière le forward-auth Authentik, Traefik injecte
    // X-authentik-username/groups + un secret partagé (X-PLUME-SSO-Secret) que SEUL Traefik connaît
    // -> le chemin direct/ClusterIP ne peut PAS usurper d'identité (pas le secret). Mapping groupe->rôle.
    // L'auth applicative (Basic argon2) reste un repli. Activé seulement si PLUME_SSO_HEADER_SECRET défini.
    //
    // DOCTRINE STANDALONE (item 5) — DÉFENSE EN PROFONDEUR confirmée : tout le bloc est gardé par
    // `!st.sso_secret.is_empty()`. Si le secret est VIDE (défaut sûr), ce chemin est ENTIÈREMENT inerte :
    // les en-têtes `x-authentik-username/groups` entrants ne sont JAMAIS lus -> aucun en-tête forgé
    // n'accorde de privilège. Et même secret posé, `x-authentik-*` n'est lu QUE si `x-plume-sso-secret`
    // correspond exactement (secret_ok) -> un en-tête `x-authentik-*` non accompagné du bon secret est
    // ignoré. >>> NE JAMAIS poser PLUME_SSO_HEADER_SECRET en exposition standalone sur Internet : sans
    // forward-auth de confiance devant (Traefik), quiconque connaît/sniffe le secret deviendrait admin.
    // Si jamais activé en standalone : exiger mTLS client-cert + TLS, et stripper x-authentik-* au bord.
    if ident.is_none() && !st.sso_secret.is_empty() {
        // Header CANONIQUE x-plume-sso-secret UNIQUEMENT (le Middleware Traefik injecte X-PLUME-SSO-Secret).
        // La valeur comparée (st.sso_secret) est inchangée.
        let sso_hdr = req.headers().get("x-plume-sso-secret")
            .and_then(|h| h.to_str().ok());
        // COMPARAISON CONSTANT-TIME (comme session/csrf) : évite d'exposer le secret par timing sur `==`.
        // Bloc gardé par `!st.sso_secret.is_empty()` -> header absent (None -> "") = longueurs différentes = false.
        let secret_ok = ct_eq(sso_hdr.unwrap_or("").as_bytes(), st.sso_secret.as_bytes());
        if secret_ok {
            // VENDOR-AGNOSTIC (C1) — NOMS d'en-têtes CONFIGURABLES (défauts = x-authentik-*, GUATX byte-identique).
            // Lus UNIQUEMENT ICI, sous `secret_ok` (le secret partagé gate déjà) : changer le NOM ne crée aucun
            // chemin de lecture hors du gate secret. Le forward-auth du DÉPLOIEMENT doit overwrite CES noms (le
            // client ne peut pas les injecter directement — concern de déploiement, documenté). `HeaderMap::get`
            // est case-insensitive ; les noms sont normalisés en minuscules au chargement (server/mod.rs).
            if let Some(user) = req.headers().get(st.sso_header_user.as_str()).and_then(|h| h.to_str().ok()).filter(|s| !s.is_empty()) {
                let groups = req.headers().get(st.sso_header_groups.as_str()).and_then(|h| h.to_str().ok()).unwrap_or("");
                if st.multi_tenant {
                    // MODE 1 (#2b) : les groupes -> map (tenant->rôle) + flag superadmin. Le rôle PER-TENANT
                    // est résolu APRÈS sélection du tenant (le rôle d'ident n'est qu'un plancher provisoire).
                    let (map, sa) = sso_grants(st, groups);
                    sso_superadmin = sa;
                    sso_grant_map = Some(map);
                    ident = Some((user.to_string(), if sa { "admin".to_string() } else { "viewer".to_string() }));
                } else {
                    // MODE 0 (INVARIANT ABSOLU) : mapping groupe->rôle EXACT, sso_role INCHANGÉ.
                    ident = Some((user.to_string(), sso_role(st, groups)));
                }
                auth_method = "sso";
            }
        }
    }
    // Agents : token Bearer accepté UNIQUEMENT sur le seam machine (ingest/métriques/responder + pull enforcer
    // /api/engagements/active) — rôle restreint, pas d'accès UI/admin. Allowlist = `agent_bearer_path` (défaut fermé).
    if ident.is_none() && agent_bearer_path(path) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            if let Some(ti) = token_lookup(st, tok.trim()) {
                // rôle 'agent' (restreint) ; name = l'hôte LIÉ au token (vide si non lié)
                // -> le responder scope les actions à cet hôte (anti-IDOR cross-agent).
                // #2a-2b : on RETIENT le tenant du token (résolu control-plane en mode 1) -> l'ingest de cet
                // agent sera routé vers SA base (R8), jamais une base tierce.
                bearer_tenant = Some(ti.tenant.clone());
                ident = Some((ti.host, "agent".to_string()));
                auth_method = "bearer";
            }
        }
    }
    // HEC (#16) — bring-your-own-forwarder : schéma d'auth Splunk `Authorization: Splunk <tok>` OU
    // `?token=<tok>`, accepté UNIQUEMENT sur les routes collector d'events (hec_collector_path, défaut
    // fermé). RÉUTILISE token_lookup (même table/infra que l'agent Bearer) -> rôle 'agent' host-bound,
    // INGEST-ONLY (route_min_role Ingest). N'INTERFÈRE PAS avec le Bearer agent (schémas + allowlists
    // disjointes). Mode 0 : path non-HEC -> branche sautée -> résolution d'identité byte-identique.
    if ident.is_none() && hec_collector_path(path) {
        if let Some(tok) = hec_token(&authz, req.uri().query()) {
            if let Some(ti) = token_lookup(st, &tok) {
                bearer_tenant = Some(ti.tenant.clone());
                ident = Some((ti.host, "agent".to_string()));
                auth_method = "hec";
            }
        }
    }
    // DATASOURCE (#52) — token read-scoped `datasource` (Bearer) accepté UNIQUEMENT sur les routes de lecture
    // externe (datasource_bearer_path, défaut fermé). Rôle viewer/editor (jamais admin/agent) + tenant du token.
    // RÉUTILISE la table `token` (mode 0) : un token datasource s'authentifie comme un token agent mais MAPPE
    // vers un rôle de LECTURE -> effective_masks(role) s'applique -> masquage #45 + RBAC hérités. N'INTERFÈRE
    // PAS avec le Bearer agent (allowlists de chemins DISJOINTES). Mode 1 : lookup renvoie None -> Basic/SSO.
    if ident.is_none() && datasource_bearer_path(path) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            if let Some(ds) = datasource_token_lookup(st, tok.trim()) {
                bearer_tenant = Some(ds.tenant.clone());
                ident = Some((ds.name, ds.role));
                auth_method = "datasource";
            }
        }
    }
    // CLIENT-READ (#39) — jeton `kind='client'` (Bearer, read-scoped) accepté UNIQUEMENT sur les routes
    // client-read (client_bearer_path, défaut fermé). Rôle `client` (read-only strict + masqué au rank 0) +
    // tenant du jeton. RÉUTILISE la table `token` (mode 0) EXACTEMENT comme le jeton datasource. N'INTERFÈRE
    // PAS avec les autres seams (allowlists de chemins DISJOINTES + filtre kind dans token_lookup). Mode 1 :
    // lookup renvoie None -> repli Basic/SSO.
    if ident.is_none() && client_bearer_path(path) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            if let Some(ci) = client_token_lookup(st, tok.trim()) {
                bearer_tenant = Some(ci.tenant.clone());
                ident = Some((ci.name, ci.role));
                auth_method = "client";
            }
        }
    }
    // DÉMO PUBLIQUE (opt-in) : si rien n'a authentifié, accès ANONYME forcé en LECTURE SEULE (viewer).
    if ident.is_none() && st.public_demo {
        ident = Some(("demo".into(), "viewer".into()));
        auth_method = "demo";
    }
    (ident, auth_method, sso_grant_map, sso_superadmin, bearer_tenant)
}

/// RÉSOLUTION TENANT + RÔLE PER-TENANT (extrait byte-identique de `auth_guard`, refactor TIER 2) — choke-point
/// unique. Mode 0 : ("default", rôle d'ident) = comportement STRICTEMENT identique (aucun control-plane, aucun
/// superadmin, aucun marqueur). Mode 1 : agent -> tenant du token ; démo -> default/viewer ; routes de gestion
/// tenants -> résolution control-plane ; user réel -> RBAC per-tenant via `resolve_tenant_access`. `Err(Response)`
/// = refus (403/…) propagé tel quel par l'orchestrateur. Zéro changement de logique vs l'inline d'origine.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_tenant_and_role(
    st: &AppState,
    req: &Request,
    path: &str,
    name: &str,
    role_floor: String,
    auth_method: &str,
    bearer_tenant: Option<String>,
    sso_grant_map: Option<&HashMap<String, String>>,
    sso_superadmin: bool,
    mutating: bool,
    breakglass: Option<&str>,
) -> Result<(String, String, bool, bool), Response> {
    let out = if !st.multi_tenant {
        ("default".to_string(), role_floor, false, false)
    } else if let Some(t) = bearer_tenant {
        (t, role_floor, false, false)
    } else if auth_method == "demo" {
        ("default".to_string(), role_floor, false, false)
    } else if path == "/api/my-tenants" || path == "/api/tenants" || path.starts_with("/api/tenants/") {
        // #2c — routes de GESTION des tenants (control-plane) : elles NE passent PAS par resolve_tenant_access
        // (pas de sémantique break-glass/marqueur opérateur sur le control-plane — ce sont des actions
        // d'administration plateforme, auditées par control_ledger). On résout l'identité + is_superadmin ;
        // le rôle PER-TENANT n'est calculé que pour les routes `grants` (tenant-admin borné à SON tenant),
        // les autres prennent le contexte `default` (TOUJOURS résoluble -> le garde fail-closed ne bloque
        // jamais un super-admin opérateur, ni un DELETE de tenant suspendu). L'autorisation fine est faite
        // par tenant_mgmt_gate (path-guard, ci-dessous) PUIS re-vérifiée DANS chaque handler.
        let is_sa = if sso_grant_map.is_some() { sso_superadmin } else { platform_user_is_superadmin(st, name) };
        let target = mgmt_target_tenant(path);
        let role = match &target {
            // Rôle PER-TENANT sur le tenant `grants` VISÉ — résolu STRICTEMENT via les grants (SSO map LIVE ou
            // table `grant`), JAMAIS via le plancher d'identité. Un non-membre (grant_role_for None) retombe sur
            // "viewer" (borne basse) et non sur role_floor : sinon un admin LOCAL/config non-superadmin
            // (role_floor="admin", volontairement exclu du data-plane par resolve_tenant_access) hériterait d'un
            // rôle "admin" sur un tenant où il n'a AUCUN grant et, comme tenant_mgmt_gate/can_manage_grants
            // vérifient `role=="admin" && tenant==tid` (or tenant EST le tid visé), gérerait ses grants
            // -> escalade cross-tenant. "viewer" -> gate + handler refusent (403).
            Some(t) => mgmt_grants_role(st, name, t, sso_grant_map, is_sa),
            None => role_floor.clone(),
        };
        (target.unwrap_or_else(|| "default".to_string()), role, is_sa, false)
    } else {
        let requested = req
            .headers()
            .get("x-plume-tenant")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().query().and_then(|qs| {
                    qs.split('&').find_map(|kv| kv.strip_prefix("tenant=").map(|v| v.to_string()))
                })
            });
        match resolve_tenant_access(st, name, sso_grant_map, sso_superadmin, requested.as_deref(), mutating, breakglass) {
            Ok(a) => (a.tenant, a.role, a.is_superadmin, a.cross_tenant),
            Err((code, msg)) => return Err((code, msg).into_response()),
        }
    };
    Ok(out)
}

/// GATES D'AUTORISATION (extrait byte-identique de `auth_guard`, refactor TIER 2), dans l'ORDRE d'origine :
/// (1) rbac_gate (rôle PER-TENANT), (2) engagement_cred_write_gate (containment eng-cred, superset fail-closed),
/// (3) tenant_mgmt_gate (path-guard gestion tenants, MODE 1 uniquement), (4) CSRF (mutations cookie-authentifiées).
/// `csrf_value` est calculé par l'orchestrateur (réutilisé dans AuthUser) et passé ici pour la comparaison
/// constant-time. `Err(Response)` = refus (403/…) propagé tel quel. Zéro changement de logique vs l'inline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_gates(
    st: &AppState,
    req: &Request,
    path: &str,
    role: &str,
    tenant: &str,
    mutating: bool,
    is_superadmin: bool,
    name: &str,
    auth_method: &str,
    csrf_value: &str,
) -> Result<(), Response> {
    // GATE RBAC (rôle PER-TENANT résolu). viewer en écriture -> 403 ; routes admin-only -> 403. #1b :
    // /api/retention|sources/settings|ledger = admin ONLY (défense en profondeur : chaque handler revérifie
    // au.role=="admin", GET compris). #1c : /api/lookups ouvert à l'editor (viewer bloqué par `mutating`).
    // NB /api/sources (inventaire READ-ONLY) reste HORS de la liste admin-only. Extrait en `rbac_gate` (test).
    if let Err((code, msg)) = rbac_gate(role, path, mutating) {
        // AUTO-INGEST : un déni sur une route MUTANTE = signal (recon/priv-esc) -> event
        // source=plume-authz action=denied (mode-0-inert : rien émis quand rien n'est refusé).
        if mutating {
            ingest_authz_denied(st, name, role, path, req.method().as_str());
        }
        return Err((code, msg).into_response());
    }
    // CONTAINMENT eng-cred (v75) : un credential d'engagement (whitebox=admin) est LECTURE SEULE — il ne peut
    // NI se forger une persistance qui survit à window_end (compte durable / reset mdp / nouvel engagement)
    // NI réduire la détection (règles/collecteurs/mode). Appliqué APRÈS rbac_gate : SUPERSET fail-closed du
    // rôle admin brut (aucune route mutante ne peut être oubliée). Gated sur le préfixe réservé -> no-op pour
    // tout compte normal (byte-identique hors engagement). La LECTURE (dont query/search : mutating=false)
    // reste ouverte -> visibilité whitebox intacte, collecte/enregistrement SOC inchangés (invariant sacré).
    if let Err((code, msg)) = engagement_cred_write_gate(name, mutating) {
        return Err((code, msg).into_response());
    }
    // #2c — PATH-GUARD gestion des tenants (MODE 1 uniquement). EN PLUS du re-check role/superadmin dans
    // chaque handler (défense en profondeur). CRUD/suspend/destroy + grants cross-tenant = SUPER-ADMIN ;
    // grants own-tenant = admin du tenant courant. Mode 0 : SAUTÉ -> les routes sont inertes (handlers
    // renvoient un état vide/`default` ou 404) -> comportement STRICTEMENT identique à aujourd'hui.
    if st.multi_tenant {
        if let Err((code, msg)) = tenant_mgmt_gate(path, role, tenant, is_superadmin) {
            return Err((code, msg).into_response());
        }
    }
    // CSRF (item 4) : exigé UNIQUEMENT pour les mutations AUTHENTIFIÉES PAR COOKIE (le SPA navigateur).
    // `mutating` exclut déjà GET/HEAD ET les POST de lecture (query/search/cancel) -> aucune lecture
    // n'exige de token. Basic/Bearer/SSO (M2M) n'ont PAS de cookie -> auth_method != "cookie" -> EXEMPTÉS
    // (les POST M2M existants — /api/ingest, /api/cancel, /api/query… — restent strictement intacts).
    if auth_method == "cookie" && mutating {
        let got = req.headers().get("x-csrf-token").and_then(|h| h.to_str().ok()).unwrap_or("");
        if !ct_eq(got.as_bytes(), csrf_value.as_bytes()) {
            return Err((StatusCode::FORBIDDEN, "CSRF token invalide ou manquant (header X-CSRF-Token)").into_response());
        }
    }
    // DÉFENSE CSRF : les sessions SSO (trusted-header amont) sont PILOTÉES PAR NAVIGATEUR mais
    // n'ont pas de plume_session -> pas de token à double-soumettre. On étend donc la protection CSRF aux
    // mutations SSO via un contrôle SAME-ORIGIN (Origin/Referer) — sans quoi elles reposaient uniquement sur le
    // SameSite de l'amont. Le M2M (Basic/Bearer/agent) n'est PAS "sso" -> strictement intact.
    if auth_method == "sso" && mutating && !sso_same_origin_ok(req) {
        return Err((StatusCode::FORBIDDEN, "CSRF : origine non autorisée (mutation SSO cross-site)").into_response());
    }
    Ok(())
}

/// POST de LECTURE (exempts de la classe `mutating`) — choke-point unique, extrait pour être TESTABLE.
/// Un POST listé ici est un READ (compile/exécute un GXQL en lecture, aucune mutation, aucun SQL brut) :
/// viewer+ (route_min_role -> Read via section 6, car `mutating=false`), pas de CSRF M2M. Toute autre
/// méthode non-GET reste `mutating` (editor+/admin). Le test `readonly_post_membership` garde cette liste.
pub(crate) fn is_readonly_post(path: &str) -> bool {
    matches!(
        path,
        "/api/query" | "/api/search" | "/api/cancel" | "/api/export"
            | "/api/ds/query" | "/api/v1/query" | "/api/v1/query_range" | "/api/v1/series" | "/api/v1/labels"
            | "/loki/api/v1/query_range"
        // #47 PIVOT / DATASETS : l'EXÉCUTION est une LECTURE (compile un GXQL généré/stocké via le chemin
        // masqué #45, aucune mutation, aucun SQL brut) -> exemptée de la classe `mutating` (viewer autorisé),
        // exactement comme /api/query. Le CRUD (/api/datamodels*, POST /api/datasets) RESTE mutating (editor+).
            | "/api/pivot/compile" | "/api/pivot/run"
        // v130 LIVE VALIDATION : /api/soql/validate COMPILE UNIQUEMENT (to_sql, JAMAIS d'exécution ni de
        // handle DB) -> pur READ advisory (viewer+), exactement comme le chemin GXQL de /api/query dont il est ⊆.
            | "/api/soql/validate"
    ) || (path.starts_with("/api/datasets/") && path.ends_with("/run"))
        // #60 WORKFLOW ACTION RESOLVE : sanitise $field$ + recompile un GXQL de navigation (aucune mutation,
        // aucun déclenchement — une réponse se joue via /api/actions) -> LECTURE (viewer+), comme /api/query.
        || (path.starts_with("/api/workflow-actions/") && path.ends_with("/resolve"))
}

pub(crate) async fn auth_guard(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    // SETUP MODE : aucun credential par défaut ; seul le wizard répond (page statique + /api/setup[-status]),
    // toutes les autres API sont bloquées. /api/setup exige le token d'installation.
    if st.pass_hash.is_empty() && st.admin.lock().is_none() && !st.public_demo {
        if !path.starts_with("/api/") || path == "/api/setup" || path == "/api/setup-status" {
            return next.run(req).await;
        }
        // FORM-LOGIN (item 5) : PLUS de `WWW-Authenticate: Basic` -> pas de popup native Chrome ; le SPA
        // affiche son propre écran de login. Le M2M (viewer/curl) envoie Basic spontanément -> 200.
        return (StatusCode::UNAUTHORIZED, "configuration requise (setup)").into_response();
    }
    // FORM-LOGIN : /api/login et /api/logout sont PUBLICS (l'auth se fait DANS le handler : verify_pw +
    // lockout brute-force Phase 3). Ils n'ont pas besoin d'identité préalable ; logout efface le cookie.
    if path == "/api/login" || path == "/api/logout" {
        return next.run(req).await;
    }
    // IdP NATIF (#44) — routes d'auth fédérée PUBLIQUES (l'auth se fait DANS le handler, aucune identité
    // préalable) : login OIDC (start/callback), login LDAP (bind), 2e facteur MFA. ADDITIF -> mode 0 : ces
    // routes n'existent que si le module est câblé ; aucune n'accorde d'accès sans validation cryptographique
    // (id_token signé / bind LDAP / code TOTP). Le CRUD des providers (/api/idp/*) et le self-service MFA
    // (/api/mfa/*) NE sont PAS ici -> ils passent le choke-point normal (admin-only / authentifié).
    if path == "/api/login/mfa" || path == "/api/auth/ldap" || path.starts_with("/api/auth/oidc/") || path.starts_with("/api/auth/saml/") {
        return next.run(req).await;
    }
    // HEC (#16) — le health-check HEC est PUBLIC (sans token, comme Splunk : les load-balancers le pinguent).
    // Aucune donnée exposée (juste « HEC is healthy »). ADDITIF : route neuve -> mode 0 byte-identique.
    if path == "/services/collector/health" {
        return next.run(req).await;
    }
    // P-HEC — le récepteur PUSH AWS Firehose s'AUTO-AUTHENTIFIE dans son handler (clé de livraison
    // `X-Amz-Firehose-Access-Key` -> firehose_token_lookup : SHA-256 sur colonne indexée, jamais le clair), car
    // l'auth n'est PAS `Authorization`/session (AWS impose ce header propriétaire) et le handler a besoin du
    // connecteur LIÉ (hors AuthUser). EXEMPTÉ ICI comme /collector/health, mais body-cap 8 Mio + rate_limit +
    // host_guard (layers en amont d'auth_guard) restent appliqués. Clé absente/mauvaise -> 403 immédiat côté
    // handler, avant tout parse/spool. Placé APRÈS la garde setup -> aucun ingest push avant configuration.
    if path == "/api/ingest/firehose" {
        return next.run(req).await;
    }
    // P-HEC — le récepteur PUSH GCP Pub/Sub s'AUTO-AUTHENTIFIE dans son handler (clé de livraison en query
    // `?token=` -> pubsub_token_lookup : SHA-256 sur colonne indexée, kind='gcp_pubsub', jamais le clair), car
    // Pub/Sub push porte le token dans l'URL de l'endpoint (pas d'Authorization). SIBLING du récepteur Firehose :
    // EXEMPTÉ ICI (EXACT match, pas un préfixe) ; body-cap 8 Mio + rate_limit + host_guard (layers amont) restent
    // appliqués. Token absent/mauvais -> 401 immédiat côté handler, avant tout parse/spool. Placé APRÈS setup.
    if path == "/api/ingest/pubsub" {
        return next.run(req).await;
    }
    // #51 DAY-2 OPS — /healthz + /readyz : sondes k8s PUBLIQUES (liveness/readiness). Aucune donnée
    // sensible (ok/ready + version + schéma). Additif -> mode 0 byte-identique (routes neuves).
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    // SHELL PWA/NAVIGATEUR PUBLIC — favicons + manifest + service-worker. Ces assets sont fetchés par le
    // NAVIGATEUR LUI-MÊME (icône d'onglet, register() du SW, manifest) dans des contextes qui NE portent PAS
    // toujours le cookie de session -> gatés, ils renvoient 401 (daemon) OU un 302 vers le login (forward-auth
    // Traefik) que le navigateur NE PEUT PAS rendre en image -> il retombe sur l'ancien favicon en cache (le
    // « carré noir »). Ce sont des fichiers PUBLICS par nature (aucune donnée sensible : icône SVG, JS du SW,
    // métadonnées PWA). Allowlist EXACTE + GET/HEAD uniquement (aucune autre route ouverte). L'IngressRoute
    // exempte DÉJÀ /sw.js + /manifest.webmanifest du forward-auth (priority 15) ; on aligne le daemon + on
    // ajoute les favicons des deux côtés. Aucune API, aucun /data : mode 0 byte-identique.
    if matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD)
        && matches!(
            path.as_str(),
            "/favicon-plume.svg" | "/favicon.svg" | "/manifest.webmanifest" | "/sw.js"
        )
    {
        return next.run(req).await;
    }
    let authz = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    // #59 SCIM 2.0 — provisioning IdP, auth par bearer DÉDIÉ (scim_token, control-plane), HORS du flux de
    // session. Mode 0 (control=None) -> 404 : l'endpoint n'existe PAS fonctionnellement -> mode 0 byte-
    // identique (aucune route SCIM active sans mode 1). Bearer valide -> injecte ScimCtx{tenant} et poursuit ;
    // invalide -> 401. Le gate rôle->permission n'est jamais contourné (SCIM mappe vers grant/valid_grant_role).
    if path.starts_with("/scim/v2/") {
        let Some(cp) = st.tenants.control.as_ref() else {
            return (StatusCode::NOT_FOUND, "SCIM indisponible (mode mono-tenant)").into_response();
        };
        match scim_authenticate(cp, &authz) {
            Some(tenant) => {
                req.extensions_mut().insert(ScimCtx { tenant });
                return next.run(req).await;
            }
            None => return (StatusCode::UNAUTHORIZED, "SCIM : bearer invalide").into_response(),
        }
    }
    // #51 DAY-2 OPS — /metrics : un jeton de scrape (Bearer PLUME_METRICS_TOKEN, comparé CONSTANT-TIME)
    // court-circuite l'auth (Prometheus n'a pas de compte). À défaut de jeton posé/de match, on NE retourne
    // PAS ici -> le flux normal d'auth_guard s'applique et EXIGE viewer+ (route_min_role Read) : /metrics
    // n'est JAMAIS anonyme au monde. Aucune autre route touchée -> mode 0 byte-identique.
    if path == "/metrics" && !st.metrics_token.is_empty() {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            if ct_eq(tok.trim().as_bytes(), st.metrics_token.as_bytes()) {
                return next.run(req).await;
            }
        }
    }
    // ANTI-BRUTE-FORCE (item 2) : si ce couple (compte Basic, IP source) est en lockout, on REFUSE
    // avant argon2 (économie CPU + frein). N'agit QUE si des identifiants Basic sont présentés (le
    // chemin SSO/Bearer/sans-creds n'est pas concerné -> k3s transparent). Seuil généreux -> le
    // légitime, qui ne s'authentifie pas en échec, ne l'atteint jamais.
    let src_ip = client_ip(&req);
    let basic_user = basic_username(&authz);
    if let Some(u) = basic_user.as_deref() {
        if let Some(retry) = auth_lock_check(&st, u, &src_ip) {
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())],
                "trop d'échecs d'authentification — réessayez plus tard").into_response();
        }
    }
    // IDENTITÉ (cookie de session / Basic / SSO trusted-header / Bearer agent / démo) — extrait byte-identique.
    let (ident, auth_method, sso_grant_map, sso_superadmin, bearer_tenant) = resolve_identity(&st, &req);
    // ANTI-BRUTE-FORCE (item 2) — comptabilité APRÈS résolution complète de l'identité (Basic/SSO/Bearer/
    // démo). Succès avec creds Basic -> réarme. Aucune identité MAIS creds Basic présentés -> ÉCHEC :
    // incrémente + AUTO-INGEST SIEM, et si la rafale franchit le seuil -> lockout (429 + Retry-After).
    // Un SSO/Bearer valide (ou l'absence de creds Basic) n'incrémente JAMAIS -> k3s/agents transparents.
    if let Some(u) = basic_user.as_deref() {
        if ident.is_some() {
            auth_record_success(&st, u, &src_ip);
        } else if let Some(retry) = auth_record_failure(&st, u, &src_ip) {
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())],
                "trop d'échecs d'authentification — réessayez plus tard").into_response();
        }
    }
    let Some((name, role_floor)) = ident else {
        // HEC (#16) : un client HEC attend une réponse HEC-SHAPED sur token invalide (code 4). Route neuve
        // -> mode 0 byte-identique (les autres 401 restent le texte nu ci-dessous).
        if hec_collector_path(&path) {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "text": "Invalid token", "code": 4 }))).into_response();
        }
        // FORM-LOGIN (item 5) : on n'envoie PLUS `WWW-Authenticate: Basic` -> aucune popup native Chrome.
        // Le 401 nu déclenche l'écran de login du SPA. Le M2M (viewer/curl) présente Basic spontanément
        // dès la 1re requête -> il est authentifié et ne voit JAMAIS ce 401 (reste 200).
        return (StatusCode::UNAUTHORIZED, "auth requise").into_response();
    };
    // RBAC : viewer = lecture seule. Les POSTs de LECTURE (query/search) sont exemptés ; tout le reste
    // (création/màj/suppression, ingest, mail/body…) est bloqué. /api/users et /api/actions = admin only.
    // #52 DATASOURCE : les POST de LECTURE des surfaces datasource (GXQL-HTTP + Prometheus query/range/series +
    // stub Loki) sont des LECTURES -> exemptés de la classe `mutating` (viewer autorisé, pas de CSRF M2M).
    let readonly_post = is_readonly_post(path.as_str());
    let mutating = !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD) && !readonly_post;
    // BREAK-GLASS (#2b/D3) : en-tête `X-Plume-Breakglass: <raison>` — SEUL vecteur d'ÉCRITURE cross-tenant
    // pour un super-admin (borné, loggé aux DEUX ledgers). Transparent partout ailleurs (jamais lu autrement).
    let breakglass = req.headers().get("x-plume-breakglass").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    // TENANT COURANT + RÔLE PER-TENANT (#2b) — extrait byte-identique (choke-point unique).
    let (tenant, role, is_superadmin, cross_tenant) = match resolve_tenant_and_role(
        &st, &req, &path, &name, role_floor, auth_method, bearer_tenant,
        sso_grant_map.as_ref(), sso_superadmin, mutating, breakglass.as_deref(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Le token CSRF est dérivé du jeton de session (stateless) et exposé au SPA via /api/me + cookie plume_csrf.
    // Calculé ICI car réutilisé à la fois par le gate CSRF (apply_gates) ET stampé dans AuthUser.
    let cookie_hdr = req.headers().get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    let session_tok = cookie_value(&cookie_hdr, "plume_session");
    let csrf_value = if auth_method == "cookie" {
        csrf_for(st.session_secret.as_slice(), session_tok.as_deref().unwrap_or(""))
    } else {
        String::new()
    };
    // GATES (rbac / engagement-cred / tenant-mgmt / CSRF) — extrait byte-identique, ordre d'origine préservé.
    if let Err(resp) = apply_gates(&st, &req, &path, &role, &tenant, mutating, is_superadmin, &name, auth_method, &csrf_value) {
        return resp;
    }
    // #2a-3 FAIL-CLOSED (choke-point unique) : en mode 1, REFUSER ici — AVANT tout handler — si la base du
    // tenant courant n'est pas résoluble (tenant suspendu, OU clé non résoluble : Vault injoignable /
    // PLUME_VAULT_TOKEN absent / key_ref cassé) : l'appelant reçoit un 403 NOMMÉ au lieu d'une base
    // cul-de-sac muette. `req_db`/`req_db_path` sont fail-closed par eux-mêmes (base/chemin CUL-DE-SAC, jamais
    // la base d'un autre tenant) — ce garde reste la couche qui le DIT à l'appelant, il n'est plus ce qui
    // empêche la fuite. `tenant_available` enregistre au passage la clé DU tenant (registre read-pool).
    // Mode 0 : sauté (multi_tenant=false) -> comportement STRICTEMENT identique.
    if st.multi_tenant && !st.tenants.tenant_available(&tenant) {
        return (StatusCode::FORBIDDEN, "tenant indisponible (base non résoluble)").into_response();
    }
    // #2b/D3/R9 — MARQUEUR STRUCTUREL d'accès OPÉRATEUR cross-tenant : un super-admin consulte/écrit un
    // tenant dont il n'est PAS membre. Émis ICI (choke-point unique, JAMAIS un handler séparé) -> impossible
    // à contourner : (a) control_ledger à CHAQUE accès ; (b) event `plume-operator-access` NON-DÉSACTIVABLE
    // dans la base du tenant visité (le client le voit), DEBOUNCÉ en lecture, FORCÉ + sev élevée en break-glass.
    if cross_tenant {
        emit_operator_access(&st, &name, &tenant, mutating, breakglass.as_deref());
    }
    // FILTRE ENVIRONNEMENT (#2d) : l'en-tête `X-Plume-Env` sélectionne un environnement intra-tenant à
    // FILTRER dans le READ PATH. INVARIANT ABSOLU mode 0 : `st.multi_tenant=false` -> IGNORÉ (env=None,
    // tout est prod, sélecteur caché côté UI) -> comportement identique. Mode 1 : valeur validée
    // (env_slug_ok, anti-injection : alnum + _/-), vide ou `__all__` -> None (= tous les environnements).
    let env = if st.multi_tenant {
        req.headers()
            .get("x-plume-env")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "__all__" && env_slug_ok(s))
            .map(|s| s.to_string())
    } else {
        None
    };
    req.extensions_mut().insert(AuthUser { name, tenant, role, is_superadmin, method: auth_method.to_string(), csrf: csrf_value, env });
    next.run(req).await
}

/// basic_auth avec cache : bcrypt (coûteux, ~250 ms) UNE fois par identifiant valide,
/// puis fast-path (TTL) -> latence µs sur les requêtes suivantes (page + polls + assets).
/// Les mauvais mots de passe ne sont JAMAIS mis en cache -> anti-bruteforce préservé.
/// Vérifie un mot de passe : argon2id (préféré) OU bcrypt (rétrocompat des hash existants).
pub(crate) fn verify_pw(pw: &str, hash: &str) -> bool {
    if hash.starts_with("$argon2") {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        PasswordHash::new(hash)
            .map(|ph| argon2::Argon2::default().verify_password(pw.as_bytes(), &ph).is_ok())
            .unwrap_or(false)
    } else {
        bcrypt::verify(pw, hash).unwrap_or(false)
    }
}

// Vérifie le header Authorization (Basic) et renvoie (nom, rôle) si valide.
// Ordre : table `user` (comptes créés) -> admin du wizard (meta) -> config statique.
pub(crate) fn authenticate(st: &AppState, authz: &str) -> Option<(String, String)> {
    const TTL: Duration = Duration::from_secs(300);
    {
        let mut cache = st.auth_cache.lock();
        if let Some((name, role, t)) = cache.get(authz) {
            if t.elapsed() < TTL {
                return Some((name.clone(), role.clone()));
            }
            cache.remove(authz);
        }
    }
    let (u, p) = authz
        .strip_prefix("Basic ")
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok())
        .and_then(|d| String::from_utf8(d).ok())
        .and_then(|s| s.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())))?;
    // 1) compte applicatif — R7 (#2a-2a) : accesseur mode-aware. Mode 0 = table `user` de la base unique
    // (INCHANGÉ) ; mode 1 = `platform_user` du control-plane (les hash d'auth ne sont plus dans la base tenant).
    let from_table: Option<(String, String)> = lookup_basic_ident(st, &u);
    let ident = if let Some((hash, role)) = from_table {
        // un nom présent dans la table fait autorité : pas de repli sur l'admin/config
        if verify_pw(&p, &hash) { Some((u.clone(), role)) } else { None }
    } else {
        let admin = st.admin.lock().clone();
        if let Some((au, ah)) = admin {
            if u == au && verify_pw(&p, &ah) { Some((u.clone(), "admin".to_string())) } else { None }
        } else if !st.pass_hash.is_empty() && u == *st.user && verify_pw(&p, st.pass_hash.as_str()) {
            Some((u.clone(), "admin".to_string()))
        } else {
            None // setup mode : pas de credential par défaut ; voir auth_guard + token d'installation
        }
    };
    if let Some((name, role)) = &ident {
        // MODE ENGAGEMENT : un credential minté (`eng-cred-*`) n'est JAMAIS mis en cache -> lookup_basic_ident
        // le RE-RÉSOUT à chaque requête (hard-expiry de la fenêtre re-vérifiée + suppression du compte prise en
        // compte sans délai). Sinon le cache TTL 300 s bypasserait l'expiry/la révocation. Coût argon2 par
        // requête acceptable (credential borné à un pentest). Comptes normaux : caching INCHANGÉ (byte-identique).
        if !name.starts_with(ENG_CRED_PREFIX) {
            let mut cache = st.auth_cache.lock();
            if cache.len() > 256 {
                cache.retain(|_, (_, _, t)| t.elapsed() < TTL);
            }
            cache.insert(authz.to_string(), (name.clone(), role.clone(), Instant::now()));
        }
    }
    ident
}
