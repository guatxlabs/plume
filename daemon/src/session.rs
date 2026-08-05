//! Sessions form-login (cookie HMAC) & endpoints d'identité : émission/vérif du jeton signé
//! (`mint_session`/`verify_session`) mêlé à l'epoch de révocation (`load_session_epoch`/`bump_session_epoch`),
//! rôle live (`live_role_for`), CSRF (`csrf_for`), cookies (`cookie_value`/`cookie_secure_suffix`), secret de
//! session (`load_session_secret`), hash/pose du mot de passe admin (`hash_pw`/`set_admin`) et les handlers
//! `setup_status`/`setup_post`/`password_post`/`login_post`/`logout_post`/`me`. Extrait de main.rs
//! (refactor split #25 — byte-identique).
use crate::*;

/// Forge un jeton de session signé : payload = `user|role|exp` (b64url), signé HMAC-SHA256.
/// Format : `<b64url(payload)>.<hex(hmac)>`. exp = now + ttl. Stateless (vérifié par HMAC).
/// L2 (RÉVOCATION) : l'`epoch` de session est MÉLANGÉ à la matière signée -> un bump d'epoch (logout /
/// changement de mdp) invalide TOUS les jetons antérieurs (leur signature recalculée avec le nouvel epoch
/// ne correspond plus). L'epoch n'est PAS exposé dans le payload lisible : la vérif le re-injecte côté
/// serveur (source de vérité = AppState.session_epoch), donc il n'est ni forgeable ni rejouable.
pub(crate) fn mint_session(secret: &[u8], user: &str, role: &str, ttl_s: i64, epoch: i64) -> String {
    let exp = now() + ttl_s.max(1);
    let payload = format!("{user}|{role}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, format!("{p_b64}|{epoch}").as_bytes());
    format!("{p_b64}.{}", hex_encode(&sig))
}

/// Vérifie un jeton de session : HMAC valide (temps constant, LIÉ à l'epoch courant) + non expiré ->
/// Some((user, role)). L2 : `epoch` = compteur de révocation LIVE ; un jeton signé avec un epoch antérieur
/// échoue à la comparaison de signature -> None (révocation serveur). Le TTL est conservé (double borne).
pub(crate) fn verify_session(secret: &[u8], token: &str, epoch: i64) -> Option<(String, String)> {
    let (p_b64, sig_hex) = token.split_once('.')?;
    let expect = hmac_sha256(secret, format!("{p_b64}|{epoch}").as_bytes());
    let got = hex_decode(sig_hex)?;
    if !ct_eq(&got, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    // payload = user|role|exp ; user peut contenir '|' -> on découpe par la DROITE (exp, role, reste).
    let mut it = s.rsplitn(3, '|');
    let exp: i64 = it.next()?.parse().ok()?;
    let role = it.next()?.to_string();
    let user = it.next()?.to_string();
    if now() >= exp {
        return None;
    }
    Some((user, role))
}

/// L2 (RE-CHECK LIVE DU RÔLE, mode 0) — rôle COURANT d'un utilisateur authentifié par COOKIE, RE-RÉSOLU à
/// chaque requête depuis la source de vérité (table `user` -> admin du wizard -> compte config statique),
/// AU LIEU du rôle FIGÉ dans le cookie. `None` = l'utilisateur N'EXISTE PLUS (compte supprimé) -> le cookie
/// est refusé (401). MÊME ordre de résolution que `authenticate`, SANS vérif de mot de passe (le HMAC du
/// cookie a DÉJÀ prouvé l'identité). Effet : un editor rétrogradé viewer / supprimé perd ses droits AVANT
/// l'expiration du TTL (12h). Mode 1 : NON appelé (le rôle PER-TENANT est déjà relu LIVE via les grants).
pub(crate) fn live_role_for(st: &AppState, user: &str) -> Option<String> {
    // 1) compte applicatif (table `user`) — fait autorité, comme dans authenticate().
    //    #23 F4 — la session cookie est DÉJÀ prouvée par HMAC : ce chemin n'a besoin QUE du RÔLE, jamais du
    //    hash. On le lit donc `SELECT role FROM user WHERE name=?` via le READ POOL (WAL, hors mutex WRITER),
    //    au lieu de lookup_basic_ident (qui SELECTe `hash` et prend le writer -> chaque requête UI cookie se
    //    sérialisait contre l'ingest). `role` n'est PAS une colonne DÉNIÉE par l'authorizer read-pool (seuls
    //    user.hash/token.token_hash le sont) et reste servie FRAÎCHE (snapshot WAL committé) -> la révocation/
    //    rétrogradation LIVE est préservée à l'identique (rôle relu à CHAQUE requête, juste sur une autre
    //    connexion). N'AFFECTE QUE le mode 0 hors eng-cred : les eng-creds (fenêtre horaire d'engagement,
    //    JAMAIS mis en cache) RESTENT sur lookup_basic_ident (writer) -> leur sémantique de fenêtre est
    //    inchangée ; le Basic-auth (qui a réellement besoin du hash) n'est PAS touché non plus. Une panne de
    //    connexion du pool (rare) retombe sur lookup_basic_ident (writer) -> aucun refus de rôle à tort.
    if !st.multi_tenant && !user.starts_with(ENG_CRED_PREFIX) {
        match role_only_via_read_pool(st, user) {
            RolePoolLookup::Found(role) => return Some(role),
            RolePoolLookup::Absent => {} // absent de `user` -> repli admin-wizard / config statique (idem historique).
            RolePoolLookup::PoolUnavailable => {
                // pool indisponible : on reproduit EXACTEMENT le chemin d'origine (writer) pour ne rien changer.
                if let Some((_, role)) = lookup_basic_ident(st, user) {
                    return Some(role);
                }
            }
        }
    } else if let Some((_, role)) = lookup_basic_ident(st, user) {
        return Some(role);
    }
    // 2) admin défini par le wizard (meta) -> admin.
    if let Some((au, _)) = st.admin.lock().clone() {
        if user == au {
            return Some("admin".to_string());
        }
    }
    // 3) compte config statique (bootstrap) -> admin.
    if !st.pass_hash.is_empty() && user == st.user.as_str() {
        return Some("admin".to_string());
    }
    None
}

/// #23 F4 — résultat TRI-ÉTAT d'une résolution de rôle par le READ POOL : distingue « trouvé » de « absent »
/// (compte disparu -> le cookie ne vaut plus rien) de « pool indisponible » (repli writer, jamais un refus à tort).
enum RolePoolLookup {
    Found(String),
    Absent,
    PoolUnavailable,
}

/// #23 F4 — lit `SELECT role FROM user WHERE name=?` sur le READ POOL (mode 0). `role` n'est pas une colonne
/// déniée par l'authorizer read-pool ; le SELECT est index-couvert (PK `name`? -> `user` est minuscule de
/// toute façon) et sert un snapshot WAL FRAIS (révocation live préservée). Aucune prise du mutex writer.
fn role_only_via_read_pool(st: &AppState, user: &str) -> RolePoolLookup {
    read_with(st.db_path.as_str(), RolePoolLookup::PoolUnavailable, |conn| {
        match conn.query_row("SELECT role FROM user WHERE name=?1", params![user], |r| r.get::<_, String>(0)) {
            Ok(role) => RolePoolLookup::Found(role),
            Err(rusqlite::Error::QueryReturnedNoRows) => RolePoolLookup::Absent,
            // erreur inattendue (verrou, corruption transitoire...) -> repli writer plutôt qu'un faux « absent ».
            Err(_) => RolePoolLookup::PoolUnavailable,
        }
    })
}

/// L2 — lit le compteur de révocation de session persistant (meta `session_epoch`, défaut 0). Chargé au
/// boot dans AppState.session_epoch (source de vérité mémoire consultée par mint/verify_session).
pub(crate) fn load_session_epoch(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key='session_epoch'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// L2 — INCRÉMENTE l'epoch de session (révocation serveur) : met à jour le compteur EN MÉMOIRE (effet
/// IMMÉDIAT sur mint/verify) ET le persiste dans meta (survit au redémarrage). Appelé par /api/logout et
/// par tout changement de mot de passe -> tous les jetons antérieurs deviennent invalides.
pub(crate) fn bump_session_epoch(st: &AppState) {
    let e = st.session_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let c = st.db.lock();
    let _ = c.execute(
        "INSERT INTO meta(key,value) VALUES('session_epoch',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
        params![e.to_string()],
    );
}

/// Token CSRF DÉRIVÉ du jeton de session (stateless) : le serveur le recalcule à chaque requête à
/// partir du cookie de session -> aucun stockage. Le SPA le renvoie en header `X-CSRF-Token`.
pub(crate) fn csrf_for(secret: &[u8], session_token: &str) -> String {
    hex_encode(&hmac_sha256(secret, format!("csrf|{session_token}").as_bytes()))
}

/// Extrait la valeur d'un cookie nommé depuis un en-tête `Cookie:` (None si absent).
pub(crate) fn cookie_value(header: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    header.split(';').map(|p| p.trim()).find_map(|p| p.strip_prefix(&prefix).map(|v| v.to_string()))
}

/// Attribut `Secure` des cookies UNIQUEMENT quand le TLS natif est actif (sinon le cookie ne serait
/// jamais émis en HTTP — k3s derrière Traefik termine le TLS au proxy, l'origine est en clair).
pub(crate) fn cookie_secure_suffix() -> &'static str {
    if TLS_ON.load(std::sync::atomic::Ordering::Relaxed) {
        "; Secure"
    } else {
        ""
    }
}

/// Secret de signature des sessions : env/conf PLUME_SESSION_SECRET (matière à clé brute) -> sinon
/// clé persistée 0600 (générée au 1er boot, comme la clé du ledger). JAMAIS de secret en dur.
pub(crate) fn load_session_secret(conf: &HashMap<String, String>) -> Vec<u8> {
    let env_secret = cfg(conf, "PLUME_SESSION_SECRET", "");
    if !env_secret.trim().is_empty() {
        return env_secret.trim().as_bytes().to_vec();
    }
    use std::os::unix::fs::PermissionsExt;
    let path = cfg(conf, "PLUME_SESSION_KEY", "/var/lib/plume/db/session.key");
    if let Ok(hex) = std::fs::read_to_string(&path) {
        if let Some(b) = hex_decode(hex.trim()) {
            if b.len() >= 32 {
                return b;
            }
        }
    }
    // MÊME DOCTRINE QUE LE TOKEN D'INSTALLATION, et pour la même raison : cette clé SIGNE les cookies de
    // session. Le « dernier recours » qui vivait ici la dérivait de l'horloge de boot
    // (`sha256("plume-session-fallback-{now}")`) — qui devine la seconde de démarrage FORGE une session
    // admin. Sans entropie il n'y a pas de clé, donc pas de service : exit 78 (EX_CONFIG), le fail-closed
    // de boot déjà employé par `db_key`/`cfg_secret`. L'exploitant peut toujours poser PLUME_SESSION_SECRET.
    let Some(b) = os_entropy::<32>() else {
        eprintln!(
            "[session] FATAL : aucune source d'entropie (ni /dev/urandom ni getrandom) — impossible de \
             fabriquer la clé de signature des sessions. AUCUNE clé dérivée d'une horloge ne sera émise. \
             Répare l'entropie de l'hôte, ou pose PLUME_SESSION_SECRET."
        );
        std::process::exit(78);
    };
    let _ = std::fs::write(&path, hex_encode(&b));
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    b.to_vec()
}

// ---------- wizard / admin (auth modifiable depuis l'UI) ----------

/// LONGUEUR MINIMALE d'un mot de passe POSÉ par plume — UN SEUL auteur pour la politique (item 3), pour
/// que le serveur, l'UI et l'aide ne puissent plus annoncer trois chiffres différents. N'affecte QUE la
/// DÉFINITION d'un mot de passe (setup, reset admin, création/màj de compte) ; les mdp existants marchent.
pub(crate) const PASSWORD_MIN_CHARS: usize = 12;

/// Nombre d'octets ALÉATOIRES d'un token d'installation (-> 2× en hex).
pub(crate) const SETUP_TOKEN_BYTES: usize = 18;

/// Matière aléatoire du token d'installation. `/dev/urandom` d'abord (chemin nominal), puis le CSPRNG de
/// l'OS SANS descripteur de fichier (`getrandom(2)` via `OsRng`, déjà utilisé par `hash_pw`) — ce second
/// essai couvre le cas où `/dev` n'est pas monté (chroot/conteneur minimal), qui est EXACTEMENT le cas où
/// le premier échoue. Les DEUX en échec -> `None` : il n'y a pas de troisième voie.
pub(crate) fn setup_token_entropy() -> Option<[u8; SETUP_TOKEN_BYTES]> {
    os_entropy::<SETUP_TOKEN_BYTES>()
}

/// LE PRODUCTEUR UNIQUE de matière secrète des chemins d'installation. `/dev/urandom` d'abord (chemin
/// nominal), puis le CSPRNG de l'OS SANS descripteur de fichier (`getrandom(2)` via `OsRng`, déjà utilisé
/// par `hash_pw`) — ce second essai couvre le cas où `/dev` n'est pas monté (chroot/conteneur minimal),
/// qui est EXACTEMENT le cas où le premier échoue. Les DEUX en échec -> `None`, et il n'y a pas de
/// troisième voie : un secret « de repli » dérivé d'une horloge ou d'un pid est ÉNUMÉRABLE, donc il est
/// pire que pas de secret du tout — il donne l'apparence de la protection. L'appelant REFUSE.
pub(crate) fn os_entropy<const N: usize>() -> Option<[u8; N]> {
    use std::io::Read;
    let mut buf = [0u8; N];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_ok() {
        return Some(buf);
    }
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    OsRng.try_fill_bytes(&mut buf).ok().map(|()| buf)
}

/// Formate le token d'installation À PARTIR DE la matière aléatoire fournie. `None` en entrée -> `None` en
/// sortie : PAS de token, donc `/api/setup` refuse tout (fail-closed). Il n'existe AUCUN repli dérivé d'une
/// horloge ou d'un pid — un tel « token » s'énumère en quelques milliers d'essais et il ouvre le compte
/// ADMIN du SIEM à un anonyme.
pub(crate) fn setup_token_from_entropy(raw: Option<[u8; SETUP_TOKEN_BYTES]>) -> Option<String> {
    raw.map(|b| hex_encode(&b))
}

/// Clé de comptage anti-rafale de `/api/setup`. Les chevrons sont HORS du charset d'un nom de compte
/// (`platform_user_name_ok`) -> ce principal ne peut collisionner avec aucun utilisateur réel.
pub(crate) const SETUP_LOCK_PRINCIPAL: &str = "<installation>";

/// Le token d'installation VAUT un mot de passe d'administrateur : sa vérification est FAIL-CLOSED sur un
/// secret attendu VIDE (hors mode setup, `st.setup_token` est vide — rien ne doit alors matcher, pas même
/// un corps sans champ `token`) et à TEMPS CONSTANT (même discipline que la signature de session et le
/// jeton de scrape `/metrics`).
pub(crate) fn setup_token_matches(expected: &str, provided: &str) -> bool {
    !expected.is_empty() && ct_eq(provided.as_bytes(), expected.as_bytes())
}

pub(crate) fn hash_pw(pw: &str) -> Option<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default().hash_password(pw.as_bytes(), &salt).ok().map(|h| h.to_string())
}

/// Pose l'admin — ET DIT SI ELLE A ÉTÉ ÉCRITE. Les trois écritures forment UN SEUL état (le nom dans `meta`,
/// la purge du hash hérité, le compte dans `user`) : elles passent donc par une TRANSACTION, et l'état EN
/// MÉMOIRE (`st.admin`, cache d'auth) n'est touché QU'APRÈS le commit. Sans cela, une base non inscriptible
/// (volume RO, disque plein, migration ratée) laissait un admin vivant dans le process, absent de la base :
/// l'appelant répondait « installé », et le redémarrage suivant repartait en mode setup.
pub(crate) fn set_admin(st: &AppState, user: &str, hash: &str) -> Result<(), String> {
    {
        let c = st.db.lock();
        let tx = c.unchecked_transaction().map_err(|e| format!("transaction : {e}"))?;
        tx.execute("INSERT INTO meta(key,value) VALUES('admin_user',?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![user])
            .map_err(|e| format!("meta.admin_user : {e}"))?;
        // ANTI-FUITE PAR EXPORT — on NE STOCKE PLUS le hash admin en CLAIR dans meta : il y était
        // exfiltrable via /api/export ou /api/query en SQL brut admin (`SELECT value FROM meta WHERE
        // key='admin_hash'`), l'authorizer read-pool ne pouvant pas filtrer meta PAR CLÉ (déni de meta.value
        // casserait schema_version/plume_mode). La SOURCE DE VÉRITÉ du hash = user.hash (déjà DÉNIÉ par
        // l'authorizer, écrit juste dessous). On purge toute copie héritée (bases pré-fix) — idempotent.
        tx.execute("DELETE FROM meta WHERE key='admin_hash'", [])
            .map_err(|e| format!("purge meta.admin_hash : {e}"))?;
        // l'admin est aussi un compte de la table user (rôle admin)
        tx.execute(
            "INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin') ON CONFLICT(name) DO UPDATE SET hash=?2, role='admin'",
            params![user, hash],
        )
        .map_err(|e| format!("compte admin : {e}"))?;
        tx.commit().map_err(|e| format!("commit : {e}"))?;
    }
    *st.admin.lock() = Some((user.to_string(), hash.to_string()));
    st.auth_cache.lock().clear(); // invalide les creds en cache (l'ancien défaut ne marche plus)
    Ok(())
}

pub(crate) async fn setup_status(State(st): State<AppState>) -> Json<Value> {
    let configured = st.admin.lock().is_some() || !st.pass_hash.is_empty();
    Json(json!({ "configured": configured }))
}

pub(crate) async fn setup_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(b): Json<Value>,
) -> Response {
    if st.admin.lock().is_some() || !st.pass_hash.is_empty() {
        return err_json(StatusCode::CONFLICT, "déjà configuré (utilise Réglages > changer le mot de passe)");
    }
    // ANTI-RAFALE : `/api/setup` est la SEULE route qu'un anonyme atteint au premier boot, et le seul secret
    // qui la garde vaut le compte admin. On réutilise TEL QUEL le compteur brute-force de `/api/login`
    // (couple (principal, IP), backoff exponentiel, AUTO-INGEST source=plume-auth) : un martèlement du token
    // d'installation est donc freiné ET visible dans le SIEM — un SOC doit voir ses propres échecs d'auth.
    let ip = peer.ip().to_string();
    if let Some(retry) = auth_lock_check(&st, SETUP_LOCK_PRINCIPAL, &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry.to_string())],
            Json(json!({ "error": "trop d'échecs sur le token d'installation — réessayez plus tard" })),
        )
            .into_response();
    }
    let token = b.str_field("token");
    if !setup_token_matches(st.setup_token.as_str(), token) {
        let _ = auth_record_failure(&st, SETUP_LOCK_PRINCIPAL, &ip);
        return forbidden("token d'installation invalide (voir le log du daemon ou /var/lib/plume/db/setup-token.txt)");
    }
    auth_record_success(&st, SETUP_LOCK_PRINCIPAL, &ip);
    let user = b.trimmed("user");
    let pw = b.str_field("password");
    // POLITIQUE MDP (item 3) — n'affecte QUE la DÉFINITION ; les mdp existants continuent de marcher.
    if user.is_empty() || pw.chars().count() < PASSWORD_MIN_CHARS {
        return bad_req(format!("utilisateur requis + mot de passe ≥ {PASSWORD_MIN_CHARS} caractères"));
    }
    let Some(h) = hash_pw(pw) else { return server_err("hash échoué") };
    // FAIL-CLOSED : tant que la pose de l'admin n'est pas ÉCRITE, il n'y a PAS d'installation — donc pas de
    // 200, pas d'effacement du token (l'exploitant doit pouvoir réessayer après réparation), pas de ledger.
    if let Err(e) = set_admin(&st, &user, &h) {
        eprintln!("[setup] pose de l'admin REFUSÉE (base non inscriptible) : {e}");
        return server_err(format!("installation NON effectuée (rien n'a été écrit) : {e}"));
    }
    // Le fichier de token porte le secret EN CLAIR : on l'écrase puis on RELIT le disque. S'il survit, on le
    // DIT — au journal, au registre et dans la réponse — au lieu de rendre un succès nu.
    let residu = erase_setup_token_file(st.db_path.as_str());
    let detail = match &residu {
        None => format!("admin défini : {user}"),
        Some(p) => {
            eprintln!("[setup] ATTENTION : {p} n'a PAS pu être effacé — le token d'installation y reste EN CLAIR ; efface-le à la main.");
            format!("admin défini : {user} — token d'installation NON effacé ({p})")
        }
    };
    ledger_append(&st.db.lock(), "setup", &detail);
    (StatusCode::OK, Json(json!({ "ok": true, "setup_token_file_removed": residu.is_none() }))).into_response()
}

/// Efface le `setup-token.txt` voisin de la base et DIT si le fichier a réellement disparu. Le token y est
/// en CLAIR : on ÉCRASE avant de délier (`shred_file`, même traitement que le résidu effacé au boot dans
/// `run()`), puis on RELIT le système de fichiers — l'appelant ne peut pas déclarer une installation propre
/// sur la foi d'un `remove_file` dont personne n'a regardé le résultat.
pub(crate) fn erase_setup_token_file(db_path: &str) -> Option<String> {
    let tp = std::path::Path::new(db_path).with_file_name("setup-token.txt");
    shred_file(&tp.to_string_lossy());
    tp.exists().then(|| tp.display().to_string())
}

pub(crate) async fn password_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    // DURCISSEMENT : ce handler écrit `set_admin` (mot de passe de l'admin). SANS ce garde,
    // un editor pouvait reset le mdp admin = takeover/lockout. Le gate `rbac_gate` classe déjà /api/password
    // ADMIN ; ce re-check DOUBLE la garde (défense en profondeur : les deux doivent bloquer un non-admin).
    if let Err(r) = require_admin(&au) { return r; }
    // l'appelant est déjà authentifié (auth_guard) ; on garde le même nom d'admin
    let new = b.str_field("new");
    // POLITIQUE MDP (item 3) — ne valide qu'au CHANGEMENT ; l'ancien mdp reste valide tant qu'inchangé.
    if new.chars().count() < PASSWORD_MIN_CHARS {
        return bad_req(format!("mot de passe ≥ {PASSWORD_MIN_CHARS} caractères"));
    }
    let user = st.admin.lock().clone().map(|(u, _)| u).unwrap_or_else(|| st.user.as_ref().clone());
    match hash_pw(new) {
        Some(h) => {
            // MÊME FAIL-CLOSED QUE `/api/setup` : si l'écriture n'a pas eu lieu, on ne bumpe SURTOUT PAS
            // l'epoch (cela déconnecterait tout le monde pour un mot de passe resté l'ancien) et on ne
            // certifie rien au registre.
            if let Err(e) = set_admin(&st, &user, &h) {
                eprintln!("[password] changement REFUSÉ (base non inscriptible) : {e}");
                return server_err(format!("mot de passe NON changé (rien n'a été écrit) : {e}"));
            }
            // L2 : un changement de mot de passe INVALIDE toutes les sessions antérieures (bump d'epoch) —
            // un attaquant tenant un ancien cookie/mdp est déconnecté par le reset, pas seulement au TTL.
            bump_session_epoch(&st);
            ledger_append(&st.db.lock(), "password", "mot de passe admin changé");
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        None => server_err("hash échoué"),
    }
}

// ---------- form-login : /api/login, /api/logout, /api/me (cookie de session signé + CSRF) ----------
// POST /api/login {user,pass} -> vérifie via la MÊME résolution de compte que Basic (table user ->
// admin -> config) puis pose `plume_session` (HttpOnly, SameSite=Strict, Path=/, Secure si TLS) +
// `plume_csrf` (lisible JS). Échec -> 401 + lockout brute-force Phase 3 (compteur (user,ip) + SIEM).
pub(crate) async fn login_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(b): Json<Value>,
) -> Response {
    let user = b.trimmed("user");
    let pass = b.str_field("pass").to_string();
    let ip = peer.ip().to_string();
    // Lockout AVANT toute vérif coûteuse (réutilise le compteur (user,ip) de la Phase 3, comme Basic).
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry.to_string())],
            Json(json!({ "error": "trop d'échecs d'authentification — réessayez plus tard" })),
        )
            .into_response();
    }
    // Réutilise EXACTEMENT la résolution de compte de Basic via un en-tête Basic synthétique -> aucun
    // chemin d'auth divergent (mêmes hash argon2/bcrypt, même priorité table/admin/config, même cache).
    let synth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    );
    let Some((name, role)) = authenticate(&st, &synth) else {
        // ÉCHEC -> lockout brute-force existant (incrémente (user,ip) + AUTO-INGEST SIEM, 429 au seuil).
        let _ = auth_record_failure(&st, &user, &ip);
        return err_json(StatusCode::UNAUTHORIZED, "identifiants invalides");
    };
    auth_record_success(&st, &user, &ip); // réarme le compteur (comme un succès Basic)
    // MFA (#44) — 2e FACTEUR : si le compte a une MFA TOTP ACTIVE (mode 0), le 1er facteur (mot de passe)
    // NE pose PAS de session : on renvoie un ticket signé court, à échanger contre un code sur /api/login/mfa.
    // INVARIANT MODE 0 : `user_mfa` VIDE (défaut) -> `mfa_enabled_for` renvoie false -> flux STRICTEMENT
    // inchangé (aucune session tant qu'aucun compte n'a volontairement activé la MFA). Mode 1 : sauté.
    if !st.multi_tenant && mfa_enabled_for(&st, &name) {
        return mfa_challenge_response(&st, &name, &role);
    }
    // L2 : le jeton est frappé avec l'epoch de session COURANT -> il reste valide après un logout/reset
    // ANTÉRIEUR (seuls les jetons émis avant le dernier bump sont révoqués).
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let token = mint_session(st.session_secret.as_slice(), &name, &role, st.session_ttl_s, epoch);
    let csrf = csrf_for(st.session_secret.as_slice(), &token);
    let secure = cookie_secure_suffix();
    let ttl = st.session_ttl_s.max(1);
    // plume_session : HttpOnly (invisible au JS) ; plume_csrf : lisible JS (le SPA le renvoie en header).
    let c_sess = format!("plume_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let c_csrf = format!("plume_csrf={csrf}; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true, "user": name, "role": role }))).into_response();
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// POST /api/logout -> efface les cookies (Set-Cookie expiré) ET révoque côté SERVEUR (L2). Public (pas
// besoin d'identité valide). L2 : incrémente l'epoch de session -> TOUS les cookies antérieurs (y compris
// un cookie EXFILTRÉ, qui survivait jusqu'ici jusqu'au TTL) deviennent immédiatement invalides côté serveur.
// GARDE ANTI-DoS (L2-fix) : le bump d'epoch (révocation GLOBALE) n'est déclenché QUE si l'appelant présente
// un cookie de session ACTUELLEMENT VALIDE. Sans cette garde, un tiers NON authentifié pourrait marteler
// /api/logout (route publique, budget per-IP standard 1200/10s) pour bumper l'epoch en boucle et déconnecter
// EN PERMANENCE tous les utilisateurs (DoS d'authentification) + amplification d'écritures DB. Le but sécu
// est préservé : un logout LÉGITIME (cookie valide) révoque bien les jetons antérieurs, y compris une COPIE
// EXFILTRÉE du même cookie. L'effacement des cookies côté navigateur, lui, reste INCONDITIONNEL.
pub(crate) async fn logout_post(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let has_valid_session = cookie_value(cookie_hdr, "plume_session")
        .and_then(|tok| verify_session(st.session_secret.as_slice(), &tok, epoch))
        .is_some();
    if has_valid_session {
        bump_session_epoch(&st);
    }
    let secure = cookie_secure_suffix();
    let exp = "Max-Age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    let c_sess = format!("plume_session=; HttpOnly; SameSite=Strict; Path=/; {exp}{secure}");
    let c_csrf = format!("plume_csrf=; SameSite=Strict; Path=/; {exp}{secure}");
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// GET /api/me -> état d'auth pour le SPA : {user, role, auth_method, csrf_token}. csrf_token non vide
// UNIQUEMENT en auth par cookie (le SPA le pose en header X-CSRF-Token sur les mutations). M2M : "".
pub(crate) async fn me(Extension(au): Extension<AuthUser>) -> Json<Value> {
    Json(json!({
        "user": au.name,
        "role": au.role,            // rôle PER-TENANT (mode 1) ou rôle global (mode 0)
        "tenant": au.tenant,        // tenant courant (#2b) ; "default" en mode 0
        "is_superadmin": au.is_superadmin, // super-admin plateforme (#2b/D3) : bandeau opérateur côté SPA
        "auth_method": au.method,
        "csrf_token": au.csrf,
    }))
}
