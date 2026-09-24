//! Sessions form-login (cookie HMAC) & endpoints d'identité : émission/vérif du jeton signé
//! (`mint_session_du_compte`/`verify_session_du_compte`) mêlé à l'epoch de révocation (`load_session_epoch`/`bump_session_epoch`),
//! rôle live (`live_role_for`), CSRF (`csrf_for`), cookies (`cookie_value`/`cookie_secure_suffix`), secret de
//! session (`load_session_secret`), hash/pose du mot de passe admin (`hash_pw`/`set_admin`) et les handlers
//! `setup_status`/`setup_post`/`password_post`/`login_post`/`logout_post`/`me`. Extrait de main.rs
//! (refactor split #25 — byte-identique). `P10.23-l` : l'époque PROPRE À UN COMPTE (`epoque_du_compte`,
//! `avancer_l_epoque_du_compte`), liée à la session et au ticket MFA. `P10.23-m` : la preuve du premier
//! facteur (`prouver_le_premier_facteur`), partagée par l'enrôlement MFA et le changement du mot de passe.
use crate::*;
use rusqlite::OptionalExtension;

/// `P10.23-l` — CE QUE LA SIGNATURE D'UN JETON AJOUTE POUR L'ÉPOQUE DE SON COMPTE. Rien pour l'époque zéro : le
/// jeton d'un compte jamais révoqué garde la forme d'avant, octet pour octet — le déploiement ne déconnecte
/// personne. Au-delà, `|compte:<k>` : le deux-points n'appartient pas à l'alphabet base64url, donc aucune matière
/// de session ne peut égaler une matière de ticket MFA (`mfa-ticket|…`) ni l'inverse.
pub(crate) fn suffixe_signe_de_l_epoque_du_compte(epoque_du_compte: i64) -> String {
    if epoque_du_compte == 0 {
        String::new()
    } else {
        format!("|compte:{epoque_du_compte}")
    }
}

/// `P10.23-l` — `<b64>.<hex>` pour l'époque de compte zéro, `<b64>.<hex>.<k>` au-delà. L'époque du compte voyage
/// EN CLAIR (elle est signée) : la vérification juge la signature AVANT toute lecture de la base, comme avant.
pub(crate) fn joindre_l_epoque_du_compte(jeton: String, epoque_du_compte: i64) -> String {
    if epoque_du_compte == 0 {
        jeton
    } else {
        format!("{jeton}.{epoque_du_compte}")
    }
}

/// `P10.23-l` — découpe un jeton (session ou ticket MFA) en `(b64, hex, époque du compte)`. Un troisième segment
/// n'est admis que sous sa forme CANONIQUE (entier strictement positif, sans signe ni zéro de tête) : un même
/// jeton n'a qu'une écriture.
pub(crate) fn decouper_le_jeton(jeton: &str) -> Option<(&str, &str, i64)> {
    let mut segments = jeton.split('.');
    let p_b64 = segments.next()?;
    let sig_hex = segments.next()?;
    let epoque_du_compte = match segments.next() {
        None => 0,
        Some(texte) => {
            let k: i64 = texte.parse().ok()?;
            if k <= 0 || k.to_string() != texte {
                return None;
            }
            k
        }
    };
    if segments.next().is_some() {
        return None;
    }
    Some((p_b64, sig_hex, epoque_du_compte))
}

/// Forge un jeton de session signé : payload = `user|role|exp` (b64url), signé HMAC-SHA256.
/// Format : `<b64url(payload)>.<hex(hmac)>`. exp = now + ttl. Stateless (vérifié par HMAC).
/// L2 (RÉVOCATION) : l'`epoch` de session est MÉLANGÉ à la matière signée -> un bump d'epoch (logout)
/// invalide TOUS les jetons antérieurs (leur signature recalculée avec le nouvel epoch
/// ne correspond plus). L'epoch n'est PAS exposé dans le payload lisible : la vérif le re-injecte côté
/// serveur (source de vérité = AppState.session_epoch), donc il n'est ni forgeable ni rejouable.
///
/// `P10.23-l` — ET L'ÉPOQUE DU COMPTE, qui ne révoque que les jetons de CE compte (réinitialisation de son mot de
/// passe par un administrateur, changement du mot de passe administrateur). Elle est signée ET portée par le jeton
/// (`joindre_l_epoque_du_compte`) ; la résolution d'identité la compare à celle du compte, lue avec son rôle.
pub(crate) fn mint_session_du_compte(secret: &[u8], user: &str, role: &str, ttl_s: i64, epoch: i64, epoque_du_compte: i64) -> String {
    let exp = now() + ttl_s.max(1);
    let payload = format!("{user}|{role}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, format!("{p_b64}|{epoch}{}", suffixe_signe_de_l_epoque_du_compte(epoque_du_compte)).as_bytes());
    joindre_l_epoque_du_compte(format!("{p_b64}.{}", hex_encode(&sig)), epoque_du_compte)
}

/// TÉMOINS SEULEMENT — le jeton d'un compte jamais révoqué (époque de compte zéro), la forme d'avant `P10.23-l`.
#[cfg(test)]
pub(crate) fn mint_session(secret: &[u8], user: &str, role: &str, ttl_s: i64, epoch: i64) -> String {
    mint_session_du_compte(secret, user, role, ttl_s, epoch, 0)
}

/// Vérifie un jeton de session : HMAC valide (temps constant, LIÉ à l'epoch courant) + non expiré ->
/// Some((user, role, époque du compte portée)). L2 : `epoch` = compteur de révocation LIVE ; un jeton signé avec un
/// epoch antérieur échoue à la comparaison de signature -> None (révocation serveur). Le TTL est conservé (double
/// borne). `P10.23-l` : cette fonction ne lit PAS la base — l'époque rendue est celle que le jeton porte, et c'est à
/// l'appelant de la comparer à celle du compte (`live_role_si_l_epoque_du_compte_vaut`, `session_ouverte_par`).
pub(crate) fn verify_session_du_compte(secret: &[u8], token: &str, epoch: i64) -> Option<(String, String, i64)> {
    let (p_b64, sig_hex, epoque_du_compte) = decouper_le_jeton(token)?;
    let expect = hmac_sha256(secret, format!("{p_b64}|{epoch}{}", suffixe_signe_de_l_epoque_du_compte(epoque_du_compte)).as_bytes());
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
    Some((user, role, epoque_du_compte))
}

/// TÉMOINS SEULEMENT — la couche cryptographique seule (signature, époque globale, expiration), SANS le jugement de
/// l'époque du compte : aucun chemin servi ne doit s'en contenter, d'où sa réserve aux témoins.
#[cfg(test)]
pub(crate) fn verify_session(secret: &[u8], token: &str, epoch: i64) -> Option<(String, String)> {
    verify_session_du_compte(secret, token, epoch).map(|(user, role, _)| (user, role))
}

/// L2 (RE-CHECK LIVE DU RÔLE, mode 0) — rôle COURANT d'un utilisateur authentifié par COOKIE, RE-RÉSOLU à
/// chaque requête depuis la source de vérité (table `user` -> admin du wizard -> compte config statique),
/// AU LIEU du rôle FIGÉ dans le cookie. `None` = l'utilisateur N'EXISTE PLUS (compte supprimé) -> le cookie
/// est refusé (401). MÊME ordre de résolution que `authenticate`, SANS vérif de mot de passe (le HMAC du
/// cookie a DÉJÀ prouvé l'identité). Effet : un editor rétrogradé viewer / supprimé perd ses droits AVANT
/// l'expiration du TTL (12h). Mode 1 : NON appelé (le rôle PER-TENANT est déjà relu LIVE via les grants).
pub(crate) fn live_role_for(st: &AppState, user: &str) -> Option<String> {
    compte_live(st, user).map(|compte| compte.role)
}

/// `P10.23-l` — mode 0 : le rôle LIVE du compte, SEULEMENT si l'époque de son compte est celle que le jeton porte.
/// Un jeton frappé avant une révocation de CE compte (époque avancée depuis) ne vaut plus rien : `None`, comme un
/// compte supprimé. Une époque NON LUE refuse aussi — une révocation qu'on n'a pas pu relire n'est pas absente.
pub(crate) fn live_role_si_l_epoque_du_compte_vaut(st: &AppState, user: &str, epoque_du_jeton: i64) -> Option<String> {
    let compte = compte_live(st, user)?;
    match compte.epoque {
        Ok(epoque) if epoque == epoque_du_jeton => Some(compte.role),
        Ok(_) => None,
        Err(cause) => {
            eprintln!("[session] WARN époque du compte '{user}' NON lue, session refusée : {cause}");
            None
        }
    }
}

/// `P10.23-l` — ce que la résolution LIVE d'un compte rend : son rôle courant et l'époque de son compte. L'époque
/// voyage en `Result` À CÔTÉ du rôle : `live_role_for` (qui ne juge aucune session) sert le rôle même quand
/// l'époque n'a pas été lue ; `live_role_si_l_epoque_du_compte_vaut` refuse alors.
struct CompteLive {
    role: String,
    epoque: rusqlite::Result<i64>,
}

/// La résolution LIVE (rôle + époque du compte) derrière `live_role_for` et `live_role_si_l_epoque_du_compte_vaut`.
fn compte_live(st: &AppState, user: &str) -> Option<CompteLive> {
    let epoque_par_l_ecrivain = || epoque_du_compte(&st.db.lock(), user);
    let mut epoque_lue_sans_ligne: Option<rusqlite::Result<i64>> = None;
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
    //    `P10.23-l` : l'époque du compte est lue PAR LE MÊME ÉNONCÉ que le rôle sur le read pool (aucune requête
    //    de plus par requête servie) ; les voies d'écrivain (eng-cred, pool indisponible) la relisent à part.
    if !st.multi_tenant && !user.starts_with(ENG_CRED_PREFIX) {
        match compte_via_read_pool(st, user) {
            LectureDuCompte::Trouve { role, epoque } => return Some(CompteLive { role, epoque }),
            // absent de `user` -> repli admin-wizard / config statique (idem historique), à l'époque lue.
            LectureDuCompte::Absent { epoque } => epoque_lue_sans_ligne = Some(epoque),
            LectureDuCompte::PoolIndisponible => {
                // pool indisponible : on reproduit EXACTEMENT le chemin d'origine (writer) pour ne rien changer.
                if let Some((_, role)) = lookup_basic_ident(st, user) {
                    return Some(CompteLive { role, epoque: epoque_par_l_ecrivain() });
                }
            }
        }
    } else if let Some((_, role)) = lookup_basic_ident(st, user) {
        return Some(CompteLive { role, epoque: epoque_par_l_ecrivain() });
    }
    // 2) admin défini par le wizard (meta) -> admin ; 3) compte config statique (bootstrap) -> admin.
    let admin_de_l_assistant = st.admin.lock().as_ref().is_some_and(|(au, _)| au == user);
    let admin_de_configuration = !st.pass_hash.is_empty() && user == st.user.as_str();
    if !admin_de_l_assistant && !admin_de_configuration {
        return None;
    }
    Some(CompteLive { role: "admin".to_string(), epoque: epoque_lue_sans_ligne.unwrap_or_else(epoque_par_l_ecrivain) })
}

/// #23 F4 — résultat TRI-ÉTAT d'une résolution de rôle par le READ POOL : distingue « trouvé » de « absent »
/// (compte disparu -> le cookie ne vaut plus rien) de « pool indisponible » (repli writer, jamais un refus à tort).
/// `P10.23-l` : « trouvé » et « absent » portent l'époque du compte, lue par le même énoncé.
enum LectureDuCompte {
    Trouve { role: String, epoque: rusqlite::Result<i64> },
    Absent { epoque: rusqlite::Result<i64> },
    PoolIndisponible,
}

/// #23 F4 — lit le rôle sur le READ POOL (mode 0). `role` n'est pas une colonne déniée par l'authorizer read-pool ;
/// le SELECT est index-couvert et sert un snapshot WAL FRAIS (révocation live préservée). Aucune prise du mutex
/// writer. `P10.23-l` — L'ÉPOQUE DU COMPTE DANS LE MÊME ÉNONCÉ : deux sous-requêtes scalaires rendent TOUJOURS une
/// ligne, `(rôle ou NULL, époque ou NULL)` ; `meta.value` n'est pas dénié non plus. Coût : une sonde de plus dans
/// l'index de clé primaire de `meta`, sur la même connexion et le même aller-retour.
fn compte_via_read_pool(st: &AppState, user: &str) -> LectureDuCompte {
    read_with(st.db_path.as_str(), LectureDuCompte::PoolIndisponible, |conn| {
        let lu = conn.query_row(
            "SELECT (SELECT role FROM user WHERE name=?1), (SELECT value FROM meta WHERE key=?2)",
            params![user, cle_de_l_epoque_du_compte(user)],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)),
        );
        match lu {
            Ok((Some(role), valeur)) => LectureDuCompte::Trouve { role, epoque: interpreter_l_epoque_du_compte(valeur) },
            Ok((None, valeur)) => LectureDuCompte::Absent { epoque: interpreter_l_epoque_du_compte(valeur) },
            // erreur inattendue (verrou, corruption transitoire...) -> repli writer plutôt qu'un faux « absent ».
            Err(_) => LectureDuCompte::PoolIndisponible,
        }
    })
}

// ─── `P10.23-l` — L'ÉPOQUE PROPRE À UN COMPTE ─────────────────────────────────────────────────────
//
// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT. Un administrateur réinitialise le mot de passe de `bob`
// (`user_update`, 204) : la session de `bob` frappée AVANT résout encore son identité, et un ticket MFA de `bob`
// émis AVANT ouvre encore une session (200, cookie) — l'époque de session est GLOBALE et `user_update` ne la touche
// pas. À l'inverse, `password_post` avançait l'époque GLOBALE : changer le mot de passe administrateur
// déconnectait TOUS les comptes (mesuré : la session d'`alice`, étrangère au changement, refusée).
//
// CE QUI EST FAIT. Chaque compte a une époque, dans `meta` sous `session_epoch:<nom>` (absente = 0), signée dans le
// jeton de session et dans le ticket MFA EN PLUS de l'époque globale, et comparée à la vérification.
//
// POURQUOI `meta` ET NON UNE COLONNE DE `user`. Une colonne est une migration, donc une porte à sens unique à la
// livraison, pour une valeur que `meta` porte déjà sous la même forme que sa voisine `session_epoch` (clé
// primaire, survit au redémarrage et à la restauration, aucune purge temporelle). Et la clé SURVIT à la
// suppression du compte, là où une colonne partirait avec sa ligne. Le coût par requête est une sonde d'index dans
// le même énoncé que le rôle (voir `compte_via_read_pool`), pas une requête de plus.
//
// POURQUOI L'ÉPOQUE VOYAGE DANS LE JETON. Sans elle, la vérification devrait lire l'époque du compte AVANT de juger
// la signature — une lecture de base offerte à tout cookie forgé. Portée en clair et signée, elle laisse la
// signature jugée d'abord, sans rien lire.

/// La clé `meta` de l'époque d'un compte — anglaise et `snake_case` comme ses voisines, dont `session_epoch`.
pub(crate) fn cle_de_l_epoque_du_compte(user: &str) -> String {
    format!("session_epoch:{user}")
}

/// Une valeur lue : absente -> 0 (jamais révoqué) ; illisible (non entière, négative) -> `Err`, rien n'est conclu.
fn interpreter_l_epoque_du_compte(valeur: Option<String>) -> rusqlite::Result<i64> {
    match valeur {
        None => Ok(0),
        Some(texte) => texte.trim().parse::<i64>().ok().filter(|k| *k >= 0).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("époque de compte illisible : `{texte}`").into(),
            )
        }),
    }
}

/// `P10.23-l` — l'époque du compte `user`, lue sur la connexion donnée. `Err` : la lecture n'a pas eu lieu, ou la
/// valeur est illisible — l'appelant refuse, il ne conclut pas à zéro.
pub(crate) fn epoque_du_compte(conn: &Connection, user: &str) -> rusqlite::Result<i64> {
    let valeur: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key=?1", params![cle_de_l_epoque_du_compte(user)], |r| r.get(0))
        .optional()?;
    interpreter_l_epoque_du_compte(valeur)
}

/// `P10.23-l` — avance d'une unité l'époque du compte `user`, SUR LA CONNEXION DE L'APPELANT (dans sa transaction :
/// la révocation et le mot de passe changent ensemble ou pas du tout) ; rend l'époque neuve. Tout jeton de session
/// et tout ticket MFA de ce compte frappés avant ne valent plus rien ; aucun autre compte n'est touché.
pub(crate) fn avancer_l_epoque_du_compte(conn: &Connection, user: &str) -> rusqlite::Result<i64> {
    let neuve = epoque_du_compte(conn, user)?.saturating_add(1);
    let ecrites = conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2",
        params![cle_de_l_epoque_du_compte(user), neuve.to_string()],
    )?;
    if ecrites != 1 {
        return Err(rusqlite::Error::StatementChangedRows(ecrites));
    }
    Ok(neuve)
}

/// `P10.23-l` — RÉVOCATION DU COMPTE NON LUE : aucun jeton n'est frappé sans son époque.
pub(crate) const CAUSE_EPOQUE_DU_COMPTE_NON_LUE: &str = "RÉVOCATION DU COMPTE NON LUE, AUCUNE SESSION OUVERTE : \
     l'époque de révocation propre à ce compte (réinitialisation ou changement de son mot de passe) n'a pas pu \
     être lue. Un jeton frappé sans elle serait refusé à la requête suivante : aucune session ni ticket n'est \
     émis, aucun échec n'est compté. Réessayez.";

/// `P10.23-l` — frappe le jeton de session de `user` à l'époque globale ET à l'époque de son compte, lue ici. Mode 1 :
/// époque de compte zéro sans lecture (la résolution d'identité du mode 1 ne la juge pas — hors périmètre). `Err` :
/// la réponse de refus (503 nommé), à rendre telle quelle.
pub(crate) fn frapper_la_session_du_compte(st: &AppState, user: &str, role: &str) -> Result<String, Response> {
    let epoque_du_compte = if st.multi_tenant {
        0
    } else {
        match epoque_du_compte(&st.db.lock(), user) {
            Ok(epoque) => epoque,
            Err(cause) => {
                eprintln!("[session] WARN époque du compte '{user}' NON lue, aucune session frappée : {cause}");
                return Err(err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_EPOQUE_DU_COMPTE_NON_LUE));
            }
        }
    };
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    Ok(mint_session_du_compte(st.session_secret.as_slice(), user, role, st.session_ttl_s, epoch, epoque_du_compte))
}

/// `P10.23-l` — un jeton de session vaut-il encore ? Signature à l'époque globale, non expiré, et (mode 0) l'époque
/// de SON compte. C'est la garde anti-DoS de `logout_post` : un jeton révoqué pour son compte ne révoque plus tout le
/// monde. L'existence du compte n'y est pas exigée (la garde d'avant ne l'exigeait pas).
fn session_ouverte_par(st: &AppState, jeton: &str) -> bool {
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::Relaxed);
    let Some((user, _, epoque_du_jeton)) = verify_session_du_compte(st.session_secret.as_slice(), jeton, epoch) else {
        return false;
    };
    st.multi_tenant || matches!(epoque_du_compte(&st.db.lock(), &user), Ok(epoque) if epoque == epoque_du_jeton)
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
/// IMMÉDIAT sur mint/verify) ET le persiste dans meta (survit au redémarrage). Appelé par /api/logout
/// -> tous les jetons antérieurs, de TOUS les comptes, deviennent invalides. `P10.23-l` : un changement de
/// mot de passe ne l'appelle plus — il avance l'époque du SEUL compte (`avancer_l_epoque_du_compte`).
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
    poser_l_administrateur(st, user, hash, false)
}

/// `set_admin`, et — `revoquer_ses_sessions` — l'époque du compte avancée DANS LA MÊME TRANSACTION (`P10.23-l`) : un
/// mot de passe changé sans que ses sessions et ses tickets MFA d'avant tombent n'est jamais écrit, ni l'inverse.
fn poser_l_administrateur(st: &AppState, user: &str, hash: &str, revoquer_ses_sessions: bool) -> Result<(), String> {
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
        if revoquer_ses_sessions {
            avancer_l_epoque_du_compte(&tx, user).map_err(|e| format!("révocation des sessions du compte : {e}"))?;
        }
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

/// `P10.23-b` — CE COMPTE A-T-IL UN MOT DE PASSE LOCAL À PROUVER ? TROIS ISSUES, JAMAIS DEUX.
///
/// Même préséance que `authenticate` (la table `user` fait autorité ; à défaut, l'administrateur de l'assistant,
/// puis celui de la configuration). Un hachage vide ou la sentinelle des comptes fédérés (`IDP_HASH_SENTINEL`)
/// n'est PAS un mot de passe : `verify_pw` le refuse toujours. Une identité SSO par en-têtes sans ligne locale n'en
/// a pas non plus. `Err` : la lecture n'a pas eu lieu — l'appelant refuse sans rien conclure.
fn le_compte_a_un_mot_de_passe_local(st: &AppState, user: &str) -> rusqlite::Result<bool> {
    let hash: Option<String> =
        st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![user], |r| r.get(0)).optional()?;
    Ok(match hash {
        Some(h) => !h.is_empty() && h != IDP_HASH_SENTINEL,
        None => {
            st.admin.lock().as_ref().is_some_and(|(nom, _)| nom == user) || (!st.pass_hash.is_empty() && st.user.as_str() == user)
        }
    })
}

/// `P10.23-b` — CE QUE REND LA PREUVE DU PREMIER FACTEUR EXIGÉE À L'ENRÔLEMENT.
pub(crate) enum PreuveDuPremierFacteur {
    /// Le mot de passe présenté est celui du compte.
    Prouvee,
    /// Aucun mot de passe présenté : rien n'est examiné ni compté.
    Absente,
    /// Le mot de passe présenté n'est pas celui du compte : compté au verrou de la connexion.
    Refusee,
    /// Le verrou (compte, adresse) de la connexion est posé : le mot de passe n'est pas examiné.
    Verrouillee(u64),
    /// Le compte n'a pas de mot de passe local (fédéré, SSO par en-têtes).
    SansMotDePasseLocal,
    /// La lecture du compte a échoué.
    CompteNonLu(String),
}

/// `P10.23-b` — LE PREMIER FACTEUR, RE-PROUVÉ À L'ENRÔLEMENT PAR LE MOT DE PASSE RE-SAISI.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-23 SUR LA FORME D'AVANT. Une session SEULE (le voleur ne connaît pas le mot de
/// passe) : `mfa_enroll` -> 200 et une graine ; `mfa_verify` avec un code de cette graine -> 200 et DIX codes de
/// secours ; puis la connexion du titulaire, avec son VRAI mot de passe, rend un ticket et demande un code que
/// seul le voleur sait produire — le titulaire est enfermé hors de son compte. Et un enrôlement EN ATTENTE du
/// titulaire était écrasé (graine remplacée) ; le code de SA graine rendait 401, compté à son frein.
///
/// POURQUOI LE MOT DE PASSE RE-SAISI, ET NON UNE SESSION « FRAÎCHE ». La session ne porte pas son heure
/// d'émission (payload `user|role|exp`) : la déduire de `exp - session_ttl_s` est faux dès que le TTL configuré
/// change entre l'émission et la vérification — et faux dans le mauvais sens quand il raccourcit (une session de
/// onze heures paraît neuve) ; l'y ajouter changerait le format du jeton et déconnecterait toutes les sessions au
/// déploiement. Surtout, une session fraîche VOLÉE passerait encore pendant la fenêtre, alors que le mot de passe
/// est exactement ce que le voleur de session n'a pas. Et la preuve est toujours disponible là où le défaut
/// mord : `login_post` est la SEULE lecture de `user_mfa` qui décide d'une connexion, et elle ne sert que les
/// comptes à mot de passe local.
///
/// LES COMPTES SANS MOT DE PASSE LOCAL (sessions posées par `oidc_callback`, `saml_acs`, `ldap_login_post` — des
/// cookies `auth_method = "cookie"` indiscernables d'une connexion par mot de passe, le compte provisionné avec
/// `IDP_HASH_SENTINEL` ; et les identités SSO par en-têtes, `auth_method = "sso"`, sans ligne locale) : REFUS NOMMÉ.
/// Ni OIDC, ni SAML, ni LDAP, ni les en-têtes SSO ne lisent `user_mfa` : une graine enrôlée sur ces comptes n'est
/// JAMAIS demandée, et la console affichait pourtant « Double authentification ACTIVE ». Leur connexion et leur
/// usage ne changent pas ; seul l'enrôlement d'un second facteur qui ne protégeait rien est refusé, avec la cause.
///
/// LE FREIN : LE VERROU (COMPTE, ADRESSE) DE LA CONNEXION, PARTAGÉ. Un mot de passe faux est compté par
/// `auth_record_failure` sur la même clé que `login_post` (et y produit le même événement d'accès pour le SIEM) :
/// cette route n'offre donc AUCUN essai de plus que `/api/login`, que n'importe qui atteint sans session.
///
/// `P10.23-m` — DÉPLACÉE ICI DEPUIS `handlers/idp.rs`, À L'IDENTIQUE (visibilité mise à part) : le changement du
/// mot de passe administrateur (`password_post`) exige la MÊME preuve, du mot de passe du compte qu'il remplace.
pub(crate) fn prouver_le_premier_facteur(st: &AppState, user: &str, ip: &str, mot_de_passe: &str) -> PreuveDuPremierFacteur {
    match le_compte_a_un_mot_de_passe_local(st, user) {
        Err(e) => return PreuveDuPremierFacteur::CompteNonLu(e.to_string()),
        Ok(false) => return PreuveDuPremierFacteur::SansMotDePasseLocal,
        Ok(true) => {}
    }
    if mot_de_passe.is_empty() {
        return PreuveDuPremierFacteur::Absente;
    }
    if let Some(attente) = auth_lock_check(st, user, ip) {
        return PreuveDuPremierFacteur::Verrouillee(attente);
    }
    // MÊME résolution que `login_post` (en-tête Basic synthétique) : aucun chemin de vérification divergent.
    let synth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{mot_de_passe}")));
    match authenticate(st, &synth) {
        Some((nom, _)) if nom == user => {
            auth_record_success(st, user, ip);
            PreuveDuPremierFacteur::Prouvee
        }
        _ => {
            let _ = auth_record_failure(st, user, ip);
            PreuveDuPremierFacteur::Refusee
        }
    }
}

/// `P10.23-m` — le champ `current` est absent ou vide : rien n'est examiné, rien n'est compté.
pub(crate) const CAUSE_MOT_DE_PASSE_ACTUEL_EXIGE: &str = "MOT DE PASSE ACTUEL EXIGÉ, MOT DE PASSE NON CHANGÉ : \
     une session seule ne prouve pas qu'elle est tenue par le titulaire, et changer le mot de passe \
     administrateur prendrait le compte. Présentez le mot de passe actuel (champ `current`) à côté du nouveau \
     (champ `new`). Rien n'est écrit, aucun échec n'est compté.";

/// `P10.23-m` — le mot de passe actuel présenté n'est pas celui du compte administrateur.
pub(crate) const CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE: &str = "MOT DE PASSE ACTUEL REFUSÉ, MOT DE PASSE NON CHANGÉ : \
     le mot de passe présenté n'est pas celui du compte administrateur. L'échec est compté au MÊME verrou que la \
     connexion (compte, adresse) et inscrit au registre ; rien n'est écrit.";

/// `P10.23-m` — le verrou (compte, adresse) de la connexion est posé : le mot de passe actuel n'est pas examiné.
pub(crate) const CAUSE_MOT_DE_PASSE_ACTUEL_VERROUILLE: &str = "TROP D'ÉCHECS DU MOT DE PASSE SUR CE COMPTE \
     DEPUIS CETTE ADRESSE : le verrou est celui de la connexion (en-tête Retry-After) ; le mot de passe actuel \
     n'est pas examiné et rien n'est écrit.";

/// `P10.23-m` — le compte administrateur visé n'a pas de mot de passe local : il n'y a rien à « changer ».
pub(crate) const CAUSE_ADMINISTRATEUR_SANS_MOT_DE_PASSE_LOCAL: &str = "MOT DE PASSE NON CHANGÉ, LE COMPTE \
     ADMINISTRATEUR N'A PAS DE MOT DE PASSE LOCAL : aucun mot de passe actuel ne peut être prouvé. Le premier \
     mot de passe administrateur se pose par l'installation (`/api/setup`, jeton d'installation). Rien n'est écrit \
     ni compté.";

/// `P10.23-m` — la lecture qui dit si le compte a un mot de passe local a échoué.
pub(crate) const CAUSE_COMPTE_NON_LU_AU_CHANGEMENT: &str = "COMPTE NON LU, MOT DE PASSE NI CHANGÉ NI REFUSÉ : la \
     lecture du compte administrateur a échoué, le mot de passe actuel n'a donc pas pu être jugé. Rien n'est écrit, \
     aucun échec n'est compté. Réessayez.";

/// POST /api/password {current, new} — change le mot de passe de l'administrateur (celui de l'assistant, à défaut
/// celui de la configuration).
///
/// `P10.23-m` — LE MOT DE PASSE ACTUEL EST EXIGÉ. MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT : `{new}` SEUL, sous une
/// session d'administrateur, rendait 200 et changeait le mot de passe — une session volée prenait le compte. La
/// preuve est `prouver_le_premier_facteur`, celle de l'enrôlement MFA : le mot de passe du compte VISÉ (celui qu'on
/// remplace), au MÊME verrou (compte, adresse) que `/api/login`, un échec compté et vu du SIEM, une ligne au
/// registre sur un mot de passe faux.
///
/// `P10.23-l` — LE CHANGEMENT RÉVOQUE LES SESSIONS ET LES TICKETS MFA DU SEUL COMPTE VISÉ (époque du compte, dans la
/// même transaction que le mot de passe). Il avançait l'époque GLOBALE : mesuré le même jour, la session d'un compte
/// étranger au changement était refusée — tout le monde était déconnecté pour un mot de passe qui n'était pas le
/// sien. Ce que la révocation globale protégeait est tenu par celle du compte : un cookie volé du compte, un ticket
/// émis sur son ancien mot de passe. Les sessions des autres comptes n'ont pas été obtenues par ce mot de passe.
pub(crate) async fn password_post(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Extension(au): Extension<AuthUser>,
    Json(b): Json<Value>,
) -> Response {
    // DURCISSEMENT : ce handler écrit `set_admin` (mot de passe de l'admin). SANS ce garde,
    // un editor pouvait reset le mdp admin = takeover/lockout. Le gate `rbac_gate` classe déjà /api/password
    // ADMIN ; ce re-check DOUBLE la garde (défense en profondeur : les deux doivent bloquer un non-admin).
    if let Err(r) = require_admin(&au) { return r; }
    // l'appelant est déjà authentifié (auth_guard) ; on garde le même nom d'admin
    let new = b.str_field("new");
    // POLITIQUE MDP (item 3) — ne valide qu'au CHANGEMENT ; l'ancien mdp reste valide tant qu'inchangé. Jugée AVANT
    // la preuve : un nouveau mot de passe irrecevable n'engage aucun essai du mot de passe actuel.
    if new.chars().count() < PASSWORD_MIN_CHARS {
        return bad_req(format!("mot de passe ≥ {PASSWORD_MIN_CHARS} caractères"));
    }
    let user = st.admin.lock().clone().map(|(u, _)| u).unwrap_or_else(|| st.user.as_ref().clone());
    let ip = peer.ip().to_string();
    match prouver_le_premier_facteur(&st, &user, &ip, b.str_field("current")) {
        PreuveDuPremierFacteur::Prouvee => {}
        PreuveDuPremierFacteur::Absente => return err_json(StatusCode::FORBIDDEN, CAUSE_MOT_DE_PASSE_ACTUEL_EXIGE),
        PreuveDuPremierFacteur::Refusee => {
            ledger_append(
                &st.db.lock(),
                "password",
                &format!("changement du mot de passe admin de '{user}' refusé (demandé par '{}') : mot de passe actuel refusé", au.name),
            );
            return err_json(StatusCode::FORBIDDEN, CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE);
        }
        PreuveDuPremierFacteur::Verrouillee(attente) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, attente.to_string())],
                Json(json!({ "error": CAUSE_MOT_DE_PASSE_ACTUEL_VERROUILLE })),
            )
                .into_response();
        }
        PreuveDuPremierFacteur::SansMotDePasseLocal => {
            return err_json(StatusCode::FORBIDDEN, CAUSE_ADMINISTRATEUR_SANS_MOT_DE_PASSE_LOCAL);
        }
        PreuveDuPremierFacteur::CompteNonLu(cause) => {
            eprintln!("[password] WARN compte '{user}' NON lu au changement du mot de passe : {cause}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_COMPTE_NON_LU_AU_CHANGEMENT);
        }
    }
    match hash_pw(new) {
        Some(h) => {
            // MÊME FAIL-CLOSED QUE `/api/setup` : si l'écriture n'a pas eu lieu, rien n'est révoqué (la révocation
            // est DANS la transaction) et on ne certifie rien au registre.
            if let Err(e) = poser_l_administrateur(&st, &user, &h, true) {
                eprintln!("[password] changement REFUSÉ (base non inscriptible) : {e}");
                return server_err(format!("mot de passe NON changé (rien n'a été écrit) : {e}"));
            }
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
    // `P10.20-b` — FAIL-CLOSED SUR LA LECTURE, PAS SEULEMENT SUR LE FACTEUR. `mfa_enabled_for` rendait
    // `false` aussi bien pour « ce compte n'a pas de MFA » que pour « la ligne n'a pas été lue » : sur une
    // panne de lecture de `user_mfa`, le mot de passe SEUL posait la session d'un compte dont le second
    // facteur est ACTIF. Une lecture non faite REFUSE désormais la connexion (503 nommé, réessayable) :
    // un refus se rattrape, un second facteur contourné non.
    if !st.multi_tenant {
        match mfa_enabled_for(&st, &name) {
            Ok(true) => return mfa_challenge_response(&st, &name, &role),
            Ok(false) => {}
            Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_LUE),
        }
    }
    // L2 : le jeton est frappé avec l'epoch de session COURANT -> il reste valide après un logout/reset
    // ANTÉRIEUR (seuls les jetons émis avant le dernier bump sont révoqués). `P10.23-l` : et à l'époque
    // COURANTE du compte ; non lue -> 503 nommé, aucune session.
    let token = match frapper_la_session_du_compte(&st, &name, &role) {
        Ok(token) => token,
        Err(refus) => return refus,
    };
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
// `P10.23-l` : « valide » inclut l'époque du compte — un cookie révoqué pour SON compte ne révoque pas tout le monde.
pub(crate) async fn logout_post(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let has_valid_session = cookie_value(cookie_hdr, "plume_session").is_some_and(|tok| session_ouverte_par(&st, &tok));
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
