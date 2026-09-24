//! Handlers HTTP de l'IdP natif (#44) : CRUD admin des fournisseurs fédérés (OIDC/LDAP/SAML seam,
//! secret write-only + redaction, miroir de `connectors.rs`), flux de login OIDC (Authorization-Code +
//! PKCE), login LDAP (bind), et MFA TOTP (enrôlement/vérif/désactivation + challenge à la connexion).
//!
//! MODE 0 UNIQUEMENT (comme le provisioning de jetons UI) : en multi-tenant, IdP/MFA vivent au control-plane
//! (hors périmètre de cet incrément) -> ces routes renvoient 501, JAMAIS un chemin fédéré cross-tenant à
//! moitié câblé. FAIL-CLOSED partout ; le cœur logique (validation JWT, bind, TOTP) est dans `idp.rs`.
use crate::*;
use rusqlite::OptionalExtension;

// `P10.20-b` — LE STATUT DE DOUBLE AUTHENTIFICATION N'A PAS DE VALEUR PAR DÉFAUT.
//
// LE DÉFAUT MESURÉ LE 2026-09-16. Les six lectures de `user_mfa` de ce module passaient par
// `query_row(..).ok()` (ou, pour la décision de connexion, `.map(..).unwrap_or(false)`), qui rend la
// MÊME valeur pour « ce compte n'a pas de second facteur » et pour « la ligne n'a pas été lue ». Les
// deux ne se valent pas : la première est un fait, la seconde est une ignorance. La cause n'est pas
// exotique — un cache de schéma de pool périmé fait sortir « no such table » comme une erreur de
// LIGNE (`flatten-avale-no-such-table-au-premier-pas`), une valeur corrompue ne se convertit pas.
//
// TROIS SITES FAISAIENT DE CETTE IGNORANCE UNE DÉCISION, ET LES TROIS PENCHAIENT DU MAUVAIS CÔTÉ :
//   * `mfa_enabled_for` — la SEULE lecture qui décide si la connexion exige un second facteur
//     (`session.rs`, `login_post`). Lecture ratée -> `false` -> le mot de passe SEUL posait la
//     session sur un compte dont la MFA est ACTIVE. C'est le contournement complet du second facteur
//     par une panne de lecture, et c'est fail-OPEN ;
//   * `mfa_enroll` — sa garde « ne peut PAS écraser une MFA déjà active » lisait `enabled` de la même
//     façon. Lecture ratée -> la garde ne voit pas la MFA active -> l'enrôlement ÉCRASE la graine et
//     repose `enabled=0` : une panne de lecture DÉSARME le second facteur du compte ;
//   * `mfa_status` — servait `{enrolled:false, enabled:false}` en 200, c'est-à-dire « ce compte n'a
//     pas de double authentification », à une console qui le peint tel quel.
//
// CE QUI EST FAIT : la lecture rend `Result<Option<_>>` (`.optional()`), l'absence de ligne reste un
// FAIT, et la lecture NON FAITE refuse — 503 nommé sur les trois routes, refus de connexion sur la
// décision. Un refus se réessaie ; un second facteur contourné ne se rattrape pas.
//
// LES TROIS AUTRES LECTURES DE `user_mfa` (`mfa_verify`, `mfa_disable`, `login_mfa_post`) sont
// laissées telles quelles À DESSEIN : leur repli REFUSE déjà (400, 404, 401) — elles n'inventent
// aucun fait, seulement une cause inexacte. C'est le rang quatre de `P10.20-b`, pas celui-ci.
pub(crate) const CAUSE_MFA_NON_LUE: &str = "STATUT DE DOUBLE AUTHENTIFICATION NON LU : la lecture de \
     `user_mfa` a échoué. Ce n'est PAS « aucun second facteur sur ce compte » — un compte peut porter \
     une MFA ACTIVE que cette lecture n'a pas vue. Toute décision qui en dépend est REFUSÉE ; \
     réessayez.";

/// `P10.21-s` — LE PAS TOTP QUE LA BASE N'A PAS CONSOMMÉ N'OUVRE AUCUNE SESSION. Le code est juste,
/// mais l'écriture qui le rend inutilisable une seconde fois (`user_mfa.last_step`, anti-rejeu) n'a
/// pas eu lieu : l'accepter laisserait CE MÊME code ouvrir une autre session pendant sa fenêtre.
pub(crate) const CAUSE_PAS_TOTP_NON_CONSOMME: &str = "SECOND FACTEUR NON CONSOMMÉ, CONNEXION REFUSÉE : \
     le code TOTP est juste, mais la base n'a pas pris l'écriture qui l'empêche de servir une seconde \
     fois (anti-rejeu). L'accepter laisserait ce même code ouvrir une autre session pendant sa fenêtre \
     de validité : aucune session n'est posée, le registre n'atteste aucune connexion, et le code \
     n'est PAS brûlé. Réessayez.";

/// `P10.21-s` — LE CODE DE SECOURS QUE LA BASE N'A PAS RETIRÉ N'OUVRE AUCUNE SESSION. Même geste que
/// le pas TOTP, sur le facteur à usage unique : un code accepté et resté dans la liste resservirait.
pub(crate) const CAUSE_CODE_DE_SECOURS_NON_CONSOMME: &str = "CODE DE SECOURS NON CONSOMMÉ, CONNEXION \
     REFUSÉE : le code de secours est juste, mais la base n'a pas pris l'écriture qui le retire de la \
     liste (usage unique). L'accepter le laisserait valable pour une autre connexion : aucune session \
     n'est posée, le registre n'atteste aucune connexion, et le code reste utilisable. Réessayez.";

/// `P10.21-s` — LA DÉSACTIVATION QUE LA BASE N'A PAS PRISE N'EST NI SERVIE NI ATTESTÉE. La route
/// rendait `ok` et le registre posait « MFA TOTP désactivée » sur un `DELETE` avalé : le compte
/// exigeait TOUJOURS son second facteur pendant que la trace non purgeable disait le contraire.
pub(crate) const CAUSE_MFA_NON_DESACTIVEE: &str = "DOUBLE AUTHENTIFICATION TOUJOURS ACTIVE : la base \
     n'a pas pris la suppression du second facteur. Le compte exige TOUJOURS un code à la connexion, et \
     le registre n'atteste aucune désactivation. Réessayez.";

/// `P10.22-r` — UNE LISTE DE CODES DE SECOURS QUI N'A PAS ÉTÉ LUE N'ACCUSE PERSONNE. Une lecture refusée ou
/// un contenu corrompu rendait « code MFA invalide » (401) : un refus, mais une FAUSSE cause, qui accusait
/// l'utilisateur d'un code peut-être juste — et le comptait comme un échec d'authentification.
pub(crate) const CAUSE_CODES_DE_SECOURS_ILLISIBLES: &str = "CODES DE SECOURS NON LUS, CODE NI ACCEPTÉ NI \
     REFUSÉ : la liste des codes de secours de ce compte n'a pas pu être lue (lecture refusée ou contenu \
     corrompu). On ne sait donc pas si le code présenté est juste : il n'est PAS déclaré invalide, il n'est \
     compté comme aucun échec, aucune session n'est posée et rien n'est modifié. Réessayez, ou présentez un \
     code TOTP.";

/// `P10.22-l` — L'ACTIVATION QUE LA BASE N'A PAS PRISE NE SERT AUCUN CODE DE SECOURS. La route rendait un
/// 500 anonyme (« activation MFA échouée ») ; elle NOMME désormais ce qui est vrai après le refus.
pub(crate) const CAUSE_MFA_NON_ACTIVEE: &str = "DOUBLE AUTHENTIFICATION NON ACTIVÉE : la base n'a pas pris \
     l'écriture qui active le second facteur. Le compte reste SANS second facteur, aucun code de secours \
     n'est servi (aucun n'a été enregistré), et le registre n'atteste aucune activation. Réessayez.";

/// `P10.22-l` — DEUX ACTIVATIONS NE SE RECOUVRENT PAS. La lecture de l'enrôlement et l'écriture qui l'active
/// n'étaient pas liées : entre les deux, une autre requête a activé ce même enrôlement, ou l'a remplacé par
/// une graine neuve, ou l'a supprimé. Cette requête n'active RIEN et ne sert aucun code.
pub(crate) const CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION: &str = "ENRÔLEMENT CHANGÉ PENDANT LA \
     VÉRIFICATION : entre la lecture de l'enrôlement et son activation, une autre requête l'a activé, \
     remplacé par une graine neuve ou supprimé. Cette requête n'active rien et ne sert aucun code de \
     secours ; rechargez l'état de la double authentification.";

/// `P10.22-m` — LE SECOND FACTEUR SE FREINE PAR COMPTE. Voir `second_facteur_freine`.
pub(crate) const CAUSE_SECOND_FACTEUR_FREINE: &str = "TROP D'ÉCHECS DU SECOND FACTEUR SUR CE COMPTE : les \
     codes sont refusés SANS être examinés jusqu'à la fin du délai (en-tête Retry-After), quelle que soit \
     l'adresse d'où ils viennent et quel que soit le ticket. Un code juste accepté remet le compte à zéro ; \
     une connexion par mot de passe, non.";

/// `P10.23-b` — UNE SESSION SEULE N'ENRÔLE PAS DE GRAINE. Voir `prouver_le_premier_facteur`. Le champ
/// `password` est absent ou vide : rien n'est examiné, rien n'est compté.
pub(crate) const CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER: &str = "MOT DE PASSE EXIGÉ POUR ENRÔLER : une graine \
     TOTP enrôlée puis activée verrouille la connexion de ce compte derrière elle, et une session seule ne \
     prouve pas qu'elle est tenue par le titulaire. Présentez le mot de passe du compte (champ `password`). \
     Aucune graine n'est posée, l'enrôlement en attente éventuel est intact, aucun échec n'est compté.";

/// `P10.23-b` — le mot de passe présenté à l'enrôlement n'est pas celui du compte.
pub(crate) const CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT: &str = "MOT DE PASSE REFUSÉ, AUCUNE GRAINE ENRÔLÉE : \
     le mot de passe présenté n'est pas celui du compte. L'échec est compté au MÊME verrou que la connexion \
     (compte, adresse) et inscrit au registre ; aucune graine n'est posée et l'enrôlement en attente éventuel \
     est intact.";

/// `P10.23-b` — le verrou (compte, adresse) de la connexion est posé : le mot de passe n'est pas examiné.
pub(crate) const CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT: &str = "TROP D'ÉCHECS DU MOT DE PASSE SUR CE \
     COMPTE DEPUIS CETTE ADRESSE : le verrou est celui de la connexion (en-tête Retry-After) ; le mot de passe \
     n'est pas examiné et aucune graine n'est posée.";

/// `P10.23-b` — un compte sans mot de passe local (fédéré, ou identité SSO par en-têtes) n'enrôle pas de graine.
pub(crate) const CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL: &str = "ENRÔLEMENT REFUSÉ, CE COMPTE N'A PAS DE MOT \
     DE PASSE LOCAL (compte fédéré OIDC, SAML ou LDAP, ou identité SSO par en-têtes) : le second facteur de \
     plume n'est demandé qu'à la connexion par mot de passe local, que ce compte n'emprunte pas — l'y enrôler \
     ne protégerait rien, et aucun mot de passe ne peut prouver que c'est son titulaire qui l'enrôle. Le second \
     facteur de ce compte est celui de son fournisseur d'identité. Rien n'est posé ni compté.";

/// `P10.23-b` — la lecture qui dit si le compte a un mot de passe local a échoué.
pub(crate) const CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT: &str = "COMPTE NON LU, ENRÔLEMENT NI ACCEPTÉ NI REFUSÉ : \
     la lecture du compte a échoué, on ne sait donc pas s'il a un mot de passe local à prouver. Aucune graine \
     n'est posée, aucun échec n'est compté. Réessayez.";

/// `P10.22-x` — LE TICKET SUIT LA RÉVOCATION DES SESSIONS. Voir `mfa_ticket_sign`. Les trois causes (signature,
/// expiration, époque révolue) partagent CETTE phrase à dessein : dire laquelle renseignerait le porteur d'un
/// vieux ticket sur ce qui s'est passé depuis, sans rien apprendre au titulaire qui recommence de toute façon.
/// `P10.23-l` — et l'époque du COMPTE : révolue, ou non relue (le refus ne conclut alors rien, il ne compte rien, et
/// l'étape du mot de passe, qui la relit pour frapper un ticket neuf, nomme la lecture ratée).
pub(crate) const CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE: &str = "TICKET MFA REFUSÉ, RECOMMENCEZ LA \
     CONNEXION PAR LE MOT DE PASSE : il est invalide, expiré (cinq minutes), ou révoqué depuis son émission — \
     un ticket en attente suit la révocation des sessions (déconnexion, changement du mot de passe \
     administrateur, réinitialisation du mot de passe du compte par un administrateur), et il n'est pas accepté \
     tant que la révocation propre à son compte n'a pas pu être relue. Aucune session n'est posée, aucun échec \
     n'est compté.";

// ---------- utilitaires locaux ----------

/// Nom de provider valide (segment d'URL sûr) : alphanumérique + `. _ -`, non vide, <= 64.
fn idp_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Nom réservé au compte admin de CONFIG (PLUME_USER + PLUME_PASS_HASH) — repli de `authenticate()`, JAMAIS
/// dans la table `user`. Un login fédéré portant ce nom est refusé (anti lockout/hijack de l'admin statique).
/// None si aucun admin de config n'est posé (pass_hash vide) -> pas de nom à réserver.
fn reserved_static_admin(st: &AppState) -> Option<&str> {
    (!st.pass_hash.is_empty()).then(|| st.user.as_str())
}

/// Refus mode-1 homogène (IdP/MFA = mono-tenant dans cet incrément).
fn deny_multitenant() -> Response {
    err_json(StatusCode::NOT_IMPLEMENTED, "IdP/MFA via l'UI réservé au mode mono-tenant (control-plane : voir la roadmap #2)")
}

/// GET JSON via le client HTTP interne (rustls/ring). Corps jamais mis dans une erreur.
fn fetch_json(url: &str) -> Result<Value, String> {
    ssrf_guard(url)?; // discovery OIDC + jwks_uri sont pilotés par la config IdP -> garde SSRF (anti 169.254/interne/rebind)
    let resp = http_call("GET", url, &[("Accept", "application/json")], None)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {} (discovery/jwks)", resp.status));
    }
    serde_json::from_slice(&resp.body).map_err(|_| "réponse non-JSON".to_string())
}

/// Pose les cookies de session (plume_session HttpOnly + plume_csrf) sur une réponse — MÊME construction
/// que `login_post` (jeton HMAC lié à l'epoch, TTL, Secure si TLS). Chemin de sortie commun OIDC/LDAP/MFA.
/// `P10.23-l` — le jeton est frappé PAR L'APPELANT, AVANT sa ligne de registre (`frapper_la_session_du_compte`, qui
/// lit l'époque du compte et peut refuser ; ou, au second facteur, l'époque que le ticket vient de prouver) : une
/// époque de compte non lue refuse la connexion sans que le registre l'ait attestée.
fn attach_session_cookies(st: &AppState, resp: &mut Response, token: &str) {
    let csrf = csrf_for(st.session_secret.as_slice(), token);
    let secure = cookie_secure_suffix();
    let ttl = st.session_ttl_s.max(1);
    let c_sess = format!("plume_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    let c_csrf = format!("plume_csrf={csrf}; SameSite=Strict; Path=/; Max-Age={ttl}{secure}");
    if let Ok(v) = c_sess.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = c_csrf.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

/// Ticket MFA signé (2e facteur en attente) : `mfa|user|role|exp`, HMAC-SHA256 (session_secret). Émis par
/// `login_post` quand le 1er facteur réussit ET que l'utilisateur a une MFA active ; consommé par
/// `login_mfa_post`. Stateless, non forgeable, borné dans le temps. Le préfixe de domaine `mfa` empêche
/// toute confusion avec un jeton de session/state OIDC.
///
/// `P10.22-x` — LE TICKET EST SIGNÉ AVEC L'ÉPOQUE DE SESSION, COMME LA SESSION QU'IL DEVIENDRA. Mesuré le
/// 2026-09-23 sur la forme d'avant (signature sur le seul payload) : un ticket émis AVANT un changement du mot de
/// passe administrateur (`password_post`, époque 0 -> 1), ou avant une déconnexion (`logout_post`, 0 -> 1), ouvrait
/// encore une session (200, cookie) — et cette session, frappée à l'époque COURANTE par `login_mfa_post`, était
/// valide APRÈS la révocation : le ticket faisait passer une session à travers elle. L'époque n'est pas dans le
/// payload lisible ; la vérification la réinjecte depuis `AppState` (`verify_session` fait de même), donc tout ce
/// qui révoque les sessions révoque les tickets en attente, et rien d'autre.
///
/// POURQUOI L'ÉPOQUE, ET NI L'EMPREINTE DU MOT DE PASSE NI L'USAGE UNIQUE. L'époque ne coûte aucune lecture, aucun
/// état et aucun refus neuf (c'est un entier en mémoire, persisté par `bump_session_epoch`) ; elle fait du ticket
/// ce qu'il est — une session en attente — soumise à la MÊME révocation, en UN point. L'empreinte du mot de passe
/// aurait couvert en plus la réinitialisation par un administrateur (`user_update`), qui ne touche pas l'époque :
/// mais cette réinitialisation laisse AUSSI vivre les sessions déjà ouvertes (mesuré : la session d'avant reste
/// valide), défaut plus lourd que cinq minutes de ticket et qui se ferme au même point pour les deux (une clé
/// neuve, hors de ce module) ; l'empreinte ajoutait une lecture à chaque ticket et un cinq cent trois neuf quand
/// elle rate. L'usage unique exigerait un état serveur (les tickets consommés jusqu'à leur expiration, perdu au
/// redémarrage) pour ne rien retirer : rejouer un ticket, c'est encore devoir présenter un code frais, que le pas
/// consommé et le frein par compte (`P10.22-m`) bornent — le ticket vaut le mot de passe pendant cinq minutes,
/// pas davantage.
///
/// `P10.23-l` — CE « MÊME POINT » EST L'ÉPOQUE DU COMPTE (`session.rs`, `epoque_du_compte`), signée ici comme dans la
/// session et portée par le ticket (`<b64>.<hex>.<k>` au-delà de zéro) : la réinitialisation par un administrateur
/// et le changement du mot de passe administrateur l'avancent, et le ticket d'avant est refusé par `login_mfa_post`
/// AVANT tout examen du code. L'époque globale reste signée : une déconnexion révoque toujours tous les tickets.
///
/// LE DOMAINE DU MESSAGE SIGNÉ EST SÉPARÉ DE CELUI DE LA SESSION. `mint_session` signe `<payload>|<époque>` ; signer
/// ici la même forme ferait passer un ticket pour un cookie de session (utilisateur `mfa|<nom>`). Le préfixe
/// `mfa-ticket|` en tête, suivi d'un entier, ne peut égaler aucun message de session (dont la tête est du base64,
/// sans barre verticale avant l'époque).
fn mfa_ticket_sign(secret: &[u8], user: &str, role: &str, ttl_s: i64, epoch: i64, epoque_du_compte: i64) -> String {
    let exp = now() + ttl_s.max(1);
    let payload = format!("mfa|{user}|{role}|{exp}");
    let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = hmac_sha256(secret, format!("mfa-ticket|{epoch}|{p_b64}{}", suffixe_signe_de_l_epoque_du_compte(epoque_du_compte)).as_bytes());
    joindre_l_epoque_du_compte(format!("{p_b64}.{}", hex_encode(&sig)), epoque_du_compte)
}

/// `P10.22-x` — `epoch` est l'époque de session COURANTE : un ticket signé sous une époque révolue est refusé.
/// `P10.23-l` — rend aussi l'époque du compte que le ticket porte (signée) ; l'appelant la compare à celle du compte.
fn mfa_ticket_verify(secret: &[u8], blob: &str, epoch: i64) -> Option<(String, String, i64)> {
    let (p_b64, sig_hex, epoque_du_compte) = decouper_le_jeton(blob)?;
    let expect = hmac_sha256(secret, format!("mfa-ticket|{epoch}|{p_b64}{}", suffixe_signe_de_l_epoque_du_compte(epoque_du_compte)).as_bytes());
    if !ct_eq(&hex_decode(sig_hex)?, &expect) {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p_b64).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut it = s.split('|');
    if it.next()? != "mfa" {
        return None;
    }
    let user = it.next()?.to_string();
    let role = it.next()?.to_string();
    let exp: i64 = it.next()?.parse().ok()?;
    if now() >= exp {
        return None;
    }
    Some((user, role, epoque_du_compte))
}

// ================================================================================================
// CRUD des fournisseurs (admin-only, mode 0). Secret write-only + redaction (miroir connectors.rs).
// ================================================================================================

pub(crate) async fn idp_providers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    // `P10.7-f` (rang 1) — LA LISTE SSO EST ENTIÈRE OU AVOUÉE. Avant : `.map(|rows| rows.flatten()
    // .collect()).unwrap_or_default()` et `Err(_) => Vec::new()` — un fournisseur d'identité dont la ligne
    // ne se décode pas disparaissait de la liste, et une voie d'authentification ACTIVE devenait invisible
    // à celui qui la croyait fermée. Le parcours est soldé en bloc.
    //
    // POURQUOI UN 5xx NOMMÉ ET NON `error` DANS LE CORPS, comme les autres listes de ce lot : le corps de
    // CETTE route est un TABLEAU NU (`Json(Value::Array(..))`), il n'a aucune clé où poser l'aveu, et lui
    // en donner une changerait le contrat (`web/idp.js:23` reçoit et itère un tableau). La forme
    // fail-closed du dépôt s'applique donc — celle de `client_case_get` et de `ledger_get` : un 5xx qui
    // NOMME sa cause, jamais une absence inventée. `web/idp.js:24-28` la peint déjà (`api()` jette sur
    // non-2xx et le module affiche « erreur : <statut> <corps> »), là où un `[]` en 200 se lirait
    // « aucun fournisseur ».
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,kind,enabled,config_json,created,updated,(secret != '') FROM idp_provider ORDER BY id")
        .and_then(|mut stmt| {
            // Le secret n'est JAMAIS projeté : seul le booléen (secret != '') sort.
            stmt.query_map([], |r| {
                let cfg_json: String = r.get(4)?;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "enabled": r.get::<_, i64>(3)? != 0,
                    "config": serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})),
                    "created": r.get::<_, i64>(5)?,
                    "updated": r.get::<_, i64>(6)?,
                    "has_secret": r.get::<_, i64>(7)? != 0,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(list) => Json(Value::Array(list)).into_response(),
        Err(_) => server_err(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
    }
}

pub(crate) async fn idp_provider_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let name = b.trimmed("name");
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide (alphanumérique, . _ - ; <= 64)");
    }
    let kind = match b.get("kind").and_then(|x| x.as_str()) {
        Some("oidc") => "oidc",
        Some("ldap") => "ldap",
        Some("saml") => "saml",
        _ => return bad_req("kind non supporté (oidc | ldap | saml)"),
    };
    let config = b.get("config").cloned().unwrap_or_else(|| json!({}));
    // Validation minimale par type (fail-closed : refuse une config inexploitable).
    match kind {
        "oidc" => {
            let c = OidcCfg::from_json(&config);
            if !c.is_usable() {
                return bad_req("config OIDC : issuer, client_id et redirect_uri requis");
            }
            if !c.redirect_uri.starts_with("https://") && !c.redirect_uri.starts_with("http://") {
                return bad_req("redirect_uri doit être une URL absolue http(s)");
            }
        }
        "ldap" => {
            let c = LdapCfg::from_json(&config);
            if c.url.is_empty() {
                return bad_req("config LDAP : url requise (ldap:// ou ldaps://)");
            }
        }
        "saml" => {
            // DURCISSEMENT #7 : want_assertions_signed=false est un footgun réel (assertions acceptées non
            // signées). GARDÉ configurable (IdP legacy signant seulement la Response) mais JAMAIS silencieux :
            // avertissement BRUYANT au moment de la config (le use-time est aussi averti dans saml_verify_and_extract).
            let c = SamlCfg::from_json(&config);
            if !c.want_assertions_signed {
                eprintln!(
                    "AVERTISSEMENT SÉCURITÉ SAML — provider '{name}' créé avec want_assertions_signed=false : assertions acceptées NON SIGNÉES (INSÉCURE, réservé à un IdP legacy). Cf. docs/NATIVE-IDP.md §5."
                );
            }
        }
        _ => {}
    }
    let enabled = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
    let secret = b.get("secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let conn = st.db.lock();
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![name, kind, enabled, config.to_string(), secret, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.idp.create",
            &format!("provider IdP '{name}' ({kind}) créé par {}", au.name), 3,
            &format!("fournisseur d'identité '{name}' ({kind}, enabled={}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "kind": kind, "enabled": enabled != 0, "has_secret": !secret.is_empty(), "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "enabled": enabled != 0 })).into_response() }
        Err(_) => { let _ = conn.execute_batch("ROLLBACK"); (StatusCode::CONFLICT, "échec de création (nom déjà pris ou audit) — réessayez").into_response() }
    }
}

pub(crate) async fn idp_provider_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    if conn.query_row("SELECT 1 FROM idp_provider WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("provider introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE idp_provider SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        if let Some(v) = b.get("config") {
            conn.execute("UPDATE idp_provider SET config_json=?1 WHERE id=?2", params![v.to_string(), id])?;
        }
        // SECRET : mis à jour UNIQUEMENT si fourni ET non vide -> omis/vide = conserver l'existant (jamais
        // d'écrasement par vide ; jamais renvoyé ni loggé).
        let mut secret_rotated = false;
        if let Some(s) = b.get("secret").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                conn.execute("UPDATE idp_provider SET secret=?1 WHERE id=?2", params![s, id])?;
                secret_rotated = true;
            }
        }
        conn.execute("UPDATE idp_provider SET updated=?1 WHERE id=?2", params![now(), id])?;
        let changed: Vec<&str> = ["enabled", "config"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn, "config.idp.update",
            &format!("provider IdP #{id} modifié ({}{}) par {}", changed.join(","), if secret_rotated { ",secret" } else { "" }, au.name), 3,
            &format!("fournisseur d'identité #{id} modifié (champs: {}{}) par {}", changed.join(","), if secret_rotated { ", secret rotaté" } else { "" }, au.name),
            &json!({ "id": id, "changed": changed, "secret_rotated": secret_rotated, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "ok": true })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

pub(crate) async fn idp_provider_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    let name: Option<String> = conn.query_row("SELECT name FROM idp_provider WHERE id=?1", params![id], |r| r.get(0)).ok();
    let Some(name) = name else { return not_found("provider introuvable") };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM idp_provider WHERE id=?1", params![id])?;
        audit_config_change(
            &conn, "config.idp.delete",
            &format!("provider IdP '{name}' (#{id}) supprimé par {}", au.name), 3,
            &format!("fournisseur d'identité '{name}' supprimé par {}", au.name),
            &json!({ "id": id, "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit: {e}")) }
    }
}

// ================================================================================================
// OIDC login (Authorization-Code + PKCE). Routes PUBLIQUES (auth_guard allowlist).
// ================================================================================================

/// Charge une ligne provider (config_json, secret) par nom + kind + enabled=1. None si absent/désactivé.
fn load_provider(st: &AppState, name: &str, kind: &str) -> Option<(Value, String)> {
    let conn = st.db.lock();
    conn.query_row(
        "SELECT config_json,secret FROM idp_provider WHERE name=?1 AND kind=?2 AND enabled=1",
        params![name, kind],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
    .map(|(cj, sec)| (serde_json::from_str(&cj).unwrap_or_else(|_| json!({})), sec))
}

/// Résout les endpoints OIDC : discovery si nécessaire (endpoints non tous overridés). Blocking (rare).
fn oidc_endpoints_for(cfg: &OidcCfg) -> Result<OidcEndpoints, String> {
    let need_discovery = cfg.authorization_endpoint.is_empty() || cfg.token_endpoint.is_empty() || cfg.jwks_uri.is_empty();
    let discovery = if need_discovery { Some(fetch_json(&cfg.discovery_url())?) } else { None };
    oidc_resolve_endpoints(cfg, discovery.as_ref())
}

/// GET /api/auth/oidc/{name}/start — démarre le login OIDC : pose un cookie de state signé (Lax, court) et
/// redirige (302) vers l'authorize endpoint. PUBLIC. Fail-closed : provider inconnu/désactivé/misconfig -> 4xx.
pub(crate) async fn oidc_start(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, _secret)) = load_provider(&st, &name, "oidc") else {
        return not_found("provider OIDC inconnu ou désactivé");
    };
    let cfg = OidcCfg::from_json(&cfg_json);
    if !cfg.is_usable() {
        return server_err("configuration OIDC incomplète");
    }
    // Réseau (discovery) -> spawn_blocking : ne bloque PAS l'exécuteur async (route publique pré-auth ;
    // http_call = std::net bloquant jusqu'à 10 s -> sinon famine du pool de workers = DoS). Cf. connectors.rs.
    let cfg_disc = cfg.clone();
    let ep = match tokio::task::spawn_blocking(move || oidc_endpoints_for(&cfg_disc)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("découverte OIDC échouée: {e}")),
        Err(_) => return server_err("échec interne (discovery)"),
    };
    let (Some(state), Some(nonce), Some(verifier)) = (rand_url_token(), rand_url_token(), rand_url_token()) else {
        return server_err("entropie noyau indisponible");
    };
    let challenge = pkce_challenge_s256(&verifier);
    let blob = oidc_state_sign(st.session_secret.as_slice(), &name, &state, &nonce, &verifier, 600);
    let secure = cookie_secure_suffix();
    // SameSite=Lax : le cookie DOIT survivre à la navigation top-level de retour depuis l'IdP (Strict le
    // droperait). HttpOnly ; Max-Age court (10 min) borné à la durée du flux.
    let cookie = format!("plume_oidc={blob}; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=600{secure}");
    let url = oidc_authorize_url(&cfg, &ep, &state, &nonce, &challenge);
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// GET /api/auth/oidc/callback?code=&state= — valide le retour IdP, échange le code, valide l'id_token,
/// mappe groupe->rôle, provisionne le compte JIT, pose la session et redirige vers `/`. PUBLIC. Fail-closed.
pub(crate) async fn oidc_callback(State(st): State<AppState>, headers: axum::http::HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    // erreur renvoyée par l'IdP (ex access_denied) -> 401, jamais de session.
    if let Some(e) = q.get("error") {
        return err_json(StatusCode::UNAUTHORIZED, format!("l'IdP a refusé l'authentification: {e}"));
    }
    // 1) State cookie signé -> provider/state/nonce/verifier attendus.
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    let Some(blob) = cookie_value(cookie_hdr, "plume_oidc") else {
        return bad_req("state de login OIDC absent (cookie manquant ou expiré)");
    };
    let Some((provider, exp_state, nonce, verifier)) = oidc_state_verify(st.session_secret.as_slice(), &blob) else {
        return bad_req("state de login OIDC invalide ou expiré");
    };
    // 2) CSRF : le state renvoyé par l'IdP DOIT == celui du cookie (temps constant).
    let got_state = q.get("state").map(String::as_str).unwrap_or("");
    if !ct_eq(got_state.as_bytes(), exp_state.as_bytes()) {
        return bad_req("state OIDC ne correspond pas (anti-CSRF)");
    }
    let Some(code) = q.get("code").filter(|c| !c.is_empty()) else {
        return bad_req("code d'autorisation absent");
    };
    // 3) Provider (re-chargé côté serveur, jamais depuis la requête).
    let Some((cfg_json, secret)) = load_provider(&st, &provider, "oidc") else {
        return not_found("provider OIDC inconnu ou désactivé");
    };
    let cfg = OidcCfg::from_json(&cfg_json);
    // Réseau -> spawn_blocking (route publique pré-auth ; jusqu'à 3 appels réseau bloquants = ~30 s -> sinon
    // famine du pool de workers async = DoS pré-auth). Miroir strict de connectors.rs.
    let cfg_disc = cfg.clone();
    let ep = match tokio::task::spawn_blocking(move || oidc_endpoints_for(&cfg_disc)).await {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("découverte OIDC échouée: {e}")),
        Err(_) => return server_err("échec interne (discovery)"),
    };
    // 4) Échange du code -> id_token (le secret ne transite QUE dans ce corps POST). Réseau -> spawn_blocking.
    let body = oidc_token_body(&cfg, code, &verifier, &secret);
    let token_url = ep.token_endpoint.clone();
    let tok_resp = match tokio::task::spawn_blocking(move || {
        ssrf_guard(&token_url)?; // le token_endpoint (config/discovery) est un égress -> garde SSRF
        http_call("POST", &token_url, &[("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")], Some(body.as_bytes()))
    }).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("échange de code échoué: {e}")),
        Err(_) => return server_err("échec interne (token)"),
    };
    if !(200..300).contains(&tok_resp.status) {
        return err_json(StatusCode::UNAUTHORIZED, format!("échange de code refusé (HTTP {})", tok_resp.status));
    }
    let tok_json: Value = match serde_json::from_slice(&tok_resp.body) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_GATEWAY, "réponse token non-JSON"),
    };
    let Some(id_token) = tok_json.get("id_token").and_then(|v| v.as_str()) else {
        return err_json(StatusCode::UNAUTHORIZED, "id_token absent de la réponse token");
    };
    // 5) JWKS + validation signature/iss/aud/exp/nonce (fail-closed). Réseau -> spawn_blocking.
    let jwks_url = ep.jwks_uri.clone();
    let jwks = match tokio::task::spawn_blocking(move || fetch_json(&jwks_url)).await {
        Ok(Ok(j)) => j,
        Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!("JWKS indisponible: {e}")),
        Err(_) => return server_err("échec interne (jwks)"),
    };
    let claims = match oidc_validate_id_token(id_token, &jwks, &cfg.issuer, &cfg.client_id, &nonce) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::UNAUTHORIZED, format!("id_token invalide: {e}")),
    };
    // 6) Identité + rôle (mapping groupe->rôle réutilisé ; fail-closed si aucun groupe mappé).
    let username = oidc_username(&claims);
    if !idp_name_ok(&username) {
        return err_json(StatusCode::UNAUTHORIZED, "nom d'utilisateur OIDC absent ou invalide");
    }
    let groups = oidc_groups_str(&claims, &cfg.group_claim);
    let Some(role) = oidc_role_mode0(&st, &groups, cfg.require_group_match) else {
        return forbidden("aucun groupe OIDC mappé à un rôle Plume (accès refusé)");
    };
    // 7) Provisioning JIT (anti-collision compte local + réservation admin bootstrap) + session.
    let jeton = match frapper_la_session_du_compte(&st, &username, &role) {
        Ok(jeton) => jeton,
        Err(refus) => return refus,
    };
    {
        let conn = st.db.lock();
        if let Err(e) = idp_provision_user(&conn, &username, &role, reserved_static_admin(&st)) {
            return (StatusCode::CONFLICT, e).into_response();
        }
        ledger_append(&conn, "login", &format!("login OIDC : '{username}' (rôle {role}) via provider '{provider}'"));
    }
    // 8) Redirige vers `/` (jamais une URL contrôlée par l'utilisateur -> pas d'open redirect) + efface le state.
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, "/")]).into_response();
    attach_session_cookies(&st, &mut resp, &jeton);
    let secure = cookie_secure_suffix();
    if let Ok(v) = format!("plume_oidc=; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=0{secure}").parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// ================================================================================================
// SAML 2.0 SP login (SP-initié, HTTP-POST ACS). Routes PUBLIQUES (auth_guard allowlist). La vérification
// XML-DSig/XSW est feature-gated (`saml`) dans idp.rs -> sans la feature, ces handlers renvoient 501.
// ================================================================================================

/// GET /api/auth/saml/{name}/start — construit l'AuthnRequest (HTTP-Redirect), pose le RelayState signé +
/// un cookie de flux (Lax, best-effort) et redirige (302) vers l'IdP. PUBLIC. Fail-closed.
pub(crate) async fn saml_start(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, secret)) = load_provider(&st, &name, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    if !cfg.is_usable() {
        return server_err("configuration SAML incomplète (idp_sso_url/idp_entity_id/sp_entity_id/acs_url/idp_x509_cert requis)");
    }
    // Génération PURE (XML + deflate + éventuelle signature RSA) — CPU ms-scale, aucun réseau : inline.
    let (url, blob) = match saml_build_authn_redirect(&cfg, &name, &secret, st.session_secret.as_slice()) {
        Ok(v) => v,
        Err(e) if e.contains("non compilé") => return err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(e) => return server_err(format!("échec de l'AuthnRequest SAML: {e}")),
    };
    let secure = cookie_secure_suffix();
    // Cookie de flux Lax = défense en profondeur : peut NE PAS survivre au POST cross-site vers l'ACS
    // (SameSite=Lax exclut les POST cross-site) -> le RelayState signé (echo IdP) reste la SOURCE DE VÉRITÉ.
    let cookie = format!("plume_saml={blob}; HttpOnly; SameSite=Lax; Path=/api/auth/saml; Max-Age=600{secure}");
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// POST /api/auth/saml/acs — Assertion Consumer Service (SÉCURITÉ-CRITIQUE). Consomme SAMLResponse+RelayState,
/// valide (checklist complète dans `saml_verify_and_extract`), mappe groupe->rôle, provisionne JIT, pose la
/// session, 302 vers `/`. PUBLIC. Fail-closed : toute anomalie -> 4xx, aucune session.
pub(crate) async fn saml_acs(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let Some(saml_response) = form.get("SAMLResponse").filter(|s| !s.is_empty()) else {
        return bad_req("SAMLResponse absente");
    };
    // 1) RelayState signé (#12) -> (provider, request_id). JAMAIS de RelayState brut fiable.
    let relay = form.get("RelayState").map(String::as_str).unwrap_or("");
    let Some((provider, request_id)) = saml_relaystate_verify(st.session_secret.as_slice(), relay) else {
        return bad_req("RelayState SAML invalide ou expiré (recommencez la connexion)");
    };
    // 2) Liaison de flux best-effort via le cookie plume_saml (si présent : DOIT concorder ; s'il a été
    //    droppé par SameSite=Lax sur le POST cross-site, on s'appuie sur le RelayState signé, autoritatif).
    let cookie_hdr = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()).unwrap_or("");
    if let Some(cval) = cookie_value(cookie_hdr, "plume_saml") {
        match saml_relaystate_verify(st.session_secret.as_slice(), &cval) {
            Some((_, cookie_req_id)) if ct_eq(cookie_req_id.as_bytes(), request_id.as_bytes()) => {}
            _ => return bad_req("liaison de flux SAML invalide (cookie/RelayState divergents)"),
        }
    }
    // 3) Provider re-chargé côté serveur (jamais depuis la requête).
    let Some((cfg_json, _secret)) = load_provider(&st, &provider, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    // 4) VÉRIFICATION + EXTRACTION (feature-gated ; anti-rejeu via le set global borné). Le verrou est tenu
    //    pendant finish_sso (l'adaptateur de rejeu l'utilise) — login peu fréquent, coût négligeable.
    let now_unix = now();
    let res = {
        let mut store = saml_replay_store().lock();
        saml_verify_and_extract(&cfg, saml_response, &request_id, now_unix, &mut *store)
    };
    let (username, groups) = match res {
        Ok(v) => v,
        Err(e) if e.contains("non compilé") => return err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(_) => return err_json(StatusCode::UNAUTHORIZED, "assertion SAML invalide"),
    };
    // 5) Identité contrainte (même politique qu'OIDC : segment sûr, pas de '|' qui casserait le token de session).
    if !idp_name_ok(&username) {
        return err_json(StatusCode::UNAUTHORIZED, "nom d'utilisateur SAML absent ou invalide (attr_username/NameID)");
    }
    // 6) Rôle (mapping groupe->rôle RÉUTILISÉ ; fail-closed si aucun groupe mappé, #13).
    let Some(role) = oidc_role_mode0(&st, &saml_groups_str(&groups), cfg.require_group_match) else {
        return forbidden("aucun groupe SAML mappé à un rôle Plume (accès refusé)");
    };
    // 7) Provisioning JIT (anti-collision compte local + réservation admin bootstrap) + session.
    let jeton = match frapper_la_session_du_compte(&st, &username, &role) {
        Ok(jeton) => jeton,
        Err(refus) => return refus,
    };
    {
        let conn = st.db.lock();
        if let Err(e) = idp_provision_user(&conn, &username, &role, reserved_static_admin(&st)) {
            return (StatusCode::CONFLICT, e).into_response();
        }
        ledger_append(&conn, "login", &format!("login SAML : '{username}' (rôle {role}) via provider '{provider}'"));
    }
    // 8) Redirige vers `/` (jamais une URL contrôlée par l'utilisateur) + efface le cookie de flux.
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, "/")]).into_response();
    attach_session_cookies(&st, &mut resp, &jeton);
    let secure = cookie_secure_suffix();
    if let Ok(v) = format!("plume_saml=; HttpOnly; SameSite=Lax; Path=/api/auth/saml; Max-Age=0{secure}").parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

/// GET /api/auth/saml/{name}/metadata — métadonnée SP (XML public, à fournir à l'IdP). PUBLIC.
pub(crate) async fn saml_metadata(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    if !idp_name_ok(&name) {
        return bad_req("nom de provider invalide");
    }
    let Some((cfg_json, _)) = load_provider(&st, &name, "saml") else {
        return not_found("provider SAML inconnu ou désactivé");
    };
    let cfg = SamlCfg::from_json(&cfg_json);
    match saml_sp_metadata_xml(&cfg) {
        Ok(xml) => ([(header::CONTENT_TYPE, "application/samlmetadata+xml")], xml).into_response(),
        Err(e) if e.contains("non compilé") => err_json(StatusCode::NOT_IMPLEMENTED, e),
        Err(e) => server_err(format!("génération métadonnée SP échouée: {e}")),
    }
}

// ================================================================================================
// LDAP login (bind). Route PUBLIQUE. Le bind réseau est feature-gated (`ldap`) dans idp.rs.
// ================================================================================================

/// POST /api/auth/ldap {provider?, user, pass} — bind LDAP/AD, mappe l'appartenance aux groupes -> rôle,
/// provisionne JIT, pose la session. PUBLIC. Anti-brute-force réutilisé (lockout (user,ip)). Fail-closed.
pub(crate) async fn ldap_login_post(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let user = b.trimmed("user");
    let pass = b.str_field("pass").to_string();
    let ip = peer.ip().to_string();
    if user.is_empty() || pass.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "user et pass requis");
    }
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())], Json(json!({ "error": "trop d'échecs — réessayez plus tard" }))).into_response();
    }
    // provider : nommé, sinon le 1er provider LDAP activé.
    let prov_name = b.trimmed("provider");
    let row: Option<(Value, String)> = if !prov_name.is_empty() {
        load_provider(&st, &prov_name, "ldap")
    } else {
        let conn = st.db.lock();
        conn.query_row(
            "SELECT config_json,secret FROM idp_provider WHERE kind='ldap' AND enabled=1 ORDER BY id LIMIT 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(cj, sec)| (serde_json::from_str(&cj).unwrap_or_else(|_| json!({})), sec))
    };
    let Some((cfg_json, bind_pw)) = row else {
        return not_found("aucun provider LDAP activé");
    };
    let cfg = LdapCfg::from_json(&cfg_json);
    // Bind bloquant (feature-gated) -> spawn_blocking : route publique pré-auth, ne bloque PAS l'exécuteur
    // async (sinon famine du pool de workers = DoS). Erreur -> échec d'auth (lockout), jamais de détail sensible.
    let (cfg_b, bind_b, user_b, pass_b) = (cfg.clone(), bind_pw.clone(), user.clone(), pass.clone());
    let auth_res = tokio::task::spawn_blocking(move || ldap_authenticate(&cfg_b, &bind_b, &user_b, &pass_b))
        .await
        .unwrap_or_else(|_| Err("échec interne LDAP".to_string()));
    match auth_res {
        Ok(role) => {
            auth_record_success(&st, &user, &ip);
            let jeton = match frapper_la_session_du_compte(&st, &user, &role) {
                Ok(jeton) => jeton,
                Err(refus) => return refus,
            };
            {
                let conn = st.db.lock();
                if let Err(e) = idp_provision_user(&conn, &user, &role, reserved_static_admin(&st)) {
                    return (StatusCode::CONFLICT, e).into_response();
                }
                ledger_append(&conn, "login", &format!("login LDAP : '{user}' (rôle {role})"));
            }
            let mut resp = Json(json!({ "ok": true, "user": user, "role": role })).into_response();
            attach_session_cookies(&st, &mut resp, &jeton);
            resp
        }
        Err(e) => {
            let _ = auth_record_failure(&st, &user, &ip);
            // ldap non compilé -> 501 explicite ; sinon 401 générique (pas de fuite : user existe/n'existe pas).
            if e.contains("non compilé") {
                err_json(StatusCode::NOT_IMPLEMENTED, e)
            } else {
                err_json(StatusCode::UNAUTHORIZED, "identifiants LDAP invalides")
            }
        }
    }
}

// ================================================================================================
// MFA TOTP : enrôlement / vérif / désactivation (self-service authentifié) + challenge au login.
// ================================================================================================

// `P10.22-m` — LE SECOND FACTEUR SE FREINE PAR COMPTE, PAS PAR COUPLE (COMPTE, ADRESSE).
//
// CE QUI A ÉTÉ MESURÉ LE 2026-09-23, SUR LA FORME D'AVANT (un attaquant qui tient le mot de passe, donc un
// ticket ; seuil 10, les défauts du produit) :
//   * une adresse, un ticket : 10 codes faux, puis 429 — le verrou par couple (compte, adresse) tient SEUL ;
//   * vingt adresses, UN SEUL ticket rejoué : 200 codes faux sans autre frein que dix par adresse, et le code
//     juste présenté depuis une vingt-et-unième adresse avec le MÊME ticket ouvrait la session ;
//   * UNE SEULE adresse, reconnexion par le mot de passe toutes les neuf erreurs : 180 codes faux, ZÉRO 429 —
//     la connexion réussie par mot de passe (`login_post` -> `auth_record_success`) REMET À ZÉRO le compteur
//     du couple que les échecs du second facteur alimentent. L'énoncé (« ne vaut que par couple ») sous-
//     comptait : même par couple, il ne valait rien contre qui tient le mot de passe ;
//   * désactivation (`mfa_disable`) et activation (`mfa_verify`), session tenue : 100 codes faux chacune,
//     AUCUN échec compté nulle part.
// Au débit que laisse le budget d'authentification par adresse (120 requêtes / 10 s), la troisième voie seule
// fait ~10 codes par seconde depuis UNE adresse, soit ~33 000 s d'espérance pour tomber sur l'un des trois
// codes valides d'une fenêtre (1 sur ~333 000) — calcul, pas mesure.
//
// L'ARBITRAGE : PAR COMPTE, ET SEULEMENT DERRIÈRE LE PREMIER FACTEUR. Un compteur d'échecs PAR COMPTE sur le
// MOT DE PASSE serait un déni de service trivial : n'importe qui verrouillerait l'administrateur en tapant
// son nom. Celui-ci n'est atteignable QU'AVEC un ticket signé (donc le mot de passe) ou une session du
// compte : sans le premier facteur, on ne peut ni l'incrémenter ni le déclencher (le témoin le joue avec des
// tickets forgés). Celui qui tient le mot de passe peut, lui, geler l'étape du code pour le titulaire — au
// plus `lock_max_s` à chaque fois ; c'est le prix assumé : l'alternative est de le laisser DEVINER le second
// facteur, et la parade au gel est celle d'une compromission du mot de passe (le changer : plus de ticket
// neuf ; ceux déjà émis tombent avec l'époque de session quand le changement la fait avancer — `P10.22-x` —,
// sinon ils expirent en cinq minutes). Le premier facteur n'est PAS freiné par ce compte : le titulaire
// obtient toujours son ticket.
//
// POURQUOI PAS PAR TICKET : le ticket se réémet à volonté avec le mot de passe ; borner ses échecs ne borne
// pas ceux du compte. Il reste sans état serveur (il sert cinq minutes, rejouable tant que l'époque de session
// ne change pas) — ce n'est plus un levier de devinette, puisque le compteur ne dépend ni du ticket ni de
// l'adresse.
//
// CE QUE LE FREIN REPREND DU VERROU EXISTANT, ET CE QU'IL EN CHANGE. Mêmes réglages (`lock_threshold`,
// `lock_base_s`, `lock_max_s` ; seuil 0 = tous les verrous coupés, par décision de l'exploitant) et même
// progression exponentielle bornée. Deux différences, voulues : (1) seul un code juste ACCEPTÉ le remet à
// zéro, jamais le mot de passe ; (2) il oublie après UN JOUR sans échec, pas quinze minutes — avec un oubli
// de 900 s égal au plafond de 900 s, attendre la fin du plus long verrou suffisait à rendre dix essais neufs.
//
// OÙ IL VIT : un état de processus (comme le cache anti-rejeu SAML de `idp/saml.rs`), clé (base, compte). Sa
// taille est bornée par le nombre de comptes RÉELS dont on tient le premier facteur (le ticket est signé : on
// n'y fabrique pas de nom), et il est purgé au-delà d'`AUTH_FAIL_CAP`. Il ne survit pas à un redémarrage.
struct EchecsDuSecondFacteur {
    consecutifs: u32,
    freine_jusqu_a: Option<Instant>,
    dernier: Instant,
}

/// Un jour sans échec efface le compte des échecs consécutifs du second facteur (`P10.22-m`).
const MEMOIRE_DES_ECHECS_DU_SECOND_FACTEUR: Duration = Duration::from_secs(24 * 3600);

fn echecs_du_second_facteur() -> &'static parking_lot::Mutex<HashMap<(String, String), EchecsDuSecondFacteur>> {
    static S: std::sync::OnceLock<parking_lot::Mutex<HashMap<(String, String), EchecsDuSecondFacteur>>> = std::sync::OnceLock::new();
    S.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// La clé du frein : le COMPTE, dans la base qui le porte — jamais l'adresse, jamais le ticket.
fn cle_du_frein_du_second_facteur(st: &AppState, user: &str) -> (String, String) {
    (st.db_path.as_str().to_string(), user.to_string())
}

/// `P10.22-m` — ce compte est-il freiné au second facteur ? `Some(secondes restantes)` si oui. Consulté AVANT
/// d'examiner le code, par les trois routes qui jugent un code : `login_mfa_post`, `mfa_disable`, `mfa_verify`.
pub(crate) fn second_facteur_freine(st: &AppState, user: &str) -> Option<u64> {
    if st.lock_threshold == 0 {
        return None;
    }
    let g = echecs_du_second_facteur().lock();
    let jusqu_a = g.get(&cle_du_frein_du_second_facteur(st, user))?.freine_jusqu_a?;
    let maintenant = Instant::now();
    (maintenant < jusqu_a).then(|| (jusqu_a - maintenant).as_secs().max(1))
}

/// `P10.22-m` — un code présenté et REFUSÉ (faux, ou pas déjà consommé). Au seuil, le compte est freiné.
fn compter_un_echec_du_second_facteur(st: &AppState, user: &str) {
    if st.lock_threshold == 0 {
        return;
    }
    let maintenant = Instant::now();
    let mut g = echecs_du_second_facteur().lock();
    if g.len() > AUTH_FAIL_CAP {
        g.retain(|_, e| e.dernier.elapsed() < MEMOIRE_DES_ECHECS_DU_SECOND_FACTEUR);
    }
    let e = g
        .entry(cle_du_frein_du_second_facteur(st, user))
        .or_insert(EchecsDuSecondFacteur { consecutifs: 0, freine_jusqu_a: None, dernier: maintenant });
    if e.dernier.elapsed() > MEMOIRE_DES_ECHECS_DU_SECOND_FACTEUR {
        e.consecutifs = 0;
        e.freine_jusqu_a = None;
    }
    e.consecutifs = e.consecutifs.saturating_add(1);
    e.dernier = maintenant;
    if e.consecutifs >= st.lock_threshold {
        // même progression que le verrou par couple : base * 2^(échecs au-delà du seuil), plafonnée.
        let au_dela = (e.consecutifs - st.lock_threshold).min(20);
        let secondes = st.lock_base_s.saturating_mul(1u64 << au_dela).min(st.lock_max_s);
        e.freine_jusqu_a = Some(maintenant + Duration::from_secs(secondes));
    }
}

/// `P10.22-m` — un code juste ACCEPTÉ (session posée, MFA activée ou désactivée) remet le compte à zéro. Le
/// mot de passe, lui, ne le touche pas : c'est ce qui rendait la devinette illimitée.
fn remettre_le_second_facteur_a_zero(st: &AppState, user: &str) {
    if st.lock_threshold == 0 {
        return;
    }
    echecs_du_second_facteur().lock().remove(&cle_du_frein_du_second_facteur(st, user));
}

/// TÉMOINS SEULEMENT — les échecs consécutifs comptés au second facteur de ce compte : ce qui permet de
/// prouver qu'un refus NOMMÉ (503) ou un refus AVANT examen (409) ne compte rien.
#[cfg(test)]
pub(crate) fn echecs_consecutifs_du_second_facteur(st: &AppState, user: &str) -> u32 {
    echecs_du_second_facteur().lock().get(&cle_du_frein_du_second_facteur(st, user)).map_or(0, |e| e.consecutifs)
}

fn refus_du_frein_du_second_facteur(attente: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, attente.to_string())],
        Json(json!({ "error": CAUSE_SECOND_FACTEUR_FREINE })),
    )
        .into_response()
}

/// `P10.20-b` — CE COMPTE EXIGE-T-IL UN SECOND FACTEUR ? TROIS ISSUES, JAMAIS DEUX.
///
/// `Ok(true)` : MFA ACTIVE (`enabled` non nul). `Ok(false)` : AUCUNE ligne, ou une ligne à `enabled=0`
/// — une absence ÉTABLIE, le mode 0 par défaut. `Err(..)` : la lecture N'A PAS EU LIEU, et l'appelant
/// doit REFUSER au lieu de traiter ce compte comme un compte sans second facteur (c'était le défaut :
/// `unwrap_or(false)` rendait une panne de lecture indiscernable de « pas de MFA », et le mot de passe
/// seul posait la session). Mode 0 uniquement (table `user_mfa` dans st.db).
pub(crate) fn mfa_enabled_for(st: &AppState, user: &str) -> rusqlite::Result<bool> {
    let conn = st.db.lock();
    Ok(conn
        .query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![user], |r| r.get::<_, i64>(0))
        .optional()?
        .map(|v| v != 0)
        .unwrap_or(false))
}

pub(crate) async fn mfa_status(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let conn = st.db.lock();
    // `P10.20-b` — `.optional()` SÉPARE les deux : `Ok(None)` est l'absence ÉTABLIE (aucun enrôlement),
    // `Err` est la lecture NON FAITE. Servir la seconde en `{enrolled:false, enabled:false}` disait à la
    // console « ce compte n'a pas de double authentification » sur une panne de lecture.
    let row: rusqlite::Result<Option<i64>> =
        conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![au.name], |r| r.get(0)).optional();
    let Ok(row) = row else {
        return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_LUE);
    };
    Json(json!({ "enrolled": row.is_some(), "enabled": row.map(|v| v != 0).unwrap_or(false) })).into_response()
}

/// POST /api/mfa/enroll {password} — génère une graine TOTP (base32) + l'URI otpauth (show-once) ; enregistre en
/// `enabled=0` (en attente de vérification). Ne PEUT PAS écraser une MFA déjà active (409 : désactiver d'abord).
/// `P10.23-b` : exige le mot de passe du compte (voir `prouver_le_premier_facteur`).
pub(crate) async fn mfa_enroll(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Extension(au): Extension<AuthUser>,
    Json(b): Json<Value>,
) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    {
        let conn = st.db.lock();
        // `P10.20-b` — LA GARDE ANTI-ÉCRASEMENT NE SE SAUTE PAS SUR UNE LECTURE RATÉE. L'écriture qui
        // suit repose `secret=<neuf>, enabled=0` : la franchir sans avoir LU `enabled` désarme le second
        // facteur d'un compte qui en a un. Une lecture non faite refuse ; elle ne conclut pas à zéro.
        let en: rusqlite::Result<Option<i64>> =
            conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![au.name], |r| r.get(0)).optional();
        let Ok(en) = en else {
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_LUE);
        };
        if en == Some(1) {
            return err_json(StatusCode::CONFLICT, "MFA déjà active (désactivez-la d'abord)");
        }
    }
    // `P10.23-b` — LA PREUVE DU PREMIER FACTEUR, APRÈS le refus qui ne dépend pas d'elle (MFA déjà active : le mot
    // de passe n'y est ni examiné ni compté) et AVANT toute graine.
    let ip = peer.ip().to_string();
    match prouver_le_premier_facteur(&st, &au.name, &ip, b.str_field("password")) {
        PreuveDuPremierFacteur::Prouvee => {}
        PreuveDuPremierFacteur::Absente => return err_json(StatusCode::FORBIDDEN, CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER),
        PreuveDuPremierFacteur::Refusee => {
            ledger_append(&st.db.lock(), "mfa", &format!("enrôlement MFA refusé pour '{}' : mot de passe re-saisi refusé", au.name));
            return err_json(StatusCode::FORBIDDEN, CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT);
        }
        PreuveDuPremierFacteur::Verrouillee(attente) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, attente.to_string())],
                Json(json!({ "error": CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT })),
            )
                .into_response();
        }
        PreuveDuPremierFacteur::SansMotDePasseLocal => return err_json(StatusCode::FORBIDDEN, CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL),
        PreuveDuPremierFacteur::CompteNonLu(cause) => {
            eprintln!("[mfa] WARN compte '{}' NON lu à l'enrôlement : {cause}", au.name);
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT);
        }
    }
    let Some(seed) = rand_bytes(20) else {
        return server_err("entropie noyau indisponible");
    };
    let secret_b32 = base32_encode(&seed);
    {
        let conn = st.db.lock();
        // `P10.23-b` — L'ENRÔLEMENT NE DÉSARME JAMAIS UNE MFA ACTIVÉE ENTRE SA LECTURE ET SON ÉCRITURE. La garde
        // ci-dessus lit `enabled` sous un verrou, l'écriture le reposait à 0 sous un autre, et la preuve du mot de
        // passe (argon2) élargit la fenêtre entre les deux. Mesuré par un banc à trois connexions : une activation
        // validée pendant ce temps était ÉCRASÉE (graine neuve, `enabled=0`, 200) — le second facteur du compte
        // désarmé par un enrôlement. La clause `WHERE user_mfa.enabled=0` rejuge dans l'écriture, et le compte de
        // lignes tranche : zéro, c'est la MFA devenue active entre-temps -> 409, comme la garde.
        match conn.execute(
            // last_step=-1 : un ré-enrôlement repart d'une graine neuve -> compteur anti-rejeu réinitialisé.
            "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,0,'[]',-1,?3,?3) \
             ON CONFLICT(user) DO UPDATE SET secret=excluded.secret, enabled=0, recovery='[]', last_step=-1, updated=excluded.updated \
             WHERE user_mfa.enabled=0",
            params![au.name, secret_b32, now()],
        ) {
            Ok(1) => {}
            Ok(0) => return err_json(StatusCode::CONFLICT, "MFA déjà active (désactivez-la d'abord)"),
            Ok(_) | Err(_) => return server_err("enregistrement de l'enrôlement échoué"),
        }
    }
    let uri = totp_uri("Plume", &au.name, &secret_b32);
    Json(json!({ "secret": secret_b32, "otpauth_uri": uri })).into_response()
}

/// POST /api/mfa/verify {code} — vérifie le 1er code TOTP -> ACTIVE la MFA + renvoie les codes de secours
/// (show-once). Un code invalide -> 401 (l'enrôlement reste en attente). Fail-closed.
pub(crate) async fn mfa_verify(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let code = b.trimmed("code");
    let row: Option<(String, i64, i64)> = {
        let conn = st.db.lock();
        conn.query_row("SELECT secret,enabled,last_step FROM user_mfa WHERE user=?1", params![au.name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok()
    };
    let Some((secret, enabled, last_step)) = row.filter(|(s, _, _)| !s.is_empty()) else {
        return bad_req("aucun enrôlement en cours (appelez /api/mfa/enroll d'abord)");
    };
    // `P10.22-l` — L'ACTIVATION EST LA TRANSITION 0 -> 1, ET ELLE SE REFUSE AVANT D'EXAMINER LE CODE. Mesuré le
    // 2026-09-23 : sur une MFA DÉJÀ ACTIVE, un code frais rendait 200, remplaçait la liste des codes de secours
    // du titulaire par dix codes neufs SERVIS EN CLAIR à l'appelant, et reposait « activée » au registre ; un
    // code faux rendait 401 — un oracle sans aucun frein. Une session volée pouvait donc deviner le TOTP par
    // cette route et repartir avec dix codes de secours. Le refus vient AVANT l'examen du code : juste ou faux,
    // la réponse est la même.
    if enabled != 0 {
        return err_json(StatusCode::CONFLICT, "MFA déjà active (désactivez-la d'abord)");
    }
    if let Some(attente) = second_facteur_freine(&st, &au.name) {
        return refus_du_frein_du_second_facteur(attente);
    }
    // ANTI-REJEU : le pas TOTP matché doit être STRICTEMENT postérieur au dernier pas consommé (last_step=-1
    // à l'enrôlement -> tout pas réel passe ; un code déjà utilisé serait <= last_step -> refusé).
    let Some(step) = totp_verify_step(&secret, &code, now(), 30, 6, 1) else {
        compter_un_echec_du_second_facteur(&st, &au.name);
        return err_json(StatusCode::UNAUTHORIZED, "code TOTP invalide");
    };
    if step <= last_step {
        compter_un_echec_du_second_facteur(&st, &au.name);
        return err_json(StatusCode::UNAUTHORIZED, "code TOTP déjà utilisé (anti-rejeu)");
    }
    let Some((clear, hashes)) = gen_recovery_codes(10) else {
        return server_err("entropie noyau indisponible");
    };
    {
        let conn = st.db.lock();
        // `P10.22-l` — L'ACTIVATION EST UN COMPARE-ET-POSE SUR L'ENRÔLEMENT QUI A ÉTÉ LU. La lecture et
        // l'écriture sont sous deux verrous distincts ; l'écriture ne rejugeait rien (`WHERE user=?`). Mesuré
        // sur deux connexions : deux activations simultanées du même code -> deux 200, deux jeux de codes de
        // secours servis, UN SEUL enregistré, « activée » deux fois au registre ; et une graine RÉENRÔLÉE
        // entre la lecture et l'écriture était activée — une graine que le code présenté n'a jamais prouvée.
        //
        // LES DEUX CLAUSES QUI FERMENT LA COURSE, ET CELLE DE L'ÉNONCÉ QUI NE LA FERMAIT PAS. `enabled=0` :
        // une seule requête franchit la transition. `secret=?5` : ce qui s'active est la graine que le code a
        // prouvée. La clause que l'énoncé prescrivait, `last_step < ?`, ne ferme PAS le réenrôlement (il remet
        // `last_step` à -1 : mutation jouée, le témoin du réenrôlement rougit sous elle seule) et ne ferme la
        // double activation que si les deux présentent le MÊME pas — aux pas p puis p+1, la seconde passe
        // (raisonné, non joué ; le témoin joue le même code, où `last_step` et `enabled=0` suffisent chacun).
        match conn.execute(
            "UPDATE user_mfa SET enabled=1, recovery=?1, last_step=?2, updated=?3 WHERE user=?4 AND enabled=0 AND secret=?5",
            params![json!(hashes).to_string(), step, now(), au.name, secret],
        ) {
            Ok(1) => {}
            // L'enrôlement lu n'est plus là tel quel : une autre requête a gagné. Rien n'est activé ICI.
            Ok(0) => return err_json(StatusCode::CONFLICT, CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION),
            Ok(n) => {
                eprintln!("[mfa] WARN activation de '{}' : {n} ligne(s) écrite(s) au lieu d'une", au.name);
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_ACTIVEE);
            }
            Err(e) => {
                eprintln!("[mfa] WARN activation de '{}' NON écrite : {e}", au.name);
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_ACTIVEE);
            }
        }
        ledger_append(&conn, "mfa", &format!("MFA TOTP activée pour '{}'", au.name));
    }
    remettre_le_second_facteur_a_zero(&st, &au.name);
    // SHOW-ONCE : les codes de secours CLAIRS ne sont renvoyés QU'ICI (seuls leurs SHA-256 sont persistés).
    Json(json!({ "ok": true, "recovery_codes": clear })).into_response()
}

/// POST /api/mfa/disable {code} — désactive la MFA de l'appelant. Exige un code TOTP (ou de secours) VALIDE
/// -> une session détournée sans le 2e facteur ne peut pas retirer la MFA. Fail-closed.
pub(crate) async fn mfa_disable(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if st.multi_tenant {
        return deny_multitenant();
    }
    let code = b.trimmed("code");
    let conn = st.db.lock();
    // `P10.22-k` — LE FACTEUR EST JUGÉ, CONSOMMÉ ET LA LIGNE SUPPRIMÉE DANS UNE SEULE TRANSACTION. Un refus de la
    // suppression annule la consommation : le code n'est pas brûlé (même contrat que la connexion, `P10.21-s`).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_DESACTIVEE);
    }
    // Lue sous le MÊME verrou et dans la MÊME transaction que la consommation et la suppression. Son repli
    // (`.ok()` -> 404) est le rang quatre de `P10.20-b`, laissé tel quel ici (voir l'en-tête du module).
    let row: Option<(String, i64, String)> = conn
        .query_row("SELECT secret,enabled,recovery FROM user_mfa WHERE user=?1", params![au.name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok();
    match desactiver_le_second_facteur(&st, &conn, &au.name, &code, row) {
        Ok(()) => {
            if let Err(e) = conn.execute_batch("COMMIT") {
                let _ = conn.execute_batch("ROLLBACK");
                eprintln!("[mfa] WARN désactivation de '{}' NON validée : {e}", au.name);
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_DESACTIVEE);
            }
            ledger_append(&conn, "mfa", &format!("MFA TOTP désactivée pour '{}'", au.name));
            drop(conn);
            remettre_le_second_facteur_a_zero(&st, &au.name);
            Json(json!({ "ok": true })).into_response()
        }
        Err(refus) => {
            let _ = conn.execute_batch("ROLLBACK");
            drop(conn);
            match refus {
                RefusDeLaDesactivation::Absente => not_found("aucune MFA enrôlée"),
                RefusDeLaDesactivation::Freinee(attente) => refus_du_frein_du_second_facteur(attente),
                RefusDeLaDesactivation::CodeRefuse => {
                    compter_un_echec_du_second_facteur(&st, &au.name);
                    err_json(StatusCode::UNAUTHORIZED, "code MFA requis pour désactiver")
                }
                RefusDeLaDesactivation::CodesDeSecoursIllisibles(cause) => {
                    eprintln!("[mfa] WARN codes de secours de '{}' NON lus : {cause}", au.name);
                    err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CODES_DE_SECOURS_ILLISIBLES)
                }
                RefusDeLaDesactivation::NonEcrite(cause) => {
                    eprintln!("[mfa] WARN désactivation de '{}' NON écrite : {cause}", au.name);
                    err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MFA_NON_DESACTIVEE)
                }
            }
        }
    }
}

/// `P10.22-k` — POURQUOI UNE DÉSACTIVATION N'A PAS LIEU. `Ok(())` de `desactiver_le_second_facteur` : le facteur
/// est juste ET consommé, la ligne est supprimée, dans la transaction encore ouverte ; tout le reste est ici,
/// et la transaction est alors ANNULÉE.
enum RefusDeLaDesactivation {
    /// Aucune ligne `user_mfa` (lue absente, ou disparue avant la suppression) : `404`, rien d'attesté.
    Absente,
    /// Le compte est freiné (`P10.22-m`) : le code n'est pas examiné.
    Freinee(u64),
    /// Le code est faux, ou c'est un pas DÉJÀ consommé (à la connexion, ou par une requête concurrente).
    CodeRefuse,
    /// `P10.22-r` — la liste des codes de secours n'a pas été lue : ni accepté, ni refusé.
    CodesDeSecoursIllisibles(String),
    /// La base n'a pas pris une écriture (consommation du pas ou suppression).
    NonEcrite(String),
}

/// `P10.22-k` — UN PAS DÉJÀ CONSOMMÉ NE DÉSACTIVE PAS LE SECOND FACTEUR. Mesuré le 2026-09-23 : connexion avec le
/// pas p, puis désactivation avec le MÊME code -> 200, MFA supprimée. La route jugeait le code par un booléen
/// sans pas (`totp_verify`), sous une justification fausse (voir `idp/totp.rs`).
///
/// POURQUOI LA DÉSACTIVATION CONSOMME LE PAS, ET NE SE CONTENTE PAS DE LE COMPARER À `last_step`. Comparer
/// suffirait en séquence ; en concurrence, non : la connexion qui consomme ce même pas et la désactivation
/// peuvent se croiser entre la lecture de `last_step` et le `DELETE`. `consommer_le_pas_totp` rejuge la
/// fraîcheur DANS l'écriture (`enabled=1 AND last_step<?`) : c'est la même définition de « frais » que celle de
/// la connexion, écrite une seule fois, et le compte de lignes tranche. La consommation vit dans la même
/// transaction que le `DELETE` : validée, la ligne n'existe plus (la consommation n'a laissé aucune trace à
/// part la suppression) ; annulée, le code n'est pas brûlé. La ligne `row` est lue par `mfa_disable` sous le
/// même verrou et dans la même transaction, donc un code de secours retiré par une connexion concurrente n'est
/// plus dans la liste lue.
fn desactiver_le_second_facteur(
    st: &AppState,
    conn: &Connection,
    user: &str,
    code: &str,
    row: Option<(String, i64, String)>,
) -> Result<(), RefusDeLaDesactivation> {
    let Some((secret, enabled, recovery)) = row else {
        return Err(RefusDeLaDesactivation::Absente);
    };
    if enabled == 1 {
        // exige un facteur valide ET FRAIS pour désactiver (TOTP non consommé, ou code de secours).
        if let Some(attente) = second_facteur_freine(st, user) {
            return Err(RefusDeLaDesactivation::Freinee(attente));
        }
        if a_la_forme_d_un_code_totp(code) {
            let Some(step) = totp_verify_step(&secret, code, now(), 30, 6, 1) else {
                return Err(RefusDeLaDesactivation::CodeRefuse);
            };
            match consommer_le_pas_totp(conn, user, step) {
                ConsommationDuFacteur::Consomme => {}
                ConsommationDuFacteur::Refuse => return Err(RefusDeLaDesactivation::CodeRefuse),
                ConsommationDuFacteur::NonEcrite(cause) | ConsommationDuFacteur::Illisible(cause) => {
                    return Err(RefusDeLaDesactivation::NonEcrite(cause))
                }
            }
        } else if code.is_empty() {
            return Err(RefusDeLaDesactivation::CodeRefuse);
        } else {
            match recovery_contains(&recovery, code) {
                Ok(true) => {}
                Ok(false) => return Err(RefusDeLaDesactivation::CodeRefuse),
                Err(cause) => return Err(RefusDeLaDesactivation::CodesDeSecoursIllisibles(cause)),
            }
        }
    }
    // `P10.21-s` — LE `DELETE` EST COMPTÉ AVANT LE REGISTRE. Avalé, il laissait la route rendre `ok` et le
    // registre attester « désactivée » pendant que le compte exigeait TOUJOURS son second facteur. Zéro ligne :
    // la ligne lue a disparu entre-temps — l'absence d'avant, `404`, sans rien attester.
    match conn.execute("DELETE FROM user_mfa WHERE user=?1", params![user]) {
        Ok(0) => Err(RefusDeLaDesactivation::Absente),
        Ok(_) => Ok(()),
        Err(e) => Err(RefusDeLaDesactivation::NonEcrite(e.to_string())),
    }
}

/// `P10.21-s` — CE QUE LA CONSOMMATION D'UN FACTEUR À USAGE UNIQUE REND (pas TOTP, code de secours). Un
/// booléen confondait « rien à consommer » et « la base n'a pas pris l'écriture » : `recovery_consume` rendait
/// `true` sur un `UPDATE` avalé, et le pas TOTP n'avait même pas de retour. Trois issues, jamais deux — et une
/// quatrième depuis `P10.22-r` : la liste des facteurs qu'on n'a pas pu LIRE.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConsommationDuFacteur {
    /// L'écriture a eu lieu, sur UNE ligne : ce facteur ne servira plus.
    Consomme,
    /// Rien à consommer : le code ne désigne aucun facteur encore valable (déjà consommé — y compris ENTRE la
    /// lecture et l'écriture, par une requête concurrente —, jamais émis, ou MFA plus active). Refus
    /// d'AUTHENTIFICATION, comme un code faux.
    Refuse,
    /// La base n'a pas pris l'écriture : le facteur est juste et RESTE utilisable. Refus NOMMÉ, jamais une
    /// session. La cause du moteur est portée pour la sortie d'erreur, jamais servie à l'appelant public.
    NonEcrite(String),
    /// `P10.22-r` — La liste des facteurs n'a pas été LUE (lecture refusée, contenu corrompu) : on ne sait PAS
    /// si le code est juste. Refus NOMMÉ, jamais une accusation, jamais un échec compté. Seul
    /// `recovery_consume` le rend ; le compare-et-pose du pas TOTP ne lit rien.
    Illisible(String),
}

/// `P10.21-s` — LA CONSOMMATION DU PAS TOTP EST UN COMPARE-ET-POSE EN BASE. La fraîcheur (`step >
/// last_step`) était jugée sur une lecture faite sous un AUTRE verrou que l'écriture : deux soumissions
/// concurrentes du même code passaient toutes deux la lecture, et l'écriture ne rejugeait rien. La clause
/// `last_step < ?1` rejuge la fraîcheur DANS l'écriture, et le compte de lignes tranche.
pub(crate) fn consommer_le_pas_totp(conn: &Connection, user: &str, step: i64) -> ConsommationDuFacteur {
    match conn.execute(
        "UPDATE user_mfa SET last_step=?1, updated=?2 WHERE user=?3 AND enabled=1 AND last_step<?1",
        params![step, now(), user],
    ) {
        Ok(1) => ConsommationDuFacteur::Consomme,
        Ok(0) => ConsommationDuFacteur::Refuse,
        Ok(n) => ConsommationDuFacteur::NonEcrite(format!("{n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => ConsommationDuFacteur::NonEcrite(e.to_string()),
    }
}

/// `P10.22-r` — LA LISTE DES CODES DE SECOURS EST LUE OU AVOUÉE ILLISIBLE, JAMAIS VIDE PAR DÉFAUT. Le
/// `unwrap_or_default()`/`unwrap_or(false)` d'avant faisait d'un contenu corrompu une liste VIDE, donc de tout
/// code de secours un code « invalide » (401), et comptait l'échec à l'utilisateur.
fn lire_les_codes_de_secours(recovery_json: &str) -> Result<Vec<String>, String> {
    serde_json::from_str::<Vec<String>>(recovery_json).map_err(|e| format!("liste des codes de secours corrompue : {e}"))
}

/// Un code de secours (clair) figure-t-il dans la liste des SHA-256 persistés ? (comparaison des hash.)
/// `Err` : la liste n'a pas été lue — ni oui, ni non (`P10.22-r`).
fn recovery_contains(recovery_json: &str, code: &str) -> Result<bool, String> {
    let want = sha256_hex(code.as_bytes());
    Ok(lire_les_codes_de_secours(recovery_json)?.iter().any(|h| ct_eq(h.as_bytes(), want.as_bytes())))
}

/// `P10.22-r` — UN CODE À LA FORME D'UN CODE TOTP N'EST JUGÉ QUE COMME UN CODE TOTP. Les codes de secours ont
/// la forme `xxxx-xxxxxx` — dix chiffres hexadécimaux, un tiret après le quatrième (`gen_recovery_codes`, dont
/// le commentaire dit « `xxxx-xxxx` », à tort) : six chiffres n'en sont jamais un, la liste n'a donc rien à
/// dire sur eux. SANS CETTE RÈGLE, LE `503` DE `P10.22-r` OUVRAIT UNE VOIE : tant que la liste est illisible,
/// chaque code TOTP faux, repassé par la liste, rendait `503` — refus qui ne compte AUCUN échec —, et le frein
/// de `P10.22-m` ne voyait plus rien passer. Six chiffres faux restent un `401` compté, liste lisible ou non.
fn a_la_forme_d_un_code_totp(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

/// Consomme (usage unique) un code de secours : le retire de la liste persistée s'il matche.
///
/// `P10.21-s` — CONSOMMÉ SEULEMENT SI L'ÉCRITURE A EU LIEU. L'`UPDATE` était avalé et la fonction rendait
/// `true` : un code de secours accepté pouvait rester dans la liste et ouvrir une autre session. La lecture et
/// l'écriture sont sous le MÊME verrou (`st.db`), donc aucune requête ne s'intercale : le compte suffit.
fn recovery_consume(st: &AppState, user: &str, code: &str) -> ConsommationDuFacteur {
    let want = sha256_hex(code.as_bytes());
    let conn = st.db.lock();
    // `P10.22-r` — TROIS ISSUES DE LECTURE, JAMAIS DEUX. Aucune ligne : la MFA a disparu (désactivation
    // concurrente), une absence ÉTABLIE -> refus d'authentification. Lecture ratée ou contenu corrompu : on ne
    // sait pas -> `Illisible`, refus NOMMÉ. Les deux rendaient `Refuse`, donc « code MFA invalide ».
    let rec: String = match conn.query_row("SELECT recovery FROM user_mfa WHERE user=?1", params![user], |r| r.get(0)).optional() {
        Ok(Some(rec)) => rec,
        Ok(None) => return ConsommationDuFacteur::Refuse,
        Err(e) => return ConsommationDuFacteur::Illisible(e.to_string()),
    };
    let mut list: Vec<String> = match lire_les_codes_de_secours(&rec) {
        Ok(list) => list,
        Err(cause) => return ConsommationDuFacteur::Illisible(cause),
    };
    let before = list.len();
    list.retain(|h| !ct_eq(h.as_bytes(), want.as_bytes()));
    if list.len() == before {
        return ConsommationDuFacteur::Refuse; // aucun code ne correspond
    }
    match conn.execute("UPDATE user_mfa SET recovery=?1, updated=?2 WHERE user=?3", params![json!(list).to_string(), now(), user]) {
        Ok(1) => ConsommationDuFacteur::Consomme,
        Ok(0) => ConsommationDuFacteur::Refuse,
        Ok(n) => ConsommationDuFacteur::NonEcrite(format!("{n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => ConsommationDuFacteur::NonEcrite(e.to_string()),
    }
}

/// POST /api/login/mfa {ticket, code} — 2e facteur du login local : consomme le ticket signé émis par
/// `login_post`, vérifie le TOTP (ou un code de secours à usage unique), pose la session. PUBLIC. Fail-closed.
pub(crate) async fn login_mfa_post(State(st): State<AppState>, ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>, Json(b): Json<Value>) -> Response {
    let ticket = b.trimmed("ticket");
    let code = b.trimmed("code");
    let ip = peer.ip().to_string();
    // `P10.22-x` — jugé à l'époque de session COURANTE : un ticket émis avant une révocation est refusé ici, avant
    // tout examen du code et sans rien compter (le porteur recommence par le mot de passe).
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::SeqCst);
    let Some((user, role, epoque_du_ticket)) = mfa_ticket_verify(st.session_secret.as_slice(), &ticket, epoch) else {
        return err_json(StatusCode::UNAUTHORIZED, CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE);
    };
    // `P10.23-l` — et à l'époque COURANTE de SON compte (réinitialisation par un administrateur, changement du mot de
    // passe administrateur) : même refus, même place, rien consommé ni compté. Une époque NON RELUE refuse sous la
    // même phrase (qui le dit) plutôt qu'en cinq cent trois : le porteur recommence par le mot de passe, et c'est
    // cette étape-là, qui la relit pour frapper un ticket neuf, qui nomme la lecture ratée (`mfa_challenge_response`).
    match epoque_du_compte(&st.db.lock(), &user) {
        Ok(epoque) if epoque == epoque_du_ticket => {}
        Ok(_) => return err_json(StatusCode::UNAUTHORIZED, CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE),
        Err(cause) => {
            eprintln!("[mfa] WARN époque du compte '{user}' NON lue, ticket refusé sans examen du code : {cause}");
            return err_json(StatusCode::UNAUTHORIZED, CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE);
        }
    }
    if let Some(retry) = auth_lock_check(&st, &user, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())], Json(json!({ "error": "trop d'échecs — réessayez plus tard" }))).into_response();
    }
    // `P10.22-m` — LE FREIN DU COMPTE, AVANT TOUT EXAMEN DU CODE : un code juste présenté pendant le frein est
    // refusé comme un faux, sinon le frein ne retiendrait que les mauvaises réponses.
    if let Some(attente) = second_facteur_freine(&st, &user) {
        return refus_du_frein_du_second_facteur(attente);
    }
    // Rôle re-résolu LIVE (le ticket n'est qu'un plancher : un changement de rôle entre les 2 facteurs est pris en compte).
    let live_role = live_role_for(&st, &user).unwrap_or(role);
    let row: Option<(String, i64)> = {
        let conn = st.db.lock();
        conn.query_row("SELECT secret,last_step FROM user_mfa WHERE user=?1 AND enabled=1", params![user], |r| Ok((r.get(0)?, r.get(1)?))).ok()
    };
    let Some((secret, last_step)) = row else {
        return err_json(StatusCode::UNAUTHORIZED, "aucune MFA active pour ce compte");
    };
    // ANTI-REJEU TOTP : un pas matché est « frais » seulement s'il est > last_step (un code capté et rejoué
    // dans sa fenêtre de ~90 s a un pas <= last_step -> refusé). Un code à la forme TOTP n'est JAMAIS traité
    // comme un code de secours -> pas de repli recovery sur un TOTP rejoué ni sur un TOTP faux.
    let matched = totp_verify_step(&secret, &code, now(), 30, 6, 1);
    let totp_fresh = matched.map_or(false, |s| s > last_step);
    // `P10.21-s` — UN FACTEUR N'EST ACCEPTÉ QUE CONSOMMÉ, ET SA CONSOMMATION REFUSÉE EST UN REFUS NOMMÉ AVANT
    // TOUTE SESSION ET TOUTE TRACE. Les deux écritures (code de secours retiré, pas TOTP posé) étaient avalées :
    // la session et « login MFA validé » suivaient, et le facteur restait rejouable (mesuré : le même code
    // ouvrait une seconde session une fois la base revenue).
    // `P10.22-r` — seul un code qui N'A PAS la forme d'un code TOTP est cherché dans la liste de secours (voir
    // `a_la_forme_d_un_code_totp`) : un code TOTP faux reste un échec COMPTÉ même quand la liste est illisible.
    let secours = if !code.is_empty() && !a_la_forme_d_un_code_totp(&code) {
        recovery_consume(&st, &user, &code)
    } else {
        ConsommationDuFacteur::Refuse
    };
    match &secours {
        ConsommationDuFacteur::NonEcrite(cause) => {
            eprintln!("[mfa] WARN code de secours de '{user}' NON consommé : {cause}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CODE_DE_SECOURS_NON_CONSOMME);
        }
        // `P10.22-r` — la liste n'a pas été lue : ni acceptation ni accusation, et AUCUN échec compté.
        ConsommationDuFacteur::Illisible(cause) => {
            eprintln!("[mfa] WARN codes de secours de '{user}' NON lus : {cause}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CODES_DE_SECOURS_ILLISIBLES);
        }
        ConsommationDuFacteur::Consomme | ConsommationDuFacteur::Refuse => {}
    }
    let rec_ok = secours == ConsommationDuFacteur::Consomme;
    if !totp_fresh && !rec_ok {
        let _ = auth_record_failure(&st, &user, &ip);
        compter_un_echec_du_second_facteur(&st, &user);
        return err_json(StatusCode::UNAUTHORIZED, "code MFA invalide");
    }
    if let Some(step) = matched.filter(|_| totp_fresh) {
        // consomme le pas TOTP (anti-rejeu) AVANT de poser la session — compté, et rejugé en base.
        let consommation = consommer_le_pas_totp(&st.db.lock(), &user, step);
        match consommation {
            ConsommationDuFacteur::Consomme => {}
            // un autre a consommé ce pas entre la lecture et l'écriture : c'est un REJEU, refusé comme le rejeu
            // séquentiel (même statut, même phrase, même échec compté).
            ConsommationDuFacteur::Refuse => {
                let _ = auth_record_failure(&st, &user, &ip);
                compter_un_echec_du_second_facteur(&st, &user);
                return err_json(StatusCode::UNAUTHORIZED, "code MFA invalide");
            }
            ConsommationDuFacteur::NonEcrite(cause) | ConsommationDuFacteur::Illisible(cause) => {
                eprintln!("[mfa] WARN pas TOTP de '{user}' NON consommé : {cause}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PAS_TOTP_NON_CONSOMME);
            }
        }
    }
    auth_record_success(&st, &user, &ip);
    remettre_le_second_facteur_a_zero(&st, &user);
    {
        let conn = st.db.lock();
        ledger_append(&conn, "login", &format!("login local MFA validé pour '{user}'{}", if rec_ok { " (code de secours)" } else { "" }));
    }
    // `P10.23-l` — la session est frappée à l'époque de compte que le ticket vient de prouver : une révocation de ce
    // compte survenue depuis la rend caduque dès la requête suivante.
    let jeton = mint_session_du_compte(
        st.session_secret.as_slice(),
        &user,
        &live_role,
        st.session_ttl_s,
        st.session_epoch.load(std::sync::atomic::Ordering::Relaxed),
        epoque_du_ticket,
    );
    let mut resp = Json(json!({ "ok": true, "user": user, "role": live_role })).into_response();
    attach_session_cookies(&st, &mut resp, &jeton);
    resp
}

/// Émet un ticket MFA (2e facteur en attente) — appelé par `login_post` (session.rs) quand le 1er facteur
/// réussit et que le compte a une MFA active. TTL court (5 min), signé à l'époque de session courante (`P10.22-x`)
/// et à l'époque COURANTE du compte (`P10.23-l`) ; celle-ci non lue -> 503 nommé, aucun ticket.
pub(crate) fn mfa_challenge_response(st: &AppState, user: &str, role: &str) -> Response {
    let epoch = st.session_epoch.load(std::sync::atomic::Ordering::SeqCst);
    let epoque_du_compte = match epoque_du_compte(&st.db.lock(), user) {
        Ok(epoque) => epoque,
        Err(cause) => {
            eprintln!("[mfa] WARN époque du compte '{user}' NON lue, aucun ticket émis : {cause}");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_EPOQUE_DU_COMPTE_NON_LUE);
        }
    };
    let ticket = mfa_ticket_sign(st.session_secret.as_slice(), user, role, 300, epoch, epoque_du_compte);
    Json(json!({ "mfa_required": true, "ticket": ticket })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_ticket_roundtrip_and_tamper() {
        let s = b"ticket-secret";
        let t = mfa_ticket_sign(s, "bob", "editor", 300, 0, 0);
        assert_eq!(mfa_ticket_verify(s, &t, 0), Some(("bob".into(), "editor".into(), 0)));
        assert!(mfa_ticket_verify(b"autre", &t, 0).is_none());
        // `P10.22-x` — une époque révolue (sessions révoquées depuis l'émission) refuse le ticket.
        assert!(mfa_ticket_verify(s, &t, 1).is_none());
        // ticket déjà expiré forgé à la main (sign clampe le TTL >= 1s) -> rejeté.
        let past = now() - 100;
        let payload = format!("mfa|bob|editor|{past}");
        let p_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let expired = format!("{p_b64}.{}", hex_encode(&hmac_sha256(s, format!("mfa-ticket|0|{p_b64}").as_bytes())));
        assert!(mfa_ticket_verify(s, &expired, 0).is_none());
        // un ticket de session (préfixe différent) ne doit pas passer pour un ticket MFA.
        let sess = mint_session(s, "bob", "editor", 300, 0);
        assert!(mfa_ticket_verify(s, &sess, 0).is_none());
        // `P10.22-x` — et l'inverse : un ticket ne passe pas pour une session, à la même époque.
        assert!(verify_session(s, &t, 0).is_none());
        // `P10.23-l` — l'époque du compte est signée et portée : rendue telle quelle, et un porteur qui la réécrit
        // (pour l'aligner sur l'époque courante du compte) casse la signature.
        let t3 = mfa_ticket_sign(s, "bob", "editor", 300, 0, 3);
        assert!(t3.ends_with(".3"), "le ticket porte l'époque de son compte : {t3}");
        assert_eq!(mfa_ticket_verify(s, &t3, 0), Some(("bob".into(), "editor".into(), 3)));
        let reecrit = format!("{}.4", t3.trim_end_matches(".3"));
        assert!(mfa_ticket_verify(s, &reecrit, 0).is_none(), "époque du compte réécrite -> refusé");
        assert!(mfa_ticket_verify(s, t3.trim_end_matches(".3"), 0).is_none(), "époque du compte retirée -> refusé");
        assert!(verify_session(s, &t3, 0).is_none(), "un ticket d'époque de compte non nulle n'est pas une session");
        let sess3 = mint_session_du_compte(s, "bob", "editor", 300, 0, 3);
        assert!(mfa_ticket_verify(s, &sess3, 0).is_none(), "ni l'inverse");
    }

    #[test]
    fn recovery_contains_matches_hash_only() {
        let (clear, hashes) = gen_recovery_codes(3).unwrap();
        let rec = json!(hashes).to_string();
        assert_eq!(recovery_contains(&rec, &clear[0]), Ok(true));
        assert_eq!(recovery_contains(&rec, "0000-0000"), Ok(false));
        // la liste persistée ne contient QUE des hash (jamais le clair).
        assert!(!rec.contains(&clear[0]));
        // `P10.22-r` — une liste illisible n'est ni un oui ni un non.
        assert!(recovery_contains("{pas une liste", &clear[0]).is_err());
    }

    #[test]
    fn idp_name_validation() {
        assert!(idp_name_ok("google"));
        assert!(idp_name_ok("azure-ad.corp_1"));
        assert!(!idp_name_ok(""));
        assert!(!idp_name_ok("bad/slash"));
        assert!(!idp_name_ok("space bar"));
    }
}
