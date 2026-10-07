//! `P10.24-m` — LE SECRET DES GESTES : UNE PREUVE QU'UNE SESSION SEULE NE PORTE PAS, EXIGÉE AVANT LES GESTES QUI
//! POSENT UN ACCÈS PERSISTANT.
//!
//! LE DÉFAUT, MESURÉ LE 2026-09-24 EN FERMANT `P10.24-a`. Une session administrateur volée crée l'administrateur `x`
//! (200, tracé en sévérité quatre), puis `x` réinitialise `adm` : la prise survit à la révocation de la session volée.
//! Exiger le mot de passe de l'auteur ne tenait pas : les administrateurs servis par le SSO d'en-têtes n'en ont pas.
//!
//! LA DÉCISION DE L'EXPLOITANT (2026-09-29) : il faut le DROIT et un SECRET DÉDIÉ, même pour un administrateur, quel
//! que soit le mode d'authentification (session locale, SSO d'en-têtes, fédération, Basic). Le secret voyage dans
//! l'en-tête `x-plume-secret-des-gestes` ; le démon n'en connaît que l'EMPREINTE (argon2id au format PHC, la même
//! famille que les mots de passe des comptes), lue dans le fichier `PLUME_GESTURE_SECRET_FILE` — un secret Docker ou
//! Kubernetes monté en fichier, ou un fichier `0640` sur un hôte. Jamais le secret en clair, ni en base ni en env.
//!
//! SANS FICHIER, AUCUN GESTE : un refus NOMMÉ qui dit comment poser le secret, jamais un repli permissif. Un
//! déploiement qui n'a pas posé le secret perd donc ces gestes — c'est voulu.
//!
//! LE FICHIER EST RELU À CHAQUE GESTE, ET NON AU DÉMARRAGE. Les gestes gardés sont rares (quelques-uns par jour au
//! plus), la lecture d'un petit fichier ne coûte rien à côté de la vérification argon2 qui suit, et la rotation
//! devient un simple remplacement du fichier : aucun mode n'a de geste de rechargement (`docs/TROIS-MODES.md` §3.2), et
//! un secret Kubernetes monté se met à jour sous le pod sans le redémarrer. Un fichier retiré ou rendu illisible
//! referme les gestes au geste suivant, sans attendre un redémarrage.
//!
//! LE FREIN : un secret FAUX est compté par `auth_record_failure` — le compteur des échecs de connexion, même backoff,
//! même événement d'accès pour le SIEM, 429 au-delà du seuil —, sur le couple (auteur, adresse) ; il s'inscrit au
//! registre avec l'auteur, jamais le secret. Un en-tête ABSENT n'est pas un essai : rien n'est examiné ni compté.
use crate::*;

/// L'en-tête qui porte le secret (contrat fixé avec la console).
pub(crate) const ENTETE_DU_SECRET_DES_GESTES: &str = "x-plume-secret-des-gestes";

/// La variable qui nomme le fichier de l'empreinte.
pub(crate) const VARIABLE_DU_FICHIER_DU_SECRET_DES_GESTES: &str = "PLUME_GESTURE_SECRET_FILE";

/// Les trois causes servies sous `cause` (contrat fixé avec la console).
pub(crate) const CAUSE_SECRET_DES_GESTES_ABSENT: &str = "secret_des_gestes_absent";
pub(crate) const CAUSE_SECRET_DES_GESTES_FAUX: &str = "secret_des_gestes_faux";
pub(crate) const CAUSE_SECRET_DES_GESTES_NON_CONFIGURE: &str = "secret_des_gestes_non_configure";

/// Le préfixe exigé d'une empreinte : argon2id, et rien d'autre (ni bcrypt, ni argon2i/argon2d).
const PREFIXE_D_EMPREINTE_ARGON2ID: &str = "$argon2id$";

/// Longueur minimale d'un secret fourni à la sous-commande (un secret engendré en fait 64).
pub(crate) const LONGUEUR_MINIMALE_DU_SECRET_DES_GESTES: usize = 16;

pub(crate) const TEXTE_SECRET_DES_GESTES_NON_CONFIGURE: &str = "GESTE REFUSÉ, LE SECRET DES GESTES N'EST PAS \
     CONFIGURÉ : créer ou promouvoir un administrateur, réinitialiser le mot de passe d'un autre compte, frapper un \
     jeton ou une clé de livraison, poser un fournisseur d'identité ou un droit, ouvrir un engagement exigent, en plus du \
     droit, un secret dédié que ce démon ne connaît pas encore. Pour le poser : engendrez son empreinte avec `plume-daemon \
     secret-des-gestes --generer > <fichier>` (le secret s'affiche une seule fois sur la sortie d'erreur), rendez ce \
     fichier lisible par le démon seul, puis pointez-le par `PLUME_GESTURE_SECRET_FILE` et redémarrez (hôte, Docker : \
     secret monté en fichier ; k3s : Secret monté en fichier) — voir docs/TROIS-MODES.md §3.11. Rien n'est écrit.";

pub(crate) const TEXTE_SECRET_DES_GESTES_ABSENT: &str = "SECRET DES GESTES EXIGÉ : ce geste pose un accès qui \
     survit à la session (compte administrateur, mot de passe d'un autre compte, jeton, fournisseur d'identité, droit, \
     engagement), et une session seule ne prouve pas qu'elle est tenue par qui a le droit de le poser. Présentez le secret des \
     gestes dans l'en-tête `x-plume-secret-des-gestes`. Rien n'est écrit, aucun échec n'est compté.";

pub(crate) const TEXTE_SECRET_DES_GESTES_FAUX: &str = "SECRET DES GESTES REFUSÉ : le secret présenté n'est pas \
     celui que ce démon attend. L'échec est compté au même frein que les échecs de connexion (429 au-delà du seuil) \
     et inscrit au registre sous votre nom ; rien n'est écrit.";

pub(crate) const TEXTE_SECRET_DES_GESTES_VERROUILLE: &str = "TROP D'ÉCHECS DU SECRET DES GESTES DEPUIS CETTE \
     ADRESSE POUR CE COMPTE : le frein est celui de la connexion (en-tête Retry-After) ; le secret n'est pas examiné \
     et rien n'est écrit.";

/// D'où le démon lit l'empreinte. Fixé au démarrage par `PLUME_GESTURE_SECRET_FILE` ; le FICHIER, lui, est relu à
/// chaque geste (voir l'en-tête du module).
#[derive(Debug, Clone)]
pub(crate) enum SourceDuSecretDesGestes {
    /// Aucun fichier nommé : tous les gestes gardés sont refusés, cause `secret_des_gestes_non_configure`.
    NonConfiguree,
    /// Le chemin du fichier qui porte l'empreinte.
    Fichier(String),
    /// TÉMOINS SEULEMENT — une empreinte tenue en mémoire (l'état de test n'écrit aucun fichier).
    #[cfg(test)]
    Empreinte(String),
}

impl SourceDuSecretDesGestes {
    /// La source nommée par la configuration : un chemin vide (ou blanc) vaut « non configuré ».
    pub(crate) fn depuis_la_configuration(chemin: &str) -> Self {
        let chemin = chemin.trim();
        if chemin.is_empty() {
            Self::NonConfiguree
        } else {
            Self::Fichier(chemin.to_string())
        }
    }

    /// L'empreinte à l'instant du geste, ou la RAISON pour laquelle il n'y en a pas (dite dans le refus et au journal).
    fn lire_l_empreinte(&self) -> Result<String, String> {
        let brute = match self {
            Self::NonConfiguree => return Err(format!("`{VARIABLE_DU_FICHIER_DU_SECRET_DES_GESTES}` n'est pas posée")),
            Self::Fichier(chemin) => std::fs::read_to_string(chemin)
                .map_err(|e| format!("le fichier nommé par `{VARIABLE_DU_FICHIER_DU_SECRET_DES_GESTES}` ({chemin}) est illisible : {e}"))?,
            #[cfg(test)]
            Self::Empreinte(empreinte) => empreinte.clone(),
        };
        juger_l_empreinte(brute.trim()).map(str::to_string)
    }
}

/// Une empreinte recevable : argon2id, au format PHC que le vérificateur sait lire.
fn juger_l_empreinte(empreinte: &str) -> Result<&str, String> {
    if empreinte.is_empty() {
        return Err("le fichier de l'empreinte est vide".into());
    }
    if !empreinte.starts_with(PREFIXE_D_EMPREINTE_ARGON2ID) {
        return Err("le fichier ne porte pas une empreinte argon2id au format PHC (`$argon2id$…`) — le secret en clair n'y a pas sa place".into());
    }
    argon2::password_hash::PasswordHash::new(empreinte)
        .map(|_| empreinte)
        .map_err(|e| format!("l'empreinte argon2id est malformée ({e})"))
}

/// Ce que la requête présente : l'en-tête du secret (s'il est là et non vide) et l'adresse du pair TCP (la même lecture
/// que `auth_guard`, clé du frein). Extracteur infaillible : un en-tête absent est une ISSUE, jugée par le geste.
pub(crate) struct SecretDesGestesPresente {
    pub(crate) valeur: Option<String>,
    pub(crate) ip: String,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for SecretDesGestesPresente {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _etat: &S) -> Result<Self, Self::Rejection> {
        let valeur = parts
            .headers
            .get(ENTETE_DU_SECRET_DES_GESTES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(Self { valeur, ip: crate::auth::ip_du_pair(&parts.extensions) })
    }
}

/// Le refus nommé du contrat : 403, `error` (la phrase) et `cause` (la clé stable).
fn refus_du_secret_des_gestes(cause: &'static str, texte: String) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": texte, "cause": cause }))).into_response()
}

/// La clé du frein : le couple (auteur, adresse). Les chevrons sont hors du jeu de caractères d'un nom de compte : ce
/// principal ne se confond avec aucun compte réel, et l'événement d'accès émis au SIEM nomme l'auteur.
fn principal_du_frein(auteur: &str) -> String {
    format!("<secret-des-gestes:{auteur}>")
}

/// `P10.24-m` — LE JUGEMENT, APPELÉ PAR CHAQUE GESTE GARDÉ APRÈS LE CONTRÔLE DU DROIT ET AVANT TOUTE ÉCRITURE.
/// `Ok(())` : le secret est prouvé. Ordre : configuration (sans empreinte, rien n'est examiné), en-tête (absent : rien
/// n'est compté), frein (verrouillé : le secret n'est pas examiné), vérification argon2 (comparaison de l'empreinte en
/// temps constant par le vérificateur `argon2`, via `verify_pw`).
pub(crate) fn exiger_le_secret_des_gestes(
    st: &AppState,
    presente: &SecretDesGestesPresente,
    auteur: &str,
    geste: &str,
) -> Result<(), Response> {
    let empreinte = match st.secret_des_gestes.lire_l_empreinte() {
        Ok(empreinte) => empreinte,
        Err(raison) => {
            eprintln!("[secret-des-gestes] WARN « {geste} » refusé à '{auteur}' : secret des gestes non configuré ({raison})");
            return Err(refus_du_secret_des_gestes(
                CAUSE_SECRET_DES_GESTES_NON_CONFIGURE,
                format!("{TEXTE_SECRET_DES_GESTES_NON_CONFIGURE} Constat : {raison}."),
            ));
        }
    };
    let Some(secret) = presente.valeur.as_deref() else {
        return Err(refus_du_secret_des_gestes(CAUSE_SECRET_DES_GESTES_ABSENT, TEXTE_SECRET_DES_GESTES_ABSENT.into()));
    };
    let principal = principal_du_frein(auteur);
    if let Some(attente) = auth_lock_check(st, &principal, &presente.ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, attente.to_string())],
            Json(json!({ "error": TEXTE_SECRET_DES_GESTES_VERROUILLE })),
        )
            .into_response());
    }
    if crate::auth::verify_pw(secret, &empreinte) {
        auth_record_success(st, &principal, &presente.ip);
        return Ok(());
    }
    let _ = auth_record_failure(st, &principal, &presente.ip);
    let trace = format!(
        "secret des gestes FAUX présenté par '{auteur}' depuis {} pour « {geste} » — geste refusé, rien n'est écrit",
        if presente.ip.is_empty() { "une adresse inconnue" } else { presente.ip.as_str() }
    );
    eprintln!("[secret-des-gestes] WARN {trace}");
    let _ = ledger_append(&st.db.lock(), "secret_des_gestes", &trace);
    Err(refus_du_secret_des_gestes(CAUSE_SECRET_DES_GESTES_FAUX, TEXTE_SECRET_DES_GESTES_FAUX.into()))
}

/// L'empreinte argon2id (format PHC) d'un secret, par le hachage des mots de passe du démon (`hash_pw`).
pub(crate) fn empreinte_du_secret_des_gestes(secret: &str) -> Option<String> {
    crate::session::hash_pw(secret)
}

/// `plume-daemon secret-des-gestes [--generer]` — l'empreinte sur la SORTIE STANDARD (pour `> fichier`), rien d'autre.
/// Sans drapeau, le secret est lu sur l'entrée standard (jamais sur la ligne de commande : `sudo` et l'historique la
/// journalisent). Avec `--generer`, un secret de 256 bits est engendré et affiché UNE fois, sur la SORTIE D'ERREUR —
/// il reste à l'écran et n'entre pas dans le fichier redirigé. Codes : 0 empreinte écrite, 1 refus (dit).
pub(crate) fn sous_commande_secret_des_gestes(args: &[String]) -> i32 {
    let generer = args.iter().skip(2).any(|a| a == "--generer");
    let secret = if generer {
        let Some(secret) = token_rand_hex() else {
            eprintln!("secret-des-gestes : entropie noyau indisponible — aucun secret engendré");
            return 1;
        };
        secret
    } else {
        use std::io::Read;
        let mut lu = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut lu) {
            eprintln!("secret-des-gestes : entrée standard illisible ({e})");
            return 1;
        }
        lu.trim().to_string()
    };
    if secret.chars().count() < LONGUEUR_MINIMALE_DU_SECRET_DES_GESTES {
        eprintln!(
            "secret-des-gestes : secret trop court (≥ {LONGUEUR_MINIMALE_DU_SECRET_DES_GESTES} caractères) — passez-le sur \
             l'entrée standard, ou engendrez-en un avec --generer"
        );
        return 1;
    }
    let Some(empreinte) = empreinte_du_secret_des_gestes(&secret) else {
        eprintln!("secret-des-gestes : hachage argon2id échoué — aucune empreinte écrite");
        return 1;
    };
    if generer {
        eprintln!("SECRET DES GESTES (affiché une seule fois, à conserver hors de l'hôte) : {secret}");
    }
    println!("{empreinte}");
    0
}

/// TÉMOINS SEULEMENT — le secret que l'état de test attend, et son empreinte (calculée une fois par processus).
#[cfg(test)]
pub(crate) const SECRET_DES_GESTES_DE_TEST: &str = "secret-des-gestes-de-test-0123456789";

#[cfg(test)]
pub(crate) fn empreinte_de_test() -> String {
    static EMPREINTE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    EMPREINTE.get_or_init(|| empreinte_du_secret_des_gestes(SECRET_DES_GESTES_DE_TEST).expect("empreinte de test")).clone()
}

/// TÉMOINS SEULEMENT — ce qu'une requête présente quand elle porte le bon secret de test.
#[cfg(test)]
pub(crate) fn presente_de_test() -> SecretDesGestesPresente {
    SecretDesGestesPresente { valeur: Some(SECRET_DES_GESTES_DE_TEST.to_string()), ip: "127.0.0.1".to_string() }
}
