//! P10.32-l — CE QUE LE CAPTEUR MAIL EMET D'UN COURRIER, ET CE QU'IL N'EN EMET PAS.
//!
//! Le serveur surveille porte du courrier professionnel ; le SIEM, lisible par un role `viewer` ou
//! vole avec sa base, ne doit pas en devenir une copie. L'evenement d'avant portait l'URL COMPLETE qui
//! avait declenche un motif (requete comprise), ou la VALEUR base64 decodee d'un de ses parametres :
//! un courriel legitime de reinitialisation ou de confirmation deposait son lien A JETON dans le SIEM.
//! Il portait aussi l'objet (160 caracteres) et l'adresse complete de l'expediteur.
//!
//! CE QUI SORT, DESORMAIS :
//!   * d'une URL : le schema, l'hote, le port et le chemin. La requete, le fragment et les identifiants
//!     (`user:pass@`) sont COUPES, et la coupure est DITE (`[requete coupee]`…) — un analyste sait qu'il
//!     manque quelque chose, et le motif a ete juge sur l'URL entiere avant la coupure ;
//!   * d'un parametre decode : le NOM du parametre, jamais sa valeur ;
//!   * d'un texte (en-tete, corps, motif d'exploitant) : le texte trouve, ses URL coupees et ses parties
//!     locales d'adresse masquees (`*@domaine`) ;
//!   * l'expediteur : `*@domaine` ;
//!   * l'objet : RIEN par defaut. `PLUME_MAIL_EMIT_SUBJECT=1` l'emet, tronque a `OBJET_MAX` caracteres.
//!     Aucune regle livree ne lit l'objet (`config.d/rules/` : aucune requete `source=mail` n'en parle).
//!     La regle vaut pour TOUT echantillon : celui d'un motif `subject`, et celui d'un motif `headers`
//!     d'exploitant dont la correspondance couvre l'en-tete `Subject:` (`echantillon_d_en_tetes`).
//!
//! CE QUI RESTE, ET POURQUOI : le COMPTE local (la boite de ce serveur) et l'identifiant du message —
//! la lecture du corps, gatee et auditee (`/api/mail/body`), les prend dans l'evenement pour viser le
//! message. Le chemin d'une URL peut porter un jeton (`/reset/<jeton>`) : il est emis, borne a
//! `MAX_SAMPLE` caracteres — c'est la limite dite de ce lot.
use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

pub const MAX_SAMPLE: usize = 200;
pub const OBJET_MAX: usize = 80;
pub const REQUETE_COUPEE: &str = "[requete coupee]";
pub const FRAGMENT_COUPE: &str = "[fragment coupe]";
pub const IDENTIFIANTS_COUPES: &str = "[identifiants coupes]";
pub const OBJET_NON_EMIS: &str = "[objet non emis]";

static LOCAL_ENTRE_GUILLEMETS: Lazy<Regex> = Lazy::new(|| Regex::new(r#""(?:[^"\\]|\\.)*"@"#).unwrap());
// Tout ce qui precede un `@` jusqu'a un blanc, un `<` ou un autre `@` : la ponctuation collee part avec
// (masquer trop plutot que laisser fuir `jean:` devant `*@`, cf. `masquer_adresses` de collectors/mail.sh).
static PARTIE_LOCALE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^\s<@]+@").unwrap());

fn tronquer(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Ce qui sort d'une URL : schema, hote, port, chemin ; le reste coupe ET dit. Les marques de coupure
/// survivent a la borne de longueur (elles sont ajoutees apres la troncature de la partie gardee).
pub fn url_coupee(brute: &str) -> String {
    let (gardee, marques) = match Url::parse(brute) {
        Ok(u) if u.has_host() => {
            let mut g = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(p) = u.port() {
                g.push_str(&format!(":{p}"));
            }
            g.push_str(u.path());
            let mut m = Vec::new();
            if !u.username().is_empty() || u.password().is_some() {
                m.push(IDENTIFIANTS_COUPES);
            }
            if u.query().is_some() {
                m.push(REQUETE_COUPEE);
            }
            if u.fragment().is_some() {
                m.push(FRAGMENT_COUPE);
            }
            (g, m)
        }
        // Une URL que la bibliotheque refuse est coupee a la main, par la meme regle : rien apres le
        // premier `?` ou `#`, rien avant un `@` de l'autorite.
        _ => {
            let mut m = Vec::new();
            let mut g = brute.to_string();
            if let Some(i) = g.find('#') {
                g.truncate(i);
                m.push(FRAGMENT_COUPE);
            }
            if let Some(i) = g.find('?') {
                g.truncate(i);
                m.insert(0, REQUETE_COUPEE);
            }
            if let Some(d) = g.find("://") {
                let reste = &g[d + 3..];
                let fin = reste.find('/').unwrap_or(reste.len());
                if let Some(a) = reste[..fin].rfind('@') {
                    g = format!("{}{}", &g[..d + 3], &reste[a + 1..]);
                    m.insert(0, IDENTIFIANTS_COUPES);
                }
            }
            (g, m)
        }
    };
    let suffixe: String = marques.iter().map(|m| format!(" {m}")).collect();
    let place = MAX_SAMPLE.saturating_sub(suffixe.chars().count());
    format!("{}{}", tronquer(&gardee, place), suffixe)
}

/// Un parametre decode a declenche le motif : son NOM, l'URL coupee, jamais la valeur.
pub fn parametre_decode(url: &str, nom: &str) -> String {
    let n = tronquer(nom, 40);
    let suffixe = format!(" [parametre {n} decode, valeur coupee]");
    let place = MAX_SAMPLE.saturating_sub(suffixe.chars().count());
    format!("{}{}", tronquer(&url_coupee(url), place), suffixe)
}

/// Une adresse : la partie locale masquee, le domaine garde (`*@example.org`). Sans `@`, `*`.
pub fn adresse_masquee(a: &str) -> String {
    if a.is_empty() {
        return String::new();
    }
    match a.rfind('@') {
        Some(i) => format!("*@{}", &a[i + 1..]),
        None => "*".to_string(),
    }
}

/// Un texte trouve par un motif (en-tete, corps, objet) : URL coupees, parties locales masquees, borne.
pub fn texte_assaini(s: &str) -> String {
    let s = crate::url_extract::URL_REGEX.replace_all(s, |c: &regex::Captures| url_coupee(&c[0]));
    let s = LOCAL_ENTRE_GUILLEMETS.replace_all(&s, "*@");
    let s = PARTIE_LOCALE.replace_all(&s, "*@");
    tronquer(&s, MAX_SAMPLE)
}

/// Les VALEURS des en-tetes `Subject:` d'un bloc d'en-tetes, en octets (`[debut, fin)`), lignes de
/// continuation comprises (une ligne qui commence par une espace ou une tabulation prolonge l'en-tete).
fn valeurs_d_objet(h: &str) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut dans_objet = false;
    let mut pos = 0;
    for ligne in h.split_inclusive('\n') {
        let contenu = ligne.trim_end_matches(['\r', '\n']);
        let fin = pos + contenu.len();
        if contenu.starts_with([' ', '\t']) {
            if dans_objet {
                if let Some(d) = out.last_mut() {
                    d.1 = fin;
                }
            }
        } else {
            dans_objet = false;
            if let Some(i) = contenu.find(':') {
                if contenu[..i].trim().eq_ignore_ascii_case("subject") {
                    // La valeur commence apres les blancs qui suivent `:` (`Subject: [objet non emis]`).
                    let blancs = contenu[i + 1..].len() - contenu[i + 1..].trim_start_matches([' ', '\t']).len();
                    out.push((pos + i + 1 + blancs, fin));
                    dans_objet = true;
                }
            }
        }
        pos += ligne.len();
    }
    out
}

/// L'echantillon d'un motif `headers` (correspondance `[debut, fin)` du bloc `h`) : la valeur de l'objet
/// y suit la regle de l'objet — remplacee par `[objet non emis]` s'il n'est pas demande, bornee a
/// `OBJET_MAX` caracteres s'il l'est —, puis le texte est assaini comme tout texte. Le motif, lui, a ete
/// juge sur le bloc ENTIER.
pub fn echantillon_d_en_tetes(h: &str, debut: usize, fin: usize, objet_demande: bool) -> String {
    let mut s = String::new();
    let mut curseur = debut;
    for (vd, vf) in valeurs_d_objet(h) {
        let (od, of) = (vd.max(debut), vf.min(fin));
        if od >= of {
            continue;
        }
        s.push_str(&h[curseur..od]);
        if objet_demande {
            let permis = h[vd..vf].char_indices().nth(OBJET_MAX).map(|(i, _)| vd + i).unwrap_or(vf);
            if od < permis {
                s.push_str(&h[od..of.min(permis)]);
            }
        } else {
            s.push_str(OBJET_NON_EMIS);
        }
        curseur = of;
    }
    s.push_str(&h[curseur..fin]);
    texte_assaini(&s)
}

/// `PLUME_MAIL_EMIT_SUBJECT` : absent, vide ou `0` -> non ; `1` -> oui ; toute autre valeur est un
/// reglage POSE et non compris, donc une erreur (jamais un repli silencieux sur l'un des deux).
pub fn emettre_l_objet(v: Option<&str>) -> Result<bool, String> {
    match v.map(str::trim) {
        None | Some("") | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(autre) => Err(format!(
            "PLUME_MAIL_EMIT_SUBJECT={autre:?} non compris : `1` emet l'objet (tronque a {OBJET_MAX} caracteres), \
             `0` ou rien ne l'emet pas"
        )),
    }
}

/// L'objet tel qu'il sort : tronque et assaini s'il est demande, sinon la marque `[objet non emis]`.
pub fn objet_emis(objet: &str, demande: bool) -> String {
    if demande {
        texte_assaini(&tronquer(objet, OBJET_MAX))
    } else {
        OBJET_NON_EMIS.to_string()
    }
}
