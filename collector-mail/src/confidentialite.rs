//! P10.32-l — CE QUE LE CAPTEUR MAIL EMET D'UN COURRIER, ET CE QU'IL N'EN EMET PAS.
//!
//! Le serveur surveille porte du courrier professionnel ; le SIEM, lisible par un role `viewer` ou
//! vole avec sa base, ne doit pas en devenir une copie. L'evenement d'avant portait l'URL COMPLETE qui
//! avait declenche un motif (requete comprise), ou la VALEUR base64 decodee d'un de ses parametres :
//! un courriel legitime de reinitialisation ou de confirmation deposait son lien A JETON dans le SIEM.
//! Il portait aussi l'objet (160 caracteres) et l'adresse complete de l'expediteur.
//!
//! CE QUI SORT, DESORMAIS :
//!   * d'une URL : le schema, l'hote, le port et le chemin, dont chaque SEGMENT qui a la forme d'un
//!     jeton est remplace par `[jeton coupe]` (`segment_a_forme_de_jeton`, regle ci-dessous). La
//!     requete, le fragment et les identifiants (`user:pass@`) sont COUPES, et la coupure est DITE
//!     (`[requete coupee]`…) — un analyste sait qu'il manque quelque chose, et le motif a ete juge sur
//!     l'URL entiere avant la coupure ;
//!   * d'un parametre decode : le NOM du parametre, jamais sa valeur ;
//!   * d'un texte (en-tete, corps, motif d'exploitant) : le texte trouve, ses URL coupees et ses parties
//!     locales d'adresse masquees (`*@domaine`). Une URL y est reconnue a son schema `http://` ou
//!     `https://` SANS EGARD A LA CASSE (`HTTPS://`, `Https://` : `URL_DANS_UN_TEXTE`) ;
//!   * l'expediteur : `*@domaine` ;
//!   * l'objet : RIEN par defaut. `PLUME_MAIL_EMIT_SUBJECT=1` l'emet ASSAINI comme un texte sur sa
//!     longueur entiere, PUIS tronque a `OBJET_MAX` caracteres (`objet_borne_apres_jugement`) : un jeton
//!     ou une partie locale qui chevauche la borne est juge entier avant la coupe. La borne peut couper
//!     une marque (`[jeton co`), jamais rendre ce que la marque remplace. Aucune regle livree ne lit
//!     l'objet (`config.d/rules/` : aucune requete `source=mail` n'en parle). La regle vaut pour TOUT
//!     echantillon : celui d'un motif `subject`, l'objet du message, et celui d'un motif `headers`
//!     d'exploitant dont la correspondance couvre l'en-tete `Subject:` (`echantillon_d_en_tetes`).
//!
//! LA FORME D'UN JETON (`segment_a_forme_de_jeton`), jugee sur le segment DECODE de l'encodage en
//! pourcentage (repris tant qu'il change, trois fois au plus : un `%2533` ne cache pas un `3`). Le
//! segment est coupe ENTIER si :
//!   * il a la forme d'un JWT ou d'un JWE compact : au moins trois parties separees par `.`, la premiere
//!     commencant par `eyJ` (l'encodage de `{"`, debut de tout en-tete JSON) et longue d'au moins
//!     `JWT_EN_TETE_MIN` caracteres, la deuxieme non vide, les suivantes eventuellement vides. Aucun
//!     alphabet n'est exige des parties : un rembourrage `=`, un `~` ou une partie de trop ne protegent
//!     pas le jeton (un segment qui commence ainsi sans en etre un est coupe aussi : masquer trop) ;
//!   * ou l'un de ses MORCEAUX — suite maximale de lettres et chiffres ASCII, `-` et `_` (l'alphabet
//!     base64url ; tout autre caractere, `.` `;` `=` `%`…, separe deux morceaux, ce qui juge la tige d'un
//!     nom de fichier et la valeur d'un `;jsessionid=`) — d'au moins `JETON_MIN` caracteres est :
//!       - un UUID (8-4-4-4-12 chiffres hexadecimaux) ;
//!       - un hexadecimal pur (chiffres seuls compris) ;
//!       - un melange lettres/chiffres d'au moins trois ALTERNANCES entre deux caracteres voisins
//!         (`a1`, `1a`) : un mot suivi d'une annee (`newsletter2026`) n'en a qu'une ;
//!       - un melange de casses dont un tiers au moins des paires de lettres voisines change de casse,
//!         SAUF une casse chameau sans deux capitales voisines (`MyAccountSettingsPage`).
//! Une fonction pure, lineaire en la longueur du segment, sans expression reguliere. La borne
//! `MAX_SAMPLE` s'applique APRES le remplacement, sur des caracteres entiers.
//!
//! CE QUI RESTE, ET POURQUOI : le COMPTE local (la boite de ce serveur) et l'identifiant du message —
//! la lecture du corps, gatee et auditee (`/api/mail/body`), les prend dans l'evenement pour viser le
//! message. La regle de forme est une heuristique, et ses bords sont dits : un jeton de moins de
//! `JETON_MIN` caracteres, un jeton long coupe par `.`, `~`, un `/` encode (`%2F`) ou tout autre
//! separateur en morceaux de moins de `JETON_MIN` caracteres chacun (`3f9a8b7c.6d5e4f30.a1b2c3d4`), un
//! jeton fait de lettres d'une seule casse hors hexadecimal, un jeton de lettres puis de chiffres sans
//! autre alternance (`ABCDEFGHIJKL12345678`) ou en casse chameau, un jeton place dans l'HOTE
//! (`<jeton>.example.org`, avec ou sans chemin, URL acceptee ou refusee par la bibliotheque), un JWT a
//! deuxieme partie vide, sortent encore, bornes a `MAX_SAMPLE` caracteres. Dans un texte, une URL d'un
//! autre schema (`ftp://`) ou sans schema (`www.example.org/…`) n'est pas reconnue : son chemin et sa
//! requete sortent tels quels. L'EXTRACTION des URL offertes aux motifs `url` (`url_extract`) reste
//! sensible a la casse : une URL `HTTPS://` d'un corps n'y est pas offerte (un angle de detection, rien
//! n'en sort).
use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

pub const MAX_SAMPLE: usize = 200;
pub const OBJET_MAX: usize = 80;
pub const REQUETE_COUPEE: &str = "[requete coupee]";
pub const FRAGMENT_COUPE: &str = "[fragment coupe]";
pub const IDENTIFIANTS_COUPES: &str = "[identifiants coupes]";
pub const JETON_COUPE: &str = "[jeton coupe]";
pub const OBJET_NON_EMIS: &str = "[objet non emis]";
/// Longueur minimale (en caracteres) d'un morceau de segment juge comme un jeton.
pub const JETON_MIN: usize = 16;
/// Longueur minimale de la premiere partie (en-tete) d'un JWT : `eyJ` et huit caracteres.
pub const JWT_EN_TETE_MIN: usize = 11;
/// Passes de decodage en pourcentage au plus (un double encodage ne cache pas le jeton).
const DECODAGES_MAX: usize = 3;

static LOCAL_ENTRE_GUILLEMETS: Lazy<Regex> = Lazy::new(|| Regex::new(r#""(?:[^"\\]|\\.)*"@"#).unwrap());
// Tout ce qui precede un `@` jusqu'a un blanc, un `<` ou un autre `@` : la ponctuation collee part avec
// (masquer trop plutot que laisser fuir `jean:` devant `*@`, cf. `masquer_adresses` de collectors/mail.sh).
static PARTIE_LOCALE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^\s<@]+@").unwrap());

fn tronquer(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn est_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Le segment decode de l'encodage en pourcentage, repris tant qu'il change (`DECODAGES_MAX` passes).
fn segment_decode(brut: &str) -> String {
    let mut s = brut.to_string();
    for _ in 0..DECODAGES_MAX {
        let d = percent_encoding::percent_decode_str(&s).decode_utf8_lossy().into_owned();
        if d == s {
            break;
        }
        s = d;
    }
    s
}

fn est_un_jwt(s: &str) -> bool {
    let parties: Vec<&str> = s.split('.').collect();
    parties.len() >= 3
        && parties[0].starts_with("eyJ")
        && parties[0].len() >= JWT_EN_TETE_MIN
        && !parties[1].is_empty()
}

fn est_un_uuid(m: &[char]) -> bool {
    m.len() == 36
        && m.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Un morceau (suite maximale de l'alphabet base64url) a-t-il la forme d'un jeton ? Regle et bords :
/// en-tete du module.
fn morceau_a_forme_de_jeton(m: &[char]) -> bool {
    if m.len() < JETON_MIN {
        return false;
    }
    if est_un_uuid(m) || m.iter().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    let (mut alternances, mut paires_de_lettres, mut changements_de_casse) = (0usize, 0usize, 0usize);
    let mut capitales_voisines = false;
    for w in m.windows(2) {
        let (a, b) = (w[0], w[1]);
        if (a.is_ascii_alphabetic() && b.is_ascii_digit()) || (a.is_ascii_digit() && b.is_ascii_alphabetic()) {
            alternances += 1;
        }
        if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() {
            paires_de_lettres += 1;
            if a.is_ascii_uppercase() != b.is_ascii_uppercase() {
                changements_de_casse += 1;
            }
            if a.is_ascii_uppercase() && b.is_ascii_uppercase() {
                capitales_voisines = true;
            }
        }
    }
    if alternances >= 3 {
        return true;
    }
    paires_de_lettres > 0 && changements_de_casse * 3 >= paires_de_lettres && capitales_voisines
}

/// Un segment de chemin (brut, tel qu'il figure dans l'URL) a-t-il la forme d'un jeton ? Jugee sur le
/// segment decode ; regle et bords : en-tete du module.
pub fn segment_a_forme_de_jeton(brut: &str) -> bool {
    let s = segment_decode(brut);
    if est_un_jwt(&s) {
        return true;
    }
    let mut morceau: Vec<char> = Vec::new();
    for c in s.chars().chain(std::iter::once('/')) {
        if est_base64url(c) {
            morceau.push(c);
            continue;
        }
        if morceau_a_forme_de_jeton(&morceau) {
            return true;
        }
        morceau.clear();
    }
    false
}

/// Le chemin, chaque segment a forme de jeton remplace par `JETON_COUPE`, le reste garde.
fn chemin_sans_jeton(chemin: &str) -> String {
    chemin
        .split('/')
        .map(|seg| if segment_a_forme_de_jeton(seg) { JETON_COUPE } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

/// Ce qui sort d'une URL : schema, hote, port, chemin sans jeton ; le reste coupe ET dit. Les marques
/// de coupure survivent a la borne de longueur (elles sont ajoutees apres la troncature de la partie
/// gardee) ; la borne s'applique apres le remplacement des jetons.
pub fn url_coupee(brute: &str) -> String {
    let (gardee, marques) = match Url::parse(brute) {
        Ok(u) if u.has_host() => {
            let mut g = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(p) = u.port() {
                g.push_str(&format!(":{p}"));
            }
            g.push_str(&chemin_sans_jeton(u.path()));
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
            // Le chemin commence au premier `/` apres l'autorite ; sans `://`, tout est chemin.
            let debut = match g.find("://") {
                Some(d) => g[d + 3..].find('/').map(|i| d + 3 + i).unwrap_or(g.len()),
                None => 0,
            };
            let g = format!("{}{}", &g[..debut], chemin_sans_jeton(&g[debut..]));
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

/// Le motif d'extraction (`url_extract::URL_REGEX`), juge SANS EGARD A LA CASSE : le schema d'une URL ne
/// depend pas de sa casse (RFC 3986, 3.1), et un `HTTPS://` ou un `Https://` dans un texte sortait sans
/// coupure, jeton du chemin et requete compris.
static URL_DANS_UN_TEXTE: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!("(?i){}", crate::url_extract::URL_REGEX.as_str())).unwrap());

/// Un texte trouve par un motif (en-tete, corps, objet) : URL coupees, parties locales masquees, borne.
pub fn texte_assaini(s: &str) -> String {
    let s = URL_DANS_UN_TEXTE.replace_all(s, |c: &regex::Captures| url_coupee(&c[0]));
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
/// y suit la regle de l'objet — remplacee par `[objet non emis]` s'il n'est pas demande ; s'il l'est,
/// ASSAINIE puis bornee (`objet_borne_apres_jugement`), la borne de `OBJET_MAX` caracteres comptant depuis
/// le debut de la valeur. Le reste du bloc est assaini comme tout texte, morceau par morceau entre les
/// valeurs d'objet : chaque limite tombe apres `Subject:` et ses blancs, sur la fin de la ligne (ou de sa
/// derniere continuation), ou sur une borne de la correspondance. Le nom de l'en-tete n'est donc plus
/// masque avec une partie locale collee a lui (`Subject:alice@example.org` -> `Subject:*@example.org`).
/// Le motif, lui, a ete juge sur le bloc ENTIER.
pub fn echantillon_d_en_tetes(h: &str, debut: usize, fin: usize, objet_demande: bool) -> String {
    let mut s = String::new();
    let mut curseur = debut;
    for (vd, vf) in valeurs_d_objet(h) {
        let (od, of) = (vd.max(debut), vf.min(fin));
        if od >= of {
            continue;
        }
        s.push_str(&texte_assaini(&h[curseur..od]));
        if objet_demande {
            let place = OBJET_MAX.saturating_sub(h[vd..od].chars().count());
            s.push_str(&objet_borne_apres_jugement(&h[od..of], place));
        } else {
            s.push_str(OBJET_NON_EMIS);
        }
        curseur = of;
    }
    s.push_str(&texte_assaini(&h[curseur..fin]));
    tronquer(&s, MAX_SAMPLE)
}

/// L'objet (ou le morceau d'objet) demande, tel qu'il sort : ASSAINI SUR SA LONGUEUR ENTIERE, puis
/// tronque a `place` caracteres. Dans l'ordre inverse, la troncature coupait un jeton qui chevauchait la
/// borne en un morceau trop court pour etre juge (`JETON_MIN`), ou une partie locale avant son `@`, et ce
/// morceau sortait en clair. La borne tombe sur un caractere entier ; elle peut couper une MARQUE
/// (`[jeton co`), jamais rendre ce que la marque remplace.
fn objet_borne_apres_jugement(objet: &str, place: usize) -> String {
    tronquer(&texte_assaini(objet), place)
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

/// L'objet tel qu'il sort : assaini puis borne a `OBJET_MAX` caracteres s'il est demande
/// (`objet_borne_apres_jugement`), sinon la marque `[objet non emis]`.
pub fn objet_emis(objet: &str, demande: bool) -> String {
    if demande {
        objet_borne_apres_jugement(objet, OBJET_MAX)
    } else {
        OBJET_NON_EMIS.to_string()
    }
}
