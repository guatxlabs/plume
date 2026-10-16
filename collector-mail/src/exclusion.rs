//! `P10.33-m` — LES COMPTES QU'UN EXPLOITANT RETIRE DU BALAYAGE.
//!
//! Le collecteur parcourait CHAQUE compte sous `PLUME_MAIL_ROOT`, sans aucun moyen d'en retirer un :
//! un exploitant qui heberge une boite qui ne doit pas etre analysee ne pouvait pas l'activer.
//! `PLUME_MAIL_EXCLURE_COMPTES` nomme ces comptes.
//!
//! LA FORME D'UNE ENTREE, SANS AMBIGUITE :
//!   * AVEC un `@` (`alice@example.test`) : l'ADRESSE complete — exclut ce compte-la seulement ;
//!   * SANS `@` (`alice`) : la PARTIE LOCALE — exclut le compte de ce nom dans CHAQUE domaine du
//!     maildir (layout plat : le domaine est `PLUME_MAIL_DOMAIN` ; layout imbrique : celui du
//!     repertoire).
//!   Entrees separees par des virgules et/ou des blancs. Comparaison EXACTE apres passage en
//!   minuscules ASCII des deux cotes : pas de prefixe, pas de suffixe, pas de motif. Un nom de compte
//!   qui porte un caractere non ASCII ne peut donc egaler aucune entree (il n'est pas exclu).
//!
//! CE QUI EST REFUSE, ET POURQUOI LE PASSAGE S'ARRETE : une entree VIDE (`alice,,bob`, virgule
//! finale), un MOTIF (`*`, `?`, `[`, `]`, `{`, `}`), un caractere HORS CLASSE (partie locale :
//! `a-z 0-9 . _ + -` ; domaine : `a-z 0-9 . -`), une adresse MAL FORMEE (deux `@`, un cote vide).
//! Ignorer l'entree fautive ferait LIRE la boite que l'exploitant a voulu retirer ; deviner ce
//! qu'elle voulait dire ferait exclure une boite qu'il n'a pas nommee. Le passage s'arrete donc AVANT
//! d'ouvrir quoi que ce soit, et l'aveu designe l'entree par son RANG et sa cause — jamais par sa
//! valeur, qui est un nom de compte.

pub const VARIABLE: &str = "PLUME_MAIL_EXCLURE_COMPTES";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entree {
    Adresse { local: String, domaine: String },
    PartieLocale(String),
}

/// La liste retenue. Vide : aucun compte n'est retire ; le passage et `body` lisent ce qu'ils lisaient,
/// a UNE exception pres, qui ne tient pas a la liste mais a sa SOURCE : un `mail.conf` present et
/// illisible arrete le balayage comme `body` (`configuration_effective`), parce que la liste qu'il peut
/// porter n'est pas jugeable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusion {
    entrees: Vec<Entree>,
}

const MOTIF: &[char] = &['*', '?', '[', ']', '{', '}'];

fn classe_locale(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '-')
}

fn classe_domaine(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-')
}

/// Les entrees brutes, dans l'ordre : chaque segment entre virgules est decoupe aux blancs ; un
/// segment entre virgules qui ne porte RIEN est une entree VIDE (rendue `""`), pas un separateur.
fn entrees_brutes(valeur: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for segment in valeur.split(',') {
        let mut morceaux = segment.split_whitespace().peekable();
        if morceaux.peek().is_none() {
            out.push("");
        }
        out.extend(morceaux);
    }
    out
}

fn entree(brute: &str) -> Result<Entree, &'static str> {
    if brute.is_empty() {
        return Err("entree vide");
    }
    if brute.contains(MOTIF) {
        return Err("motif glob : la comparaison est exacte");
    }
    let e = brute.to_ascii_lowercase();
    match e.split_once('@') {
        None => {
            if !e.chars().all(classe_locale) {
                return Err("caractere hors classe");
            }
            Ok(Entree::PartieLocale(e))
        }
        Some((local, domaine)) => {
            if local.is_empty() || domaine.is_empty() || domaine.contains('@') {
                return Err("adresse mal formee");
            }
            if !local.chars().all(classe_locale) || !domaine.chars().all(classe_domaine) {
                return Err("caractere hors classe");
            }
            Ok(Entree::Adresse { local: local.to_string(), domaine: domaine.to_string() })
        }
    }
}

impl Exclusion {
    /// Lit la valeur de la variable. Absente ou faite de blancs seuls : liste vide. Sinon CHAQUE entree
    /// doit etre valide, ou rien n'est retenu : l'erreur nomme le rang (a partir de 1) et la cause.
    pub fn lire(valeur: Option<&str>) -> Result<Self, String> {
        let v = match valeur {
            Some(v) if !v.trim().is_empty() => v,
            _ => return Ok(Self::default()),
        };
        let mut entrees = Vec::new();
        for (i, brute) in entrees_brutes(v).into_iter().enumerate() {
            let e = entree(brute).map_err(|cause| {
                format!(
                    "{VARIABLE} : entree n°{} refusee ({cause}) — passage arrete AVANT toute lecture, \
                     aucun compte n'est ouvert ; corrige la liste (adresse complete `local@domaine` \
                     ou partie locale seule, comparaison exacte)",
                    i + 1
                )
            })?;
            entrees.push(e);
        }
        Ok(Self { entrees })
    }

    pub fn est_vide(&self) -> bool {
        self.entrees.is_empty()
    }

    /// `local@domaine` (tel que le layout le nomme) est-il exclu ? Egalite EXACTE, en minuscules ASCII.
    pub fn exclut(&self, local: &str, domaine: &str) -> bool {
        let local = local.to_ascii_lowercase();
        let domaine = domaine.to_ascii_lowercase();
        self.entrees.iter().any(|e| match e {
            Entree::PartieLocale(l) => *l == local,
            Entree::Adresse { local: l, domaine: d } => *l == local && *d == domaine,
        })
    }

    /// Ajoute les entrees d'une autre liste (`body` joint celle de son environnement et celle du
    /// fichier de configuration : une entree posee a l'un OU a l'autre exclut).
    pub fn joindre(mut self, autre: Exclusion) -> Exclusion {
        self.entrees.extend(autre.entrees);
        self
    }

    /// Le repertoire que `body` s'apprete a lire est-il retire, AU SENS DU BALAYAGE ? `composants` est
    /// son chemin RESOLU (liens et `.` compris), relatif a la racine du maildir.
    ///   * `[compte]` : compte du layout plat, que le balayage nomme `<compte>@<domaine_plat>` ;
    ///   * `[parent, compte]` : compte `<compte>@<parent>` du layout imbrique — OU dossier d'un compte
    ///     plat (`alice/.Sent`) : retire aussi quand `parent` l'est au premier niveau, comme le balayage
    ///     retire entier un repertoire de premier niveau dont le nom est exclu ;
    ///   * toute autre forme (la racine elle-meme, plus profond) ne designe aucun compte que le
    ///     balayage nomme : elle est REFUSEE, faute de pouvoir dire qu'elle n'est pas retiree.
    /// L'adresse ECRITE par le demandeur n'entre pas dans la decision : en layout plat, `alice@autre`
    /// et `alice@example.test.` resolvent la meme boite `alice`, et c'est la boite qu'on juge.
    pub fn exclut_chemin(&self, composants: &[String], domaine_plat: &str) -> bool {
        match composants {
            [compte] => self.exclut(compte, domaine_plat),
            [parent, compte] => self.exclut(compte, parent) || self.exclut(parent, domaine_plat),
            _ => true,
        }
    }
}

/// Le fichier que `plume-collector-mail.service` charge (`EnvironmentFile=`) et que le collecteur RELIT
/// lui-meme (`configuration_effective`, balayage ET `body`) : lance par le demon (`PLUME_MAIL_BODY_CMD`),
/// `body` herite de l'environnement du demon, qui ne charge pas ce fichier. Sans cette relecture, une
/// liste posee ou la documentation le dit ne protegeait que le balayage.
pub const VARIABLE_FICHIER: &str = "PLUME_MAIL_CONF";
pub const FICHIER_DEFAUT: &str = "/etc/plume/mail.conf";

/// Valeur de `cle` dans un fichier au format `EnvironmentFile=` (sous-ensemble : `CLE=valeur`, lignes
/// `#` et `;` ignorees, guillemets simples ou doubles englobants retires, la DERNIERE affectation
/// l'emporte, comme sous systemd). Une valeur que ce sous-ensemble ne comprend pas reste telle quelle :
/// la lecture de la liste la refuse ensuite (caractere hors classe), elle n'est jamais ignoree.
pub fn valeur_du_fichier(texte: &str, cle: &str) -> Option<String> {
    let mut retenue = None;
    for ligne in texte.lines() {
        let l = ligne.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        if k.trim() != cle {
            continue;
        }
        let v = v.trim();
        let v = ['"', '\'']
            .iter()
            .find_map(|q| v.strip_prefix(*q).and_then(|r| r.strip_suffix(*q)))
            .unwrap_or(v);
        retenue = Some(v.to_string());
    }
    retenue
}

/// Le domaine du layout plat quand rien ne le nomme (le defaut historique du balayage).
pub const DOMAINE_DEFAUT: &str = "localhost";

/// `P10.33-m` — LE DOMAINE DU LAYOUT PLAT, UNE SEULE REGLE POUR LE BALAYAGE ET POUR `body`.
///
/// C'est la precedence que `plume-collector-mail.service` donne au balayage : `EnvironmentFile=` charge
/// `mail.conf` PAR-DESSUS l'environnement. Le fichier qui PORTE la cle decide donc, meme d'une valeur
/// VIDE (sous systemd elle ecrase l'environnement, et le balayage retombe sur le defaut) ; l'environnement
/// ne compte que si le fichier ne porte pas la cle ; une valeur vide de l'environnement vaut le defaut.
/// Deux regles distinctes faisaient nommer la meme boite `alice@localhost` au balayage et
/// `alice@example.test` a `body` : l'une retirait le compte, l'autre le lisait.
pub fn domaine_effectif(du_fichier: Option<&str>, de_l_environnement: Option<&str>) -> String {
    du_fichier
        .or(de_l_environnement)
        .filter(|v| !v.is_empty())
        .unwrap_or(DOMAINE_DEFAUT)
        .to_string()
}

/// Ce que le balayage ET `body` appliquent : la liste (environnement JOINT au fichier) et le domaine du
/// layout plat.
#[derive(Debug)]
pub struct Configuration {
    pub exclusion: Exclusion,
    pub domaine: String,
}

/// Pourquoi la configuration n'est pas jugeable : la cause (vocabulaire de `lisibilite`) et un texte qui
/// ne cite aucune valeur de la liste.
#[derive(Debug)]
pub struct ConfigurationRefusee {
    pub cause: &'static str,
    pub message: String,
}

/// `P10.33-m` — LA CONFIGURATION EFFECTIVE, LUE PAR UNE SEULE FONCTION.
///
/// `mail.conf` (`PLUME_MAIL_CONF` pour un autre chemin) n'est lu que s'il EXISTE : absent, l'environnement
/// seul. Present et lisible : sa liste rejoint celle de l'environnement, son `PLUME_MAIL_DOMAIN` decide
/// (`domaine_effectif`). Present et ILLISIBLE : REFUS, que l'environnement porte une liste ou non — la
/// liste du fichier peut nommer un compte que celle de l'environnement ne nomme pas, et lire alors la
/// boite qu'elle retire est la fuite que cette cle ferme. Le refus vaut aussi liste vide : on ne sait pas
/// qu'elle est vide.
pub fn configuration_effective() -> Result<Configuration, ConfigurationRefusee> {
    let chemin = std::env::var(VARIABLE_FICHIER)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| FICHIER_DEFAUT.to_string());
    let fichier = match std::fs::read_to_string(&chemin) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(ConfigurationRefusee {
                cause: crate::lisibilite::cause_io(&e),
                message: format!(
                    "{chemin} present mais illisible ({}) : la liste {VARIABLE} qu'il peut porter n'est pas \
                     jugeable, aucune boite n'est ouverte",
                    e.kind()
                ),
            })
        }
    };
    let du_fichier = |cle: &str| fichier.as_deref().and_then(|t| valeur_du_fichier(t, cle));
    let forme = |message: String| ConfigurationRefusee { cause: crate::lisibilite::CAUSE_FORME_INCONNUE, message };
    let de_l_environnement = Exclusion::lire(std::env::var(VARIABLE).ok().as_deref())
        .map_err(|e| forme(format!("environnement : {e}")))?;
    let de_la_configuration =
        Exclusion::lire(du_fichier(VARIABLE).as_deref()).map_err(|e| forme(format!("{chemin} : {e}")))?;
    let domaine = domaine_effectif(
        du_fichier("PLUME_MAIL_DOMAIN").as_deref(),
        std::env::var("PLUME_MAIL_DOMAIN").ok().as_deref(),
    );
    Ok(Configuration { exclusion: de_l_environnement.joindre(de_la_configuration), domaine })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_lecture_retient_les_deux_formes_et_refuse_chaque_entree_invalide_par_son_rang() {
        assert_eq!(Exclusion::lire(None).unwrap(), Exclusion::default());
        assert!(Exclusion::lire(Some("  \t ")).unwrap().est_vide());
        let x = Exclusion::lire(Some("Alice, bob@Example.TEST  carol")).unwrap();
        assert!(x.exclut("alice", "example.test") && x.exclut("ALICE", "autre.example.test"));
        assert!(x.exclut("bob", "example.test") && !x.exclut("bob", "autre.example.test"));
        assert!(x.exclut("carol", "example.test"));
        // EXACTE : ni prefixe, ni suffixe.
        assert!(!x.exclut("alic", "example.test") && !x.exclut("alicex", "example.test"));
        assert!(!x.exclut("xalice", "example.test"));
        // Non ASCII : la casse ASCII seule est pliee (le signe kelvin ne devient pas un `k`).
        let k = Exclusion::lire(Some("kalice")).unwrap();
        assert!(!k.exclut("\u{212A}alice", "example.test"));
        for (valeur, rang, cause) in [
            ("alice,,bob", 2, "entree vide"),
            ("alice,", 2, "entree vide"),
            ("ali*", 1, "motif glob"),
            ("alice bo?b", 2, "motif glob"),
            ("al/ice", 1, "hors classe"),
            ("alice@exa_mple.test", 1, "hors classe"),
            ("@example.test", 1, "mal formee"),
            ("alice@", 1, "mal formee"),
            ("a@b@example.test", 1, "mal formee"),
            ("\u{e9}lise", 1, "hors classe"),
        ] {
            let e = Exclusion::lire(Some(valeur)).unwrap_err();
            assert!(e.contains(&format!("n°{rang} ")) && e.contains(cause), "{valeur:?} -> {e}");
            assert!(!e.contains(valeur.trim_end_matches(',')), "l'aveu ne recopie pas l'entree : {e}");
        }
    }

    #[test]
    fn le_chemin_resolu_decide_et_le_fichier_se_lit_comme_systemd() {
        let c = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let x = Exclusion::lire(Some("alice@example.test carol")).unwrap();
        assert!(x.exclut_chemin(&c(&["alice"]), "example.test"));
        assert!(!x.exclut_chemin(&c(&["alice"]), "autre.test"), "l'adresse vise le domaine du layout plat");
        assert!(x.exclut_chemin(&c(&["alice", ".Sent"]), "example.test"), "dossier d'un compte plat retire");
        assert!(x.exclut_chemin(&c(&["Example.TEST", "alice"]), "localhost"));
        assert!(x.exclut_chemin(&c(&["autre.test", "carol"]), "localhost"));
        assert!(!x.exclut_chemin(&c(&["autre.test", "alice"]), "localhost"));
        assert!(x.exclut_chemin(&c(&[]), "example.test") && x.exclut_chemin(&c(&["a", "b", "c"]), "x"));
        let t = "# commentaire\n; autre\nPLUME_MAIL_EXCLURE_COMPTES=bob\n  PLUME_MAIL_EXCLURE_COMPTES = \"alice bob\"\nPLUME_MAIL_DOMAIN='example.test'\nX=1";
        assert_eq!(valeur_du_fichier(t, VARIABLE).as_deref(), Some("alice bob"), "la derniere l'emporte");
        assert_eq!(valeur_du_fichier(t, "PLUME_MAIL_DOMAIN").as_deref(), Some("example.test"));
        assert_eq!(valeur_du_fichier(t, "ABSENTE"), None);
        let joint = Exclusion::lire(Some("bob")).unwrap().joindre(Exclusion::lire(Some("alice")).unwrap());
        assert!(joint.exclut("bob", "d") && joint.exclut("alice", "d"));
    }
}
