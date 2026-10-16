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

/// La liste retenue. Vide = le comportement d'avant cette cle, a l'identique.
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

    /// Meme question pour une adresse ecrite d'un bloc (sous-commande `body`). Une adresse sans `@`
    /// ne designe aucun compte du layout : elle n'est pas exclue ici, et `body` la refuse ensuite.
    pub fn exclut_adresse(&self, adresse: &str) -> bool {
        match adresse.split_once('@') {
            Some((l, d)) => self.exclut(l, d),
            None => false,
        }
    }
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
}
