//! `P3.10-b` — LA DÉCOUPE D'UNE LIGNE DÉLIMITÉE, LE MÊME TEXTE QUE CELUI DU DÉMON. Le parseur `delimiter`
//! de l'agent découpait par `line.split(delimiter)` nu : une cellule quotée contenant le séparateur était
//! coupée en deux, `""` restait tel quel, et la ligne d'en-têtes devenait un événement. Le démon découpe
//! conformément depuis `P3.10-a` (`daemon/src/parsers.rs`, `decouper_une_ligne_csv`) ; cette fonction en est
//! la COPIE, et un témoin du démon exige que les deux corps soient identiques à l'octet — deux caisses,
//! un seul texte. Ce qu'elle ne fait pas, comme là-bas : un retour à la ligne à l'intérieur d'une cellule
//! quotée (la ligne EST l'unité) et un guillemet non refermé prend le reste de la ligne, sans erreur.

/// Découpe une ligne délimitée : séparateur hors guillemets ; une cellule qui COMMENCE par `"` est quotée
/// jusqu'au `"` fermant, `""` vaut un `"` littéral ; `\r`/`\n` finals ôtés. Aucune borne ici.
pub fn decouper_une_ligne_delimitee(ligne: &str, delim: u8) -> Vec<String> {
    let ligne = ligne.trim_end_matches(['\r', '\n']);
    let mut cellules: Vec<String> = Vec::new();
    let mut courante = String::new();
    let mut entre_guillemets = false;
    let mut debut_de_cellule = true;
    let mut it = ligne.chars().peekable();
    while let Some(c) = it.next() {
        if entre_guillemets {
            if c == '"' {
                if it.peek() == Some(&'"') { courante.push('"'); it.next(); } else { entre_guillemets = false; }
            } else {
                courante.push(c);
            }
            continue;
        }
        if debut_de_cellule && c == '"' {
            entre_guillemets = true;
            debut_de_cellule = false;
            continue;
        }
        if c.is_ascii() && c as u8 == delim {
            cellules.push(std::mem::take(&mut courante));
            debut_de_cellule = true;
            continue;
        }
        debut_de_cellule = false;
        courante.push(c);
    }
    cellules.push(courante);
    cellules
}

#[cfg(test)]
mod tests {
    use super::decouper_une_ligne_delimitee;

    #[test]
    fn guillemets_et_separateur_quote_sont_respectes() {
        assert_eq!(decouper_une_ligne_delimitee(r#""a, b",x,"dit ""x""",y"#, b','), vec!["a, b", "x", "dit \"x\"", "y"]);
    }

    #[test]
    fn fin_de_ligne_otee_cellule_vide_et_guillemet_non_referme() {
        assert_eq!(decouper_une_ligne_delimitee("1;2;;4\r\n", b';'), vec!["1", "2", "", "4"]);
        assert_eq!(decouper_une_ligne_delimitee(r#""non refermé,reste"#, b','), vec!["non refermé,reste"]);
    }

    #[test]
    fn l_utf8_traverse_la_decoupe() {
        assert_eq!(decouper_une_ligne_delimitee("é,ü,\"ç,c\"", b','), vec!["é", "ü", "ç,c"]);
    }
}
