//! `P10.32-q` — LA FEUILLE REGEXP DU TIER FROID REFUSE CE QUE LE CHAUD REFUSE.
//!
//! Avant (ccfa0875), `build_leaf` compilait `champ=~motif` et `champ:~motif` par `regex::Regex::new`, sans le plafond de
//! 512 octets du chaud : un motif trop long, refusé par l'UDF `regexp`, était vectorisé au froid. Désormais
//! la feuille passe par `crate::regex_de_requete::compiler_motif` ; un motif refusé rend `None` (FALLBACK) et
//! c'est le chemin chaud qui dit le refus. Mutants : `S4_FROID_SANS_PLAFOND`, puis `M_LONG_CHARS` (longueur
//! comptée en caractères), retirés avant le commit.
//! Témoins du chaud : `daemon/src/tests/regex_de_requete_bornee.rs`.
use super::*;
use crate::regex_de_requete::LONGUEUR_MAX_DU_MOTIF;

#[test]
fn feuille_regex_du_froid_refuse_le_motif_de_513_octets() {
    let trop_long = "a".repeat(LONGUEUR_MAX_DU_MOTIF + 1);
    let a_la_limite = "a".repeat(LONGUEUR_MAX_DU_MOTIF);
    assert!(build_leaf("=~", "message", &trop_long).is_none(), "`=~` : 513 octets -> FALLBACK");
    assert!(build_leaf("=", "message", &format!("~{trop_long}")).is_none(), "`=~…` : 513 octets -> FALLBACK");
    assert!(build_leaf(":", "message", &format!("~{trop_long}")).is_none(), "`:~…` : 513 octets -> FALLBACK");
    // Contre-épreuve : à la limite, la feuille reste vectorisée (le plafond ne mord pas trop tôt).
    assert!(matches!(build_leaf("=~", "message", &a_la_limite), Some(Pred::Regex { .. })));
    assert!(matches!(build_leaf("=", "message", &format!("~{a_la_limite}")), Some(Pred::Regex { .. })));
}

#[test]
fn feuille_regex_du_froid_refuse_le_programme_trop_gros() {
    let motif = r"\w{100}";
    assert!(regex::Regex::new(motif).is_ok(), "contre-épreuve : le défaut de la bibliothèque l'admettrait");
    assert!(build_leaf("=~", "message", motif).is_none(), "programme au-delà du plafond -> FALLBACK");
    assert!(matches!(build_leaf("=~", "message", r"code=5[0-9]"), Some(Pred::Regex { .. })));
}

#[test]
fn feuille_regex_du_froid_refuse_le_motif_multioctet_de_514_octets() {
    // 257 « é » : 514 octets, 257 caractères — la limite est en octets, au froid comme au chaud.
    let trop_long = "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2 + 1);
    let a_la_limite = "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2);
    assert!(trop_long.chars().count() <= LONGUEUR_MAX_DU_MOTIF && trop_long.len() > LONGUEUR_MAX_DU_MOTIF);
    assert!(build_leaf("=~", "message", &trop_long).is_none(), "`=~` : 514 octets -> FALLBACK");
    assert!(build_leaf("=", "message", &format!("~{trop_long}")).is_none(), "`=~…` : 514 octets -> FALLBACK");
    assert!(matches!(build_leaf("=~", "message", &a_la_limite), Some(Pred::Regex { .. })), "512 octets : vectorisé");
}
