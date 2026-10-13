// P7.18-a — LES RÉ-EXPORTS DE LA FAÇADE `sqlite_plafond` QUE SEULS LES TESTS LISENT SONT SOUS `cfg(test)`
// ================================================================================================
// `controle_positif_de_la_mesure`, `quota_pour` (feuille `quota_deversement`) et `residus_de_deversement`
// (feuille `repertoire_de_deversement`) étaient ré-exportés par la façade SANS `cfg(test)` : la production
// les prend à la source, seuls des tests passent par `crate::sqlite_plafond::…`, et le binaire compilait
// avec deux avertissements `unused import` (`cargo check --features ldap,cold_tier`, sqlite_plafond.rs:153
// et :168 à 2e4fe6eb). Ce témoin tient :
//   (a) aucun des trois n'est ré-exporté par le texte de PRODUCTION de la façade ;
//   (b) les noms que la production lit par la façade y restent ré-exportés (déplacement pur, rien perdu) ;
//   (c) le juge n'est pas vacant : sur les deux `use` d'avant, il trouve les trois noms.
// CE QU'IL NE PROUVE PAS : l'absence d'avertissement elle-même — seule la compilation hors test la montre.

#[cfg(test)]
mod reexports_du_plafond_hors_production_tests {
    use crate::db_open::door_tests::texte_de_production;

    const FACADE: &str = "sqlite_plafond.rs";
    const RESERVES_AUX_TESTS: [&str; 3] = ["controle_positif_de_la_mesure", "quota_pour", "residus_de_deversement"];
    const LUS_PAR_LA_PRODUCTION: [&str; 5] =
        ["oublier_refus_de_quota", "phrase_du_quota", "refus_de_quota_de_deversement", "QuotaDeversement", "deversement_init"];
    /// Les deux `use` de la façade tels qu'ils étaient à 2e4fe6eb.
    const AVANT: &str = "pub(crate) use crate::quota_deversement::{\n    controle_positif_de_la_mesure, oublier_refus_de_quota, phrase_du_quota, quota_pour, refus_de_quota_de_deversement,\n    QuotaDeversement,\n};\npub(crate) use crate::repertoire_de_deversement::{deversement_init, residus_de_deversement};\n";

    /// Les noms ré-exportés (`pub(crate) use …`) par le texte de PRODUCTION de `src` (items `#[cfg(test)]`
    /// et commentaires retirés), instruction jointe jusqu'à son `;`.
    fn reexports_de_production(src: &str) -> Vec<String> {
        let lignes: Vec<String> = texte_de_production(std::path::Path::new(FACADE), src).into_iter().map(|(_, l)| l).collect();
        let mut noms = Vec::new();
        let mut i = 0;
        while i < lignes.len() {
            if !lignes[i].starts_with("pub(crate) use ") {
                i += 1;
                continue;
            }
            let mut instr = String::new();
            while i < lignes.len() {
                instr.push_str(&lignes[i]);
                instr.push(' ');
                i += 1;
                if instr.trim_end().ends_with(';') {
                    break;
                }
            }
            let corps = instr.trim().trim_end_matches(';');
            let liste = match (corps.find('{'), corps.rfind('}')) {
                (Some(a), Some(b)) => corps[a + 1..b].to_string(),
                _ => corps.rsplit("::").next().unwrap_or("").to_string(),
            };
            noms.extend(liste.split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()));
        }
        noms
    }

    fn facade() -> String {
        std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join(FACADE)).unwrap()
    }

    #[test]
    fn a_les_trois_reexports_lus_par_les_seuls_tests_sont_hors_production() {
        let prod = reexports_de_production(&facade());
        let fautifs: Vec<_> = RESERVES_AUX_TESTS.iter().filter(|n| prod.iter().any(|p| p == *n)).collect();
        assert!(fautifs.is_empty(), "ré-exportés hors `cfg(test)` par {FACADE} : {fautifs:?} — import inutilisé du binaire");
    }

    #[test]
    fn b_les_noms_lus_par_la_production_restent_reexportes() {
        let prod = reexports_de_production(&facade());
        let perdus: Vec<_> = LUS_PAR_LA_PRODUCTION.iter().filter(|n| !prod.iter().any(|p| p == *n)).collect();
        assert!(perdus.is_empty(), "{FACADE} ne ré-exporte plus en production : {perdus:?}\n{prod:?}");
    }

    #[test]
    fn c_le_juge_trouve_les_trois_noms_dans_l_etat_d_avant() {
        let prod = reexports_de_production(AVANT);
        for n in RESERVES_AUX_TESTS.iter().chain(LUS_PAR_LA_PRODUCTION.iter()) {
            assert!(prod.iter().any(|p| p == n), "le juge ne voit pas `{n}` dans l'état d'avant : {prod:?}");
        }
        // un `use` sous `cfg(test)` n'est pas de la production.
        assert!(reexports_de_production("#[cfg(test)]\npub(crate) use crate::x::{quota_pour};\n").is_empty());
    }
}
