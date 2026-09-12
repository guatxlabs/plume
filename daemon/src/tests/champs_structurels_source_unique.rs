// `P11.19-a` (second volet, groundwork) — LES CHAMPS STRUCTURELS ONT UNE SOURCE UNIQUE.
//
// `field_filter::STRUCTURAL_DENY` était RECOPIÉ verbatim dans `knowledge.rs` : deux listes littérales du même
// ensemble, qu'une édition pouvait faire DÉRIVER — un champ structurel ajouté à l'une mais pas à l'autre, et
// un chemin (aliasing de savoir) aurait laissé RÉÉCRIRE un nom que l'autre (filtre de champ) refuse, cassant
// pagination/temps/anti-doublon/routage. La copie est retirée ; `knowledge::validate_ko_ident` lit désormais
// l'AUTORITÉ. Ce témoin dérive sa population de l'autorité elle-même : si l'ensemble grandit, il couvre le
// nouveau champ sans être touché, et une re-duplication qui laisserait tomber un champ le fait ROUGIR.

#[test]
fn les_champs_structurels_de_l_autorite_sont_refuses_comme_objet_de_savoir() {
    for &champ in crate::field_filter::STRUCTURAL_DENY {
        assert!(
            crate::knowledge::validate_ko_ident(champ).is_err(),
            "champ structurel `{champ}` de l'autorité DOIT être refusé par validate_ko_ident (source unique)"
        );
    }
    // Témoin négatif : un nom NON structurel passe — sinon la garde refuserait tout et ne prouverait rien.
    assert!(
        crate::knowledge::validate_ko_ident("mon_champ").is_ok(),
        "un champ non structurel doit passer la validation d'objet de savoir"
    );
}
