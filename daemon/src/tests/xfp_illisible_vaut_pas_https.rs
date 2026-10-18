// `P10.32-t` (seconde relecture) — UNE LIGNE `X-Forwarded-Proto` ILLISIBLE VAUT « PAS HTTPS ».
//
// `https_annonce_par_les_entetes` lit toutes les lignes de l'en-tête ; une ligne qui n'est pas du texte visible (octet
// obs-text, accepté par `HeaderValue::from_bytes`) rend `false` pour toute la requête, même à côté d'une ligne `https`,
// au lieu d'être sautée.
//
// MUTANT JOUÉ (sous cfg!(test), par VERIF_MUT, retiré avant le commit) : `t_ligne_illisible_ignoree` (la ligne illisible
// est sautée) -> rouge.
mod xfp_illisible_vaut_pas_https {
    use super::*;

    fn entetes(lignes: &[&[u8]]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for l in lignes {
            h.append("x-forwarded-proto", axum::http::HeaderValue::from_bytes(l).expect("valeur d'en-tête acceptée"));
        }
        h
    }

    #[test]
    fn p1032t_une_ligne_x_forwarded_proto_illisible_vaut_pas_https() {
        let pair = "192.0.2.10";
        let liste = ["192.0.2.10".to_string()];
        // Contre-épreuve : deux lignes https d'un pair de la liste -> https.
        assert!(crate::auth::https_annonce_par_les_entetes(pair, &entetes(&[b"https", b"https"]), &liste), "contrôle : https annoncé");
        for lignes in [&[b"https".as_slice(), b"http\xff".as_slice()][..], &[b"http\xff".as_slice(), b"https".as_slice()][..], &[b"https\xff".as_slice()][..]] {
            assert!(
                !crate::auth::https_annonce_par_les_entetes(pair, &entetes(lignes), &liste),
                "une ligne X-Forwarded-Proto illisible a été ignorée : https cru ({lignes:?})"
            );
        }
    }
}
