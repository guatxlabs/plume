// =====================================================================================
// `P10.32-q` (reste « jetons Sigma hors `re` ») — TOUT JETON SIGMA PASSE PAR LE CONSTRUCTEUR DE L'UDF.
//
// LE DÉFAUT, LU SUR d6e44893 AVANT LE CORRECTIF. `sigma_regex_token` (`sigma.rs`), seule voie des jetons
// `contains`/`startswith`/`endswith`/égalité/mot-clé, ne comparait que `pattern.len()` à
// `LONGUEUR_MAX_DU_MOTIF` ; seule la branche `|re` compilait par `compiler_motif`. Un motif court que l'UDF
// refuse (programme au-delà de `PLAFOND_DU_PROGRAMME`, ou syntaxe) aurait été émis tel quel.
//
// LE CORRECTIF. `sigma_regex_token` délègue à `compiler_motif` : mêmes plafonds de longueur et de programme
// que l'UDF. Le dépassement du plafond de programme est un refus NOMMÉ
// (`REFUS_SIGMA_PLAFOND_DU_PROGRAMME`) qui dit la borne, jamais une lecture ratée.
//
// L'ATTEINTE, ÉTABLIE PAR L'EXÉCUTION (`jetons_hors_re_les_plus_lourds_tiennent_sous_le_plafond`) : les
// fragments générés hors `re` sont `(?i)`, `^`, `$`, `.` (pour `?`), `.*` (pour `*`) et des littéraux
// échappés. Les valeurs les plus lourdes que la longueur admet (`?` répété jusqu'à 512 octets, `*` répété,
// lettres à pliage de casse non ASCII `k`/`s`) se compilent SOUS le plafond : aucun jeton contains,
// startswith, endswith, égalité ou mot-clé n'atteint le plafond de programme. Le correctif ferme donc ce
// reste PAR CONSTRUCTION (un seul constructeur, parité tenue) ; il ne répare pas une règle muette observée.
// Marge mesurée sur d6e44893 (imprimée par le témoin, `--no-capture`) : le motif `?` au plus lourd demande
// un `size_limit` entre 256 Kio et 512 Kio, sous le plafond de 1 Mio ; `k`/`s` au plus lourd, au plus 128 Kio.
//
// MUTANTS (variable de mutation, retirés avant le commit) : `W3_LONGUEUR_SEULE` (retour au seul plafond de longueur),
// `W3_REFUS_ANONYME` (le dépassement du plafond de programme rendu par le message générique).
// =====================================================================================
mod sigma_jetons_hors_re_compiles_comme_l_udf {
    use crate::regex_de_requete::{compiler_motif, MotifRefuse, LONGUEUR_MAX_DU_MOTIF, PLAFOND_DU_PROGRAMME};
    use crate::sigma::{sigma_field_tokens, sigma_regex_token, sigma_selection_item, REFUS_SIGMA_PLAFOND_DU_PROGRAMME};
    use serde_json::{json, Value};

    /// Le motif d'un jeton `champ=~motif`.
    fn motif_du_jeton(jeton: &str) -> &str {
        jeton.split_once("=~").map(|(_, m)| m).expect("jeton regex attendu")
    }

    /// Plus petite puissance de deux de `size_limit` qui admet le motif (mesure de marge, imprimée).
    fn plus_petit_plafond_admis(motif: &str) -> usize {
        let mut limite = 1usize << 10;
        while regex::RegexBuilder::new(motif).size_limit(limite).build().is_err() {
            limite <<= 1;
            assert!(limite <= PLAFOND_DU_PROGRAMME << 4, "motif hors de toute borne raisonnable : {motif}");
        }
        limite
    }

    #[test]
    fn jeton_court_au_programme_trop_gros_refuse_par_un_refus_nomme() {
        let motif = r"\w{100}";
        assert!(motif.len() <= LONGUEUR_MAX_DU_MOTIF, "contre-épreuve : la longueur seule l'admettrait");
        assert!(
            matches!(compiler_motif(motif), Err(MotifRefuse::Invalide(regex::Error::CompiledTooBig(_)))),
            "contre-épreuve : l'UDF le refuse pour son programme"
        );
        let e = sigma_regex_token("CommandLine", motif).expect_err("l'import doit refuser ce que l'UDF refuse");
        assert!(e.contains(REFUS_SIGMA_PLAFOND_DU_PROGRAMME), "refus non nommé : {e}");
        assert!(e.contains(&PLAFOND_DU_PROGRAMME.to_string()), "la borne n'est pas dite : {e}");
        assert!(e.contains("non importée"), "{e}");
        assert!(!e.contains("lecture") && !e.contains("illisible"), "un plafond dit comme une lecture ratée : {e}");
    }

    #[test]
    fn jeton_court_syntaxiquement_invalide_refuse_sans_le_nom_du_plafond() {
        let e = sigma_regex_token("CommandLine", "*foo").expect_err("l'UDF refuse ce motif : l'import aussi");
        assert!(e.contains("invalide") && e.contains("non importée"), "{e}");
        assert!(!e.contains(REFUS_SIGMA_PLAFOND_DU_PROGRAMME), "une erreur de syntaxe n'est pas un plafond : {e}");
    }

    #[test]
    fn parite_avec_le_constructeur_de_l_udf() {
        let famille: Vec<String> = vec![
            "(?i)whoami".into(),
            format!("(?i){}", ".".repeat(LONGUEUR_MAX_DU_MOTIF - 4)),
            format!("(?i){}", ".".repeat(LONGUEUR_MAX_DU_MOTIF - 3)),
            format!("(?i)^{}$", ".*".repeat(253)),
            format!("(?i){}", "k".repeat(LONGUEUR_MAX_DU_MOTIF - 4)),
            "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2),
            "é".repeat(LONGUEUR_MAX_DU_MOTIF / 2 + 1),
            r"\w{100}".into(),
            r"\w{10}".into(),
            "*foo".into(),
            r"(?i)k{5000}".into(),
            r"\x{1f600}".into(),
        ];
        for motif in &famille {
            assert_eq!(
                sigma_regex_token("f", motif).is_ok(),
                compiler_motif(motif).is_ok(),
                "parité rompue pour {motif:?}"
            );
        }
    }

    #[test]
    fn jetons_hors_re_les_plus_lourds_tiennent_sous_le_plafond() {
        // (clé, valeur) : les valeurs les plus lourdes pour l'automate que la longueur admette encore.
        let place = |gabarit: usize| LONGUEUR_MAX_DU_MOTIF - gabarit;
        let cas: Vec<(&str, String)> = vec![
            ("CommandLine|contains", "?".repeat(place(4))),
            ("CommandLine|startswith", "?".repeat(place(5))),
            ("CommandLine|endswith", "?".repeat(place(5))),
            ("CommandLine", "?".repeat(place(6))),
            ("CommandLine|contains", "*".repeat(place(4) / 2)),
            ("CommandLine", "*?".repeat(place(6) / 3)),
            ("CommandLine|contains", "k".repeat(place(4))),
            ("CommandLine|contains", "s".repeat(place(4))),
            ("CommandLine|contains|all", "?".repeat(place(4))),
        ];
        for (cle, valeur) in &cas {
            let v = if cle.ends_with("|all") { json!([valeur, valeur]) } else { Value::String(valeur.clone()) };
            let jetons = sigma_field_tokens(cle, &v)
                .unwrap_or_else(|e| panic!("{cle} ({} octets) : le plafond de programme est atteint : {e}", valeur.len()));
            for jeton in &jetons {
                let motif = motif_du_jeton(jeton);
                assert!(compiler_motif(motif).is_ok(), "parité : jeton émis que l'UDF refuserait : {motif}");
                eprintln!(
                    "{cle} : motif de {} octets, admis dès size_limit = {} (plafond {PLAFOND_DU_PROGRAMME})",
                    motif.len(),
                    plus_petit_plafond_admis(motif)
                );
            }
        }
        // Mot-clé (littéral sans joker) au pliage de casse non ASCII.
        let jetons = sigma_selection_item(&Value::String("k".repeat(place(4)))).expect("mot-clé au plus lourd");
        assert!(compiler_motif(motif_du_jeton(&jetons[0])).is_ok());
        // Contre-épreuve : un octet de plus et c'est la LONGUEUR qui refuse, avec son message — ces valeurs
        // sont bien les plus longues admises.
        let e = sigma_field_tokens("CommandLine|contains", &Value::String("?".repeat(place(4) + 1))).unwrap_err();
        assert!(e.contains("trop long"), "{e}");
    }

    #[test]
    fn regle_hors_re_au_plus_lourd_traduite_par_le_point_d_entree() {
        let doc = json!({
            "title": "Jokers au plus lourd",
            "logsource": { "category": "process_creation", "product": "windows" },
            "detection": { "selection": { "CommandLine|contains": "?".repeat(LONGUEUR_MAX_DU_MOTIF - 4) }, "condition": "selection" },
            "level": "low"
        });
        let t = crate::sigma::sigma_translate(&doc).expect("traduite : aucun plafond de programme atteint");
        let motif = t.query.split("CommandLine=~").nth(1).and_then(|r| r.split_whitespace().next()).expect("jeton présent");
        assert!(compiler_motif(motif).is_ok(), "{motif}");
    }
}
