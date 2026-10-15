    // ================================================================================================
    // `P10.32-k` (côté démon) — `dataacl` entre au canal d'aveu (`collected::SOURCES_DU_CANAL_D_AVEU`) AVANT
    // que `collectors/dataacl.sh` n'appelle une aide d'aveu. Le miroir table == texte des capteurs
    // (`champs_etendus_servis_par_source.rs`) tolère cet écart pour les SEULES sources annoncées ci-dessous,
    // et se tait seul le jour où le capteur nomme la source (lu ⊇ annoncées : attendu == lu). Les témoins :
    //   1. épreuves synthétiques de l'écart : une source de la table ni lue ni annoncée rougit ; une source
    //      annoncée retirée de la table rougit ; une source lue absente de la table rougit ; l'arrivée du
    //      capteur ne rougit rien ;
    //   2. sur les constantes réelles : chaque annoncée est une source livrée, est dans la table, et la route
    //      lui sert les couples cités `lib.sh`.
    // Ce que ces témoins ne tiennent pas : le capteur lui-même (lot de la session des capteurs), et le
    // contenu servi entre les deux dates (champs de `lib.sh` listés pour `dataacl` sans qu'il les écrive).
    // Mutants joués (variable d environnement sous cfg!(test), retirés avant le commit) : `SANS_DATAACL` (la route n'impute plus
    // lib.sh à dataacl), `EXCEPTION_ELARGIE` (toute source de la table absente du texte tolérée), `ATTENDU_LU_SEUL`
    // (attendu = lu, sans les annoncées : rougit tant que le capteur manque).
    // ================================================================================================

    /// Sources inscrites au canal d'aveu AVANT que leur capteur ne les nomme littéralement. Une entrée
    /// devient inerte (rien à retoucher) le jour où le capteur la nomme ; elle ne se retire qu'à ce moment.
    const CESP_AVEU_ANNONCEES: &[&str] = &["dataacl"];

    /// Ce que `SOURCES_DU_CANAL_D_AVEU` doit valoir : les sources lues dans le texte des capteurs, plus les annoncées.
    fn cesp_aveu_attendu(lu: &std::collections::BTreeSet<String>, annoncees: &[&str]) -> std::collections::BTreeSet<String> {
        let mut attendu = lu.clone();
        attendu.extend(annoncees.iter().map(|s| s.to_string()));
        attendu
    }

    /// Les écarts entre la table et l'attendu, dans les DEUX sens, chacun nommé.
    fn cesp_ecarts_du_canal_d_aveu(
        table: &std::collections::BTreeSet<String>,
        lu: &std::collections::BTreeSet<String>,
        annoncees: &[&str],
    ) -> Vec<String> {
        let attendu = cesp_aveu_attendu(lu, annoncees);
        let mut ecarts: Vec<String> = table
            .difference(&attendu)
            .map(|s| format!("{s} : dans la table, ni nommée par un capteur ni annoncée"))
            .collect();
        ecarts.extend(attendu.difference(table).map(|s| format!("{s} : nommée par un capteur ou annoncée, absente de la table")));
        ecarts
    }

    fn cesp_ensemble(v: &[&str]) -> std::collections::BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn le_canal_d_aveu_ne_tolere_que_la_source_annoncee() {
        let lu = cesp_ensemble(&["clamav", "fail2ban"]);
        let ann = &["dataacl"][..];
        // Avant le capteur : table = lu ∪ annoncées, aucun écart.
        assert!(cesp_ecarts_du_canal_d_aveu(&cesp_ensemble(&["clamav", "dataacl", "fail2ban"]), &lu, ann).is_empty());
        // Une source de la table ni lue ni annoncée : rouge, et nommée.
        let e = cesp_ecarts_du_canal_d_aveu(&cesp_ensemble(&["clamav", "dataacl", "fail2ban", "minio"]), &lu, ann);
        assert!(e.len() == 1 && e[0].starts_with("minio :"), "{e:?}");
        // L'annoncée retirée de la table : rouge.
        let e = cesp_ecarts_du_canal_d_aveu(&cesp_ensemble(&["clamav", "fail2ban"]), &lu, ann);
        assert!(e.len() == 1 && e[0].starts_with("dataacl :"), "{e:?}");
        // Une source lue dans le texte, absente de la table : rouge.
        let lu_plus = cesp_ensemble(&["clamav", "fail2ban", "web"]);
        let e = cesp_ecarts_du_canal_d_aveu(&cesp_ensemble(&["clamav", "dataacl", "fail2ban"]), &lu_plus, ann);
        assert!(e.len() == 1 && e[0].starts_with("web :"), "{e:?}");
        // Le capteur arrive et nomme la source : l'exception se tait, rien à retoucher.
        let lu_apres = cesp_ensemble(&["clamav", "dataacl", "fail2ban"]);
        assert!(cesp_ecarts_du_canal_d_aveu(&cesp_ensemble(&["clamav", "dataacl", "fail2ban"]), &lu_apres, ann).is_empty());
    }

    #[test]
    fn la_source_annoncee_est_au_canal_d_aveu_et_en_recoit_les_champs() {
        let table: std::collections::BTreeSet<String> = crate::collected::SOURCES_DU_CANAL_D_AVEU.iter().map(|s| s.to_string()).collect();
        assert!(CESP_AVEU_ANNONCEES.contains(&"dataacl"), "{CESP_AVEU_ANNONCEES:?}");
        let lib: Vec<&str> = crate::collected::couples_etendus().into_iter().filter(|(_, c)| *c == "lib.sh").map(|(f, _)| f).collect();
        assert!(lib.len() >= 5, "couples cités lib.sh : {lib:?}");
        for s in CESP_AVEU_ANNONCEES {
            assert!(table.contains(*s), "{s} annoncée mais absente de SOURCES_DU_CANAL_D_AVEU");
            assert!(crate::handlers::sources::SOURCES_LIVREES.iter().any(|(l, _)| l == s), "{s} annoncée mais pas une source livrée");
            // Ce que la route sert : les couples du fichier émetteur ET ceux de lib.sh, exactement.
            let servi = crate::handlers::sources::champs_etendus_de_source(s).unwrap_or_else(|| panic!("{s} : servi null"));
            let emetteur = cesp_fichier_de(s).unwrap().rsplit('/').next().unwrap();
            let mut attendu: Vec<&str> = crate::collected::couples_etendus().into_iter()
                .filter(|(_, c)| *c == "lib.sh" || *c == emetteur).map(|(f, _)| f).collect();
            attendu.sort_unstable();
            attendu.dedup();
            assert_eq!(servi, attendu, "{s} : champs servis ≠ couples de {emetteur} ∪ couples de lib.sh");
            for c in &lib {
                assert!(servi.contains(c), "{s} : le canal d'aveu écrit `{c}`, non servi");
            }
        }
    }
