    // ============================================================================================
    // P11.6-a — UNE TECHNIQUE ATT&CK NE SE LIT PAS PAR SON SEUL NUMÉRO.
    // La matrice de couverture (`/api/coverage/attack`) servait des identifiants sans nom : le champ
    // `name` que lit la surface n'était jamais émis. Les témoins ci-dessous DÉRIVENT leur population —
    // le catalogue du cœur, les techniques citées par les règles LIVRÉES (sources de seeds + overlays
    // `config.d`) — et n'énumèrent aucun identifiant à la main, sauf pour les témoins de forme.
    // ============================================================================================

    /// Tout identifiant `T####[.###]` cité dans un texte livré. Dérivé par motif, pas par liste.
    fn techniques_citees_dans(texte: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let b = texte.as_bytes();
        let mut i = 0;
        while i + 5 <= b.len() {
            if b[i] == b'T' && b[i + 1..i + 5].iter().all(|c| c.is_ascii_digit()) && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
                let mut j = i + 5;
                if j + 4 <= b.len() && b[j] == b'.' && b[j + 1..j + 4].iter().all(|c| c.is_ascii_digit()) {
                    j += 4;
                }
                if j >= b.len() || !b[j].is_ascii_alphanumeric() {
                    out.insert(std::str::from_utf8(&b[i..j]).unwrap().to_string());
                }
                i = j;
                continue;
            }
            i += 1;
        }
        out
    }

    /// Les fichiers de règles livrés sous `config.d` (règles, catalogue, Sigma), lus depuis l'arbre.
    fn textes_des_regles_livrees() -> Vec<(String, String)> {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("config.d");
        let mut out = Vec::new();
        let mut pile = vec![racine.join("rules"), racine.join("sigma")];
        while let Some(dir) = pile.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    pile.push(p);
                } else if let Ok(t) = std::fs::read_to_string(&p) {
                    out.push((p.display().to_string(), t));
                }
            }
        }
        out.push(("daemon/src/seeds.rs".into(), include_str!("../seeds.rs").to_string()));
        out
    }

    #[test]
    fn p11_6a_chaque_technique_du_catalogue_a_un_nom() {
        let sans_nom: Vec<&str> = guatx_core::attack::CATALOG
            .iter()
            .map(|(tid, _)| *tid)
            .filter(|tid| crate::attack_names::technique_name(tid).map(|n| n.trim().is_empty()).unwrap_or(true))
            .collect();
        assert!(sans_nom.is_empty(), "techniques du catalogue sans nom : {sans_nom:?}");
        // Réciproque : un nom qui ne désigne plus une technique du catalogue est une dérive de la table.
        let catalogue: std::collections::HashSet<&str> = guatx_core::attack::CATALOG.iter().map(|(t, _)| *t).collect();
        let hors_catalogue: Vec<&str> = crate::attack_names::TECHNIQUE_NAMES.iter().map(|(t, _)| *t).filter(|t| !catalogue.contains(t)).collect();
        assert!(hors_catalogue.is_empty(), "noms sans technique au catalogue : {hors_catalogue:?}");
        assert!(guatx_core::attack::CATALOG.len() >= 150, "plancher de population : le catalogue a maigri ({})", guatx_core::attack::CATALOG.len());
    }

    #[test]
    fn p11_6a_chaque_technique_citee_par_une_regle_livree_a_un_nom() {
        let textes = textes_des_regles_livrees();
        assert!(textes.len() >= 10, "plancher : {} fichiers de règles livrées lus, la découverte est cassée", textes.len());
        let mut citees = std::collections::BTreeSet::new();
        for (_, t) in &textes {
            citees.extend(techniques_citees_dans(t));
        }
        assert!(citees.len() >= 20, "plancher : {} techniques citées par les règles livrées", citees.len());
        let sans_nom: Vec<&String> = citees.iter().filter(|t| crate::attack_names::technique_name(t).is_none()).collect();
        assert!(sans_nom.is_empty(), "techniques citées par une règle livrée et SANS nom : {sans_nom:?}");
        // Une sous-technique citée se résout par elle-même ou par son parent, jamais en chaîne vide.
        for t in citees.iter().filter(|t| t.contains('.')) {
            let n = crate::attack_names::technique_name(t).unwrap();
            assert!(n.contains(": ") || n.contains("sous-technique"), "{t} -> « {n} »");
        }
    }

    #[test]
    fn p11_6a_la_matrice_porte_le_nom_a_cote_de_l_identifiant() {
        let tags = vec!["T1110.003".to_string(), "T1190".to_string(), "T9999".to_string()];
        let v = crate::handlers::alerts::build_attack_matrix(&tags, &HashMap::new());
        let mut vus = 0;
        let mut inconnus = Vec::new();
        for tac in v["tactics"].as_array().unwrap() {
            for t in tac["techniques"].as_array().unwrap() {
                vus += 1;
                let tid = t["tid"].as_str().unwrap();
                match t.get("name") {
                    Some(Value::String(n)) => assert!(!n.trim().is_empty(), "{tid} : nom vide"),
                    Some(Value::Null) | None => inconnus.push(tid.to_string()),
                    other => panic!("{tid} : forme de nom inattendue {other:?}"),
                }
            }
        }
        assert!(vus >= 150, "la matrice a rendu {vus} techniques");
        // Le SEUL identifiant sans nom est celui hors catalogue, replié dans `unmapped` : le client doit
        // pouvoir distinguer « nom inconnu » (null) d'un nom — jamais une chaîne vide ambiguë.
        assert_eq!(inconnus, vec!["T9999".to_string()], "identifiants rendus sans nom");
        let t1110 = v["tactics"].as_array().unwrap().iter().flat_map(|t| t["techniques"].as_array().unwrap().clone()).find(|t| t["tid"] == "T1110").unwrap();
        assert_eq!(t1110["name"], "Brute Force");
        assert_eq!(t1110["rule_count"], 1, "T1110.003 compte pour sa parente T1110");
    }

    #[test]
    fn p11_6a_resolution_des_sous_techniques_et_des_identifiants_hors_format() {
        use crate::attack_names::technique_name as nom;
        assert_eq!(nom("T1110").as_deref(), Some("Brute Force"));
        assert_eq!(nom("t1110.003 ").as_deref(), Some("Brute Force: Password Spraying"), "casse et blancs tolérés");
        assert_eq!(nom("T1110.999").as_deref(), Some("Brute Force (sous-technique .999)"), "sous-technique inconnue -> résolue par le parent, dite comme telle");
        assert_eq!(nom("T9999"), None, "hors catalogue -> None, jamais une chaîne vide");
        assert_eq!(nom("foo"), None);
        assert_eq!(nom("T1110.x"), None);
        assert!(nom("T1488").unwrap().contains("retiré"), "un identifiant retiré d'ATT&CK le dit dans son nom");
    }
