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
        let v = crate::handlers::alerts::build_attack_matrix(&tags, &[], &[], &HashMap::new());
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

    // ============================================================================================
    // P11.6-c — LE CATALOGUE EST SERVI ENTIER PAR UNE ROUTE DÉDIÉE, ET LA CONSOLE N'EN PORTE PLUS.
    // Ce que le démon nomme, la route le sert tel quel : chaque technique du catalogue du cœur, chaque
    // sous-technique nommée, le gabarit du cas « parent seul connu », et les deux comptes. Le premier
    // témoin confronte l'objet servi à `technique_name` sur TOUTE la population (dérivée, jamais listée) ;
    // le second traverse le routeur réel : un lecteur reçoit l'objet, une requête sans identité est refusée.
    // ============================================================================================

    #[test]
    fn p11_6c_le_catalogue_servi_nomme_chaque_technique_comme_le_demon() {
        use crate::attack_names::{catalogue_attack_json, technique_name, FORME_SOUS_TECHNIQUE_INCONNUE, SUBTECHNIQUE_NAMES};
        let v = catalogue_attack_json();
        let techniques = v["techniques"].as_object().expect("`techniques` est un objet");
        let sous = v["sub_techniques"].as_object().expect("`sub_techniques` est un objet");
        // Population : exactement le catalogue du cœur, et exactement les sous-techniques nommées — une technique
        // que le démon ne saurait pas nommer MANQUERAIT ici, et ce compte la trahit.
        assert_eq!(techniques.len(), guatx_core::attack::CATALOG.len(), "techniques servies ≠ catalogue du cœur");
        assert_eq!(sous.len(), SUBTECHNIQUE_NAMES.len(), "sous-techniques servies ≠ sous-techniques nommées");
        assert_eq!(v["counts"]["techniques"].as_u64(), Some(techniques.len() as u64));
        assert_eq!(v["counts"]["sub_techniques"].as_u64(), Some(sous.len() as u64));
        for (tid, tactique) in guatx_core::attack::CATALOG {
            let servi = techniques.get(*tid).unwrap_or_else(|| panic!("{tid} absente du catalogue servi"));
            assert_eq!(servi["name"].as_str(), technique_name(tid).as_deref(), "{tid} : le nom servi n'est pas celui que le démon rend");
            assert!(!servi["name"].as_str().unwrap_or("").trim().is_empty(), "{tid} : nom servi vide");
            assert_eq!(servi["tactic"].as_str(), Some(*tactique), "{tid} : tactique servie");
        }
        for (sid, _) in SUBTECHNIQUE_NAMES {
            let servi = sous.get(*sid).unwrap_or_else(|| panic!("{sid} absente des sous-techniques servies"));
            assert_eq!(servi["name"].as_str(), technique_name(sid).as_deref(), "{sid} : nom composé servi ≠ démon");
            assert!(servi["name"].as_str().unwrap().contains(": "), "{sid} : une sous-technique connue se sert composée « Parent: Sous-technique »");
            assert_eq!(servi["parent"].as_str(), guatx_core::attack::parent_technique(sid).as_deref(), "{sid} : parent servi");
        }
        // Le gabarit servi est CELUI que `technique_name` applique : composé côté client avec le nom servi du
        // parent, il rend mot pour mot ce que le démon rendrait pour une sous-technique qu'il ne connaît pas.
        let gabarit = v["forms"]["unknown_sub_technique"].as_str().expect("gabarit servi");
        assert_eq!(gabarit, FORME_SOUS_TECHNIQUE_INCONNUE);
        let parent = techniques["T1110"]["name"].as_str().unwrap();
        let compose = gabarit.replace("{parent}", parent).replace("{n}", "999");
        assert_eq!(Some(compose), technique_name("T1110.999"), "composition client ≠ composition démon");
        assert!(gabarit.contains("{parent}") && gabarit.contains("{n}"), "un gabarit sans ses deux trous ne compose rien");
    }

    #[tokio::test]
    async fn p11_6c_la_route_du_catalogue_est_lue_par_un_lecteur_et_refusee_sans_identite() {
        let (st, _base) = router_test_state("catalogue-attack");
        let addr = router_serve(st).await;
        let (sans_identite, _) = router_probe_corps(addr, "GET", "/api/attack/catalogue", None, &[]).await;
        assert_eq!(sans_identite, 401, "le catalogue reste derrière l'identité, comme tout /api/");
        use base64::Engine as _;
        let lecteur = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("vwr:viewerpw12345"));
        let (statut, corps) = lire_le_corps_entier(addr, "/api/attack/catalogue", &lecteur).await;
        assert_eq!(statut, 200, "un lecteur reçoit le catalogue");
        let v: Value = serde_json::from_str(&corps).unwrap_or_else(|e| panic!("corps non-JSON ({e}) : {}", &corps[..corps.len().min(200)]));
        assert_eq!(v, crate::attack_names::catalogue_attack_json(), "la route sert l'objet que la fonction pure rend, sans rien y ajouter ni retirer");
        // Les deux identifiants rencontrés SANS NOM en usage réel (2026-08-27) : la technique est servie nommée,
        // la sous-technique d'exploitant se compose du parent servi et du gabarit servi.
        assert_eq!(v["techniques"]["T1562"]["name"], "Impair Defenses");
        let parent = v["techniques"]["T1195"]["name"].as_str().unwrap();
        let compose = v["forms"]["unknown_sub_technique"].as_str().unwrap().replace("{parent}", parent).replace("{n}", "002");
        assert_eq!(Some(compose), crate::attack_names::technique_name("T1195.002"));
    }

    /// Recolle un corps en transfert morcelé : `taille-hex\r\n octets \r\n … 0\r\n\r\n`. Sur les octets, pas sur des
    /// caractères. Le routeur sert ses corps `Json` ainsi (mesuré le 2026-09-10 : « 3649\r\n{… ») : un témoin de
    /// route qui lit le corps après la ligne vide reçoit les tailles dans son JSON s'il ne recolle pas.
    fn demorceler(b: &[u8]) -> String {
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let fin_taille = b[i..].windows(2).position(|w| w == b"\r\n").map(|k| i + k).unwrap_or(b.len());
            let taille_txt = std::str::from_utf8(&b[i..fin_taille]).unwrap_or("0").split(';').next().unwrap_or("0").trim();
            let taille = usize::from_str_radix(taille_txt, 16).unwrap_or(0);
            if taille == 0 { break; }
            let debut = fin_taille + 2;
            let fin = (debut + taille).min(b.len());
            out.extend_from_slice(&b[debut..fin]);
            i = fin + 2;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// GET authentifié sur le routeur réel -> (statut, corps ENTIER recollé). Lit jusqu'à EOF (`Connection: close`)
    /// et dé-morcelle si la réponse est en transfert morcelé — la sonde bornée de `rbac.rs` ne garde qu'un début.
    async fn lire_le_corps_entier(addr: std::net::SocketAddr, chemin: &str, authz: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!("GET {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: {authz}\r\n\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let txt = String::from_utf8_lossy(&buf).into_owned();
        let statut: u16 = txt.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        let brut = txt.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        let corps = if txt.to_ascii_lowercase().contains("transfer-encoding: chunked") { demorceler(brut.as_bytes()) } else { brut };
        (statut, corps)
    }
