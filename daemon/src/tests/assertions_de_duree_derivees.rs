    /// `P8.27-d` (4) — LE BALAYAGE DES ASSERTIONS DE DURÉE D'HORLOGE EST DÉRIVÉ, PLUS ÉCRIT À LA MAIN.
    ///
    /// Le balayage de `P7.19-b` (commentaire de `query_verify.rs`) énumérait ses membres à la main ; la
    /// cellule `P8.27-d` a mesuré qu'il rendait une population plus étroite que le critère qu'il énonce,
    /// et oubliait un membre écrit dans le fichier même qui l'énonçait. Ici le CRITÈRE est appliqué par
    /// la machine, sur tous les fichiers de tests du démon : est MEMBRE une assertion dont la condition
    /// borne PAR LE HAUT (`<`, `<=`) une durée d'horloge MESURÉE — `.elapsed()` en clair, ou un nom lié
    /// dans le même fichier à un `.elapsed()` / à une durée rendue par un banc (`duree_ms`) — par une
    /// CONSTANTE ABSOLUE (un littéral, `Duration::from_*(…)`, ou un nom en capitales). Une borne
    /// INFÉRIEURE après un sommeil injecté, ou une RELATION entre deux mesures de la même fenêtre, n'est
    /// pas membre : la lenteur de la machine ne peut pas les faire rougir. C'est le critère du balayage,
    /// mot pour mot.
    ///
    /// Chaque membre trouvé doit être TRAITÉ — nommé ci-dessous avec sa raison (étalonné, filet
    /// d'instrument, borne elle-même temporelle, ou NON TRAITÉ et dit) — et un membre neuf, écrit
    /// demain dans n'importe quel fichier, rougit tant qu'il n'est pas nommé. L'instrument se valide :
    /// il doit trouver au moins trois membres et au moins un fichier qui mesure une horloge, sans quoi
    /// il serait vert par vacuité.
    #[test]
    fn les_assertions_sur_une_duree_d_horloge_sont_derivees_et_chacune_est_traitee() {
        /// (fichier, fragment de la condition, raison) — la population TRAITÉE, avec sa raison écrite.
        const TRAITEES: &[(&str, &str, &str)] = &[
            ("cases.rs", "d < std::time::Duration::from_secs(2)",
             "NON TRAITÉ, et dit (`P7.19-b`) : un tick jugé contre un mur sans étalonnage ni canal de refus — le corriger demande une concordance ou le canal partagé"),
            ("entrees_scriptees_bornees.rs", "duree_ms < 10_000",
             "la borne jugée est elle-même une durée d'horloge (TIMEOUT=1 s), marge 10× : il n'y a pas de mesure sans horloge à cet endroit"),
            ("entrees_scriptees_bornees.rs", "duree_ms < 5_000",
             "même banc, plafond de lignes sur une commande infinie : la coupe est par nature temporelle, marge 5×"),
            ("vieillissement_serie.rs", "mur0.elapsed() < MUR_MAX",
             "FILET d'instrument (600× le CPU visé) : son message impute l'oracle qui n'avance pas, jamais la machine lente"),
            // LE MEMBRE QUE LE BALAYAGE À LA MAIN AVAIT OUBLIÉ, dans le fichier même qui l'énonçait (`P8.27-d`) :
            // trouvé par ce témoin à sa première exécution.
            ("query_verify.rs", "attente < QB_FILET_MS",
             "FILET (le message le dit) : 12× le plus gros budget, 500× au-dessus de la pire latence d'interruption mesurée et 7× sous la durée naturelle de la requête témoin — il ne mesure pas, il détecte une garde qui n'a pas tiré"),
        ];
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tests");
        let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir(&racine).unwrap().flatten().map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs")).collect();
        fichiers.sort();
        let est_constante = |cote: &str| -> bool {
            let c = cote.trim().trim_end_matches(',');
            let c = c.trim();
            let litteral = c.chars().next().is_some_and(|ch| ch.is_ascii_digit());
            let duree = c.contains("Duration::from_");
            let capitale = !c.is_empty() && c.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch.is_ascii_digit()) && c.chars().any(|ch| ch.is_ascii_uppercase());
            litteral || duree || capitale
        };
        let mut membres: Vec<(String, String)> = Vec::new();
        let mut fichiers_avec_horloge = 0usize;
        for f in &fichiers {
            let src = std::fs::read_to_string(f).unwrap();
            let nom = f.file_name().unwrap().to_string_lossy().into_owned();
            if src.contains(".elapsed()") || src.contains("duree_ms") { fichiers_avec_horloge += 1; }
            // Les NOMS liés à une mesure d'horloge dans ce fichier : `let X = …elapsed()…` et les durées
            // rendues par un banc (`duree_ms`, quelle que soit la liaison).
            let mut noms: Vec<String> = vec!["duree_ms".to_string()];
            for l in src.lines() {
                let t = l.trim_start();
                if t.starts_with("let ") && t.contains(".elapsed()") {
                    if let Some(reste) = t.strip_prefix("let ") {
                        let ident: String = reste.trim_start_matches("mut ").chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                        if !ident.is_empty() { noms.push(ident); }
                    }
                }
            }
            // Chaque assertion, prise ENTIÈRE (parenthèses équilibrées), réduite à sa condition (premier
            // argument), les commentaires écartés.
            let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
            let mut pos = 0usize;
            while let Some(i) = code[pos..].find("assert!(") {
                let debut = pos + i + "assert!(".len();
                let (mut prof, mut fin, mut virgule) = (1i32, None, None);
                for (k, ch) in code[debut..].char_indices() {
                    match ch {
                        '(' | '[' | '{' => prof += 1,
                        ')' | ']' | '}' => { prof -= 1; if prof == 0 { fin = Some(debut + k); break; } }
                        ',' if prof == 1 && virgule.is_none() => virgule = Some(debut + k),
                        _ => {}
                    }
                }
                let Some(fin) = fin else { break };
                let condition = code[debut..virgule.unwrap_or(fin)].split_whitespace().collect::<Vec<_>>().join(" ");
                pos = fin;
                // Une borne par le HAUT : `<` ou `<=` hors `<<` et hors chevrons de type.
                let Some(op) = condition.find(" < ").or_else(|| condition.find(" <= ")) else { continue };
                let (gauche, droite) = (&condition[..op], &condition[op + 3..]);
                let mesure = gauche.contains(".elapsed()")
                    || noms.iter().any(|n| gauche.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == n));
                if mesure && est_constante(droite) {
                    membres.push((nom.clone(), condition.clone()));
                }
            }
        }
        assert!(fichiers_avec_horloge >= 3, "INSTRUMENT : {fichiers_avec_horloge} fichier(s) de tests mesurent une horloge — le balayage ne verrait rien");
        assert!(membres.len() >= 3, "INSTRUMENT : {} membre(s) trouvés — le critère ne reconnaît plus ce qu'il reconnaissait ({:?})", membres.len(), membres);
        let mut non_traites = Vec::new();
        for (fichier, condition) in &membres {
            let traitee = TRAITEES.iter().any(|(f, frag, _)| f == fichier && condition.contains(frag));
            if !traitee { non_traites.push(format!("{fichier} : `{condition}`")); }
        }
        assert!(
            non_traites.is_empty(),
            "{} assertion(s) bornent par le haut une durée d'horloge MESURÉE par une constante absolue sans être TRAITÉES — la lenteur \
             de la machine peut les faire rougir en disant « propriété violée » là où la vérité est « pas pu mesurer ». Étalonnez-les \
             (concordance, canal de refus) ou nommez-les dans TRAITEES avec leur raison :\n{}",
            non_traites.len(), non_traites.join("\n")
        );
        // Une exemption qui ne correspond plus à rien est une liste morte : elle rougit aussi.
        for (f, frag, _) in TRAITEES {
            assert!(membres.iter().any(|(fi, c)| fi == f && c.contains(frag)), "exemption sans objet : {f} `{frag}` — l'assertion a bougé ou disparu, mettre la liste à jour");
        }
        println!("[durées] {} membre(s) dérivés dans {} fichier(s) mesurant une horloge : {:?}", membres.len(), fichiers_avec_horloge, membres);
    }
