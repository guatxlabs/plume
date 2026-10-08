    // ================================================================================================
    // `P11.19-a` (reste de la vague E) — UN PRODUCTEUR DONT LA SOURCE SE RÈGLE À LA CONFIGURATION EST AVOUÉ.
    // Mesuré sur af310b3 : `collector-syslog` émet sous `env_or("PLUME_SYSLOG_SOURCE", default_source(..))`
    // (défaut `fortigate` ou `syslog`, aucune des deux n'est livrée) ; réglée sur une source livrée, celle-ci
    // reçoit dix-neuf clés littérales et des clés dynamiques que sa liste close ne doit à aucun fichier, et aucun
    // aveu de la racine de /api/sources ne le disait. Le témoin est DÉRIVÉ de la caisse : le levier, les sources
    // par défaut et l'ensemble des clés littérales sont relus dans `collector-syslog/src`, portée = le répertoire.
    // Mutants joués (rouges, retirés avant le commit) : `F6_SANS_AVEU` (aveu retiré de la porte), `F6_CLE_OUBLIEE`
    // (`receiver_peer` retiré de l'aveu), `F6_LEVIER_RENOMME` (levier renommé dans le texte relu de main.rs) ;
    // second tour : `fortigate` retiré de la clause des défauts, clause « aucune n'est livrée » renversée, forçage
    // du parseur auto retiré de la caisse, clé posée par `String::from("…")`.
    // Troisième tour : la portée est l'ARBORESCENCE de `collector-syslog/src` (parcours récursif, un module vendeur
    // sous un sous-répertoire est relu) ; l'aveu d'indisponibilité est relu à TOUT site d'appel de la caisse hors
    // module de test, préfixé ou non ; une clé dynamique est tolérée par SITE (fichier, expression, liaison), plus
    // par le seul nom de sa variable.
    // LIMITE DITE : les clés sont relues sur un sac nommé `fields` (`fields.insert`/`fields.entry`, formes
    // littérales "k", "k".into(), "k".to_string(), "k".to_owned(), String::from("k")) ; toute autre première
    // valeur sur ce sac doit être un site dynamique NOMMÉ ci-dessous, sinon rouge. Un sac sous un AUTRE nom de
    // variable ou un objet `json!` n'est pas relu : le seul de la caisse (`lisibilite.rs`, event_indisponibilite)
    // est tenu hors de la source réglée parce que chacun de ses appels part sous `HOTE_NON_LU`, vérifié ci-dessous ;
    // un appel par un alias (`use … as …`) ou par un pointeur de fonction n'est pas relu.
    // ================================================================================================

    /// Les sites DYNAMIQUES tolérés sur le sac `fields`, un par un : (fichier, première valeur, liaison de la
    /// variable dans ce fichier). Paires brutes FortiGate assainies ; paramètres structurés RFC 5424. Chaque site
    /// doit exister exactement une fois, sa liaison doit être présente, et aucune liaison littérale (`let key = "…"`)
    /// de la même variable ne doit exister dans le fichier.
    const CSS_SITES_DYNAMIQUES: &[(&str, &str, &str)] = &[
        ("fortigate.rs", "key", "let key = sanitize_key("),
        ("parser.rs", "k.clone()", "for (k, v) in &frame.sd"),
    ];

    /// Tous les `.rs` sous `dir`, récursivement, triés.
    fn css_fichiers_rs(dir: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("répertoire de collector-syslog lisible") {
            let chemin = e.unwrap().path();
            if chemin.is_dir() {
                css_fichiers_rs(&chemin, acc);
            } else if chemin.extension().and_then(|x| x.to_str()) == Some("rs") {
                acc.push(chemin);
            }
        }
        acc.sort();
    }

    /// Le texte d'un fichier HORS de son module de test de fin (`#[cfg(test)]` suivi de `mod tests {`).
    fn css_hors_tests(texte: &str) -> &str {
        match texte.find("#[cfg(test)]\nmod tests {") {
            Some(i) => &texte[..i],
            None => texte,
        }
    }

    /// Relit les clés littérales que la caisse pose dans un sac `fields`, sur TOUS les `.rs` de l'arborescence ;
    /// une première valeur qui n'est ni une forme littérale reconnue ni un site dynamique nommé est rendue à part.
    fn css_cles_de_la_caisse(dir: &std::path::Path) -> (std::collections::BTreeSet<String>, Vec<String>) {
        let appel = regex::Regex::new(r#"\bfields\.(?:insert|entry)\(\s*([^,()]*(?:\([^()]*\))?[^,()]*)"#).unwrap();
        let litteral = regex::Regex::new(
            r#"^(?:"([A-Za-z0-9_]+)"(?:\.into\(\)|\.to_string\(\)|\.to_owned\(\))?|String::from\(\s*"([A-Za-z0-9_]+)"\s*\))$"#,
        )
        .unwrap();
        let mut fichiers = Vec::new();
        css_fichiers_rs(dir, &mut fichiers);
        let mut cles = std::collections::BTreeSet::new();
        let mut non_lues = Vec::new();
        let mut vus: std::collections::BTreeMap<(String, String), usize> = std::collections::BTreeMap::new();
        for chemin in &fichiers {
            let texte = std::fs::read_to_string(chemin).unwrap();
            let relatif = chemin.strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/");
            for c in appel.captures_iter(&texte) {
                let arg = c[1].trim();
                if let Some(l) = litteral.captures(arg) {
                    cles.insert(l.get(1).or(l.get(2)).unwrap().as_str().to_string());
                } else if let Some((_, var, liaison)) = CSS_SITES_DYNAMIQUES.iter().find(|(f, a, _)| *f == relatif && *a == arg) {
                    *vus.entry((relatif.clone(), arg.to_string())).or_default() += 1;
                    let nom = var.split('.').next().unwrap();
                    if !texte.contains(liaison) || texte.contains(&format!("let {nom} = \"")) {
                        non_lues.push(format!("{relatif}: {arg} (liaison « {liaison} » absente, ou liaison littérale de {nom})"));
                    }
                } else {
                    non_lues.push(format!("{relatif}: {arg}"));
                }
            }
        }
        for (f, a, _) in CSS_SITES_DYNAMIQUES {
            let n = vus.get(&(f.to_string(), a.to_string())).copied().unwrap_or(0);
            if n != 1 {
                non_lues.push(format!("{f}: site dynamique {a} vu {n} fois, attendu une"));
            }
        }
        (cles, non_lues)
    }

    #[tokio::test]
    async fn collector_syslog_est_avoue_sous_la_source_que_l_exploitant_regle() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let dir = racine.join("collector-syslog/src");

        // La route sert la porte de lecture, et l'aveu y est UNE fois.
        let (_tmp, p) = imp_base_disque("css-aveu");
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        let servis: Vec<String> = v["champs_etendus_ne_voit_pas"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        assert_eq!(servis, crate::handlers::sources::champs_etendus_ne_voit_pas(), "la route sert la porte de lecture des aveux");
        let porteurs: Vec<&String> = servis.iter().filter(|a| a.contains("collector-syslog")).collect();
        assert_eq!(porteurs.len(), 1, "un aveu collector-syslog exactement : {servis:#?}");
        let aveu = porteurs[0].as_str();

        // Le LEVIER, relu là où la caisse le lit.
        let main = std::fs::read_to_string(dir.join("main.rs")).expect("collector-syslog/src/main.rs");
        let ligne = main.lines().find(|l| l.trim_start().starts_with("source: env_or(\"")).expect("prémisse : la source de la caisse se lit par env_or");
        let levier = ligne.split('"').nth(1).expect("levier littéral");
        assert!(ligne.contains("default_source("), "prémisse : le défaut vient de parser::default_source : {ligne}");
        assert!(aveu.contains(levier), "l'aveu doit nommer le levier que la caisse lit ({levier}) : {aveu}");

        // Les sources PAR DÉFAUT, relues dans `default_source`, et aucune n'est livrée.
        let parser = std::fs::read_to_string(dir.join("parser.rs")).expect("collector-syslog/src/parser.rs");
        let corps: String = parser
            .lines()
            .skip_while(|l| !l.contains("pub fn default_source("))
            .take_while(|l| *l != "}")
            .collect::<Vec<_>>()
            .join("\n");
        let defauts: std::collections::BTreeSet<&str> = corps.split("=> \"").skip(1).filter_map(|r| r.split('"').next()).collect();
        assert!(defauts.len() >= 2, "prémisse : défauts relus dans default_source ({defauts:?})");
        // La clause des défauts, et elle seule : « (défaut A ou B selon le parseur ».
        let clause = aveu
            .split_once("(défaut ")
            .and_then(|(_, r)| r.split_once(" selon le parseur"))
            .map(|(x, _)| x)
            .expect("clause « (défaut … selon le parseur » dans l'aveu");
        let nommes: std::collections::BTreeSet<&str> = clause.split(" ou ").map(str::trim).collect();
        assert_eq!(nommes, defauts, "la clause des défauts de l'aveu doit nommer EXACTEMENT les défauts de default_source : {aveu}");
        let une_livree = defauts.iter().any(|d| crate::handlers::sources::SOURCES_LIVREES.iter().any(|(s, _)| s == d));
        assert!(!une_livree, "prémisse du texte : aucune source par défaut n'est livrée ({defauts:?})");
        assert!(
            aveu.contains(&format!("défaut {clause} selon le parseur, aucune des deux n'étant une source livrée")),
            "l'aveu doit dire qu'aucune source par défaut n'est livrée, juste après la clause des défauts : {aveu}"
        );
        // Le parseur auto, dans les DEUX sens : il force fortigate si et seulement si l'aveu le dit.
        let auto: String = parser
            .lines()
            .skip_while(|l| !l.starts_with("impl VendorParser for Auto"))
            .take_while(|l| *l != "}")
            .collect::<Vec<_>>()
            .join("\n");
        assert!(auto.contains("fn parse("), "prémisse : impl VendorParser for Auto relu dans parser.rs");
        let force = auto.contains(".parse(frame, \"fortigate\"");
        assert_eq!(
            force,
            aveu.contains("le parseur auto range sous fortigate une trame reconnue FortiGate"),
            "le forçage fortigate du parseur auto et l'aveu doivent concorder : {aveu}"
        );
        // L'aveu d'indisponibilité (objet json!, non relu) part sous HOTE_NON_LU, jamais sous la source réglée :
        // TOUT appel de la caisse hors module de test, préfixé ou non, dans n'importe quel fichier.
        let site = regex::Regex::new(r"(\bfn\s+)?\bevent_indisponibilite\s*\(\s*([^,]*),").unwrap();
        let hote = regex::Regex::new(r"^(?:(?:crate::)?lisibilite::)?HOTE_NON_LU$").unwrap();
        let mut fichiers = Vec::new();
        css_fichiers_rs(&dir, &mut fichiers);
        let mut appels = 0usize;
        let mut hors_hote = Vec::new();
        for chemin in &fichiers {
            let texte = std::fs::read_to_string(chemin).unwrap();
            for c in site.captures_iter(css_hors_tests(&texte)) {
                if c.get(1).is_some() {
                    continue;
                }
                appels += 1;
                let premier = c[2].trim();
                if !hote.is_match(premier) {
                    hors_hote.push(format!("{}: {premier}", chemin.display()));
                }
            }
        }
        assert!(appels >= 1, "prémisse : la caisse émet event_indisponibilite hors de ses tests");
        assert!(hors_hote.is_empty(), "event_indisponibilite doit partir sous HOTE_NON_LU, ses clés n'étant pas relues : {hors_hote:?}");

        // Les CLÉS : exactement l'ensemble littéral relu dans la caisse, dans les deux sens.
        let (emises, non_lues) = css_cles_de_la_caisse(&dir);
        assert!(non_lues.is_empty(), "première valeur non relue sur le sac fields (ni littérale, ni clé dynamique nommée) : {non_lues:?}");
        assert!(emises.len() >= 15 && emises.contains("receiver_peer") && emises.contains("syslog_facility"), "prémisse : clés de la caisse relues ({emises:?})");
        let entre = aveu.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("liste entre crochets");
        let avouees: std::collections::BTreeSet<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(avouees, emises, "l'aveu collector-syslog doit nommer EXACTEMENT les clés littérales que la caisse pose");
        assert!(aveu.contains("clés dynamiques"), "les clés brutes FortiGate et les paramètres structurés sont dynamiques : {aveu}");
    }
