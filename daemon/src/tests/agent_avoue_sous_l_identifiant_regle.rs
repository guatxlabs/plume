    // ================================================================================================
    // `P11.19-a` (reste) — LES SOURCES DE L'AGENT DONT L'IDENTIFIANT SE RÈGLE SONT AVOUÉES.
    // Mesuré à la vérification du lot collector-syslog : la clé vise les producteurs dont la source se règle à la
    // configuration, au pluriel ; l'agent en a sept (`name` des sources génériques file/command/http, `id` de
    // journald, wineventlog, oslog et de la source d'intégrité). Une source générique émet sous son `name`
    // (generic.rs, line_to_event), qui peut nommer une source livrée ; et l'aveu d'indisponibilité de l'agent part
    // sous l'identifiant de la source illisible avec un sac de clés littérales. Seul le FIM sous `integrity` était
    // avoué. Le témoin est DÉRIVÉ : leviers relus dans config.rs dans les deux sens, émission générique relue sans
    // clé littérale hors tests, clés d'indisponibilité relues dans lisibilite.rs, nommées EXACTEMENT par l'aveu.
    // Mutants joués (rouges, retirés avant le commit) : levier neuf `d_otel_name` dans config.rs, clé neuve dans
    // le sac d'indisponibilité, clé littérale posée par generic.rs hors tests.
    // LIMITE DITE : les champs d'une source générique sont ceux du parseur que l'exploitant déclare ; aucune liste
    // ne peut les borner, l'aveu le dit et le témoin ne tient que l'absence de clé littérale posée par la caisse.
    // ================================================================================================

    /// Le texte d'un fichier HORS de son module de test de fin.
    fn aar_hors_tests(texte: &str) -> &str {
        match texte.find("#[cfg(test)]\nmod tests {") {
            Some(i) => &texte[..i],
            None => texte,
        }
    }

    #[test]
    fn les_sources_de_l_agent_a_identifiant_regle_sont_avouees_exactement() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let aveux = crate::handlers::sources::champs_etendus_ne_voit_pas();
        let porteurs: Vec<&&str> = aveux.iter().filter(|a| a.contains("line_to_event")).collect();
        assert_eq!(porteurs.len(), 1, "un aveu des sources de l'agent à identifiant réglé exactement : {aveux:#?}");
        let aveu = *porteurs[0];

        // LES LEVIERS : chaque défaut `d_*_name` / `d_*_id` de config.rs est nommé, et l'aveu n'en nomme pas d'autre.
        let config = std::fs::read_to_string(racine.join("agent/src/config.rs")).expect("agent/src/config.rs");
        let defaut = regex::Regex::new(r"\bfn (d_[a-z]+_(?:name|id))\(\)").unwrap();
        let leviers: std::collections::BTreeSet<&str> = defaut.captures_iter(&config).map(|c| c.get(1).unwrap().as_str()).collect();
        assert!(leviers.contains("d_file_name") && leviers.contains("d_fim_id") && leviers.len() >= 7, "prémisse : leviers relus ({leviers:?})");
        let nomme = regex::Regex::new(r"\b(d_[a-z]+_(?:name|id))\b").unwrap();
        let nommes: std::collections::BTreeSet<&str> = nomme.captures_iter(aveu).map(|c| c.get(1).unwrap().as_str()).collect();
        assert_eq!(nommes, leviers, "l'aveu doit nommer EXACTEMENT les défauts d'identifiant de l'agent : {aveu}");

        // L'ÉMISSION GÉNÉRIQUE : sous le nom réglé, champs du seul parseur de l'exploitant (aucune clé littérale).
        let generic = std::fs::read_to_string(racine.join("agent/src/source/generic.rs")).expect("agent/src/source/generic.rs");
        let vivant = aar_hors_tests(&generic);
        assert!(vivant.contains("pub fn line_to_event(") && vivant.contains("source: name.to_string()"), "prémisse : line_to_event émet sous le nom réglé");
        assert!(vivant.contains("let fields = Value::Object(parser.apply(line));"), "prémisse : les champs viennent du seul parseur déclaré");
        let cle_litterale = regex::Regex::new(r#"\binsert\(\s*"|json!\(\s*\{"#).unwrap();
        assert!(!cle_litterale.is_match(vivant), "generic.rs pose une clé littérale hors tests : l'aveu « arbitraires » ne tient plus");

        // L'AVEU D'INDISPONIBILITÉ part sous l'identifiant de la source illisible.
        let main = std::fs::read_to_string(racine.join("agent/src/main.rs")).expect("agent/src/main.rs");
        assert!(main.contains("lisibilite::event_indisponibilite(source, host,"), "prémisse : avouer_indisponibilite émet sous l'identifiant reçu");
        assert!(main.contains("let id = r.source_id().to_string();"), "prémisse : l'identifiant est celui du lecteur");

        // Ses clés, relues dans lisibilite.rs : exactement celles de l'aveu.
        let texte = std::fs::read_to_string(racine.join("agent/src/lisibilite.rs")).expect("agent/src/lisibilite.rs");
        let debut = texte.find("pub fn event_indisponibilite(").expect("event_indisponibilite présent");
        let corps = &texte[debut..];
        let corps = &corps[..corps.find("\n}\n").expect("fin de event_indisponibilite")];
        let sac = &corps[corps.find("json!({").expect("sac json!") + 7..];
        let sac = &sac[..sac.find("});").expect("fin du sac")];
        let mut emises: std::collections::BTreeSet<String> = sac
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"').and_then(|r| r.split_once('"')).filter(|(_, a)| a.trim_start().starts_with(':')).map(|(k, _)| k.to_string()))
            .collect();
        for r in corps.split("fields[\"").skip(1) {
            emises.insert(r.split_once('"').map(|(k, _)| k.to_string()).expect("clé ajoutée au sac"));
        }
        assert!(emises.contains("verdict") && emises.contains("hors_vocabulaire") && emises.len() >= 8, "prémisse : sac relu ({emises:?})");
        let entre = aveu.split_once("les clés [").and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("liste entre crochets");
        let avouees: std::collections::BTreeSet<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(avouees, emises, "l'aveu doit nommer EXACTEMENT les clés d'indisponibilité de l'agent : {aveu}");
    }
