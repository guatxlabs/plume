// =================================================================================================
// S29 — UNE PROPRIÉTÉ D'ENVIRONNEMENT AFFIRMÉE EN PROSE N'A AUCUN MOYEN DE VIEILLIR
//
// LE PROBLÈME, ET SON PÉRIMÈTRE MESURÉ. Un balayage des commentaires de l'arbre Rust — critère écrit,
// rejouable, sens désambiguïsé — rend, le 2026-08-20 : 12 534 blocs de commentaire, 420 qui portent un
// terme de bac à sable, de système de fichiers ou de noyau, et 258 PHRASES qui AFFIRMENT quelque chose
// de cet environnement. Un quart seulement porte une date. Le nombre n'est pas le sujet : deux balayages
// menés sur des critères différents ne se comparent pas, et c'est précisément ce qui manquait — aucun
// des deux n'était rejouable.
//
// LE CRITÈRE QUI DÉCIDE DE CE QUI EST TRAITÉ ICI N'EST PAS « EST-CE VRAI ? », C'EST « QUE SE PASSE-T-IL
// SI ÇA CESSE DE L'ÊTRE, ET QUI L'APPREND ? ». Une allégation fausse qui fait planter le processus est
// bénigne : on la découvre le jour même. Une allégation fausse qui laisse le système rendre une valeur
// RASSURANTE — zéro alerte, un journal d'apparence normale, un service qui démarre — n'est découverte
// par personne. Les quatre gardes ci-dessous tiennent les quatre allégations de ce second type dont le
// FAISEUR DE VÉRITÉ est un fichier de ce dépôt. C'est la ligne de partage utile : sur 258 allégations,
// 84 portent sur l'hôte (noyau, cgroup, système de fichiers) et AUCUNE garde de source ne peut les
// tenir — celles-là se MESURENT à l'exécution, ou cessent d'être des affirmations.
//
// CE QUE CES GARDES NE FONT PAS, écrit pour être opposable :
//   - elles ne jugent aucune phrase. Elles lisent le FICHIER que la phrase prend à témoin. Une garde qui
//     prétendrait relire de la prose produirait du bruit et finirait désarmée ;
//   - elles ne couvrent pas les 254 autres allégations, et c'est délibéré : les traiter en masse
//     remplacerait 254 affirmations non vérifiées par 254 formulations non vérifiées ;
//   - une allégation tenue ici peut rester fausse sur un hôte donné (un opérateur édite l'unité qu'il
//     déploie). Ce qui est tenu, c'est ce que CE DÉPÔT livre — ni plus, ni moins.
//
// CHAQUE GARDE VALIDE SON PROPRE INSTRUMENT AVANT DE CONCLURE. Un balayage de source qui ne trouverait
// rien parce que son parcours est cassé rendrait vert en étant aveugle — c'est le mode de panne le plus
// fréquent de cette famille de gardes. Chacune exige donc un TÉMOIN POSITIF (une chose qu'elle DOIT
// trouver dans l'arbre réel) et un TÉMOIN NÉGATIF (une chose qu'elle ne doit PAS trouver, typiquement
// l'occurrence en COMMENTAIRE du motif qu'elle interdit dans le code). Si l'un des deux manque, la garde
// ÉCHOUE au lieu de conclure.
//
// LES DEUX PIÈGES QUE CES GARDES ÉVITENT PAR CONSTRUCTION, parce qu'ils ont déjà été payés ici :
//   1. un balayage de source matche AUSSI les commentaires — y compris celui qui cite la forme fautive
//      pour l'expliquer. Le code est donc dépouillé de ses commentaires avant lecture, et l'occurrence
//      en commentaire sert de témoin négatif ;
//   2. citer un mot n'est pas l'employer : les CHAÎNES LITTÉRALES sont dépouillées elles aussi — sans
//      quoi le message d'erreur d'une garde suffirait à la faire échouer sur elle-même.
// =================================================================================================
#[cfg(test)]
mod allegations_d_environnement_tests {
    use std::path::{Path, PathBuf};

    /// La racine du dépôt : ces gardes lisent des fichiers qui vivent À CÔTÉ du crate (`systemd/`,
    /// `collectors/`), pas dedans.
    /// `parent()` et NON `join("..")` : un chemin qui garde un `..` ne se préfixe plus, et `relatif`
    /// rendrait alors le chemin ABSOLU de la machine qui a exécuté la suite — dans un message de garde
    /// d'un dépôt public. Mesuré : la première forme l'a fait.
    fn racine_du_depot() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("INSTRUMENT : le crate n'a pas de répertoire parent")
            .to_path_buf()
    }

    /// Chemin RELATIF à la racine du dépôt : un message de garde ne recopie jamais l'arborescence de la
    /// machine qui l'a exécutée.
    fn relatif(p: &Path) -> String {
        p.strip_prefix(racine_du_depot()).unwrap_or(p).display().to_string()
    }

    // --------------------------------------------------------------------------------------------
    // DÉPOUILLEMENT — ne garder que ce qui est EXÉCUTÉ
    // --------------------------------------------------------------------------------------------

    /// Rend `src` privé de ses commentaires (`//`, `/* */`) ET de ses chaînes littérales (`"…"`,
    /// `r"…"`, `r#"…"#`), les sauts de ligne préservés pour que les numéros de ligne restent justes.
    ///
    /// LES LITTÉRAUX DE CARACTÈRE SONT TRAITÉS, et ce n'est pas un raffinement : `'"'` est une forme
    /// courante dans un analyseur, et un dépouilleur qui la prendrait pour le début d'une chaîne
    /// avalerait le code jusqu'au guillemet suivant — donc masquerait peut-être l'occurrence qu'on
    /// cherche. Une garde aveugle qui rend vert est pire que pas de garde.
    fn code_execute_rust(src: &str) -> String {
        let o: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0usize;
        let pousser_blancs = |out: &mut String, tranche: &[char]| {
            for c in tranche {
                out.push(if *c == '\n' { '\n' } else { ' ' });
            }
        };
        while i < o.len() {
            let c = o[i];
            // chaîne brute `r"…"` / `r#"…"#`
            if c == 'r'
                && (i == 0 || !(o[i - 1].is_alphanumeric() || o[i - 1] == '_'))
                && i + 1 < o.len()
                && (o[i + 1] == '"' || o[i + 1] == '#')
            {
                let mut d = 0usize;
                let mut j = i + 1;
                while j < o.len() && o[j] == '#' {
                    d += 1;
                    j += 1;
                }
                if j < o.len() && o[j] == '"' {
                    j += 1;
                    while j < o.len() {
                        if o[j] == '"' && o[j + 1..].iter().take(d).all(|&x| x == '#') {
                            j += 1 + d;
                            break;
                        }
                        j += 1;
                    }
                    pousser_blancs(&mut out, &o[i..j.min(o.len())]);
                    i = j;
                    continue;
                }
            }
            if c == '"' {
                let mut j = i + 1;
                while j < o.len() {
                    if o[j] == '\\' {
                        j += 2;
                        continue;
                    }
                    if o[j] == '"' {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                pousser_blancs(&mut out, &o[i..j.min(o.len())]);
                i = j;
                continue;
            }
            if c == '\'' {
                // `'x'` ou `'\n'` = littéral de caractère ; `'a` nu = durée de vie (on avance d'un cran).
                let ferme_simple = i + 2 < o.len() && o[i + 2] == '\'';
                let ferme_echappe = i + 3 < o.len() && o[i + 1] == '\\' && o[i + 3] == '\'';
                if ferme_simple || ferme_echappe {
                    let j = if ferme_simple { i + 3 } else { i + 4 };
                    pousser_blancs(&mut out, &o[i..j]);
                    i = j;
                    continue;
                }
                out.push(c);
                i += 1;
                continue;
            }
            if c == '/' && i + 1 < o.len() && o[i + 1] == '/' {
                let mut j = i;
                while j < o.len() && o[j] != '\n' {
                    j += 1;
                }
                pousser_blancs(&mut out, &o[i..j]);
                i = j;
                continue;
            }
            if c == '/' && i + 1 < o.len() && o[i + 1] == '*' {
                let mut j = i + 2;
                while j + 1 < o.len() && !(o[j] == '*' && o[j + 1] == '/') {
                    j += 1;
                }
                let fin = (j + 2).min(o.len());
                pousser_blancs(&mut out, &o[i..fin]);
                i = fin;
                continue;
            }
            out.push(c);
            i += 1;
        }
        out
    }

    /// Rend un script shell privé de ses commentaires. Un `#` n'ouvre un commentaire que HORS
    /// guillemets et en début de mot : `"…#H#…"` et `${x#préfixe}` ne sont pas des commentaires.
    fn code_execute_shell(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for ligne in src.split('\n') {
            let o: Vec<char> = ligne.chars().collect();
            let mut quote: Option<char> = None;
            let mut i = 0usize;
            while i < o.len() {
                let c = o[i];
                match quote {
                    Some(q) => {
                        out.push(c);
                        if c == '\\' && q == '"' {
                            if let Some(&s) = o.get(i + 1) {
                                out.push(s);
                            }
                            i += 2;
                            continue;
                        }
                        if c == q {
                            quote = None;
                        }
                    }
                    None => {
                        if c == '"' || c == '\'' {
                            quote = Some(c);
                            out.push(c);
                        } else if c == '#' && (i == 0 || o[i - 1].is_whitespace()) {
                            break;
                        } else {
                            out.push(c);
                        }
                    }
                }
                i += 1;
            }
            out.push('\n');
        }
        out
    }

    /// Rend un fichier d'unité systemd privé de ses commentaires (`#` ou `;` en tête de ligne).
    fn code_execute_unite(src: &str) -> String {
        src.split('\n')
            .map(|l| if l.trim_start().starts_with('#') || l.trim_start().starts_with(';') { "" } else { l })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn collecter_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collecter_rs(&p, out);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }

    /// LE CORPUS DES ÉMETTEURS HORS-RUST : les collecteurs shell/python livrés, plus les deux
    /// amorceurs. DÉRIVÉ du répertoire, jamais énuméré — un collecteur ajouté demain entre dans la
    /// garde sans que personne y pense.
    fn corpus_des_collecteurs() -> Vec<PathBuf> {
        let racine = racine_du_depot();
        let mut out = Vec::new();
        for sous in ["collectors", "collectors/windows"] {
            if let Ok(rd) = std::fs::read_dir(racine.join(sous)) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_file() {
                        out.push(p);
                    }
                }
            }
        }
        for amorce in ["bootstrap.sh", "bootstrap-agent.sh"] {
            let p = racine.join(amorce);
            if p.is_file() {
                out.push(p);
            }
        }
        out.sort();
        out
    }

    /// LES UNITÉS LIVRÉES par ce dépôt, dérivées du répertoire `systemd/`.
    fn unites_livrees() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(racine_du_depot().join("systemd")) {
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
                if ext == "service" || ext == "timer" {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    // --------------------------------------------------------------------------------------------
    // L'INSTRUMENT, PROUVÉ SUR DES ÉCHANTILLONS DONT ON CONNAÎT LA RÉPONSE
    // --------------------------------------------------------------------------------------------

    /// TÉMOIN POSITIF ET TÉMOIN NÉGATIF DU DÉPOUILLEMENT LUI-MÊME. Les quatre gardes qui suivent ne
    /// valent que ce que vaut ce dépouillement : s'il laissait passer un commentaire, la garde
    /// accuserait la prose qui l'explique ; s'il avalait du code, elle rendrait vert en étant aveugle.
    /// Les deux sens sont donc exercés ici, sur des échantillons écrits pour ça, sans toucher à l'arbre.
    #[test]
    fn le_depouillement_separe_ce_qui_est_execute_de_ce_qui_est_ecrit() {
        // Rust — le mot INTERDIT vit une fois dans un commentaire, une fois dans une chaîne, une fois
        // dans le code. Seule la troisième doit survivre.
        let echantillon = concat!(
            "// motif INTERDIT cité pour l'expliquer\n",
            "let m = \"motif INTERDIT dans une chaîne\";\n",
            "/* motif INTERDIT dans un bloc */\n",
            "let guillemet = '\"'; let apres = motif_INTERDIT_execute();\n",
            "let brut = r#\"motif INTERDIT brut\"#;\n"
        );
        let code = code_execute_rust(echantillon);
        assert_eq!(
            code.matches("INTERDIT").count(),
            1,
            "dépouillement Rust : {} occurrence(s) survivante(s), une seule est du code\n{code}",
            code.matches("INTERDIT").count()
        );
        assert!(
            code.contains("motif_INTERDIT_execute"),
            "dépouillement Rust : le littéral de caractère '\"' a fait avaler le code qui le suit — \
             une garde bâtie là-dessus serait AVEUGLE :\n{code}"
        );
        assert_eq!(
            echantillon.lines().count(),
            code.lines().count(),
            "dépouillement Rust : les numéros de ligne ont bougé, un message de garde désignerait la \
             mauvaise ligne"
        );

        // Shell — un `#` en début de mot ouvre un commentaire ; entre guillemets, non.
        let sh = code_execute_shell("a=\"#H#\"  # ceci est un commentaire\nb=INTERDIT\n");
        assert!(sh.contains("#H#"), "dépouillement shell : un `#` entre guillemets a été pris pour un commentaire\n{sh}");
        assert!(!sh.contains("commentaire"), "dépouillement shell : le commentaire a survécu\n{sh}");
        assert!(sh.contains("INTERDIT"), "dépouillement shell : du code a été avalé\n{sh}");

        // Unité systemd — une directive commentée n'est pas une directive.
        let unite = code_execute_unite("#EnvironmentFile=/x\n;EnvironmentFile=/y\nEnvironment=PLUME_CONFIG=/z\n");
        assert!(
            !unite.contains("EnvironmentFile"),
            "dépouillement d'unité : une directive COMMENTÉE compte comme posée\n{unite}"
        );
        assert!(unite.contains("PLUME_CONFIG"), "dépouillement d'unité : une directive réelle a été perdue\n{unite}");
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 1 — « aucun TraceLayer / access-log n'est monté »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `ingest/pubsub.rs` et `main.rs` affirment qu'AUCUN journal de requêtes
    /// n'est monté, et c'est ce qui rend acceptable qu'une route d'ingestion accepte son secret dans la
    /// query-string. La note ajoutait « À FLAGGER pour la revue » — c'est-à-dire qu'elle confiait à la
    /// vigilance humaine une propriété dont la violation ne casse RIEN : un journal de requêtes monté
    /// demain recopierait ces secrets dans les journaux sans qu'aucun test ne rougisse, sans qu'aucune
    /// réponse change, et sans qu'aucun exploitant ait de raison de regarder. C'est le silence maximal :
    /// tout continue de fonctionner, et la fuite est dans un fichier d'apparence normale.
    ///
    /// TROIS PORTES, PARCE QUE LA PROPRIÉTÉ EN A TROIS. (1) la dépendance ne doit pas fournir la
    /// couche — `tower-http` sans sa fonctionnalité `trace` ne compile pas de `TraceLayer` ; (2) aucun
    /// code exécuté ne doit la nommer ; (3) aucune ligne exécutée ne doit journaliser l'URI ou la query.
    /// Fermer seulement (2) laisserait passer un journal maison écrit à la main.
    #[test]
    fn aucun_journal_de_requetes_ne_peut_capturer_la_query_string() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        collecter_rs(&racine, &mut fichiers);
        // 205 fichiers .rs MESURÉS sous `daemon/src` le 2026-08-20 ; le plancher est volontairement bas
        // (ajouter ou retirer un module est de la routine et ne doit pas obliger à toucher la garde).
        assert!(
            fichiers.len() >= 150,
            "INSTRUMENT : {} fichier(s) .rs balayé(s) sous {} — parcours cassé, la garde ne verrait rien",
            fichiers.len(),
            relatif(&racine)
        );
        let moi = Path::new(file!()).file_name().unwrap().to_string_lossy().into_owned();

        let couche = ["TraceLayer", "tower_http::trace"];
        let journaux = ["eprintln!", "println!", "tracing::", "log::", "warn!", "info!", "error!", "debug!"];
        let (mut cite_en_prose, mut fautifs) = (0usize, Vec::<String>::new());
        for f in &fichiers {
            if f.file_name().map(|n| n.to_string_lossy() == moi).unwrap_or(false) {
                continue;
            }
            let brut = std::fs::read_to_string(f).unwrap_or_default();
            cite_en_prose += couche.iter().map(|m| brut.matches(m).count()).sum::<usize>();
            let code = code_execute_rust(&brut);
            for (i, ligne) in code.lines().enumerate() {
                let rel = relatif(f);
                if let Some(m) = couche.iter().find(|m| ligne.contains(**m)) {
                    fautifs.push(format!("{rel}:{} monte `{m}`", i + 1));
                }
                if (ligne.contains(".uri()") || ligne.contains(".query()"))
                    && journaux.iter().any(|j| ligne.contains(j))
                {
                    fautifs.push(format!("{rel}:{} journalise l'URI ou la query", i + 1));
                }
            }
        }
        // TÉMOIN NÉGATIF, sur l'arbre réel : le nom interdit EST écrit dans ce dépôt — en commentaire,
        // là où la propriété est expliquée. S'il n'apparaît plus nulle part, ce n'est pas que la
        // propriété est mieux tenue : c'est que le dépouillement a mangé la prose ET le code.
        assert!(
            cite_en_prose >= 2,
            "INSTRUMENT : le nom de la couche interdite n'apparaît nulle part dans le texte brut — \
             le balayage ne lit pas les fichiers qu'il croit lire"
        );
        assert!(
            fautifs.is_empty(),
            "un journal de requêtes est monté : {fautifs:?}\nla route Pub/Sub accepte son secret dans \
             la query-string PARCE QUE rien ne journalise l'URI ; si cela change, la query DOIT être \
             rédigée avant journalisation"
        );

        // PORTE 1 — la dépendance elle-même. Une couche qui ne se compile pas ne se monte pas.
        let cargo = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("INSTRUMENT : `daemon/Cargo.toml` illisible");
        let ligne_tower = cargo
            .lines()
            .find(|l| l.trim_start().starts_with("tower-http"))
            .expect("INSTRUMENT : `tower-http` n'est plus déclaré — la garde mesure une dépendance absente");
        assert!(
            !ligne_tower.contains("\"trace\""),
            "`tower-http` compile désormais sa fonctionnalité `trace` : {ligne_tower}"
        );
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 2 — « aucun collecteur légitime n'émet de source `plume-*` »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `state::ext_ingest_source` renomme `ext:<source>` toute source ARRIVANT par
    /// l'ingestion qui usurpe le préfixe réservé aux events de contrôle. Le commentaire justifie que
    /// cette protection ne casse rien par un « (vérifié : collectors/*, bootstrap-agent) » sans date et
    /// sans mécanisme.
    ///
    /// CE QUE SON VIEILLISSEMENT PRODUIRAIT : un collecteur nommé dans le préfixe réservé verrait TOUS
    /// ses événements renommés en silence. Ils ne sont ni perdus ni journalisés comme rejetés — ils
    /// arrivent sous un autre nom. Le panneau de ce capteur reste vide, l'exploitant lit « aucun
    /// événement », et rien dans le système ne distingue ce cas d'un capteur qui n'a rien à dire.
    #[test]
    fn aucun_collecteur_n_emet_dans_le_namespace_de_controle() {
        // LE PRÉFIXE EST LU CHEZ CELUI QUI RENOMME, pas recopié : si `ext_ingest_source` change de
        // préfixe, la garde suit — et si sa forme change au point de n'être plus lisible, elle échoue.
        let source_de_state = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/state.rs"),
        )
        .expect("INSTRUMENT : `daemon/src/state.rs` illisible");
        // On repère le CORPS de la fonction (donc du code, pas sa prose de tête) puis on relit sur la
        // même ligne le littéral que le dépouillement a effacé : c'est la valeur qui décide, à
        // l'exécution, de ce qui est renommé.
        let debut = code_execute_rust(&source_de_state)
            .lines()
            .position(|l| l.contains("fn ext_ingest_source"))
            .expect(
                "INSTRUMENT : `ext_ingest_source` introuvable dans le CODE de `state.rs` — la garde \
                 refuse de conclure sur un préfixe qu'elle aurait inventé",
            );
        let prefixe = source_de_state
            .lines()
            .skip(debut)
            .take(12)
            .find_map(|l| {
                let d = l.find("starts_with(\"")? + "starts_with(\"".len();
                let f = l[d..].find('"')? + d;
                Some(l[d..f].to_string())
            })
            .expect("INSTRUMENT : le préfixe réservé n'est plus lisible dans `ext_ingest_source`");
        assert!(!prefixe.is_empty(), "INSTRUMENT : préfixe réservé vide");

        let corpus = corpus_des_collecteurs();
        // 45 fichiers MESURÉS le 2026-08-20 (collecteurs shell/python + windows + deux amorceurs).
        assert!(
            corpus.len() >= 30,
            "INSTRUMENT : {} fichier(s) de collecteur balayé(s) — parcours cassé, la garde ne verrait rien",
            corpus.len()
        );

        // Les DEUX formes par lesquelles un nom de source naît côté collecteur : le littéral JSON, et le
        // PREMIER argument des fabriques de `lib.sh`. Les deux sont dérivées de l'usage réel, pas devinées.
        let fabriques = [
            "heartbeat",
            "plume_report_availability",
            "plume_unavailable",
            "plume_disabled",
            "plume_missing_config",
            "plume_subsystem_absent",
            "plume_unreachable",
        ];
        let (mut sites, mut mentions_brutes, mut fautifs) = (0usize, 0usize, Vec::<String>::new());
        for f in &corpus {
            let brut = std::fs::read_to_string(f).unwrap_or_default();
            mentions_brutes += brut.matches(&prefixe).count();
            let code = code_execute_shell(&brut);
            for (i, ligne) in code.lines().enumerate() {
                let mut noms: Vec<String> = Vec::new();
                let mut reste = ligne;
                while let Some(d) = reste.find("\"source\"") {
                    let apres = &reste[d + "\"source\"".len()..];
                    let Some(dp) = apres.find(':') else { break };
                    let apres = apres[dp + 1..].trim_start();
                    if let Some(v) = apres.strip_prefix('"') {
                        if let Some(fin) = v.find('"') {
                            noms.push(v[..fin].to_string());
                        }
                    }
                    reste = &reste[d + "\"source\"".len()..];
                }
                for fab in fabriques {
                    let mut reste = ligne;
                    while let Some(d) = reste.find(fab) {
                        let apres = reste[d + fab.len()..].trim_start();
                        let avant_ok = d == 0
                            || !reste[..d].chars().next_back().map(|c| c.is_alphanumeric() || c == '_').unwrap_or(false);
                        if avant_ok {
                            let arg: String =
                                apres.chars().take_while(|c| !c.is_whitespace()).collect();
                            if !arg.is_empty() {
                                noms.push(arg.trim_matches(|c| c == '"' || c == '\'').to_string());
                            }
                        }
                        reste = &reste[d + fab.len()..];
                    }
                }
                sites += noms.len();
                for n in noms {
                    if n.starts_with(&prefixe) {
                        fautifs.push(format!("{}:{} émet la source `{n}`", relatif(f), i + 1));
                    }
                }
            }
        }
        // TÉMOIN POSITIF : la garde doit VOIR des noms de source. 73 sites d'émission mesurés le
        // 2026-08-20 — un zéro voudrait dire que la forme d'émission a changé et que la garde lit à côté.
        assert!(
            sites >= 40,
            "INSTRUMENT : {sites} site(s) d'émission reconnu(s) dans le corpus — la forme par laquelle un \
             collecteur nomme sa source a changé, la garde ne mesure plus rien"
        );
        // TÉMOIN NÉGATIF : le préfixe est écrit des centaines de fois dans ces scripts (chemins,
        // noms d'unités, variables). AUCUNE de ces occurrences ne doit être accusée : la garde lit un
        // CHAMP DE SOURCE, pas un mot.
        assert!(
            mentions_brutes >= 50,
            "INSTRUMENT : le préfixe réservé n'apparaît que {mentions_brutes} fois dans le corpus brut — \
             les fichiers lus ne sont pas ceux qu'on croit"
        );
        assert!(
            fautifs.is_empty(),
            "un collecteur émet dans le namespace de contrôle : {fautifs:?}\n`ext_ingest_source` \
             renommerait ces événements en silence — le capteur paraîtrait muet"
        );
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 3 — « `collectors/integrity.sh` surveille /etc/systemd/system/*.service et *.timer »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `seeds.rs` sème une règle « vecteur de persistance ajouté » (T1543) qui
    /// interroge `source=integrity change=ajout severity>=3`, et justifie sa couverture en affirmant ce
    /// que le capteur d'intégrité surveille. Le capteur est un script shell ; la règle est une ligne de
    /// SQL semée ; rien ne les relie.
    ///
    /// CE QUE SON VIEILLISSEMENT PRODUIRAIT — et c'est le pire silence de tout le recensement : si le
    /// script cessait de hacher ce répertoire, la règle continuerait de s'exécuter, sur zéro ligne, et
    /// ne lèverait JAMAIS d'alerte. Un SOC sans alerte de persistance a exactement l'apparence d'un SOC
    /// sain. Le mode de panne ne produit ni erreur, ni journal, ni chiffre anormal : il produit du calme.
    #[test]
    fn le_capteur_d_integrite_surveille_toujours_le_repertoire_d_unites() {
        let script = racine_du_depot().join("collectors/integrity.sh");
        let brut = std::fs::read_to_string(&script)
            .expect("INSTRUMENT : `collectors/integrity.sh` illisible — la garde refuse de conclure");
        let code = code_execute_shell(&brut);

        let repertoire = "/etc/systemd/system";
        // TÉMOIN NÉGATIF, ET IL EST INDÉPENDANT DE LA SUBSTANCE — c'est le point : le répertoire est
        // nommé dans l'en-tête du script, qui est un COMMENTAIRE. Ces lignes-là doivent avoir disparu du
        // texte dépouillé. Un premier jet mêlait à cette vérification le fait de trouver la ligne
        // exécutée : commenter la ligne surveillée faisait alors échouer la garde sur son INSTRUMENT,
        // c'est-à-dire avec le mauvais diagnostic. Les deux questions sont désormais séparées.
        let en_commentaire: Vec<&str> = brut
            .lines()
            .filter(|l| l.trim_start().starts_with('#') && l.contains(repertoire))
            .collect();
        assert!(
            !en_commentaire.is_empty(),
            "INSTRUMENT : plus aucun commentaire de ce script ne nomme `{repertoire}` — le témoin \
             négatif a disparu, la garde ne peut plus prouver qu'elle ignore la prose"
        );
        assert!(
            en_commentaire.iter().all(|l| !code.contains(l.trim())),
            "INSTRUMENT : une ligne de COMMENTAIRE a survécu au dépouillement — la garde serait \
             satisfaite par une phrase au lieu d'une ligne exécutée"
        );

        let surveille = code.lines().any(|l| {
            l.contains(&format!("{repertoire}/*.service"))
                && l.contains(&format!("{repertoire}/*.timer"))
                && l.contains("emit_hash unit")
        });
        assert!(
            surveille,
            "aucune ligne EXÉCUTÉE de {} ne hache `{repertoire}/*.service` ET `{repertoire}/*.timer` \
             sous le genre `unit`.\nLa règle semée « vecteur de persistance ajouté » (T1543) interroge \
             `source=integrity change=ajout severity>=3` : sans cette ligne elle ne lèvera plus jamais \
             d'alerte, et un SOC muet ressemble à un SOC sain.",
            relatif(&script)
        );
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 4 — « `systemd/plume-daemon.service` ne porte AUCUN `EnvironmentFile` »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE, écrite QUATRE fois (`backup.rs`, `crypto/mod.rs`, et deux fichiers de test) :
    /// l'unité du démon ne porte aucun `EnvironmentFile`, et c'est CE FAIT qui justifie deux décisions —
    /// router toutes les lectures de réglages par `cfg()` plutôt que d'ajouter la directive, et déposer
    /// la clé SQLCipher dans un fichier de configuration 0640 plutôt que dans l'environnement.
    ///
    /// CE QUE SON VIEILLISSEMENT PRODUIRAIT : ajouter la directive est un geste NATUREL — c'est la façon
    /// ordinaire de donner sa configuration à une unité, et le démon continuerait de démarrer et de
    /// servir exactement pareil. La seule chose qui changerait est que `PLUME_DB_KEY` et
    /// `PLUME_PASS_HASH` deviendraient lisibles dans l'environnement du processus, pour tout ce qui
    /// partage son espace de noms de processus. Aucun test ne rougirait, aucune réponse ne changerait,
    /// aucune ligne de journal ne le dirait.
    ///
    /// LA GARDE PORTE AUSSI `Environment=PLUME_CONFIG=` : les quatre commentaires n'affirment pas
    /// seulement l'ABSENCE de la directive, mais que le fichier de configuration est LA voie — ce qui
    /// suppose que l'unité désigne ce fichier. Les deux moitiés de l'allégation sont tenues ensemble.
    #[test]
    fn l_unite_du_daemon_ne_porte_aucun_environmentfile() {
        let unites = unites_livrees();
        // 88 unités livrées MESURÉES le 2026-08-20 ; plancher bas, le jeu bouge à chaque capteur ajouté.
        assert!(
            unites.len() >= 60,
            "INSTRUMENT : {} unité(s) trouvée(s) sous `systemd/` — parcours cassé",
            unites.len()
        );

        // TÉMOIN POSITIF, SUR DONNÉES RÉELLES : la directive interdite ici est POSÉE par d'autres unités
        // livrées (29 mesurées le 2026-08-20). Le détecteur sait donc la voir ; s'il n'en trouvait plus
        // AUCUNE, c'est qu'il ne sait plus la reconnaître, et son silence sur l'unité du démon ne
        // prouverait rien.
        let porteuses: Vec<String> = unites
            .iter()
            .filter(|u| {
                code_execute_unite(&std::fs::read_to_string(u).unwrap_or_default())
                    .lines()
                    .any(|l| l.trim_start().starts_with("EnvironmentFile"))
            })
            .map(|u| u.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            porteuses.len() >= 5,
            "INSTRUMENT : {} unité(s) porteuse(s) d'`EnvironmentFile` — le détecteur ne reconnaît plus \
             la directive, son verdict sur l'unité du démon serait un silence, pas une preuve",
            porteuses.len()
        );

        let unite = racine_du_depot().join("systemd/plume-daemon.service");
        let texte = std::fs::read_to_string(&unite)
            .expect("INSTRUMENT : `systemd/plume-daemon.service` illisible — la garde refuse de conclure");
        let code = code_execute_unite(&texte);
        let pose: Vec<&str> = code.lines().filter(|l| l.trim_start().starts_with("EnvironmentFile")).collect();
        assert!(
            pose.is_empty(),
            "`{}` porte désormais {pose:?}.\nQuatre commentaires du démon justifient leur conception par \
             son ABSENCE : avec la directive, tout ce que porte le fichier de configuration — dont la clé \
             SQLCipher et l'empreinte du mot de passe — devient lisible dans l'environnement du processus, \
             sans qu'aucun test ne rougisse ni qu'aucune réponse change.",
            relatif(&unite)
        );
        assert!(
            code.lines().any(|l| l.trim_start().starts_with("Environment=PLUME_CONFIG=")),
            "`{}` ne désigne plus de fichier de configuration : l'autre moitié de l'allégation — « le \
             fichier est LA voie » — n'est plus vraie, et les réglages qui n'ont pas d'équivalent en \
             environnement deviennent muets.",
            relatif(&unite)
        );
    }
}
