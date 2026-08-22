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
// par personne. Les gardes ci-dessous tiennent les allégations de ce second type dont le FAISEUR DE
// VÉRITÉ est un fichier de ce dépôt. C'est la ligne de partage utile : sur 258 allégations, 84 portent
// sur l'hôte (noyau, cgroup, système de fichiers) et AUCUNE garde de source ne peut les tenir —
// celles-là se MESURENT à l'exécution, ou cessent d'être des affirmations.
//
// LE RECENSEMENT A DÉSORMAIS UN INSTRUMENT, à côté de ce fichier :
// `recenser_les_allegations_d_environnement.py`, critère publié dans son en-tête. Le premier balayage
// n'en avait laissé aucun, et ses chiffres ne sont donc pas rejouables. Rejoué le 2026-08-22 avec le
// critère publié : 13 681 blocs, 506 candidats, 396 phrases qui affirment, 30 qui nomment un fichier de
// ce dépôt (32 une fois la garde 5 réécrite : ses deux phrases nomment désormais `deploy/k3s.yaml`) —
// réparties en cinq déjà tenues, neuf tenues ici, une FAUSSE et réécrite, et le reste classé hors lot
// dans l'index public. Les deux séries ne se comparent pas : critères différents.
//
// CE QUE CES GARDES NE FONT PAS, écrit pour être opposable :
//   - elles ne jugent aucune phrase. Elles lisent le FICHIER que la phrase prend à témoin. Une garde qui
//     prétendrait relire de la prose produirait du bruit et finirait désarmée ;
//   - elles ne couvrent pas les centaines d'autres allégations, et c'est délibéré : les traiter en masse
//     remplacerait des affirmations non vérifiées par des formulations non vérifiées ;
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
//      quoi le message d'erreur d'une garde suffirait à la faire échouer sur elle-même. L'exception est
//      NOMMÉE : quand la chose cherchée est un littéral (`VmHWM`, une clé de configuration), la garde
//      garde les chaînes et retire seulement les commentaires, et le dit.
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
        depouiller_rust(src, false)
    }

    /// Rend `src` privé de ses seuls commentaires, CHAÎNES CONSERVÉES. Nécessaire quand la chose
    /// cherchée est précisément un littéral : un lecteur de `/proc/self/status` nomme `VmHWM` dans une
    /// chaîne, et le dépouillement complet le rendrait invisible — la garde serait aveugle.
    fn code_sans_commentaires_rust(src: &str) -> String {
        depouiller_rust(src, true)
    }

    fn depouiller_rust(src: &str, garder_les_chaines: bool) -> String {
        let o: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0usize;
        let pousser_blancs = |out: &mut String, tranche: &[char]| {
            for c in tranche {
                out.push(if *c == '\n' { '\n' } else { ' ' });
            }
        };
        let pousser_chaine = |out: &mut String, tranche: &[char]| {
            if garder_les_chaines {
                out.extend(tranche.iter());
            } else {
                for c in tranche {
                    out.push(if *c == '\n' { '\n' } else { ' ' });
                }
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
                    pousser_chaine(&mut out, &o[i..j.min(o.len())]);
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
                pousser_chaine(&mut out, &o[i..j.min(o.len())]);
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

    /// Lit un fichier du dépôt, ou REFUSE DE CONCLURE : un fichier absent n'est pas un fichier vide.
    fn lire_du_depot(rel: &str) -> String {
        std::fs::read_to_string(racine_du_depot().join(rel))
            .unwrap_or_else(|e| panic!("INSTRUMENT : `{rel}` illisible ({e}) — la garde refuse de conclure"))
    }

    /// Relit, sur la ligne `i` (0-based) du TEXTE BRUT, le `n`-ième littéral `"…"` — celui que le
    /// dépouillement a effacé. C'est la voie par laquelle une garde lit une VALEUR chez celui qui
    /// l'emploie (un chemin par défaut, un préfixe) au lieu de la recopier.
    fn litteral_sur_la_ligne(brut: &str, i: usize, n: usize) -> Option<String> {
        let morceaux: Vec<&str> = brut.lines().nth(i)?.split('"').collect();
        morceaux.get(1 + 2 * n).map(|s| s.to_string())
    }

    /// Une durée systemd (`120s`, `15min`, `1h`) en secondes ; `None` si la forme n'est pas reconnue.
    fn secondes_systemd(d: &str) -> Option<i64> {
        let d = d.trim();
        let coupe = d.find(|c: char| !c.is_ascii_digit())?;
        let n: i64 = d[..coupe].parse().ok()?;
        Some(n * match d[coupe..].trim() { "s" | "sec" => 1, "min" | "m" => 60, "h" => 3600, _ => return None })
    }

    /// La valeur d'une directive `Cle=valeur` dans le CODE d'une unité.
    fn directive(code: &str, cle: &str) -> Option<String> {
        code.lines().find_map(|l| l.trim_start().strip_prefix(&format!("{cle}=")).map(|v| v.trim().to_string()))
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
        // Chaînes CONSERVÉES : le littéral survit, le commentaire et le bloc non.
        let avec_chaines = code_sans_commentaires_rust(echantillon);
        assert_eq!(
            avec_chaines.matches("INTERDIT").count(),
            3,
            "dépouillement Rust (chaînes conservées) : {} occurrence(s), trois sont du code ou des chaînes\n{avec_chaines}",
            avec_chaines.matches("INTERDIT").count()
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
    // GARDE 3 — « `collectors/integrity.sh` hache le chemin de recherche d'unités systemd, DÉRIVÉ,
    //            sur les types qui exécutent quelque chose et sur les drop-ins »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `seeds.rs` sème une règle « vecteur de persistance ajouté » (T1543) qui
    /// interroge `source=integrity change=ajout severity>=3`, et justifie sa couverture en affirmant ce
    /// que le capteur d'intégrité surveille. Le capteur est un script shell ; la règle est une ligne de
    /// SQL semée ; rien ne les relie.
    ///
    /// CE QUE SON VIEILLISSEMENT PRODUIRAIT — et c'est le pire silence de tout le recensement : si le
    /// script cessait de hacher ces répertoires, la règle continuerait de s'exécuter, sur zéro ligne, et
    /// ne lèverait JAMAIS d'alerte. Un SOC sans alerte de persistance a exactement l'apparence d'un SOC
    /// sain. Le mode de panne ne produit ni erreur, ni journal, ni chiffre anormal : il produit du calme.
    ///
    /// CE QUE LA PROPRIÉTÉ EST DEVENUE (P3.8-a). Elle tenait UNE ligne — `/etc/systemd/system/*.service`
    /// et `*.timer` — et c'était un trou de couverture : ni `/run/systemd/system`, ni
    /// `/usr/local/lib/systemd/system`, ni les drop-ins `*.d/*.conf`, ni les `.socket`/`.path`. Un drop-in
    /// qui ajoute un `ExecStartPre=` est une persistance ordinaire, et il ne produisait rien. La liste des
    /// répertoires est désormais DÉRIVÉE (`systemd-analyze unit-paths`) avec un repli documenté écrit une
    /// fois ; la garde tient donc QUATRE choses dans le code exécuté : la dérivation, la table de repli
    /// (qui doit contenir les trois répertoires que la clé nommait), les six types d'unités, et le glob
    /// des drop-ins — chacune sur une ligne qui hache sous le genre `unit`. Le témoin dynamique
    /// (`.github/scripts/verifier-fim-couvre-les-unites-systemd.sh`) exécute le capteur contre un
    /// répertoire temporaire et exige l'événement ; cette garde tient la SOURCE, lui tient le COMPORTEMENT.
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

        // L'INSTRUMENT DE CETTE GARDE, VALIDÉ DANS LES DEUX SENS sur des fragments fabriqués : la ligne
        // des drop-ins est reconnue quand elle est exécutée, et ignorée quand elle est commentée. Sans
        // ces deux témoins, une ligne commentée pourrait satisfaire la substance ci-dessous.
        let hache_les_dropins = |texte: &str| {
            texte.lines().any(|l| l.contains("*.d/*.conf") && l.contains("emit_hash unit"))
        };
        let fragment = "for f in \"$_ud\"/*.d/*.conf; do emit_hash unit \"$f\"; done\n";
        assert!(hache_les_dropins(&code_execute_shell(fragment)), "INSTRUMENT : la ligne des drop-ins exécutée n'est pas reconnue");
        assert!(
            !hache_les_dropins(&code_execute_shell(&format!("# {fragment}"))),
            "INSTRUMENT : la ligne des drop-ins COMMENTÉE est reconnue — une phrase satisferait la garde"
        );

        // (1) LA DÉRIVATION : le chemin de recherche est demandé au gestionnaire, pas écrit.
        assert!(
            code.lines().any(|l| l.contains("systemd-analyze unit-paths")),
            "aucune ligne EXÉCUTÉE de {} ne dérive le chemin de recherche par `systemd-analyze unit-paths` : \
             la liste des répertoires d'unités est redevenue une liste écrite, qui vieillit sans le dire.",
            relatif(&script)
        );
        // (2) LA TABLE DE REPLI, écrite une fois, et qui contient au moins les trois répertoires que la
        //     clé P3.8-a nommait comme absents de l'ancienne couverture.
        let repli = code
            .lines()
            .find_map(|l| litteral_sur_la_ligne(l, 0, 0).filter(|_| l.trim_start().starts_with("UNIT_DIRS_DOC=")))
            .unwrap_or_default();
        let repli: Vec<&str> = repli.split_whitespace().collect();
        for attendu in ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system"] {
            assert!(
                repli.contains(&attendu),
                "la table de repli `UNIT_DIRS_DOC=` de {} ne contient plus `{attendu}` (trouvé : {repli:?}) : \
                 sans `systemd-analyze`, ce répertoire ne serait plus haché et la règle T1543 n'y verrait rien.",
                relatif(&script)
            );
        }
        // (3) LES TYPES : ceux qui exécutent ou déclenchent quelque chose, et ils sont hachés sous `unit`.
        let types = code
            .lines()
            .find_map(|l| litteral_sur_la_ligne(l, 0, 0).filter(|_| l.trim_start().starts_with("UNIT_TYPES=")))
            .unwrap_or_default();
        let types: Vec<&str> = types.split_whitespace().collect();
        for attendu in ["service", "timer", "socket", "path", "mount", "automount"] {
            assert!(
                types.contains(&attendu),
                "`UNIT_TYPES=` de {} ne couvre plus `.{attendu}` (trouvé : {types:?}) : une unité de ce type \
                 déposée sur l'hôte ne produirait aucun événement.",
                relatif(&script)
            );
        }
        assert!(
            code.lines().any(|l| l.contains("$UNIT_TYPES") && l.contains("emit_hash unit")),
            "aucune ligne EXÉCUTÉE de {} ne hache les types de `$UNIT_TYPES` sous le genre `unit`.",
            relatif(&script)
        );
        // (4) LES DROP-INS : `<unité>.d/*.conf`, hachés sous `unit` — c'est le silence que la clé fermait.
        assert!(
            hache_les_dropins(&code),
            "aucune ligne EXÉCUTÉE de {} ne hache les drop-ins `*.d/*.conf` sous le genre `unit`.\nUn drop-in \
             qui ajoute un `ExecStartPre=` à une unité existante est une persistance ordinaire : sans cette \
             ligne la règle semée « vecteur de persistance ajouté » (T1543, `source=integrity change=ajout \
             severity>=3`) ne le verra jamais, et un SOC muet ressemble à un SOC sain.",
            relatif(&script)
        );
        // (5) LA VOIE EST DITE dans l'événement : un lecteur distingue la liste dérivée de la liste écrite.
        assert!(
            code.contains("unit_dirs_from"),
            "l'événement `kind=unit` de {} ne porte plus `unit_dirs_from` : la voie de dérivation n'est plus dite.",
            relatif(&script)
        );
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 4 — « `systemd/plume-daemon.service` ne porte AUCUN `EnvironmentFile` »
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE, écrite QUATRE fois (`backup/mod.rs`, `crypto/mod.rs`, et deux fichiers de test) :
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

    // ============================================================================================
    // LOT DU 2026-08-22 — le reste des allégations qui NOMMENT un fichier de ce dépôt, triées par le
    // silence qu'elles produiraient en cessant d'être vraies. Rang SILENCE COMPLET d'abord.
    // L'instrument du recensement vit à côté : `recenser_les_allegations_d_environnement.py`.
    // ============================================================================================

    // --------------------------------------------------------------------------------------------
    // GARDE 5 — « le manifeste k3s livré sauvegarde depuis son UNIQUE conteneur »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION RÉFUTÉE, PUIS RÉÉCRITE. Quatre commentaires (`backup/mod.rs` ×2, `server.rs`, `main.rs`)
    /// affirmaient que « le conteneur PRINCIPAL ne fait JAMAIS de backup » et que le destinataire d'escrow
    /// est « posé UNIQUEMENT sur le SIDECAR `plume-daemon backup` » — et c'est sur ce fait qu'ils ont
    /// retiré le signal de posture du démarrage du serveur. Lu le 2026-08-22, `deploy/k3s.yaml` n'a
    /// QU'UN conteneur, et lui pose `PLUME_BACKUP_INTERVAL` : l'ordonnanceur NATIF du serveur sauvegarde,
    /// sans destinataire — et ce chemin-là n'émettait alors aucun signal (branché depuis, P8.25-a :
    /// `posture_de_sauvegarde_native.rs` le tient). Ce que cette garde tient est ce que le
    /// manifeste dit de lui-même : « sans cette variable, ce déploiement NE SAUVEGARDE RIEN » — et rien
    /// ne le dirait, le pod démarre et sert à l'identique. Elle tient aussi ce que le même manifeste
    /// livre comme secret : une clé SQLCipher VIDE (chiffrement opt-in), jamais une valeur par défaut
    /// que toutes les installations partageraient.
    #[test]
    fn le_manifeste_k3s_livre_sauvegarde_depuis_son_unique_conteneur() {
        let brut = lire_du_depot("deploy/k3s.yaml");
        let code = code_execute_shell(&brut);
        // TÉMOIN NÉGATIF : le destinataire d'escrow n'est écrit qu'en COMMENTAIRE (décision documentée).
        assert!(brut.contains("PLUME_BACKUP_AGE_RECIPIENT"), "INSTRUMENT : le manifeste lu n'est pas celui qu'on croit");
        assert!(!code.contains("PLUME_BACKUP_AGE_RECIPIENT"), "INSTRUMENT : une ligne COMMENTÉE du manifeste a survécu");
        let conteneurs = code.lines().filter(|l| l.trim_start().starts_with("image:")).count();
        assert_eq!(conteneurs, 1, "`deploy/k3s.yaml` livre {conteneurs} conteneur(s) : la prose du démon parle d'un sidecar qui n'existe pas, ou d'un unique conteneur qui n'est plus seul");
        let valeur = |cle: &str| -> Option<String> {
            let l = code.lines().find(|l| l.contains(cle))?;
            let v = l.split("value:").nth(1)?.trim().trim_start_matches('"');
            Some(v.chars().take_while(|c| *c != '"' && *c != ' ' && *c != '}').collect())
        };
        let intervalle: u64 = valeur("PLUME_BACKUP_INTERVAL").and_then(|v| v.parse().ok()).unwrap_or(0);
        assert!(intervalle > 0, "`deploy/k3s.yaml` ne pose plus `PLUME_BACKUP_INTERVAL` > 0 : ce déploiement NE SAUVEGARDE RIEN, et rien ne le dit");
        assert!(code.lines().any(|l| l.trim() == "readOnlyRootFilesystem: true"), "`deploy/k3s.yaml` : le pod n'est plus en racine lecture seule — la raison pour laquelle `config.d` et `web/` sont cuits dans l'image n'est plus vraie");
        let cle = code.lines().find(|l| l.trim_start().starts_with("PLUME_DB_KEY:")).expect("INSTRUMENT : `PLUME_DB_KEY` absent du Secret livré");
        assert!(cle.trim().ends_with("\"\""), "`deploy/k3s.yaml` livre une clé SQLCipher NON VIDE : toutes les installations partageraient la même — {cle}");
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 6 — « `config.d` et `web/` sont CUITS dans l'image, là où le démon les cherche »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `overlays.rs` charge parsers, règles et playbooks sous `PLUME_CONFIG_DIR`,
    /// « DÉFAUT /usr/local/share/plume/config.d — répertoire BAKED dans l'image, comme web/ ». Le chemin
    /// par défaut est LU chez le démon, le Dockerfile est lu ensuite : si l'un des deux bouge sans
    /// l'autre, le démon démarre, sert, et charge ZÉRO règle — un catalogue vide a l'air d'un catalogue.
    #[test]
    fn l_image_livree_cuit_la_configuration_la_ou_le_demon_la_cherche() {
        let lire_defaut = |rel: &str, cle: &str| -> String {
            let brut = lire_du_depot(rel);
            // chaînes conservées : la clé cherchée EST un littéral ; les commentaires, eux, sont retirés
            let i = code_sans_commentaires_rust(&brut).lines().position(|l| l.contains(cle) && l.contains("cfg("))
                .unwrap_or_else(|| panic!("INSTRUMENT : aucune lecture `cfg(… {cle} …)` dans le CODE de `{rel}`"));
            litteral_sur_la_ligne(&brut, i, 1).unwrap_or_else(|| panic!("INSTRUMENT : le défaut de `{cle}` n'est plus lisible dans `{rel}`"))
        };
        let config = lire_defaut("daemon/src/overlays.rs", "PLUME_CONFIG_DIR");
        let web = lire_defaut("daemon/src/server.rs", "PLUME_WEB");
        assert!(config.starts_with('/') && web.starts_with('/'), "INSTRUMENT : défauts lus `{config}` / `{web}` — pas des chemins");
        let brut = lire_du_depot("Dockerfile");
        let code = code_execute_unite(&brut);
        // TÉMOINS : le Dockerfile est abondamment commenté (rien de cela ne doit survivre), et il COPIE.
        assert!(brut.lines().filter(|l| l.starts_with('#')).count() >= 10, "INSTRUMENT : le Dockerfile lu n'a plus de commentaires — ce n'est pas celui qu'on croit");
        assert!(!code.lines().any(|l| l.starts_with('#')), "INSTRUMENT : un commentaire du Dockerfile a survécu au dépouillement");
        assert!(code.lines().filter(|l| l.starts_with("COPY ")).count() >= 3, "INSTRUMENT : le Dockerfile ne copie presque rien — parcours cassé");
        for (source, cible, cle) in [("config.d", &config, "PLUME_CONFIG_DIR"), ("web", &web, "PLUME_WEB")] {
            assert!(code.lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == ["COPY", source, cible.as_str()]),
                "le Dockerfile ne cuit plus `{source}` en `{cible}`, le chemin où le démon le cherche par défaut : le pod (racine lecture seule) démarrerait avec un catalogue VIDE");
            assert!(code.contains(&format!("{cle}={cible}")), "le Dockerfile ne pose plus `{cle}={cible}` : l'image et le démon ne désignent plus le même répertoire");
        }
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 7 — « `bootstrap.sh` pose `/etc/plume/soc.conf` en 0640 »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `crypto/mod.rs` justifie que la clé SQLCipher vive dans le fichier de
    /// configuration parce que « le fichier 0640 est LE bon endroit pour cette clé ». Le fichier est
    /// écrit par `cat >` — donc avec l'umask du shell, 0644 — et c'est une ligne SÉPARÉE qui le referme.
    /// Retirer cette ligne ne casse rien : le démon lit le fichier exactement pareil, et tout utilisateur
    /// local lit la clé et l'empreinte du mot de passe.
    #[test]
    fn l_amorceur_referme_le_fichier_de_configuration_apres_l_avoir_ecrit() {
        let brut = lire_du_depot("bootstrap.sh");
        let code = code_execute_shell(&brut);
        let fichier = "/etc/plume/soc.conf";
        // TÉMOIN NÉGATIF : l'en-tête du bloc nomme le fichier ET le mode, en commentaire.
        let prose: Vec<&str> = brut.lines().filter(|l| l.trim_start().starts_with('#') && l.contains(fichier)).collect();
        assert!(!prose.is_empty(), "INSTRUMENT : plus aucun commentaire ne nomme `{fichier}` — le témoin négatif a disparu");
        assert!(prose.iter().all(|l| !code.contains(l.trim())), "INSTRUMENT : un commentaire a survécu au dépouillement");
        let lignes: Vec<&str> = code.lines().collect();
        let ecriture = lignes.iter().position(|l| l.contains(&format!("> {fichier}")))
            .expect("INSTRUMENT : `bootstrap.sh` n'écrit plus `/etc/plume/soc.conf` par redirection — la forme a changé, relire");
        let referme = lignes[ecriture..].iter().take(16).any(|l| l.contains(&format!("chmod 0640 {fichier}")) || l.contains(&format!("-m0640 {fichier}")));
        assert!(referme, "`bootstrap.sh` écrit `{fichier}` (ligne {}) sans le refermer en 0640 dans les lignes qui suivent : la clé SQLCipher et l'empreinte du mot de passe restent lisibles par tout utilisateur local, et le démon démarre pareil", ecriture + 1);
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 8 — « AUCUN consommateur de ce dépôt ne lit `VmHWM` ; le RSS courant se lit dans `statm` »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `vieillissement_serie.rs` REMET À ZÉRO la crête mémoire du processus
    /// (`clear_refs`) pour la mesurer par fenêtre, et justifie que ce soit sans effet de bord par « AUCUN
    /// consommateur dans ce dépôt ne lit `VmHWM` (`metrics.rs` lit le RSS COURANT via `statm`) ». Un
    /// lecteur de `VmHWM` ajouté demain — une métrique exportée, un diagnostic — recevrait une crête
    /// FENÊTRÉE en la croyant cumulée : un nombre plausible, faux, et personne pour le dire.
    /// CHAÎNES CONSERVÉES ici, et c'est le point : `VmHWM` se lit par un littéral.
    #[test]
    fn la_crete_memoire_n_a_qu_un_lecteur_et_le_rss_courant_se_lit_ailleurs() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        collecter_rs(&racine, &mut fichiers);
        assert!(fichiers.len() >= 150, "INSTRUMENT : {} fichier(s) balayé(s) — parcours cassé", fichiers.len());
        let (mut lecteur_attendu, mut autres) = (false, Vec::<String>::new());
        for f in &fichiers {
            let rel = relatif(f);
            if rel.contains("/tests/") { continue; }
            let code = code_sans_commentaires_rust(&std::fs::read_to_string(f).unwrap_or_default());
            let lit = code.lines().any(|l| l.contains("VmHWM"));
            if rel.ends_with("/vieillissement_serie.rs") { lecteur_attendu = lit; } else if lit { autres.push(rel); }
        }
        // TÉMOIN POSITIF : le lecteur légitime est VU — sinon la garde ne reconnaît plus la forme.
        assert!(lecteur_attendu, "INSTRUMENT : `vieillissement_serie.rs` ne lit plus `VmHWM` dans son code — la garde ne sait plus reconnaître un lecteur");
        assert!(autres.is_empty(), "de nouveaux consommateurs lisent `VmHWM` : {autres:?} — la crête est REMISE À ZÉRO par fenêtre par `vieillissement_serie.rs`, ils liraient une valeur fenêtrée en la croyant cumulée");
        let mesure = code_sans_commentaires_rust(&lire_du_depot("daemon/src/mesure_environnement.rs"));
        assert!(mesure.lines().any(|l| l.contains("statm") && l.contains("join(")), "le RSS courant ne se lit plus dans `/proc/self/statm` (`mesure_environnement.rs`) : l'autre moitié de l'allégation n'est plus vraie");
        assert!(code_execute_rust(&lire_du_depot("daemon/src/metrics.rs")).contains("mesure_environnement::cpu_rss()"), "`metrics.rs` ne passe plus par `mesure_environnement::cpu_rss()` pour le RSS courant");
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 9 — « le capteur YARA émet la source que la règle semée interroge »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `seeds.rs` sème « `search source=yara` » et affirme que `collectors/yara.sh`
    /// « émet des events `source=yara category=malware` en severity 4 », règles lues dans
    /// `/etc/plume/yara.d`. Un capteur renommé ne casse rien : la règle s'exécute sur zéro ligne, à
    /// jamais — un match YARA est précisément l'événement qu'on ne veut pas rater en silence.
    #[test]
    fn le_capteur_yara_emet_la_source_que_la_regle_semee_interroge() {
        let regle = crate::DETECTION_RULES_V53.iter().find(|r| r.1.contains("source=")).expect("INSTRUMENT : aucune règle de `DETECTION_RULES_V53` n'interroge une source");
        let source: String = regle.1.split("source=").nth(1).unwrap().chars().take_while(|c| !c.is_whitespace()).collect();
        let brut = lire_du_depot("collectors/yara.sh");
        let code = code_execute_shell(&brut);
        assert!(brut.lines().filter(|l| l.trim_start().starts_with('#') && l.contains(&source)).count() >= 3, "INSTRUMENT : l'en-tête du capteur ne nomme plus `{source}` — témoin négatif disparu");
        // le JSON est écrit dans une chaîne shell, guillemets ÉCHAPPÉS : on lit la forme désechappée
        let emissions: Vec<String> = code.lines().map(|l| l.replace("\\\"", "\"")).filter(|l| l.contains("\"source\":\"")).collect();
        assert!(!emissions.is_empty(), "INSTRUMENT : aucune émission `\"source\":\"…\"` dans le CODE de `collectors/yara.sh` — la forme a changé");
        for l in &emissions {
            assert!(l.contains(&format!("\"source\":\"{source}\"")), "`collectors/yara.sh` émet une autre source que `{source}` interrogée par la règle semée : {l}");
            assert!(l.contains("\"category\":\"malware\"") && l.contains("\"severity\":4"), "`collectors/yara.sh` n'émet plus `category=malware severity=4` : {l}");
        }
        assert!(code.lines().any(|l| l.contains("RULES_DIR=") && l.contains("/etc/plume/yara.d")), "`collectors/yara.sh` ne lit plus ses règles dans `/etc/plume/yara.d` par défaut");
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 10 — « la mesure qu'interroge la règle « fuite slab » est publiée par `resources.sh` »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `seeds.rs` sème une règle sur `metric mem_slab_mb` et la justifie par
    /// « SUnreclaim (mem_slab_mb de resources.sh) ». Le nom de série est lu dans la règle SEMÉE (base
    /// de test, même chemin que la production), puis cherché chez le capteur. Renommer la série d'un
    /// côté rend la règle inerte pour toujours, avec l'apparence d'un hôte sans fuite.
    #[test]
    fn la_mesure_que_la_regle_fuite_slab_interroge_est_publiee_par_le_capteur() {
        let conn = super::test_db();
        crate::seed_slab_rule(&conn);
        let requete: String = conn.query_row("SELECT query FROM rule WHERE query LIKE 'metric %' AND name LIKE '%slab%'", [], |r| r.get(0))
            .expect("INSTRUMENT : la règle « fuite slab » n'est plus semée sous cette forme");
        let serie: String = requete.trim_start_matches("metric ").chars().take_while(|c| !c.is_whitespace()).collect();
        assert!(!serie.is_empty(), "INSTRUMENT : nom de série vide dans `{requete}`");
        let brut = lire_du_depot("collectors/resources.sh");
        let code = code_execute_shell(&brut);
        // TÉMOIN NÉGATIF : `SUnreclaim` est expliqué en commentaire ; cette prose ne doit pas survivre.
        let prose: Vec<&str> = brut.lines().filter(|l| l.trim_start().starts_with('#') && l.contains("SUnreclaim")).collect();
        assert!(!prose.is_empty() && prose.iter().all(|l| !code.contains(l.trim())), "INSTRUMENT : témoin négatif absent ou survivant ({} ligne(s) de prose)", prose.len());
        assert!(code.lines().filter(|l| l.trim_start().starts_with("ajoute_mesure ")).count() >= 4, "INSTRUMENT : `resources.sh` ne publie presque plus rien par `ajoute_mesure` — la forme a changé");
        assert!(code.lines().any(|l| l.trim_start().starts_with(&format!("ajoute_mesure {serie} "))), "`collectors/resources.sh` ne publie plus `{serie}`, la série qu'interroge la règle semée `{requete}` : la règle ne lèvera plus jamais");
        assert!(code.lines().any(|l| l.contains("champ_meminfo SUnreclaim")), "`collectors/resources.sh` ne lit plus `SUnreclaim` : la série `{serie}` ne mesure plus ce que la règle croit");
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 11 — « `collectors/auditd.sh` rend `action=failure` quand l'`execve` échoue »  (silence complet)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : les deux émetteurs Windows (`agent/src/source/windows.rs`,
    /// `plume-collector.ps1`) posent l'issue d'un 4688 en s'alignant sur « le flux Linux, où
    /// `auditd.sh` rend `action=failure` quand l'`execve` échoue ». Si le capteur Linux cessait de
    /// porter l'issue, `category=exec action=failure` rendrait zéro sur Linux et des lignes sur Windows :
    /// la MÊME requête ne dirait plus la même chose selon l'OS, sans erreur.
    #[test]
    fn le_capteur_auditd_porte_l_issue_d_un_execve() {
        let brut = lire_du_depot("collectors/auditd.sh");
        let code = code_execute_shell(&brut);
        assert!(brut.lines().filter(|l| l.trim_start().starts_with('#') && l.contains("execve")).count() >= 3, "INSTRUMENT : l'en-tête ne parle plus d'`execve` — témoin négatif disparu");
        let emissions: Vec<&str> = code.lines().filter(|l| l.contains("af(\"syscall\"")).collect();
        assert!(!emissions.is_empty(), "INSTRUMENT : aucune ligne du CODE de `auditd.sh` ne pose le champ `syscall` — la forme d'émission a changé");
        for l in &emissions {
            assert!(l.contains("af(\"action\",(succ==\"no\")?\"failure\":\"success\")"), "`collectors/auditd.sh` n'assoit plus `action` sur l'issue de l'appel (`succ`) : {}", l.trim());
        }
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 12 — « la fenêtre de corroboration couvre la première passe du capteur d'intégrité »  (bruyant -> fatigue)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : `maj_corroboree.rs` DÉRIVE sa fenêtre de « `plume-integrity.timer` déclenche
    /// à `OnBootSec=120s` puis toutes les `OnUnitActiveSec=15min` ». Le rang est BRUYANT — une fenêtre
    /// trop courte fait alerter chaque déploiement du produit — mais le bruit de maintenance est ce qui
    /// fait cesser de lire un capteur, et la relation est arithmétique : elle se tient en six lignes.
    #[test]
    fn la_fenetre_de_corroboration_couvre_la_premiere_passe_du_capteur_d_integrite() {
        let code = code_execute_unite(&lire_du_depot("systemd/plume-integrity.timer"));
        let lire = |cle: &str| directive(&code, cle).and_then(|v| secondes_systemd(&v))
            .unwrap_or_else(|| panic!("INSTRUMENT : `{cle}=` absent ou illisible dans `systemd/plume-integrity.timer`"));
        let (boot, cadence, marge) = (lire("OnBootSec"), lire("OnUnitActiveSec"), lire("AccuracySec"));
        assert!(boot + cadence + marge < crate::FENETRE_DE_CORROBORATION_S,
            "`systemd/plume-integrity.timer` ({boot} s + {cadence} s + {marge} s) déborde la fenêtre de corroboration ({} s) : la première passe après un déploiement tomberait hors fenêtre et chaque mise à jour du produit alerterait", crate::FENETRE_DE_CORROBORATION_S);
    }

    // --------------------------------------------------------------------------------------------
    // GARDE 13 — « les amorceurs posent les unités par `install`, SANS substitution »  (bruyant -> fatigue)
    // --------------------------------------------------------------------------------------------

    /// L'ALLÉGATION TENUE : la corroboration compare l'empreinte DÉPLOYÉE à l'empreinte LIVRÉE — elle
    /// suppose que « l'octet déposé dans `/etc/systemd/system` est l'octet livré ». Un `sed` ajouté à
    /// l'amorceur ne casserait rien : chaque déploiement redeviendrait une alerte (fail-closed), et c'est
    /// le capteur entier qu'on cesse alors de lire.
    #[test]
    fn les_amorceurs_posent_les_unites_sans_substitution() {
        let mut deposes = 0usize;
        for script in ["bootstrap.sh", "bootstrap-agent.sh"] {
            let code = code_execute_shell(&lire_du_depot(script));
            for (i, l) in code.lines().enumerate().filter(|(_, l)| l.contains("/etc/systemd/system")) {
                let mots: Vec<&str> = l.split_whitespace().collect();
                let pose_un_fichier = mots.iter().position(|m| *m == "install").map(|p| !mots[p + 1..].contains(&"-d")).unwrap_or(false);
                if pose_un_fichier { deposes += 1; }
                let substitue = ["sed", "envsubst", "cat >", "echo", "printf", "tee"].iter().any(|m| l.contains(m));
                assert!(!substitue, "{script}:{} transforme ou écrit une unité au lieu de la poser telle quelle : {}", i + 1, l.trim());
            }
        }
        // TÉMOIN POSITIF : 27 dépôts par `bootstrap.sh` mesurés le 2026-08-20 ; plancher bas.
        assert!(deposes >= 20, "INSTRUMENT : {deposes} dépôt(s) d'unité reconnus dans les amorceurs — la forme `install … /etc/systemd/system/` a changé");
    }

    // --------------------------------------------------------------------------------------------
    // LE VOLET HÔTE — ce qu'aucune garde de source n'atteint, et ce qui en a été fait
    // --------------------------------------------------------------------------------------------
    //
    // LE LOT. L'instrument (`--hote`) rend le 2026-08-22, arbre courant, 78 phrases dont le faiseur de
    // vérité est un chemin d'hôte ; 15 sont des faux amis mesurés et désormais classés à part par
    // l'instrument (8 `arbre` : la phrase dit où CE CODE nomme le chemin ; 7 `exemple` : le chemin est
    // un jeton de recherche, une algèbre de chemins ou une comparaison). Restent 63, triées par le
    // SILENCE PRODUIT — « si ça cesse d'être vrai sur l'hôte cible, que rend le processus, et qui
    // l'apprend ? » — avec le critère écrit avant le tri : BRUYANT (refus, plantage, test rouge, alerte
    // qui part), AMORTI (un aveu nommé absorbe — `Illisible`, `PasDeMesure`, `None` — ou la fausseté
    // ne peut rendre la conception que PLUS prudente), SILENCE PARTIEL (une ligne de journal, rien
    // d'autre), SILENCE COMPLET (le processus continue et rend une valeur rassurante). Rendu : 21
    // bruyantes, 19 amorties, aucune en silence partiel, 2 en silence complet, 3 explicatives sans
    // dépendant ; 18 phrases du lot ne sont pas des allégations d'hôte mais des descriptions du code ou
    // d'un chemin de configuration (résidu de l'instrument, laissé tel quel : le corriger serait annoter
    // de la prose).
    //
    // LE RANG SILENCE COMPLET COMPTE DEUX ALLÉGATIONS. (1) « SQLite délie le fichier temporaire
    // aussitôt après l'avoir ouvert, donc il disparaît à la fermeture, y compris si le processus
    // meurt » (`sqlite_plafond.rs`) — faiseur : le moteur vendoré (`unixOpen`, `osUnlink` sauf
    // `SQLITE_UNLINK_AFTER_CLOSE`, relu le 2026-08-22 dans le 3.39.4 que `libsqlite3-sys` embarque ici) et le noyau. Si
    // elle lâche, des valeurs d'événement EN CLAIR restent sous un nom dans un répertoire que personne
    // n'ouvre, et la bannière continue de dire « activé vers … ». Issue (i) : MESURÉE à l'exécution,
    // même forme et même endroit que les mesures de `S32` — `entrees_nommees_depuis` rend `Lue([])` ou
    // `Illisible{cause}`, jamais « vide » faute de regarder ; la bannière porte le mot stable
    // `residus-en-clair=`. C'est ce que les deux tests ci-dessous tiennent. (2) « le capteur
    // d'intégrité a raison de surveiller `/etc/systemd/system` : y déposer une unité est un vecteur de
    // persistance » (`maj_corroboree.rs`) — faiseur : le chemin de recherche d'unités de systemd, compilé
    // dans le gestionnaire et documenté (`systemd.unit(5)`). Issue (iii) : laissée, parce que ce chemin
    // n'a jamais changé de forme et que le démon ne tourne pas sur l'hôte du capteur. Les AUTRES
    // répertoires du même chemin de recherche (`/run/systemd/system`, `/usr/local/lib/systemd/system`), les
    // drop-ins `*.d/*.conf` et les `.socket`/`.path` étaient un trou de COUVERTURE, pas une allégation
    // fausse ; `P3.8-a` l'a fermé (liste dérivée de `systemd-analyze unit-paths`, repli documenté), et la
    // garde 3 ci-dessus tient désormais la dérivation, la table de repli, les types et les drop-ins.
    //
    // TROIS PHRASES FAUSSES AU MOT PRÈS, sans dépendant, réécrites pour dire ce qui est su : « le silence
    // vaut `/tmp` » (le moteur vendoré essaie `TMPDIR`, `/var/tmp`, `/usr/tmp`, `/tmp`, `.` dans cet
    // ordre) ; « `1`/`2`/`3` : bits soft-dirty » (ce sont les bits référencé/accédé ; soft-dirty est `4`) ;
    // « `/tmp` est un tmpfs » (vrai sur un poste, faux sur un hôte Debian ou un exécuteur d'intégration
    // continue). Aucun comportement ne dépendait d'elles.

    /// L'ALLÉGATION MESURÉE : « SQLite délie son temporaire aussitôt ouvert ». Son observable exact est
    /// « aucun nom ne subsiste dans le répertoire de déversement au démarrage ». La mesure est exercée
    /// dans les DEUX sens sur un temporaire possédé — un vide rend un VRAI zéro, un nom planté est rendu
    /// avec son nom, la sonde d'écriture (qui est à nous) ne compte pas — et dans le sens qui interdit
    /// une fonction qui ne saurait jamais rien : un répertoire absent rend `illisible` avec sa cause, pas
    /// « aucun résidu ».
    #[test]
    fn un_residu_de_deversement_est_mesure_jamais_suppose_absent() {
        use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ABSENTE, VERDICT_ILLISIBLE, VERDICT_LU};
        use crate::sqlite_plafond::residus_de_deversement;
        use crate::tmp_possede::TmpPossede;
        let tmp = TmpPossede::neuf("s29-residus");

        let vide = residus_de_deversement(&tmp);
        assert_eq!(vide.verdict(), VERDICT_LU, "un répertoire présent et vide EST une mesure");
        assert_eq!(vide.valeur(), Some(&vec![]), "et c'est un VRAI zéro");

        std::fs::write(tmp.join(".sonde-ecriture"), b"1").expect("fixture : sonde");
        let sonde_seule = residus_de_deversement(&tmp);
        assert_eq!(sonde_seule, Mesure::Lue(vec![]), "la sonde d'écriture est à nous : elle n'est pas un résidu");

        std::fs::write(tmp.join("etilqs_4f2a9c"), b"valeur d'evenement en clair").expect("fixture : résidu");
        let un = residus_de_deversement(&tmp);
        assert_eq!(un, Mesure::Lue(vec!["etilqs_4f2a9c".to_string()]), "un nom qui subsiste est rendu AVEC son nom");

        let absent = residus_de_deversement(&tmp.join("sqltmp-qui-n-existe-pas"));
        assert_eq!(absent.verdict(), VERDICT_ILLISIBLE, "un répertoire absent n'est PAS un répertoire sans résidu");
        assert_eq!(absent.cause(), CAUSE_SOURCE_ABSENTE, "la cause nomme ce qui manque");
        assert!(absent.valeur().is_none(), "aucune liste publiable quand on n'a pas regardé");
    }

    /// LA BANNIÈRE DIT LA MESURE AVEC UN MOT STABLE, et seul `=0` est calme. Trois cas exclusifs, un mot
    /// chacun ; un répertoire non listé n'est jamais rendu comme un répertoire vide.
    #[test]
    fn la_banniere_de_deversement_porte_le_constat_de_residus() {
        use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_REFUSEE};
        use crate::sqlite_plafond::{banniere, constat_de_residus, Deversement, Tri};
        let calme = constat_de_residus(&Mesure::Lue(vec![]));
        assert!(calme.contains("residus-en-clair=0"), "{calme}");
        let un = constat_de_residus(&Mesure::Lue(vec!["etilqs_4f2a9c".to_string()]));
        assert!(un.contains("residus-en-clair=1") && un.contains("etilqs_4f2a9c"), "le nom doit être dit : {un}");
        assert!(!un.contains("residus-en-clair=0"), "{un}");
        let aveugle = constat_de_residus(&Mesure::Illisible { cause: CAUSE_SOURCE_REFUSEE, detail: "sqltmp : EACCES".into() });
        assert!(aveugle.contains("residus-en-clair=illisible") && aveugle.contains(CAUSE_SOURCE_REFUSEE), "{aveugle}");
        assert!(!aveugle.contains("residus-en-clair=0"), "ne pas avoir regardé n'est pas avoir vu zéro : {aveugle}");
        // Et le mot traverse la bannière réelle, dans le segment du déversement.
        let b = banniere(
            Deversement::Vers(std::path::PathBuf::from("/x/sqltmp"), Mesure::Lue(vec!["etilqs_4f2a9c".to_string()])),
            Mesure::Lue(Tri::SurDisque { compile: 2, local: 1 }),
        );
        let segment = b.split_once("— déversement").expect("segment de déversement").1;
        assert!(segment.contains("residus-en-clair=1") && segment.contains("etilqs_4f2a9c"), "{b}");
    }
}
