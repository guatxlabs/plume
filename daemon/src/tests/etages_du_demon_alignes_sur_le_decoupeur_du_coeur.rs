// =====================================================================================
// `P10.32-u`, `P10.32-v` — LES JUGES D'ÉTAGES DU DÉMON VOIENT EXACTEMENT LES ÉTAGES QUE LE CŒUR COMPILE, sur le
// corpus fabriqué ci-dessous ET quand une macro cache un pipeline.
//
// LES TROIS JUGES. `keyset_applicable` et `keyset_projection_augment` (`handlers/query.rs`), `AnswerShape::of_gxql`
// (`cold_store/exactness.rs`). Ils découpent le texte détendu des macros par le découpeur du compilateur lui-même
// (`guatx_core::soql::soql_split_pipes`) : une barre ou un crochet entre guillemets doubles n'y est pas une
// frontière, une barre en tête ou un étage vide n'y fabrique rien.
//
// CE QUI A CHANGÉ AVEC LE COMPILATEUR 0.2.6. Le découpeur du cœur respectait les seuls crochets ; il respecte
// désormais aussi les guillemets doubles, et un guillemet non fermé est refusé à la compilation. Les juges
// coupaient, eux, sur TOUTE barre verticale. Mesuré contre 0.2.6 avant leur alignement :
//   - `search x | where a="p|table b"` (UNE étape `where` pour le cœur) : l'augmentation réécrivait
//     `search x | where a="p| table b",ts,id`, que le cœur compile en comparant `a` à `p| table b",ts,id` : la
//     valeur tapée n'était plus celle comparée, zéro ligne sans erreur sur la page au curseur ;
//   - le sens n'était pas toujours prudent : `search x | rex m "(?<a>x|where (?<ts>z))"` est une seule étape `rex`
//     qui crée une colonne `ts` ; le démon y voyait `rex m "(?<a>x` puis `where …` et posait le curseur ;
//   - et prudent ailleurs : `search x | where a="p|stats count"` (un seul `where`) se voyait refuser le curseur.
//
// LES CAS QUI ÉTAIENT « REFUSÉS PAR LE CŒUR ». Trois compilent désormais en une seule étape dont le littéral garde
// sa barre (`where a="p|stats count"`, `where m="err|warn"`, `where a="x|sort -id"`) ; deux restent refusés, pour
// une autre raison que la barre (`where a='p|stats count'` : l'apostrophe n'est pas un guillemet et `stats count'`
// est une syntaxe invalide ; `rex field=m …` : `field=m` n'est pas un nom de champ). Le cas qui démontrait la
// prescription fail-open (`where a="p|stats count|where b="q"`, compilé en `COUNT(*)` par 0.2.5) est REFUSÉ pour
// guillemet non fermé : le cœur ne le sert pas, le démon le juge comme une seule étape `where`, et la route rend
// le refus du compilateur avant toute page (`formes_non_lues_refusees_par_la_route.rs`).
//
// LA VUE DU CŒUR. Pour une requête que `to_sql` compile : `soql_split_pipes`, puis, pour chaque étage hors le
// premier, le MÊME prédicat d'étage que le démon, appliqué à l'étage dont les barres sont neutralisées (`neutre`) :
// il n'en reste aucune, donc la vue du cœur ne dépend pas de la façon dont le juge découpe. La propriété est
// l'ÉGALITÉ des deux vues sur tout le corpus qui compile, macros comprises. Une requête que le cœur refuse n'est
// servie par aucune voie : ce que les juges en disent est écrit cas par cas, sans propriété.
//
// MUTANTS. Chacun des trois sites ramené à `split('|')`, séparément : le témoin d'égalité de son juge rougit
// (`etages_alignes_keyset_vues_egales_au_coeur`, `etages_alignes_augmentation_garde_les_frontieres`,
// `etages_alignes_froid_vues_egales_au_coeur`).
//
// LE TEXTE RÉ-ÉMIS PAR L'AUGMENTATION EST LE TEXTE DÉTENDU, même quand il n'y a rien à ajouter. Le rendre brut
// (backticks compris) ferait compiler à la voie du curseur un texte où l'alias CIM de lecture n'atteint plus le
// corps d'une macro : `category=exec` caché dans une macro ne retrouverait plus l'historique `process`. Mutant
// `AUG_RAW_SI_INCHANGE` (le retour « rien à réécrire » rend le texte brut) : rouges
// `etages_alignes_augmentation_sans_projection_rend_le_texte_detendu`,
// `etages_alignes_augmentation_macros_rend_les_etages_du_texte_detendu` et
// `etages_alignes_augmentation_macro_cim_l_alias_atteint_le_corps`.
// =====================================================================================
mod etages_du_demon_alignes_sur_le_decoupeur_du_coeur {
    use guatx_core::soql::{KnowledgeSet, Schema};

    /// Corpus FABRIQUÉ : guillemets doubles et simples, barre dans un littéral, crochets, crochets dans des
    /// guillemets, `[` non fermé, `]` orphelin, barre en tête et en queue, étage vide, majuscules, alternative
    /// d'expression régulière, groupe nommé `ts` après une barre citée, littéral qui ressemble à une projection,
    /// premier étage de projection, guillemet non fermé.
    const CORPUS: &[&str] = &[
        "search x",
        "search x | where a=1",
        "search x | where a=1 | table b",
        "search x | stats count",
        "search x | STATS count",
        "search x | WHERE a=1",
        "search x | sort -ts",
        "search x | sort -id",
        "search x | where a=\"p|stats count\"",
        "search x | where a='p|stats count'",
        "search x | where a=\"p|stats count|where b=\"q\"",
        "search x | where a=\"p|where b\"",
        "search x | where a=\"x|sort -id\"",
        "search x | where m=\"err|warn\"",
        "search x | where m=\"err| head 5\"",
        "search x | rex field=m \"(?<a>x|y)\"",
        "search x | rex m \"(?<a>x|y)\"",
        "search x | rex m \"(?<a>x|where (?<ts>z))\"",
        "search x | eval z=\"a|where y\"",
        "search x | where a=\"[x|stats]\"",
        "search x | where a='[' | stats count",
        "search x | where a=\"]\" | stats count",
        "search x | where a=\"[\" | eval ts=1",
        "search x | eval y=\"[\" | where ts>0",
        "search x | append [search y | stats count]",
        "search x | append [search y | where a=1]",
        "search x | where a=\"p|table b|where c=\"q\"",
        "search x | where a=\"p|table b\"",
        "search x | where a=\"p|table b\" | table c",
        "search x | where a=\"p | table b",
        "fields a | where b=1",
        "| stats count",
        "| where a=1",
        "search x | where a=1 |",
        "search x || where a=1",
        "search x | | stats count",
    ];

    /// Requêtes SANS barre ni crochet dans un littéral : tout découpeur y voit les mêmes étages.
    const SANS_BARRE_LITTERALE: &[&str] = &[
        "search x",
        "search x | where a=1",
        "search x | where a=1 | table b",
        "search x | stats count",
        "search x | STATS count",
        "search x | WHERE a=1",
        "search x | sort -ts",
        "search x | sort -id",
        "search x | where a=1 |",
        "search x || where a=1",
    ];

    /// Le cas qui démontrait la prescription fail-open sous 0.2.5 : désormais refusé pour guillemet non fermé.
    const PRESCRIPTION_FAIL_OPEN: &str = "search x | where a=\"p|stats count|where b=\"q\"";
    /// Sa phrase de refus, telle que le compilateur 0.2.6 la rend.
    const REFUS_GUILLEMET_OCTET_44: &str = "guillemet non fermé : le « \" » à l'octet 44 ouvre un texte qui ne se referme pas avant la fin de la requête ; fermez-le (`champ=\"valeur\"`), ou retirez-le";
    /// Refusés par 0.2.5, compilés par 0.2.6 : une seule étape `where`, littéral (barre comprise) dans le SQL.
    const COMPILES_DESORMAIS: &[(&str, &str)] = &[
        ("search x | where a=\"p|stats count\"", "= 'p|stats count'"),
        ("search x | where m=\"err|warn\"", "= 'err|warn'"),
        ("search x | where a=\"x|sort -id\"", "= 'x|sort -id'"),
    ];
    /// Toujours refusés, pour une raison qui n'est pas la barre.
    const TOUJOURS_REFUSES: &[(&str, &str)] = &[
        ("search x | where a='p|stats count'", "stats : syntaxe invalide 'count''"),
        ("search x | rex field=m \"(?<a>x|y)\"", "rex : champ invalide : field=m"),
    ];
    /// Un littéral qui ressemble à une projection : une seule étape `where` pour le cœur.
    const LITTERAL_QUI_RESSEMBLE_A_UNE_PROJECTION: &str = "search x | where a=\"p|table b\"";
    /// Une étape `rex` qui crée une colonne `ts` derrière une barre de son motif.
    const REX_QUI_NOMME_TS: &str = "search x | rex m \"(?<a>x|where (?<ts>z))\"";

    fn compile(q: &str) -> Result<String, String> {
        guatx_core::soql::to_sql(q, 0, 0, &Schema::events())
    }

    fn decoupe_du_coeur(q: &str) -> Vec<String> {
        guatx_core::soql::soql_split_pipes(q)
    }

    /// Découpeur FABRIQUÉ, celui des juges avant leur alignement : coupe sur toute barre.
    fn decoupe_naive(q: &str) -> Vec<String> {
        q.split('|').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }

    /// Découpeur FABRIQUÉ qui ne coupe jamais.
    fn decoupe_jamais(q: &str) -> Vec<String> {
        vec![q.trim().to_string()]
    }

    /// L'étage, barres neutralisées : le prédicat d'étage le juge sans qu'aucun découpeur puisse le recouper.
    fn neutre(etage: &str) -> String {
        etage.replace('|', " ")
    }

    /// Branche un découpeur sur le prédicat d'étage du démon : tous les étages hors le premier doivent passer.
    fn vue(decoupe: fn(&str) -> Vec<String>, predicat_etage: &dyn Fn(&str) -> bool, q: &str) -> bool {
        decoupe(q).iter().skip(1).all(|e| predicat_etage(&format!("search x | {}", neutre(e))))
    }

    /// Corpus qui compile, et les requêtes où les deux vues divergent.
    fn divergences(demon: &dyn Fn(&str) -> bool, coeur: &dyn Fn(&str) -> bool) -> (usize, Vec<String>) {
        let mut compilees = 0;
        let mut ecarts = Vec::new();
        for q in CORPUS.iter().copied().filter(|q| compile(q).is_ok()) {
            compilees += 1;
            if demon(q) != coeur(q) {
                ecarts.push(format!("`{q}` : démon {}, cœur {}", demon(q), coeur(q)));
            }
        }
        (compilees, ecarts)
    }

    fn coeur_keyset(q: &str) -> bool {
        vue(decoupe_du_coeur, &crate::keyset_applicable, q)
    }

    /// Jeu de savoir FABRIQUÉ : une macro qui cache un agrégat, une qui n'est qu'un filtre, une projection, et
    /// deux dont le corps porte une barre entre guillemets.
    fn savoir_a_macros() -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        ks.add_macro("agg", vec![], "| stats count");
        ks.add_macro("filtre", vec![], "source=x");
        ks.add_macro("proj", vec![], "| table b");
        ks.add_macro("barre", vec![], "| where a=\"p|stats count\"");
        ks.add_macro("barre_proj", vec![], "| where a=\"p|table b\"");
        ks
    }

    /// Corpus à macros (jeu `savoir_a_macros`).
    const CORPUS_MACROS: &[&str] = &[
        "search x `agg`",
        "search `filtre`",
        "search x `proj`",
        "search x `barre`",
        "search x `barre_proj`",
        "search x `barre_proj` | table c",
        "search `filtre` | rex m \"(?<a>x|where (?<ts>z))\"",
    ];

    /// Vue du cœur sur une requête à macros : compilée avec le savoir, découpée sur le texte détendu.
    fn coeur_macros(q: &str, predicat: &dyn Fn(&str) -> bool) -> Option<bool> {
        let ks = savoir_a_macros();
        guatx_core::soql::to_sql(q, 0, 0, &Schema::events().with_knowledge(ks.clone())).ok()?;
        let detendu = guatx_core::soql::expand_macros(q, &ks).ok()?;
        Some(decoupe_du_coeur(&detendu).iter().skip(1).all(|e| predicat(&format!("search x | {}", neutre(e)))))
    }

    #[test]
    fn etages_alignes_ancrage_par_le_vrai_compilateur() {
        assert_eq!(compile(PRESCRIPTION_FAIL_OPEN), Err(REFUS_GUILLEMET_OCTET_44.to_string()), "refusé pour guillemet non fermé");
        for (q, litteral) in COMPILES_DESORMAIS {
            let sql = compile(q).unwrap_or_else(|e| panic!("`{q}` compile désormais : {e}"));
            assert!(sql.contains(litteral), "`{q}` : une seule étape `where`, littéral entier : {sql}");
            assert!(!sql.contains("COUNT(") && !sql.contains("ORDER BY"), "`{q}` : aucune étape fabriquée par la barre : {sql}");
            assert_eq!(decoupe_du_coeur(q).len(), 2, "`{q}` : deux étapes pour le cœur");
        }
        for (q, debut) in TOUJOURS_REFUSES {
            let e = compile(q).expect_err(q);
            assert!(e.starts_with(debut), "`{q}` : refus attendu « {debut} … », rendu : {e}");
        }
        let sql = compile(LITTERAL_QUI_RESSEMBLE_A_UNE_PROJECTION).expect("une seule étape where");
        assert!(sql.ends_with("WHERE json_extract(fields,'$.a') = 'p|table b'"), "{sql}");
        let sql = compile(REX_QUI_NOMME_TS).expect("une seule étape rex");
        assert!(sql.contains("AS \"ts\""), "la seule étape `rex` crée une colonne ts : {sql}");
        let sql = guatx_core::soql::to_sql("search x `agg`", 0, 0, &Schema::events().with_knowledge(savoir_a_macros()))
            .expect("une macro-pipeline compile");
        assert!(sql.contains("COUNT("), "la macro cache un agrégat que le cœur compile : {sql}");
    }

    /// Égalité des vues sur le corpus qui compile, puis ce que le démon rend sur chaque cas que la mesure a nommé.
    #[test]
    fn etages_alignes_keyset_vues_egales_au_coeur() {
        let (compilees, ecarts) = divergences(&crate::keyset_applicable, &coeur_keyset);
        assert!(compilees >= 20, "corpus compilé trop maigre : {compilees}");
        assert!(ecarts.is_empty(), "keyset_applicable ne voit pas les étages du cœur : {ecarts:#?}");
        // Les cas de la mesure, verdict écrit.
        assert!(crate::keyset_applicable("search x | where a=\"p|stats count\""), "un seul `where` : curseur");
        assert!(crate::keyset_applicable("search x | where a=\"[x|stats]\""), "barre entre crochets cités : un seul `where`");
        assert!(crate::keyset_applicable("search x | where a='[' | stats count"), "le cœur n'y voit qu'un `where` (crochet ouvert)");
        assert!(!crate::keyset_applicable(REX_QUI_NOMME_TS), "l'étape `rex` nomme ts : pas de curseur");
        assert!(crate::keyset_applicable("| where a=1"), "barre en tête : `where a=1` est la base pour le cœur");
        assert!(crate::keyset_applicable("| stats count"), "barre en tête : `stats count` est la base (termes libres)");
        // Refusé par le cœur : le juge y voit une seule étape `where`, la compilation refuse avant toute page.
        assert!(crate::keyset_applicable(PRESCRIPTION_FAIL_OPEN));
        assert!(compile(PRESCRIPTION_FAIL_OPEN).is_err());
    }

    #[test]
    fn etages_alignes_keyset_temoin_positif_vues_egales_sans_barre_litterale() {
        for q in SANS_BARRE_LITTERALE {
            assert_eq!(crate::keyset_applicable(q), coeur_keyset(q), "vues divergentes sur `{q}`");
        }
        assert!(crate::keyset_applicable("search x | where a=1 | table b"));
        assert!(!crate::keyset_applicable("search x | stats count"));
    }

    /// L'instrument prend en défaut l'ancien découpeur (dans les DEUX sens) et un découpeur muet.
    #[test]
    fn etages_alignes_keyset_epreuve_de_l_instrument() {
        let naive = |q: &str| vue(decoupe_naive, &crate::keyset_applicable, q);
        let (_, ecarts) = divergences(&naive, &coeur_keyset);
        let nomme = |q: &str| ecarts.iter().any(|e| e.starts_with(&format!("`{q}`")));
        assert!(nomme(REX_QUI_NOMME_TS), "l'ancien découpeur posait le curseur sur un `rex` qui nomme ts : {ecarts:#?}");
        assert!(naive(REX_QUI_NOMME_TS) && !coeur_keyset(REX_QUI_NOMME_TS));
        assert!(nomme("search x | where a=\"p|stats count\""), "et le refusait à un seul `where` : {ecarts:#?}");
        let jamais = |q: &str| vue(decoupe_jamais, &crate::keyset_applicable, q);
        let (_, ecarts) = divergences(&jamais, &coeur_keyset);
        assert!(ecarts.iter().any(|e| e.starts_with("`search x | stats count`")), "un découpeur muet doit être pris en défaut : {ecarts:#?}");
    }

    /// `keyset_projection_augment` : mêmes étages que le cœur, chaque étage hors projection À L'OCTET (un littéral
    /// n'est jamais touché), ts/id ajoutés à la seule projection que le cœur voit.
    #[test]
    fn etages_alignes_augmentation_garde_les_frontieres() {
        let mut vus = 0;
        for q in CORPUS.iter().copied().filter(|q| crate::keyset_applicable(q) && compile(q).is_ok()) {
            let (aug, _) = crate::keyset_projection_augment(q);
            let (avant, apres) = (decoupe_du_coeur(q), decoupe_du_coeur(&aug));
            assert_eq!(avant.len(), apres.len(), "étages du cœur changés : `{q}` -> `{aug}`");
            for (i, (a, b)) in avant.iter().zip(&apres).enumerate() {
                let projection = i > 0 && matches!(a.split_whitespace().next(), Some("table" | "fields"));
                if projection {
                    assert!(b.starts_with(a.as_str()), "projection réécrite au lieu d'être complétée : `{a}` -> `{b}`");
                } else {
                    assert_eq!(a, b, "étage {i} réécrit : `{q}` -> `{aug}`");
                }
            }
            assert!(compile(&aug).is_ok(), "le texte augmenté compile : `{aug}`");
            vus += 1;
        }
        assert!(vus >= 12, "corpus applicable trop maigre : {vus}");
        let (aug, ajoutees) = crate::keyset_projection_augment("search x | where a=1 | table b");
        assert_eq!(ajoutees, 2);
        assert_eq!(decoupe_du_coeur(&aug), vec!["search x", "where a=1", "table b,ts,id"]);
        // Rien à ajouter : texte rendu À L'OCTET (blancs et barre finale compris).
        assert_eq!(crate::keyset_projection_augment("search x  |where a=1 |"), ("search x  |where a=1 |".to_string(), 0));
        // Une projection à compléter : les étages du cœur sont rejoints sur ` | `, l'étage vide est jeté.
        assert_eq!(crate::keyset_projection_augment("search x || where a=1 |table b"), ("search x | where a=1 | table b,ts,id".to_string(), 2));
        // Premier étage de projection : jamais augmenté (ce n'est pas un étage pour le cœur).
        assert!(crate::keyset_applicable("fields a | where b=1"));
        assert_eq!(crate::keyset_projection_augment("fields a | where b=1"), ("fields a | where b=1".to_string(), 0));
        // Littéral qui ressemble à une projection : rien à ajouter, texte rendu à l'octet, valeur comparée intacte.
        assert!(crate::keyset_applicable(LITTERAL_QUI_RESSEMBLE_A_UNE_PROJECTION));
        assert_eq!(
            crate::keyset_projection_augment(LITTERAL_QUI_RESSEMBLE_A_UNE_PROJECTION),
            (LITTERAL_QUI_RESSEMBLE_A_UNE_PROJECTION.to_string(), 0)
        );
        // Une vraie projection derrière ce littéral : elle seule reçoit ts/id, le littéral reste entier.
        let (aug, ajoutees) = crate::keyset_projection_augment("search x | where a=\"p|table b\" | table c");
        assert_eq!((aug.as_str(), ajoutees), ("search x | where a=\"p|table b\" | table c,ts,id", 2));
        assert!(compile(&aug).unwrap().contains("= 'p|table b'"), "valeur comparée = valeur tapée : `{aug}`");
    }

    #[test]
    fn etages_alignes_keyset_lit_le_texte_detendu_des_macros() {
        let ks = savoir_a_macros();
        assert!(!crate::keyset_applicable_selon("search x `agg`", || ks.clone()), "macro-agrégat : pas de curseur");
        assert!(crate::keyset_applicable_selon("search `filtre`", || ks.clone()), "macro-filtre : curseur gardé");
        assert!(crate::keyset_applicable_selon("search x `proj`", || ks.clone()), "macro-projection : curseur gardé");
        assert!(!crate::keyset_applicable_selon("search x `inconnue`", || ks.clone()), "détente en échec : refus");
        assert!(!crate::keyset_applicable_selon("search x `agg`", KnowledgeSet::new), "aucune macro définie : refus");
        // L'augmentation lit le même texte détendu : la projection cachée reçoit ts/id, et le texte compile.
        let (aug, ajoutees) = crate::keyset_projection_augment_selon("search x `proj`", || ks.clone());
        assert_eq!(ajoutees, 2, "`{aug}`");
        assert_eq!(decoupe_du_coeur(&aug), vec!["search x", "table b,ts,id"]);
        assert!(compile(&aug).is_ok(), "le texte détendu et augmenté compile : `{aug}`");
        // Sans backtick : texte strictement inchangé.
        assert_eq!(crate::keyset_projection_augment_selon("search x | table b", KnowledgeSet::new).0, "search x | table b,ts,id");
        // Macro dont le corps porte une barre citée : le littéral n'est pas touché, la projection suivante l'est.
        let (aug, ajoutees) = crate::keyset_projection_augment_selon("search x `barre_proj` | table c", || ks.clone());
        assert_eq!(ajoutees, 2, "`{aug}`");
        assert_eq!(decoupe_du_coeur(&aug), vec!["search x", "where a=\"p|table b\"", "table c,ts,id"]);
    }

    /// Égalité des vues sur le corpus à macros (la vue du cœur compile avec le savoir et découpe le texte détendu).
    #[test]
    fn etages_alignes_keyset_vues_egales_au_coeur_macros_comprises() {
        let ks = savoir_a_macros();
        let mut compilees = 0;
        let mut ecarts = Vec::new();
        for q in CORPUS_MACROS {
            let Some(coeur) = coeur_macros(q, &crate::keyset_applicable) else { continue };
            compilees += 1;
            let demon = crate::keyset_applicable_selon(q, || ks.clone());
            if demon != coeur {
                ecarts.push(format!("`{q}` : démon {demon}, cœur {coeur}"));
            }
        }
        assert!(compilees >= 6, "corpus à macros compilé trop maigre : {compilees}");
        assert!(ecarts.is_empty(), "{ecarts:#?}");
        assert!(crate::keyset_applicable_selon("search x `barre`", || ks.clone()), "barre citée dans la macro : un seul `where`");
    }

    /// Les POINTS D'ENTRÉE que le gestionnaire appelle (`keyset_applicable`, `keyset_projection_augment`) passent eux
    /// aussi par la détente : sous le savoir actif d'un test (vide, aucun état global posé), une macro ne se détend pas
    /// et le curseur est REFUSÉ, l'augmentation ne touche à rien. Un point d'entrée qui jugerait le texte brut (backticks
    /// retirés, ou détente sautée) rendrait le curseur à un agrégat caché : ce témoin rougit (mutants `W_KA_BRUT`,
    /// `W_AUG_BRUT`). Contrôle positif : sans backtick, le même point d'entrée garde le curseur et augmente.
    #[test]
    fn etages_alignes_les_points_d_entree_passent_par_la_detente() {
        assert!(!crate::keyset_applicable("search x `agg`"), "macro non détendue au point d'entrée : pas de curseur");
        assert_eq!(crate::keyset_projection_augment("search x `proj` | table c"), ("search x `proj` | table c".to_string(), 0));
        assert!(crate::keyset_applicable("search x | table b"), "contrôle positif : sans backtick, curseur gardé");
        assert_eq!(crate::keyset_projection_augment("search x | table b"), ("search x | table b,ts,id".to_string(), 2));
    }

    /// Une macro dont le corps écrit l'égalité que l'alias CIM de lecture élargit (`soql_glue::cim_read_alias_exec`).
    const MACRO_CIM: &str = "k4_cim_exec";

    fn savoir_cim() -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        ks.add_macro(MACRO_CIM, vec![], "category=exec");
        ks
    }

    /// Rien à ajouter, une macro dans le texte : l'augmentation rend la détente du cœur de ce même texte, sans aucun
    /// backtick, et 0 colonne ajoutée ; de même avec des étages derrière la macro.
    #[test]
    fn etages_alignes_augmentation_sans_projection_rend_le_texte_detendu() {
        let ks = savoir_a_macros();
        let juger = |q: &str| {
            assert!(crate::keyset_applicable_selon(q, || ks.clone()), "`{q}` : curseur");
            let detendu = guatx_core::soql::expand_macros(q, &ks).unwrap_or_else(|e| panic!("`{q}` : détente : {e}"));
            assert!(!detendu.contains('`'), "contrôle : la détente du cœur ne laisse aucun backtick : `{detendu}`");
            let (rendu, ajoutees) = crate::keyset_projection_augment_selon(q, || ks.clone());
            assert!(!rendu.contains('`'), "`{q}` : le texte rendu ne porte aucun backtick : `{rendu}`");
            assert_eq!((rendu.as_str(), ajoutees), (detendu.as_str(), 0), "`{q}` : texte détendu, rien d'ajouté");
        };
        juger("search `filtre`");
        juger("search `filtre` | where a=1");
        juger("search x `barre`");
    }

    /// Sur le corpus à macros, pour chaque requête que le curseur juge applicable : le texte augmenté ne porte aucun
    /// backtick, et ses étages pour le cœur sont ceux du texte DÉTENDU, la projection complétée mise à part.
    #[test]
    fn etages_alignes_augmentation_macros_rend_les_etages_du_texte_detendu() {
        let ks = savoir_a_macros();
        let mut vus = 0;
        let mut sans_ajout = 0;
        for q in CORPUS_MACROS.iter().copied().filter(|q| crate::keyset_applicable_selon(q, || ks.clone())) {
            let detendu = guatx_core::soql::expand_macros(q, &ks).unwrap_or_else(|e| panic!("`{q}` : détente : {e}"));
            let (aug, ajoutees) = crate::keyset_projection_augment_selon(q, || ks.clone());
            assert!(!aug.contains('`'), "`{q}` : le texte augmenté ne porte aucun backtick : `{aug}`");
            let (attendu, rendu) = (decoupe_du_coeur(&detendu), decoupe_du_coeur(&aug));
            assert_eq!(attendu.len(), rendu.len(), "étages du texte détendu changés : `{q}` -> `{aug}`");
            for (i, (a, b)) in attendu.iter().zip(&rendu).enumerate() {
                let projection = i > 0 && matches!(a.split_whitespace().next(), Some("table" | "fields"));
                if projection {
                    assert!(b.starts_with(a.as_str()), "projection réécrite au lieu d'être complétée : `{a}` -> `{b}`");
                } else {
                    assert_eq!(a, b, "étage {i} réécrit : `{q}` -> `{aug}`");
                }
            }
            if ajoutees == 0 {
                sans_ajout += 1;
            }
            vus += 1;
        }
        assert!(vus >= 5, "corpus à macros applicable trop maigre : {vus}");
        assert!(sans_ajout >= 3, "cas sans projection à compléter trop peu nombreux : {sans_ajout}");
    }

    /// L'EFFET, par la chaîne de la branche keyset de `POST /api/query` (`handlers/query.rs`) : `keyset_projection_augment`
    /// puis `soql_to_sql_masked_keyset_x` sur le texte qu'il rend. La macro est détendue AVANT la compilation, donc
    /// l'alias CIM de lecture, que le store applique au texte compilé, atteint son corps : le SQL retrouve aussi
    /// l'historique `process`. Épreuve : le texte BRUT compilé avec le même savoir ne porte que la forme nue (l'alias
    /// passe avant la détente du cœur, limite écrite dans `soql_glue.rs`).
    #[test]
    fn etages_alignes_augmentation_macro_cim_l_alias_atteint_le_corps() {
        let ks = savoir_cim();
        let q = format!("search `{MACRO_CIM}`");
        assert!(crate::keyset_applicable_selon(&q, || ks.clone()), "un filtre caché dans une macro : curseur");
        let (aug, ajoutees) = crate::keyset_projection_augment_selon(&q, || ks.clone());
        assert_eq!(ajoutees, 0, "rien à compléter : `{aug}`");
        let sql = crate::soql_to_sql_masked_keyset_x(&aug, 0, 0, None, &guatx_core::soql::FieldMaskSet::new())
            .unwrap_or_else(|e| panic!("le texte rendu par l'augmentation compile : `{aug}` : {e}"));
        assert!(sql.contains("'exec'") && sql.contains("'process'"), "l'alias CIM atteint le corps de la macro : {sql}");
        let brut = guatx_core::soql::to_sql(
            &crate::cim_read_alias_exec(&q),
            0,
            0,
            &Schema::events().with_knowledge(ks).with_cursor_id(true),
        )
        .expect("le texte brut compile avec le savoir");
        assert!(brut.contains("'exec'") && !brut.contains("'process'"), "épreuve : le texte brut ne porte que la forme nue : {brut}");
    }

    #[cfg(feature = "cold_tier")]
    mod exactitude_froide {
        use super::*;

        fn demon_par_evenement(q: &str) -> bool {
            crate::cold_store::AnswerShape::of_gxql(q).is_per_event()
        }

        fn coeur_par_evenement(q: &str) -> bool {
            vue(decoupe_du_coeur, &demon_par_evenement, q)
        }

        #[test]
        fn etages_alignes_froid_vues_egales_au_coeur() {
            let (compilees, ecarts) = divergences(&demon_par_evenement, &coeur_par_evenement);
            assert!(compilees >= 20, "corpus compilé trop maigre : {compilees}");
            assert!(ecarts.is_empty(), "of_gxql ne voit pas les étages du cœur : {ecarts:#?}");
            assert!(demon_par_evenement("search x | where a=\"p|stats count\""), "un seul `where` : par-événement");
            assert!(demon_par_evenement("| stats count"), "barre en tête : la base, par-événement");
            assert!(!demon_par_evenement("search x | where a=\"]\" | stats count"), "agrégat : dérivé");
            // Refusé par le cœur : une seule étape `where` aux yeux du juge, aucune réponse servie.
            assert!(demon_par_evenement(PRESCRIPTION_FAIL_OPEN));
            assert!(compile(PRESCRIPTION_FAIL_OPEN).is_err());
            let ks = savoir_a_macros();
            let mut compilees = 0;
            let mut ecarts = Vec::new();
            for q in CORPUS_MACROS {
                let Some(coeur) = coeur_macros(q, &demon_par_evenement) else { continue };
                compilees += 1;
                let demon = crate::cold_store::AnswerShape::of_gxql_selon(q, || ks.clone()).is_per_event();
                if demon != coeur {
                    ecarts.push(format!("`{q}` : démon {demon}, cœur {coeur}"));
                }
            }
            assert!(compilees >= 6, "corpus à macros compilé trop maigre : {compilees}");
            assert!(ecarts.is_empty(), "{ecarts:#?}");
        }

        #[test]
        fn etages_alignes_froid_temoin_positif_vues_egales_sans_barre_litterale() {
            for q in SANS_BARRE_LITTERALE {
                assert_eq!(demon_par_evenement(q), coeur_par_evenement(q), "vues divergentes sur `{q}`");
            }
            assert!(demon_par_evenement("search x | where a=1 | table b"));
            assert!(!demon_par_evenement("search x | stats count"));
        }

        #[test]
        fn etages_alignes_froid_epreuve_de_l_instrument() {
            let naive = |q: &str| vue(decoupe_naive, &demon_par_evenement, q);
            let (_, ecarts) = divergences(&naive, &coeur_par_evenement);
            assert!(
                ecarts.iter().any(|e| e.starts_with("`search x | where a=\"p|stats count\"`")),
                "l'ancien découpeur refusait l'exactitude à un seul `where` : {ecarts:#?}"
            );
            let jamais = |q: &str| vue(decoupe_jamais, &demon_par_evenement, q);
            let (_, ecarts) = divergences(&jamais, &coeur_par_evenement);
            assert!(ecarts.iter().any(|e| e.starts_with("`search x | stats count`")), "découpeur muet non pris en défaut : {ecarts:#?}");
        }

        #[test]
        fn etages_alignes_froid_lit_le_texte_detendu_des_macros() {
            use crate::cold_store::AnswerShape;
            let ks = savoir_a_macros();
            assert!(!AnswerShape::of_gxql_selon("search x `agg`", || ks.clone()).is_per_event(), "macro-agrégat : dérivé");
            assert!(AnswerShape::of_gxql_selon("search `filtre`", || ks.clone()).is_per_event(), "macro-filtre : par-événement");
            assert!(!AnswerShape::of_gxql_selon("search x `inconnue`", || ks.clone()).is_per_event(), "détente en échec : aveu");
            assert!(!AnswerShape::of_gxql_selon("search x `agg`", KnowledgeSet::new).is_per_event(), "aucune macro : aveu");
        }

        /// Le POINT D'ENTRÉE `AnswerShape::of_gxql` (celui des trois sites du gestionnaire) passe par la détente :
        /// sous le savoir actif d'un test (vide), une macro ne se détend pas et l'exactitude par-événement n'est PAS
        /// affirmée (mutant `W_OG_BRUT` : rouge). Contrôle positif : sans backtick, un filtre reste par-événement.
        #[test]
        fn etages_alignes_froid_le_point_d_entree_passe_par_la_detente() {
            use crate::cold_store::AnswerShape;
            assert!(!AnswerShape::of_gxql("search x `agg`").is_per_event(), "macro non détendue au point d'entrée : aveu");
            assert!(AnswerShape::of_gxql("search x | where a=1").is_per_event(), "contrôle positif : filtre par-événement");
        }
    }
}
