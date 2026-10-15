// =====================================================================================
// `P10.32-u` — LES JUGES D'ÉTAGES DU DÉMON NE VOIENT JAMAIS MOINS D'ÉTAGES QUE LE CŒUR N'EN COMPILE, sur le
// corpus fabriqué ci-dessous ET quand une macro cache un pipeline.
//
// LE CONSTAT (vrai, relu sur 00ea0ad1). Trois sites du démon découpent la requête sur TOUTE barre verticale,
// sans guillemets ni crochets : `keyset_applicable` et `keyset_projection_augment` (`handlers/query.rs`),
// `AnswerShape::of_gxql` (`cold_store/exactness.rs`).
//
// LA PRESCRIPTION (« découper en respectant les guillemets ») EST FAIL-OPEN. Le découpeur du compilateur
// épinglé (`guatx_core::soql::soql_split_pipes`, `P10.32-v`, hors de ce dépôt) est LUI AUSSI aveugle aux
// guillemets : il ne respecte que les crochets. Cas MESURÉ par le vrai compilateur (`to_sql`) :
// `search x | where a="p|stats count|where b="q"` compile en `SELECT COUNT(*)…` (le cœur coupe dans les
// deux littéraux) alors qu'un découpeur sensible aux guillemets n'y voit qu'un `where` : curseur posé sur un
// agrégat, exactitude froide affirmée sur un compte. Les cas plus courts (`where a="p|stats count"`, etc.)
// sont REFUSÉS par le cœur (erreur de compilation) : ils ne prouvent rien, et le témoin le dit.
//
// L'ACCUSATION QUE LA PREMIÈRE VERSION TAISAIT. Le cœur détend les macros AVANT de découper : `search x
// `agg`` avec `agg = | stats count` compile un `COUNT(*)`, alors que les trois juges lisaient le texte brut
// (aucune barre) et le disaient par-événement / paginable au curseur. Remède (production) : les juges lisent
// le texte DÉTENDU par `guatx_core::soql::expand_macros` (`soql_detendu_pour_juger`), avec le jeu de savoir
// de la compilation ; une détente en échec vaut REFUS.
//
// LA VUE DU CŒUR. Une requête que `to_sql` refuse ne sert rien : elle n'est jamais dangereuse. Pour une
// requête qui compile, `soql_split_pipes`, puis, pour chaque étage hors le premier, le MÊME prédicat d'étage
// que le démon, appliqué à la TÊTE de l'étage. La propriété est une IMPLICATION : démon accepte et cœur
// compile => le découpage du cœur accepte aussi.
// =====================================================================================
mod etages_du_demon_alignes_sur_le_decoupeur_du_coeur {
    use guatx_core::soql::{KnowledgeSet, Schema};

    /// Corpus FABRIQUÉ : guillemets doubles et simples, barre dans un littéral, crochets, crochets dans des
    /// guillemets, `[` non fermé, `]` orphelin, barre en tête et en queue, étage vide, majuscules, alternative
    /// d'expression régulière, projection après une barre citée, premier étage de projection.
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
        "search x | where a=\"[x|stats]\"",
        "search x | where a='[' | stats count",
        "search x | where a=\"]\" | stats count",
        "search x | where a=\"[\" | eval ts=1",
        "search x | eval y=\"[\" | where ts>0",
        "search x | append [search y | stats count]",
        "search x | append [search y | where a=1]",
        "search x | where a=\"p|table b|where c=\"q\"",
        "fields a | where b=1",
        "| stats count",
        "| where a=1",
        "search x | where a=1 |",
        "search x || where a=1",
        "search x | | stats count",
    ];

    /// Requêtes SANS barre ni crochet dans un littéral : les deux découpeurs y voient les mêmes étages.
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

    /// Le cas MESURÉ qui démontre la prescription fail-open (le cœur compile un `COUNT(*)`).
    const PRESCRIPTION_FAIL_OPEN: &str = "search x | where a=\"p|stats count|where b=\"q\"";
    /// Les cas cités à tort par la première version : le cœur les REFUSE, ils ne prouvent rien.
    const REFUSES_PAR_LE_COEUR: &[&str] = &[
        "search x | where a=\"p|stats count\"",
        "search x | where a='p|stats count'",
        "search x | where m=\"err|warn\"",
        "search x | rex field=m \"(?<a>x|y)\"",
        "search x | where a=\"x|sort -id\"",
    ];
    /// Un écart CONSERVATEUR : barre dans un littéral entre crochets — le cœur n'y coupe pas, le démon si.
    const ECART_CONSERVATEUR: &str = "search x | where a=\"[x|stats]\"";
    /// Projection après une barre citée : le cœur coupe avant `table b`, l'augmentation doit y ajouter ts/id.
    const PROJECTION_APRES_BARRE_CITEE: &str = "search x | where a=\"p|table b|where c=\"q\"";

    fn compile(q: &str) -> Result<String, String> {
        guatx_core::soql::to_sql(q, 0, 0, &Schema::events())
    }

    fn decoupe_du_coeur(q: &str) -> Vec<String> {
        guatx_core::soql::soql_split_pipes(q)
    }

    /// Découpeur FABRIQUÉ sensible aux guillemets (doubles et simples) : la prescription de la cellule.
    fn decoupe_sensible_aux_guillemets(q: &str) -> Vec<String> {
        let (mut out, mut cur, mut cite) = (Vec::new(), String::new(), None::<char>);
        for c in q.chars() {
            match (c, cite) {
                ('"' | '\'', None) => {
                    cite = Some(c);
                    cur.push(c);
                }
                (c2, Some(o)) if c2 == o => {
                    cite = None;
                    cur.push(c);
                }
                ('|', None) => out.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        out.push(cur);
        out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }

    /// Découpeur FABRIQUÉ qui ne coupe jamais.
    fn decoupe_jamais(q: &str) -> Vec<String> {
        vec![q.trim().to_string()]
    }

    fn tete(etage: &str) -> &str {
        etage.split('|').next().unwrap_or("").trim()
    }

    /// Branche un découpeur sur le prédicat d'étage du démon : tous les étages hors le premier doivent passer.
    fn vue(decoupe: fn(&str) -> Vec<String>, predicat_etage: fn(&str) -> bool, q: &str) -> bool {
        decoupe(q).iter().skip(1).all(|e| predicat_etage(&format!("search x | {}", tete(e))))
    }

    /// Démon accepte, le cœur COMPILE et son découpage refuse : doit être vide.
    fn ecarts_dangereux(demon: &dyn Fn(&str) -> bool, coeur: &dyn Fn(&str) -> bool) -> Vec<&'static str> {
        CORPUS.iter().copied().filter(|q| demon(q) && compile(q).is_ok() && !coeur(q)).collect()
    }

    /// Démon refuse, le cœur compile et son découpage accepte : l'écart conservateur.
    fn ecarts_conservateurs(demon: &dyn Fn(&str) -> bool, coeur: &dyn Fn(&str) -> bool) -> Vec<&'static str> {
        CORPUS.iter().copied().filter(|q| !demon(q) && compile(q).is_ok() && coeur(q)).collect()
    }

    fn coeur_keyset(q: &str) -> bool {
        vue(decoupe_du_coeur, crate::keyset_applicable, q)
    }

    /// Jeu de savoir FABRIQUÉ : une macro qui cache un agrégat, une qui n'est qu'un filtre, une projection.
    fn savoir_a_macros() -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        ks.add_macro("agg", vec![], "| stats count");
        ks.add_macro("filtre", vec![], "source=x");
        ks.add_macro("proj", vec![], "| table b");
        ks
    }

    #[test]
    fn etages_alignes_ancrage_par_le_vrai_compilateur() {
        let sql = compile(PRESCRIPTION_FAIL_OPEN).expect("le cœur compile le cas fail-open");
        assert!(sql.contains("COUNT("), "le cœur y compile un agrégat : {sql}");
        for q in REFUSES_PAR_LE_COEUR {
            assert!(compile(q).is_err(), "`{q}` : le cœur refuse cette requête, elle ne prouve rien");
        }
        let sql = guatx_core::soql::to_sql("search x `agg`", 0, 0, &Schema::events().with_knowledge(savoir_a_macros()))
            .expect("une macro-pipeline compile");
        assert!(sql.contains("COUNT("), "la macro cache un agrégat que le cœur compile : {sql}");
    }

    #[test]
    fn etages_alignes_keyset_le_demon_refuse_chaque_fois_que_le_coeur_refuse() {
        let dangereux = ecarts_dangereux(&crate::keyset_applicable, &coeur_keyset);
        assert!(dangereux.is_empty(), "keyset_applicable accepte un étage non conservateur compilé : {dangereux:?}");
        let conservateurs = ecarts_conservateurs(&crate::keyset_applicable, &coeur_keyset);
        assert!(conservateurs.contains(&ECART_CONSERVATEUR), "écart conservateur attendu absent : {conservateurs:?}");
        assert!(!crate::keyset_applicable(PRESCRIPTION_FAIL_OPEN));
        assert!(!coeur_keyset(PRESCRIPTION_FAIL_OPEN));
    }

    #[test]
    fn etages_alignes_keyset_temoin_positif_vues_egales_sans_barre_litterale() {
        for q in SANS_BARRE_LITTERALE {
            assert_eq!(crate::keyset_applicable(q), coeur_keyset(q), "vues divergentes sur `{q}`");
        }
        assert!(crate::keyset_applicable("search x | where a=1 | table b"));
        assert!(!crate::keyset_applicable("search x | stats count"));
    }

    #[test]
    fn etages_alignes_keyset_epreuve_de_l_instrument() {
        let guillemets = |q: &str| vue(decoupe_sensible_aux_guillemets, crate::keyset_applicable, q);
        let dangereux = ecarts_dangereux(&guillemets, &coeur_keyset);
        assert!(dangereux.contains(&PRESCRIPTION_FAIL_OPEN), "la prescription doit être prise en défaut sur le cas mesuré : {dangereux:?}");
        let jamais = |q: &str| vue(decoupe_jamais, crate::keyset_applicable, q);
        let dangereux = ecarts_dangereux(&jamais, &coeur_keyset);
        assert!(dangereux.contains(&"search x | stats count"), "un découpeur muet doit être pris en défaut : {dangereux:?}");
    }

    /// `keyset_projection_augment` ré-émet les fragments : mêmes frontières, premier étage intact, et la
    /// projection que le CŒUR voit après une barre citée reçoit ts/id.
    #[test]
    fn etages_alignes_augmentation_garde_les_frontieres() {
        let mut vus = 0;
        for q in CORPUS.iter().copied().filter(|q| crate::keyset_applicable(q)) {
            let (aug, _) = crate::keyset_projection_augment(q);
            assert_eq!(aug.matches('|').count(), q.matches('|').count(), "barres perdues : `{q}` -> `{aug}`");
            let (avant, apres) = (decoupe_du_coeur(q), decoupe_du_coeur(&aug));
            assert_eq!(avant.len(), apres.len(), "étages du cœur changés : `{q}` -> `{aug}`");
            assert_eq!(avant.first(), apres.first(), "premier étage réécrit : `{q}` -> `{aug}`");
            vus += 1;
        }
        assert!(vus >= 5, "corpus applicable trop maigre : {vus}");
        let (aug, ajoutees) = crate::keyset_projection_augment("search x | where a=1 | table b");
        assert_eq!(ajoutees, 2);
        assert_eq!(decoupe_du_coeur(&aug), vec!["search x", "where a=1", "table b,ts,id"]);
        // Premier étage de projection : jamais augmenté (ce n'est pas un étage pour le cœur).
        assert!(crate::keyset_applicable("fields a | where b=1"));
        assert_eq!(crate::keyset_projection_augment("fields a | where b=1"), ("fields a | where b=1".to_string(), 0));
        // Projection après une barre citée : le cœur coupe avant `table b`, l'augmentation aussi.
        assert!(crate::keyset_applicable(PROJECTION_APRES_BARRE_CITEE));
        let (aug, ajoutees) = crate::keyset_projection_augment(PROJECTION_APRES_BARRE_CITEE);
        assert_eq!(ajoutees, 2, "`{aug}`");
        assert!(decoupe_du_coeur(&aug).iter().any(|e| e == "table b,ts,id"), "ts/id absents de la projection du cœur : `{aug}`");
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

    #[cfg(feature = "cold_tier")]
    mod exactitude_froide {
        use super::*;

        fn demon_par_evenement(q: &str) -> bool {
            crate::cold_store::AnswerShape::of_gxql(q).is_per_event()
        }

        fn coeur_par_evenement(q: &str) -> bool {
            vue(decoupe_du_coeur, demon_par_evenement, q)
        }

        #[test]
        fn etages_alignes_froid_le_demon_refuse_chaque_fois_que_le_coeur_refuse() {
            let dangereux = ecarts_dangereux(&demon_par_evenement, &coeur_par_evenement);
            assert!(dangereux.is_empty(), "of_gxql dit par-événement un agrégat compilé : {dangereux:?}");
            let conservateurs = ecarts_conservateurs(&demon_par_evenement, &coeur_par_evenement);
            assert!(conservateurs.contains(&ECART_CONSERVATEUR), "écart conservateur attendu absent : {conservateurs:?}");
            assert!(!demon_par_evenement(PRESCRIPTION_FAIL_OPEN));
            assert!(!coeur_par_evenement(PRESCRIPTION_FAIL_OPEN));
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
            let guillemets = |q: &str| vue(decoupe_sensible_aux_guillemets, demon_par_evenement, q);
            let dangereux = ecarts_dangereux(&guillemets, &coeur_par_evenement);
            assert!(dangereux.contains(&PRESCRIPTION_FAIL_OPEN), "la prescription doit être prise en défaut sur le cas mesuré : {dangereux:?}");
            let jamais = |q: &str| vue(decoupe_jamais, demon_par_evenement, q);
            let dangereux = ecarts_dangereux(&jamais, &coeur_par_evenement);
            assert!(dangereux.contains(&"search x | stats count"), "découpeur muet non pris en défaut : {dangereux:?}");
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
