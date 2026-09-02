    // ===================== GXQL COMPLÉTION IDE (v129) =====================
    // Garde-fous de l'autocomplétion native de la barre Explore : (a) chaque gabarit livré COMPILE via
    // `to_sql`, (b) le vocabulaire de complétion (commandes/fonctions/opérateurs) est un SOUS-ENSEMBLE
    // STRICT de ce que le compilateur fermé accepte, (c) les valeurs connues (`source`) viennent du ROLLUP
    // borné et JAMAIS d'un scan `event`, (d) les endpoints sont gatés en LECTURE (viewer+, pas `agent`).

    use guatx_core::soql::{
        to_sql, Schema, SOQL_BASE_KEYWORDS, SOQL_EVAL_FUNCTIONS, SOQL_FILTER_OPERATORS,
        SOQL_KEYWORDS, SOQL_PIPE_COMMANDS, SOQL_STATS_FUNCTIONS,
    };

    /// (a) INVARIANT « les gabarits livrés compilent » : chaque `soql` de la palette embarquée passe
    /// `to_sql(&Schema::events())`. Un gabarit invalide (token hors-grammaire, faute de frappe) casse la CI
    /// ICI -> il ne peut pas être servi cassé à l'analyste.
    #[test]
    fn soql_templates_all_compile() {
        let sch = Schema::events();
        let tpls = soql_template_queries();
        assert!(tpls.len() >= 10, "la palette doit livrer ~10-20 gabarits, {} trouvés", tpls.len());
        for (id, q) in &tpls {
            assert!(!q.trim().is_empty(), "gabarit '{id}' : soql vide");
            match to_sql(q, 0, 0, &sch) {
                Ok(sql) => assert!(sql.to_ascii_uppercase().contains("SELECT"), "gabarit '{id}' : SQL sans SELECT ?"),
                Err(e) => panic!("gabarit '{id}' NE COMPILE PAS : {q}\n  -> {e}"),
            }
        }
    }

    /// (b) INVARIANT « complétion ⊆ compilateur » — COMMANDES : chaque commande de `SOQL_PIPE_COMMANDS`
    /// (que l'endpoint expose telle quelle) compile dans une requête minimale via `to_sql`. Retirer un bras
    /// du `match` de dispatch du compilateur fait ÉCHOUER ce test -> le vocabulaire ne peut pas dériver.
    #[test]
    fn completion_vocab_commands_compile() {
        let sch = Schema::events();
        // Requête minimale VALIDE par commande (args syntaxiques minimaux, from/to=0 -> pas de filtre ts).
        let minimal = |cmd: &str| -> String {
            let stage = match cmd {
                "stats" => "stats count".to_string(),
                "timechart" => "timechart count".to_string(),
                "where" => "where severity > 0".to_string(),
                "sort" => "sort ts".to_string(),
                "head" => "head 5".to_string(),
                "limit" => "limit 5".to_string(),
                "rex" => "rex message \"(?<w>x)\"".to_string(),
                "fields" => "fields source".to_string(),
                "table" => "table source".to_string(),
                "rename" => "rename source AS s".to_string(),
                "dedup" => "dedup source".to_string(),
                "top" => "top source".to_string(),
                "rare" => "rare source".to_string(),
                "eventstats" => "eventstats count".to_string(),
                "rate" => "rate".to_string(),
                "eval" => "eval x = 1".to_string(),
                "append" => "append [search]".to_string(),
                "join" => "join source [search]".to_string(),
                "mvexpand" => "mvexpand fields".to_string(),
                "lookup" => "lookup reftable source".to_string(),
                other => panic!("commande '{other}' non couverte par le test de vocabulaire — ajouter un cas minimal"),
            };
            format!("search | {stage}")
        };
        for cmd in table_declaree!(SOQL_PIPE_COMMANDS) {
            let q = minimal(cmd);
            assert!(
                to_sql(&q, 0, 0, &sch).is_ok(),
                "commande de complétion '{cmd}' REJETÉE par le compilateur (dérive vocab⊄grammaire) : {q} -> {:?}",
                to_sql(&q, 0, 0, &sch)
            );
        }
    }

    /// (b bis) INVARIANT « complétion ⊆ compilateur » — FONCTIONS STATS : chaque fonction de
    /// `SOQL_STATS_FUNCTIONS` compile dans `search | stats <fn>[(champ)]`.
    #[test]
    fn completion_vocab_stats_functions_compile() {
        let sch = Schema::events();
        for f in table_declaree!(SOQL_STATS_FUNCTIONS) {
            let q = if *f == "count" { "search | stats count".to_string() } else { format!("search | stats {f}(source)") };
            assert!(to_sql(&q, 0, 0, &sch).is_ok(), "fonction stats de complétion '{f}' REJETÉE : {q} -> {:?}", to_sql(&q, 0, 0, &sch));
        }
    }

    /// (b ter) INVARIANT « complétion ⊆ compilateur » — FONCTIONS EVAL : chaque fonction de
    /// `SOQL_EVAL_FUNCTIONS` est ACCEPTÉE par le chemin `eval` (elle EST l'allowlist référencée par
    /// `soql_expr_sql` -> ne peut pas dériver, mais on le VÉRIFIE aussi via `to_sql`).
    #[test]
    fn completion_vocab_eval_functions_compile() {
        let sch = Schema::events();
        for f in table_declaree!(SOQL_EVAL_FUNCTIONS) {
            let q = format!("search | eval x = {f}(source)");
            assert!(to_sql(&q, 0, 0, &sch).is_ok(), "fonction eval de complétion '{f}' REJETÉE : {q} -> {:?}", to_sql(&q, 0, 0, &sch));
        }
    }

    /// (b quater) INVARIANT « complétion ⊆ compilateur » — OPÉRATEURS : chaque opérateur de
    /// `SOQL_FILTER_OPERATORS` compile dans un filtre de base `search field<op>valeur`.
    #[test]
    fn completion_vocab_operators_compile() {
        let sch = Schema::events();
        for op in table_declaree!(SOQL_FILTER_OPERATORS) {
            // numérique pour les comparateurs d'ordre (severity), textuel pour = / != / : / =~.
            let q = match *op {
                ">" | ">=" | "<" | "<=" => format!("search severity{op}1"),
                _ => format!("search source{op}x"),
            };
            assert!(to_sql(&q, 0, 0, &sch).is_ok(), "opérateur de complétion '{op}' REJETÉ : {q} -> {:?}", to_sql(&q, 0, 0, &sch));
        }
    }

    /// (c) INVARIANT « aucun scan event » : les valeurs `source` connues viennent de la table DÉRIVÉE
    /// `event_rollup` (pré-agrégée, petite) et JAMAIS de `event`. On PROUVE la source de lecture : une
    /// source présente UNIQUEMENT dans `event` n'apparaît PAS ; une source présente dans `event_rollup`
    /// apparaît. Si le code scannait `event`, le test échouerait (il verrait `only_in_event`).
    #[test]
    fn known_values_source_reads_rollup_not_event() {
        let conn = test_db();
        // Source présente SEULEMENT dans `event` (piège : ne doit PAS remonter).
        conn.execute(
            "INSERT INTO event(ts,source,message,origin) VALUES(?1,'only_in_event','x','')",
            params![now()],
        )
        .unwrap();
        // Sources présentes dans le ROLLUP borné (doivent remonter).
        for src in ["only_in_rollup", "sshd", "web"] {
            conn.execute(
                "INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(?1,?2,0,'',3)",
                params![now(), src],
            )
            .unwrap();
        }
        let got = soql_known_sources(&conn);
        assert!(got.contains(&"only_in_rollup".to_string()), "source du rollup manquante : {got:?}");
        assert!(got.contains(&"sshd".to_string()) && got.contains(&"web".to_string()), "sources rollup manquantes : {got:?}");
        assert!(
            !got.contains(&"only_in_event".to_string()),
            "FUITE : une source présente uniquement dans `event` a remonté -> le code a scanné `event` : {got:?}"
        );
    }

    /// (d) INVARIANT « endpoint gaté en lecture » : `/api/soql/schema` et `/api/soql/templates` sont classés
    /// `Read` (viewer+) par `route_min_role` (GET, non-mutant) — jamais admin-only, jamais ouvert au rôle
    /// `agent` (ingest-only). Le vocabulaire de grammaire n'est pas une surface admin (ni secret ni config).
    #[test]
    fn soql_meta_routes_are_read_gated() {
        for path in ["/api/soql/schema", "/api/soql/templates"] {
            assert!(
                matches!(route_min_role(path, false), MinRole::Read),
                "{path} devrait être Read (viewer+), obtenu {:?}",
                route_min_role(path, false)
            );
            // viewer/editor/admin satisfont Read ; `agent` (token ingest-only) NON.
            assert!(role_satisfies("viewer", route_min_role(path, false)), "viewer doit lire {path}");
            assert!(!role_satisfies("agent", route_min_role(path, false)), "le rôle agent ne doit PAS lire {path}");
        }
    }

    // ===================== v130 — LIVE VALIDATION (feature 1) + DOC INLINE (feature 2) =====================

    /// (v130-a) VALIDATION d'une requête VALIDE : `/api/soql/validate` compile via `to_sql` et renvoie
    /// `valid:true`. On appelle le handler DIRECTEMENT — il ne prend QUE `Json` (aucun `State<AppState>`,
    /// aucune base) : le test ne peut compiler QUE parce que le handler n'a aucun accès DB (preuve structurelle).
    #[tokio::test]
    async fn validate_valid_query_is_valid() {
        let out = soql_validate(Json(json!({ "soql": "search source=sudo | stats count by source | sort -count" }))).await.0;
        assert_eq!(out["valid"], json!(true), "requête valide -> valid:true, obtenu {out}");
        assert!(out.get("error").is_none(), "pas d'erreur attendue sur une requête valide : {out}");
    }

    /// (v130-b) VALIDATION d'une requête INVALIDE + ZÉRO EXÉCUTION / ZÉRO EFFET DE BORD. `search | frobnicate`
    /// (commande hors-grammaire) -> `valid:false` + message d'erreur du compilateur. PREUVE « compile-only » :
    ///   1) STRUCTURELLE — `soql_validate` est appelé avec le SEUL extracteur `Json` ; s'il exécutait quoi que
    ///      ce soit il lui faudrait un `State<AppState>`/`Connection`, que ce test NE fournit PAS -> il ne
    ///      compilerait même pas. Le handler n'a donc PHYSIQUEMENT aucun chemin d'exécution ni de scan `event`.
    ///   2) COMPORTEMENTALE — une requête qui, si elle était EXÉCUTÉE, lirait des events (`search source=x |
    ///      stats count`) renvoie `valid:true` SANS aucune base présente : la validité ne dépend QUE de la
    ///      compilation (grammaire), jamais de données -> aucune requête n'a été lancée.
    #[tokio::test]
    async fn validate_compiles_only_never_executes() {
        // Requête grammaticalement invalide -> valid:false + erreur (message du compilateur fermé).
        let bad = soql_validate(Json(json!({ "soql": "search | frobnicate" }))).await.0;
        assert_eq!(bad["valid"], json!(false), "requête invalide -> valid:false, obtenu {bad}");
        assert!(
            bad.get("error").and_then(|e| e.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            "une requête invalide doit renvoyer un message d'erreur non vide : {bad}"
        );
        // Requête qui LIRAIT des events si exécutée -> valide par COMPILATION SEULE, sans aucune base.
        let ok = soql_validate(Json(json!({ "soql": "search source=nexistepas | stats count" }))).await.0;
        assert_eq!(ok["valid"], json!(true), "validité = compilation, pas exécution (aucune base) : {ok}");
    }

    /// (v130-c) `/api/soql/validate` est un POST de LECTURE gaté viewer+ : `is_readonly_post` le classe READ
    /// (-> mutating=false) ET `route_min_role(..., false)` renvoie `Read`. Sans `is_readonly_post`, le POST
    /// serait `mutating` -> editor+ (fuite de gating). Le rôle `agent` (ingest-only) ne satisfait PAS Read.
    #[test]
    fn validate_is_read_gated() {
        assert!(is_readonly_post("/api/soql/validate"), "/api/soql/validate doit être un POST de LECTURE (readonly_post)");
        assert!(matches!(route_min_role("/api/soql/validate", false), MinRole::Read), "validate doit être Read (viewer+)");
        assert!(role_satisfies("viewer", route_min_role("/api/soql/validate", false)), "viewer doit valider");
        assert!(!role_satisfies("agent", route_min_role("/api/soql/validate", false)), "agent ne doit PAS valider");
    }

    /// (v130-d) CAP de LONGUEUR appliqué : au-delà de `SOQL_VALIDATE_MAX_LEN` caractères -> `valid:false` +
    /// message « trop longue », AVANT toute compilation (borne défensive anti-abus, endpoint appelé à la frappe).
    #[tokio::test]
    async fn validate_length_cap_enforced() {
        let huge = format!("search host={}", "a".repeat(SOQL_VALIDATE_MAX_LEN + 10));
        assert!(huge.chars().count() > SOQL_VALIDATE_MAX_LEN);
        let out = soql_validate(Json(json!({ "soql": huge }))).await.0;
        assert_eq!(out["valid"], json!(false), "au-delà du cap -> valid:false : {out}");
        assert!(
            out["error"].as_str().unwrap_or("").contains("trop longue"),
            "le cap doit renvoyer un message explicite : {out}"
        );
    }

    /// (v130-e) COUVERTURE DOC : CHAQUE token du vocabulaire (`SOQL_*` + champs cœur CIM) a une description
    /// NON VIDE. Un token ajouté aux consts du cœur sans description casse ICI -> la doc inline ne peut pas
    /// omettre silencieusement un token (garde-fou anti-dérive, miroir de « complétion ⊆ compilateur »).
    #[test]
    fn soql_docs_cover_all_vocab() {
        let check = |table: &[(&'static str, &'static str)], tokens: &[&str], label: &str| {
            for t in tokens {
                let d = doc_desc(table, t);
                assert!(
                    d.map(|s| !s.trim().is_empty()).unwrap_or(false),
                    "doc {label} : token '{t}' sans description non vide (obtenu {d:?})"
                );
            }
        };
        check(DOC_BASE_KEYWORDS, table_declaree!(SOQL_BASE_KEYWORDS), "base_keywords");
        check(DOC_COMMANDS, table_declaree!(SOQL_PIPE_COMMANDS), "commands");
        check(DOC_STATS_FUNCTIONS, table_declaree!(SOQL_STATS_FUNCTIONS), "stats_functions");
        check(DOC_EVAL_FUNCTIONS, table_declaree!(SOQL_EVAL_FUNCTIONS), "eval_functions");
        check(DOC_OPERATORS, table_declaree!(SOQL_FILTER_OPERATORS), "operators");
        check(DOC_KEYWORDS, table_declaree!(SOQL_KEYWORDS), "keywords");
        check(DOC_FIELDS, table_declaree!(CIM_CORE_FIELDS), "fields");
    }
