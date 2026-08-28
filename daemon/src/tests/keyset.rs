// KEYSET (#28) — pagination par CURSEUR `(ts,id)` : preuve de PARCOURS INTÉGRAL sans plafond (fin du cap
// 10 000 qui CACHAIT des événements). On teste le SQL RÉELLEMENT émis par le daemon : compile via le
// choke-point store (`soql_to_sql_masked_keyset_x` -> cursor_id=true) PUIS wrap via `page_sql`, exécuté
// sur une base in-memory au schéma de prod. `keyset_finalize` (contrat has_more/next_cursor) est testé isolément.

    use guatx_core::soql::FieldMaskSet;

    // Exécute UNE page keyset sur `conn` et renvoie le Value {columns,rows,stats} comme run_query_ex (mêmes
    // types de cellule) -> pour appliquer `keyset_finalize` à l'identique du handler.
    fn ks_run_page(conn: &Connection, sql: &str) -> serde_json::Value {
        let mut stmt = conn.prepare(sql).unwrap();
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let ncol = cols.len();
        let mut out: Vec<serde_json::Value> = Vec::new();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let mut r = Vec::with_capacity(ncol);
            for i in 0..ncol {
                let v = match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => json!(n),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t).into_owned()),
                    rusqlite::types::ValueRef::Blob(b) => json!(format!("<blob {} o>", b.len())),
                };
                r.push(v);
            }
            out.push(serde_json::Value::Array(r));
        }
        json!({ "columns": cols, "rows": out, "stats": { "truncated": false } })
    }

    // Indice d'une colonne par nom dans un Value {columns:[...]}.
    fn ks_col(v: &serde_json::Value, name: &str) -> usize {
        v["columns"].as_array().unwrap().iter().position(|c| c == name).unwrap_or_else(|| panic!("colonne {name} absente"))
    }

    // Parcourt TOUTES les pages keyset de `search source=auditd` (fenêtre 0,0 = sans borne) et renvoie la liste
    // ORDONNÉE des (ts,id) visités + le nombre de pages. Émule EXACTEMENT le handler : compile keyset une fois,
    // puis boucle page_sql(curseur) -> keyset_finalize -> next_cursor.
    fn ks_traverse(conn: &Connection, lim: i64) -> (Vec<(i64, i64)>, usize) {
        let base = crate::soql_to_sql_masked_keyset_x("search source=auditd", 0, 0, None, &FieldMaskSet::new()).unwrap();
        let mut cursor: Option<(i64, i64)> = None;
        let mut seen: Vec<(i64, i64)> = Vec::new();
        let mut pages = 0usize;
        loop {
            let page_sql = crate::page_sql(&base, crate::keyset_plan(cursor, 0), lim);
            let mut v = ks_run_page(conn, &page_sql);
            let ti = ks_col(&v, "ts");
            let ii = ks_col(&v, "id");
            for r in v["rows"].as_array().unwrap() {
                seen.push((r[ti].as_i64().unwrap(), r[ii].as_i64().unwrap()));
            }
            crate::keyset_finalize(&mut v, lim, None);
            pages += 1;
            if !v["has_more"].as_bool().unwrap() {
                assert!(v["next_cursor"].is_null(), "dernière page -> next_cursor doit être null");
                break;
            }
            let nc = &v["next_cursor"];
            cursor = Some((nc["ts"].as_i64().unwrap(), nc["id"].as_i64().unwrap()));
            assert!(pages < 10_000, "garde-fou anti-boucle infinie");
        }
        (seen, pages)
    }

    fn ks_ins(c: &Connection, ts: i64) {
        c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'auditd','x','')", params![ts]).unwrap();
    }

    // (1) PREMIÈRE page = les `lim` lignes les PLUS RÉCENTES, triées ts DESC, id DESC.
    #[test]
    fn keyset_first_page_newest_ordered() {
        let c = test_db();
        for ts in 100..125 { ks_ins(&c, ts); } // 25 lignes, ts 100..124 (id croissant avec ts)
        let base = crate::soql_to_sql_masked_keyset_x("search source=auditd", 0, 0, None, &FieldMaskSet::new()).unwrap();
        assert!(base.contains(",id FROM") || base.trim_end().contains("id FROM") || base.contains("id FROM event"),
            "keyset compile DOIT projeter `id` : {base}");
        let mut v = ks_run_page(&c, &crate::page_sql(&base, crate::keyset_plan(None, 0), 10));
        let ti = ks_col(&v, "ts");
        let rows = v["rows"].as_array().unwrap().clone();
        assert_eq!(rows.len(), 10, "première page = lim lignes");
        // ts DESC strict (ts distincts) : 124,123,...,115
        let got: Vec<i64> = rows.iter().map(|r| r[ti].as_i64().unwrap()).collect();
        let want: Vec<i64> = (115..125).rev().collect();
        assert_eq!(got, want, "première page = 10 plus récents, ts DESC");
        crate::keyset_finalize(&mut v, 10, None);
        assert_eq!(v["has_more"], json!(true), "25 > 10 -> has_more");
        assert_eq!(v["next_cursor"]["ts"], json!(115), "curseur = ts de la dernière ligne rendue");
    }

    // (2)+(4) PARCOURS INTÉGRAL : visite CHAQUE ligne EXACTEMENT une fois, ZÉRO chevauchement/trou, y compris
    // aux ts ÉGAUX (tiebreak id). Dernière page < lim -> has_more:false / next_cursor:null.
    #[test]
    fn keyset_full_traversal_no_gap_no_dup_with_ties() {
        let c = test_db();
        // 7 ts distincts × 5 lignes au MÊME ts = 35 lignes ; ties massifs pour éprouver le tiebreak id.
        let mut expected = 0;
        for ts in 200..207 {
            for _ in 0..5 { ks_ins(&c, ts); expected += 1; }
        }
        // + quelques lignes solitaires (ts uniques) intercalées
        for ts in [150, 175, 300] { ks_ins(&c, ts); expected += 1; }
        let (seen, pages) = ks_traverse(&c, 8); // lim non-multiple de 35+3=38 -> dernière page partielle
        assert_eq!(seen.len(), expected, "toutes les lignes visitées, aucune en trop");
        // AUCUN doublon
        let uniq: std::collections::HashSet<_> = seen.iter().cloned().collect();
        assert_eq!(uniq.len(), expected, "ZÉRO doublon (tiebreak id aux ts égaux)");
        // ORDRE global monotone décroissant (ts DESC, id DESC) SANS trou
        for w in seen.windows(2) {
            assert!(w[0] > w[1], "ordre strict ts DESC,id DESC : {:?} doit précéder {:?}", w[0], w[1]);
        }
        // == au set complet de la table
        let mut all: Vec<(i64, i64)> = c
            .prepare("SELECT ts,id FROM event WHERE source='auditd'").unwrap()
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap()
            .map(|r| r.unwrap()).collect();
        all.sort_by(|a, b| b.cmp(a)); // ts DESC, id DESC
        assert_eq!(seen, all, "l'ensemble collecté == l'ensemble complet, dans l'ordre keyset");
        assert!(pages >= 5, "38 lignes / lim 8 -> au moins 5 pages (parcours réel)");
    }

    // (3) DERNIÈRE page renvoyée par le parcours : moins de lim -> has_more:false explicite.
    #[test]
    fn keyset_last_page_partial_stops() {
        let c = test_db();
        for ts in 400..413 { ks_ins(&c, ts); } // 13 lignes
        let base = crate::soql_to_sql_masked_keyset_x("search source=auditd", 0, 0, None, &FieldMaskSet::new()).unwrap();
        // page 1 (10), page 2 (3 -> partielle)
        let mut v1 = ks_run_page(&c, &crate::page_sql(&base, crate::keyset_plan(None, 0), 10));
        crate::keyset_finalize(&mut v1, 10, None);
        assert_eq!(v1["has_more"], json!(true));
        let cur = (v1["next_cursor"]["ts"].as_i64().unwrap(), v1["next_cursor"]["id"].as_i64().unwrap());
        let mut v2 = ks_run_page(&c, &crate::page_sql(&base, crate::keyset_plan(Some(cur), 0), 10));
        assert_eq!(v2["rows"].as_array().unwrap().len(), 3, "reste 3 lignes");
        crate::keyset_finalize(&mut v2, 10, None);
        assert_eq!(v2["has_more"], json!(false), "3 < 10 -> dernière page");
        assert!(v2["next_cursor"].is_null(), "dernière page -> next_cursor null");
    }

    // (5) CONTRAT keyset_finalize isolé : has_more/next_cursor/limite + défense sur colonnes manquantes.
    #[test]
    fn keyset_finalize_contract() {
        // exactement lim lignes -> has_more + curseur = dernière ligne
        let mut full = json!({ "columns": ["ts", "host", "id"], "rows": [[9, "a", 1], [8, "b", 2], [7, "c", 3]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut full, 3, None);
        assert_eq!(full["has_more"], json!(true));
        assert_eq!(full["next_cursor"], json!({ "ts": 7, "id": 3 }));
        assert_eq!(full["limit"], json!(3));
        // moins que lim -> dernière page
        let mut part = json!({ "columns": ["ts", "id"], "rows": [[9, 1]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut part, 3, None);
        assert_eq!(part["has_more"], json!(false));
        assert!(part["next_cursor"].is_null());
        // troncature run_query_ex (max_rows atteint) < lim -> il RESTE des lignes -> has_more (curseur fourni)
        let mut trunc = json!({ "columns": ["ts", "id"], "rows": [[9, 1], [8, 2]], "stats": { "truncated": true } });
        crate::keyset_finalize(&mut trunc, 100, None);
        assert_eq!(trunc["has_more"], json!(true), "truncated -> il reste des lignes");
        assert_eq!(trunc["next_cursor"], json!({ "ts": 8, "id": 2 }));
        // DÉFENSIF : colonnes ts/id absentes (curseur inextractible) -> pas de has_more (arrêt, jamais boucle infinie)
        let mut noid = json!({ "columns": ["source", "message"], "rows": [["a", "x"], ["b", "y"], ["c", "z"]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut noid, 3, None);
        assert_eq!(noid["has_more"], json!(false), "sans colonne curseur on n'affirme pas has_more");
        assert!(noid["next_cursor"].is_null());
    }

    // (6) MODE 0 : la compilation NON-keyset (cursor_id=false) est BYTE-IDENTIQUE à soql_to_sql_x et NE projette
    // PAS `id` ; la variante keyset AJOUTE `id`. Preuve que les autres callers (détection/panneaux/export) restent
    // intacts (ils n'appellent JAMAIS la variante keyset).
    #[test]
    fn keyset_compile_is_additive_mode0_intact() {
        let empty = FieldMaskSet::new();
        let plain = crate::soql_to_sql_masked_x("search source=auditd", 0, 0, None, &empty).unwrap();
        let plain_unmasked = crate::soql_to_sql_x("search source=auditd", 0, 0, None).unwrap();
        assert_eq!(plain, plain_unmasked, "masque VIDE -> masked == non-masqué (mode 0)");
        let ks = crate::soql_to_sql_masked_keyset_x("search source=auditd", 0, 0, None, &empty).unwrap();
        assert_ne!(plain, ks, "keyset diffère (id ajouté)");
        // le plain ne doit PAS finir par projeter id là où le keyset le fait : le keyset contient une projection id
        // supplémentaire que le plain n'a pas.
        assert!(ks.matches("id").count() >= plain.matches("id").count() + 1, "keyset projette `id` en plus : plain={plain}\nks={ks}");
    }

    // SÉCURITÉ : le curseur i64 formaté dans le SQL est injection-safe (valeurs entières uniquement) — on prouve
    // que page_sql produit littéralement les entiers, sans texte.
    #[test]
    fn keyset_cursor_is_i64_only_no_injection() {
        let sql = crate::page_sql("SELECT ts,id FROM event", crate::keyset_plan(Some((1700000000, 42)), 0), 50);
        assert!(sql.contains("ts < 1700000000 OR (ts = 1700000000 AND id < 42)"), "curseur = entiers littéraux : {sql}");
        assert!(sql.ends_with("ORDER BY ts DESC, id DESC LIMIT 50"));
    }

    /// `P10.5-f` — L'ORDRE DU WRAP EST ÉCRIT UNE FOIS, ET LES DEUX QUI EN DÉPENDENT LE LISENT LÀ.
    ///
    /// Il l'était en deux endroits qui ne se parlaient pas — la clause `ORDER BY` de `page_sql` en toutes
    /// lettres, et la règle « quels `| sort` sont certifiables » écrite à la main dans `keyset_applicable`
    /// — et ils avaient DIVERGÉ : la prose du prédicat promettait déjà `-ts` / `-ts,-id`, son code admettait
    /// `-id`. Les deux dérivent désormais de `KEYSET_ORDRE`.
    ///
    /// CE QUE CETTE GARDE TIENT, et pourquoi elle n'est pas une tautologie : les trois formes de page sont
    /// ancrées EN TOUTES LETTRES (donc byte-identiques à la clause écrite en dur qu'elles remplacent), et
    /// les tris certifiés sont EXERCÉS depuis la liste elle-même — pas recopiés. Toucher `KEYSET_ORDRE`
    /// change la clause SQL servie ET l'ensemble des tris certifiés, et cette garde rougit des deux côtés.
    #[test]
    fn keyset_lordre_du_wrap_est_ecrit_une_fois_et_ancre() {
        assert_eq!(
            crate::KEYSET_ORDRE,
            ["-ts", "-id"],
            "l'ordre du wrap a changé : la clause SQL et les tris certifiés changent AVEC lui — c'est \
             délibéré ou c'est un accident, mais ça ne passe pas en silence"
        );
        // LA CLAUSE, EN TOUTES LETTRES, sur les trois variantes keyset.
        for (plan, attendu) in [
            (crate::keyset_plan(None, 0), "SELECT * FROM (Q) ORDER BY ts DESC, id DESC LIMIT 7"),
            (crate::keyset_plan(None, 20), "SELECT * FROM (Q) ORDER BY ts DESC, id DESC LIMIT 7 OFFSET 20"),
            (
                crate::keyset_plan(Some((9, 3)), 0),
                "SELECT * FROM (Q) WHERE ts < 9 OR (ts = 9 AND id < 3) ORDER BY ts DESC, id DESC LIMIT 7",
            ),
        ] {
            assert_eq!(crate::page_sql("Q", plan, 7), attendu, "la clause dérivée doit être celle qui était écrite en dur");
        }
        // Et l'OFFSET NU reste SANS `ORDER BY` : l'ordre y demeure celui du SQL compilé (pré-keyset).
        assert_eq!(crate::page_sql("Q", crate::PagePlan::Offset(5), 7), "SELECT * FROM (Q) LIMIT 7 OFFSET 5");
        // LES TRIS CERTIFIÉS SONT EXACTEMENT LES PRÉFIXES NON VIDES, exercés DEPUIS la liste.
        for k in 1..=crate::KEYSET_ORDRE.len() {
            let tri = crate::KEYSET_ORDRE[..k].join(",");
            assert!(crate::keyset_applicable(&format!("search x | sort {tri}")), "préfixe `{tri}` : certifiable");
        }
        // TÉMOINS NÉGATIFS, construits depuis la MÊME liste : priorité inversée, et clé de tête répétée.
        if crate::KEYSET_ORDRE.len() >= 2 {
            let inverse: Vec<&str> = crate::KEYSET_ORDRE.iter().rev().copied().collect();
            assert!(
                !crate::keyset_applicable(&format!("search x | sort {}", inverse.join(","))),
                "ordre inversé : le wrap le CONTREDIT, il ne le raffine pas"
            );
            let repetee = format!("{},{}", crate::KEYSET_ORDRE[0], crate::KEYSET_ORDRE[0]);
            assert!(
                !crate::keyset_applicable(&format!("search x | sort {repetee}")),
                "clé de tête répétée : ce n'est pas un préfixe de l'ordre du wrap"
            );
        }
    }

    // APPLICABILITÉ KEYSET — DÉRIVÉE, pas énumérée. Le prédicat n'énumère plus les commandes qui CASSENT
    // le wrap (il y en avait deux : `table`, `fields`) : il énumère celles qui rendent UNE ligne par
    // ÉVÉNEMENT sans réordonner, et refuse tout le reste PAR DÉFAUT — y compris une commande GXQL qui
    // n'existe pas encore. Les projections redeviennent applicables parce que le daemon RESTITUE `ts`/`id`
    // dans leur liste (`keyset_projection_augment`), pas parce qu'on a fait une exception pour elles.
    #[test]
    fn keyset_applicability_is_derived_not_enumerated() {
        // (P3 restituée par l'augmentation) — les projections sont désormais SERVIES par le curseur.
        assert!(crate::keyset_applicable("search source=suricata category=alert | table ts,message"));
        assert!(crate::keyset_applicable("search source=conntrack | sort -ts | table dst_host,dst_ip"));
        assert!(crate::keyset_applicable("search source=mail | fields rcpt,sender"));
        // Détection insensible à la casse (le prédicat), MAIS l'augmentation ré-émet la commande
        // telle qu'écrite : `| TABLE a` reste refusé par le compilateur, comme avant.
        assert!(crate::keyset_applicable("search x | TABLE a"), "casse-insensible");
        let (aug, n) = crate::keyset_projection_augment("search x | TABLE a");
        assert_eq!(n, 2);
        assert!(aug.contains("TABLE a,ts,id"), "casse PRÉSERVÉE (sinon on ferait compiler l'incompilable) : {aug}");
        // Étages préservant la ligne et l'ordre.
        assert!(crate::keyset_applicable("search source=auditd"));
        assert!(crate::keyset_applicable("search source=auditd | sort -ts | head 100"));
        assert!(crate::keyset_applicable("search source=web | where severity>=2"));
        assert!(crate::keyset_applicable("search x | dedup host"));
        // (P2) — un tri sur une AUTRE clé serait ÉCRASÉ par le wrap `ORDER BY ts DESC, id DESC` : le
        // client recevrait des lignes triées autrement que demandé. C'était le cas AVANT (mesuré sur la
        // base de banc : `| sort severity` rendait severity [2,2,2,2,3,2] au lieu de [1,1,1,1,1,1]).
        assert!(!crate::keyset_applicable("search severity>=1 | sort severity"));
        assert!(!crate::keyset_applicable("search severity>=1 | sort -host"));
        assert!(!crate::keyset_applicable("search x | sort ts"), "ts ASC n'est pas l'ordre du wrap");
        assert!(crate::keyset_applicable("search x | sort -ts,-id"), "la clé du wrap elle-même");
        // (P2) `P10.5-f` — LAXITÉ VERS LE HAUT, corrigée. Le prédicat certifiait `sort` dès que toutes les
        // clés valaient `-ts` OU `-id` : `| sort -id` seul passait, alors que la page servie est ordonnée
        // `(ts DESC, id DESC)`, qui n'est PAS `id DESC` — et l'`id` froid est SYNTHÉTIQUE, réemployé d'une
        // partition à l'autre (mesuré : `cold_store/tests.rs::ks_id_synthetique_ne_sordonne_pas_entre_partitions`).
        // Les tris tenables sont les PRÉFIXES de l'ordre du wrap ; aucune des trois formes ci-dessous n'en
        // est un, et aucune n'est ÉNUMÉRÉE dans le prédicat.
        assert!(!crate::keyset_applicable("search x | sort -id"), "`-id` seul : le wrap trie d'abord par ts");
        assert!(!crate::keyset_applicable("search x | sort -id,-ts"), "priorité inversée : pas un préfixe");
        assert!(!crate::keyset_applicable("search x | sort -ts,-ts"), "2e clé absente de l'ordre du wrap");
        // (P1) — agrégation : plus une ligne par événement.
        assert!(!crate::keyset_applicable("search x | stats count by host"));
        assert!(!crate::keyset_applicable("search x | timechart count"));
        assert!(!crate::keyset_applicable("search x | top host"));
        // (P1) — duplication de lignes : `(ts,id)` n'est plus UNIQUE, le curseur strict `<` sauterait les
        // doublons de la ligne frontière (perte silencieuse).
        assert!(!crate::keyset_applicable("search x | mvexpand tags"));
        // (P1) — lignes étrangères sans clé keyset.
        assert!(!crate::keyset_applicable("search x | append [search y]"));
        assert!(!crate::keyset_applicable("search x | join host [search y]"));
        assert!(!crate::keyset_applicable("search x | lookup t host"));
        // (P3) — un étage qui CRÉE des colonnes et NOMME la clé de tri peut la redéfinir/la dupliquer.
        assert!(!crate::keyset_applicable("search x | eval ts=0"));
        assert!(!crate::keyset_applicable("search x | rename host AS id"));
        assert!(crate::keyset_applicable("search x | eval sev2=severity*2"), "eval qui ne touche pas la clé");
        // REFUS PAR DÉFAUT : une commande inconnue (future) n'est PAS keyset-able sans qu'on l'ait nommée.
        assert!(!crate::keyset_applicable("search x | commande-qui-nexiste-pas foo"));
    }

    // AUGMENTATION DE PROJECTION — c'est ce qui remplace le refus. Elle doit (a) ajouter EXACTEMENT les clés
    // manquantes, (b) ne rien ajouter si elles sont déjà là, (c) laisser les passe-plat tranquilles, et
    // (d) dire COMBIEN de colonnes retirer de la réponse pour rendre au client sa projection exacte.
    #[test]
    fn keyset_projection_augment_restores_the_sort_key() {
        let (aug, n) = crate::keyset_projection_augment("search severity>=1 | table ts,host,source");
        assert_eq!(n, 1, "`ts` déjà présent -> seul `id` est ajouté");
        assert!(aug.ends_with("table ts,host,source,id"), "{aug}");
        let (aug, n) = crate::keyset_projection_augment("search x | fields host,message");
        assert_eq!(n, 2, "ni `ts` ni `id` -> les deux sont ajoutés");
        assert!(aug.ends_with("fields host,message,ts,id"), "{aug}");
        let (aug, n) = crate::keyset_projection_augment("search x | table ts,id");
        assert_eq!(n, 0, "clé complète -> aucune colonne ajoutée");
        assert_eq!(aug, "search x | table ts,id", "SOQL inchangée quand il n'y a rien à ajouter");
        let (aug, n) = crate::keyset_projection_augment("search x | table *");
        assert_eq!((aug.as_str(), n), ("search x | table *", 0), "`table *` est un passe-plat");
        let (aug, n) = crate::keyset_projection_augment("search source=auditd");
        assert_eq!((aug.as_str(), n), ("search source=auditd", 0), "aucune projection -> identité STRICTE");
        // `table` sépare aussi par BLANCS : la liste est relue puis ré-émise en virgules (forme acceptée).
        let (aug, n) = crate::keyset_projection_augment("search x | table host source");
        assert_eq!(n, 2);
        assert!(aug.ends_with("table host source,ts,id"), "{aug}");
    }

    // Le trim rend au client EXACTEMENT sa projection : les colonnes ajoutées pour le wrap disparaissent,
    // et `next_cursor` (fabriqué AVANT le trim) reste exploitable. Sans le trim, le client verrait des
    // colonnes qu'il n'a pas demandées -> le résultat aurait CHANGÉ.
    #[test]
    fn keyset_trim_returns_the_requested_projection_only() {
        let mut v = json!({ "columns": ["ts","host","id"], "rows": [[10, "h1", 7], [9, "h2", 6]] });
        crate::keyset_trim_helper_cols(&mut v, 1);
        assert_eq!(v["columns"], json!(["ts","host"]));
        assert_eq!(v["rows"], json!([[10, "h1"], [9, "h2"]]));
        // n=0 -> no-op STRICT
        let mut w = json!({ "columns": ["ts","host"], "rows": [[10, "h1"]] });
        let before = w.clone();
        crate::keyset_trim_helper_cols(&mut w, 0);
        assert_eq!(w, before);
        // garde-fou : plus d'ajouts que de colonnes -> on ne mutile rien
        let mut x = json!({ "columns": ["ts"], "rows": [[10]] });
        let before = x.clone();
        crate::keyset_trim_helper_cols(&mut x, 3);
        assert_eq!(x, before, "jamais de réponse mutilée : on préfère ne rien retirer");
    }

    // UN SEUL FABRICANT DE PAGE. Le défaut n'était pas « ce site d'appel utilise OFFSET » : c'était que
    // TROIS sites composaient leur propre clause de page, donc un quatrième pouvait naître sans que
    // personne ne le remarque. L'invariant : dans handlers/query.rs, aucune ligne non commentée ne
    // fabrique un `OFFSET` hors du corps de `page_sql`.
    #[test]
    fn page_sql_is_the_only_place_that_builds_an_offset() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/query.rs"),
        )
        .unwrap();
        let mut in_page_sql = false;
        let mut seen_inside = 0usize;
        let mut offenders: Vec<&str> = Vec::new();
        for line in src.lines() {
            if line.starts_with("pub(crate) fn page_sql(") {
                in_page_sql = true;
            } else if in_page_sql && line.starts_with('}') {
                in_page_sql = false;
            }
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("///") {
                continue;
            }
            if code.contains("OFFSET") {
                if in_page_sql {
                    seen_inside += 1;
                } else {
                    offenders.push(line);
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "une page est fabriquée hors de `page_sql` — un chemin de pagination peut donc retomber sur \
             OFFSET sans passer par la décision unique : {offenders:?}"
        );
        assert!(seen_inside >= 2, "invariant vide = invariant mort : `page_sql` doit bien contenir les formes OFFSET (vu {seen_inside})");
    }

    // REPRO EXACTE du bug : `search … | table cols` NON-keyset + wrap OFFSET s'exécute SANS « no such column:
    // ts/id » et rend des lignes. C'est le chemin que le handler emprunte désormais pour les requêtes projetées.
    #[test]
    fn table_projection_offset_runs_no_missing_column() {
        let c = test_db();
        for ts in 500..515 { ks_ins(&c, ts); } // 15 lignes source=auditd
        // le handler, requête projetée -> keyset shadow=false -> compile NON-keyset (soql_to_sql_masked_x)…
        let base = crate::soql_to_sql_masked_x("search source=auditd | table ts,id", 0, 0, None, &FieldMaskSet::new()).unwrap();
        // …puis wrap OFFSET (PAS le wrap keyset : aucun ORDER BY ts,id externe qui casserait sur une projection).
        let page = format!("SELECT * FROM ({base}) LIMIT 5 OFFSET 0");
        let v = ks_run_page(&c, &page); // panique si SQLite renvoie une erreur (prepare/exec)
        assert_eq!(v["rows"].as_array().unwrap().len(), 5, "page offset de 5 lignes servie sans erreur SQL");
        assert_eq!(v["columns"].as_array().unwrap().len(), 2, "projection `table ts,id` respectée (2 colonnes)");
    }

    // ============================================================================================
    // LE CURSEUR KEYSET SE RENVOIE **TEL QUEL** — aucun module de la console ne le reconstruit.
    //
    // POURQUOI C'EST UNE PROPRIÉTÉ DU PRODUIT ET PAS UNE CONVENTION. Une ligne FROIDE n'a pas d'`id`
    // (il n'est pas stocké en Parquet) : chaque voie froide lui en fabrique un, et pas le même — rowid
    // de la table d'hydratation côté oracle, `seq*COLD_FILE_MAX_ROWS+position` côté colonnaire. Le
    // démon pose donc, SUR LE CURSEUR QU'IL ÉMET, l'espace d'identifiant dans lequel ce nombre a un
    // sens (`ESPACE_ID_COLD_VECTORISE`), et il ne sert la page suivante que s'il le retrouve. Un module
    // qui recopie `{ ts: nc.ts, id: nc.id }` PERD ce champ — et le démon REFUSE alors la page plutôt
    // que d'en servir une qui commence ailleurs. C'est un refus honnête, mais c'est une traversée
    // cassée, et elle l'était : `web/dashboards.js` reconstruisait le curseur (mesuré le 2026-08-28).
    //
    // LA POPULATION EST DÉRIVÉE, PAS ÉNUMÉRÉE : tous les modules de `web/` qui nomment `next_cursor`.
    // Un module de pagination écrit demain y entre le jour où il est écrit.
    #[test]
    fn aucun_module_web_ne_reconstruit_le_curseur_keyset() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("racine du dépôt").join("web");
        // UNE RECONSTRUCTION EST UNE **PROPRIÉTÉ**, PAS UN ORDRE D'ÉCRITURE : un littéral d'objet dont
        // les clés sont EXACTEMENT `{ts,id}` et dont les DEUX valeurs lisent `ts` et `id` sur le MÊME
        // porteur. La forme, PAS la ligne : la première version de ce prédicat exigeait le mot
        // `next_cursor` sur la MÊME ligne, et la reconstruction réelle tient sur DEUX (`const nc =
        // j.next_cursor;` puis l'objet).
        //
        // ET LA DEUXIÈME VERSION ÉTAIT MUETTE SUR UNE PERMUTATION (mesuré le 2026-08-28). Elle ancrait
        // la sous-chaîne `{ts:` en tête d'accolade : `{ id: c.id, ts: c.ts }` — sémantiquement
        // IDENTIQUE, et l'ordre naturel quand on écrit l'`id` d'abord — n'était pas vu, pas plus que
        // `{ ts: c['ts'], id: c['id'] }` ou un littéral passé à `Object.assign`. Une garde franchissable
        // par une permutation ne garde rien : on juge donc la propriété, dans un ordre quelconque.
        let reconstruit = |texte: &str| -> bool {
            let t: Vec<char> = texte.chars().filter(|c| !c.is_whitespace()).collect();
            // `porteur.ts` / `porteur['ts']` / `porteur["ts"]` -> le NOM du porteur, sinon `None`.
            let porteur_de = |v: &str, cle: &str| -> Option<String> {
                for suffixe in [format!(".{cle}"), format!("['{cle}']"), format!("[\"{cle}\"]")] {
                    if let Some(p) = v.strip_suffix(suffixe.as_str()) {
                        if !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$') {
                            return Some(p.to_string());
                        }
                    }
                }
                None
            };
            for (i, c) in t.iter().enumerate() {
                if *c != '{' {
                    continue;
                }
                // Le corps du littéral : jusqu'à la première accolade, ouvrante ou fermante. Une
                // ouvrante -> objet imbriqué, ce n'est pas CE littéral-ci (celui de l'intérieur sera
                // examiné à son tour par la boucle).
                let Some(d) = t[i + 1..].iter().position(|c| *c == '}' || *c == '{') else { continue };
                if t[i + 1 + d] == '{' {
                    continue;
                }
                let corps: String = t[i + 1..i + 1 + d].iter().collect();
                let champs: Vec<&str> = corps.split(',').collect();
                if champs.len() != 2 {
                    continue; // les clés sont EXACTEMENT deux : `{ts,id}` et rien d'autre
                }
                let mut porteurs: std::collections::BTreeMap<&str, String> = Default::default();
                for ch in champs {
                    let Some((cle, val)) = ch.split_once(':') else { continue };
                    let cle = cle.trim_matches(|c| c == '\'' || c == '"');
                    if cle != "ts" && cle != "id" {
                        continue;
                    }
                    if let Some(porteur) = porteur_de(val, cle) {
                        porteurs.insert(if cle == "ts" { "ts" } else { "id" }, porteur);
                    }
                }
                if porteurs.len() == 2 && porteurs["ts"] == porteurs["id"] {
                    return true; // les deux clés, le même porteur : c'est une recopie
                }
            }
            false
        };
        // INSTRUMENT VALIDÉ DANS LES DEUX SENS AVANT TOUT VERDICT — sur la forme EXACTE mesurée (deux
        // lignes, comme dans le module), sur les formes qui la PERMUTENT ou changent d'accès, et sur
        // celles qui la corrigent.
        assert!(
            reconstruit("const nc = j.next_cursor;\n  spg.cursors[p] = (nc && typeof nc.ts === 'number') ? { ts: nc.ts, id: nc.id } : null;"),
            "témoin POSITIF : la reconstruction mesurée le 2026-08-28 doit être RECONNUE, même répartie sur deux lignes"
        );
        assert!(
            reconstruit("reqBody.cursor = { id: cur.id, ts: cur.ts };"),
            "témoin POSITIF (LA PERMUTATION) : l'`id` écrit en premier est la MÊME reconstruction — c'est ce cas-là que le prédicat ancré sur l'accolade suivie de `ts:` laissait passer"
        );
        assert!(
            reconstruit("Object.assign({}, { id: nc['id'], ts: nc['ts'] })"),
            "témoin POSITIF : l'accès par crochets, dans un littéral imbriqué, recopie tout autant"
        );
        assert!(
            !reconstruit("const nc = j.next_cursor;\n  spg.cursors[p] = (nc && typeof nc.ts === 'number') ? nc : null;"),
            "témoin NÉGATIF : renvoyer l'objet reçu TEL QUEL ne doit pas être accusé"
        );
        assert!(!reconstruit("const nc = { ts: 1, id: 2 };"), "témoin NÉGATIF : un objet qui ne RECOPIE rien n'est pas concerné");
        assert!(
            !reconstruit("const c = { ts: nc.ts, id: nc.id, espace: nc.espace };"),
            "témoin NÉGATIF : un littéral qui recopie AUSSI l'espace ne perd pas la marque — la propriété porte sur « exactement ts et id »"
        );

        let mut fichiers = 0usize;
        let mut vus = 0usize;
        let mut fautifs: Vec<String> = Vec::new();
        for e in std::fs::read_dir(&racine).expect("web/ lisible") {
            let p = e.expect("entrée lisible").path();
            if p.extension().and_then(|x| x.to_str()) != Some("js") {
                continue;
            }
            let src = std::fs::read_to_string(&p).expect("module web lisible");
            if !src.contains("next_cursor") {
                continue;
            }
            fichiers += 1;
            // Les COMMENTAIRES sont retirés avant lecture : un commentaire qui CITE la forme fautive
            // (celui du module corrigé le fait, et celui-ci aussi) n'en est pas une.
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(|l| {
                    vus += usize::from(l.contains("next_cursor"));
                    l
                })
                .collect::<Vec<_>>()
                .join("\n");
            if reconstruit(&code) {
                fautifs.push(p.file_name().unwrap().to_string_lossy().to_string());
            }
        }
        assert!(
            fichiers >= 2 && vus >= 2,
            "INSTRUMENT : la population est vide ou presque ({fichiers} module(s), {vus} site(s)) — ce verdict ne mesurerait rien"
        );
        assert!(
            fautifs.is_empty(),
            "un module de la console RECONSTRUIT le curseur keyset au lieu de renvoyer celui qu'il a reçu : {fautifs:?} — \
             tout champ que le démon y ajoute (l'espace d'identifiant du browse froid) est perdu, et la page suivante est REFUSÉE"
        );
    }

    // ============================================================================================
    // `P10.5-g` — LA RÈGLE D'ENTRÉE DE LA MARQUE S'APPLIQUE **AVANT** LA PORTE, ET INDÉPENDAMMENT DE
    // SON ÉTAT D'ARMEMENT.
    //
    // LE TROISIÈME SENS, MESURÉ LE 2026-08-28. Deux sens étaient fermés (curseur froid SANS marque,
    // dans les deux directions). Celui-ci restait ouvert : un curseur froid QUI PORTE la marque
    // partait quand même vers l'oracle dès que la porte de la voie vectorisée se fermait ENTRE deux
    // pages, sans qu'une seule ligne de code ne consulte la marque — la règle d'entrée vivait DANS
    // `cold_keyset_vectorized_page`, la décision de l'appeler vivait AU-DESSUS d'elle.
    //
    // LES QUATRE CAUSES DE FERMETURE, ÉPROUVÉES UNE PAR UNE. Elles vivent maintenant dans UNE
    // fonction (`voie_colonnaire_pour_cette_page`), qui est la valeur que la règle d'entrée LIT et
    // que le dispatch LIT — pas deux écritures d'une même condition, une seule valeur.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ks_les_causes_qui_ferment_la_voie_colonnaire_sont_eprouvees_une_par_une() {
        let conf_armee: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut conf_desarmee = std::collections::HashMap::new();
        conf_desarmee.insert("PLUME_COLD_VECTORIZED".to_string(), "0".to_string());
        let gxql = "search source=auditd";

        // TÉMOIN POSITIF — sans lui, quatre `None` ne prouveraient rien : la porte s'OUVRE bel et bien.
        assert_eq!(
            crate::voie_colonnaire_pour_cette_page(Some(1_700_000_000), Some(&conf_armee), 0, Some(gxql)).as_deref(),
            Some(gxql),
            "TÉMOIN POSITIF EN ÉCHEC : frontière posée, route armée par défaut, masques vides, aucun saut — la voie DOIT être prise"
        );
        // (a) LE RÉGLAGE DE L'EXPLOITANT, relu à CHAQUE requête par `load_config()` -> effet immédiat.
        assert!(
            crate::voie_colonnaire_pour_cette_page(Some(1_700_000_000), Some(&conf_desarmee), 0, Some(gxql)).is_none(),
            "(a) `PLUME_COLD_VECTORIZED=0` ferme la voie"
        );
        // (b) UNE RÈGLE DE MASQUE DE CHAMP effective pour l'appelant -> aucune capture pour le routeur.
        assert!(
            crate::voie_colonnaire_pour_cette_page(Some(1_700_000_000), Some(&conf_armee), 0, None).is_none(),
            "(b) masque effectif (aucune capture GXQL) ferme la voie"
        );
        // (c) UN CLIENT QUI RENVOIE LE CURSEUR AVEC UN `offset` NON NUL.
        assert!(
            crate::voie_colonnaire_pour_cette_page(Some(1_700_000_000), Some(&conf_armee), 1, Some(gxql)).is_none(),
            "(c) `offset > 0` ferme la voie (le saut-à-la-page reste sur le fallback capé)"
        );
        // ET LA QUATRIÈME, celle qui ne demande même pas de réglage : la fenêtre n'atteint pas le froid
        // (ou le tier froid est éteint) -> aucune frontière -> aucune voie colonnaire.
        assert!(
            crate::voie_colonnaire_pour_cette_page(None, Some(&conf_armee), 0, Some(gxql)).is_none(),
            "aucune frontière froide -> la voie n'est pas prise"
        );
        assert!(
            crate::voie_colonnaire_pour_cette_page(Some(1_700_000_000), None, 0, Some(gxql)).is_none(),
            "configuration indisponible -> fermé (défaut SÛR), jamais « on suppose armé »"
        );

        // LA LECTURE DE L'ESPACE — les deux marques connues, l'inconnue, et CE QUE LA MARQUE DE
        // L'ORACLE PORTE EN PLUS DE SON NOM.
        assert_eq!(
            crate::lire_espace_du_curseur(crate::ESPACE_ID_COLD_VECTORISE),
            crate::EspaceCurseur::Colonnaire,
            "la marque du browse colonnaire n'a qu'un lecteur : lui"
        );
        // L'ALLER-RETOUR : ce que l'oracle ÉCRIT est exactement ce que la lecture REND. Une seule
        // écriture de la forme, une seule lecture — sans quoi les deux dérivent.
        for empreinte in [0u64, 1, 0x0123_4567_89ab_cdef, u64::MAX] {
            assert_eq!(
                crate::lire_espace_du_curseur(&crate::espace_oracle(empreinte)),
                crate::EspaceCurseur::Oracle { empreinte },
                "la marque de l'oracle porte SA NUMÉROTATION, et elle se relit à l'identique"
            );
        }
        // LE MOT NU, CELUI QUE LA VERSION PRÉCÉDENTE ÉMETTAIT : il nomme un LECTEUR, jamais une
        // NUMÉROTATION. Il n'a donc plus de lecteur, et c'est le coût assumé du lot — une fois, au
        // déploiement, un client en cours de pagination froide repart de la première page.
        assert_eq!(
            crate::lire_espace_du_curseur("cold-union"),
            crate::EspaceCurseur::SansLecteur,
            "l'`cold-union` NU d'avant la comparaison d'empreinte ne dit pas CE QUI a été numéroté : il se refuse"
        );
        // UNE MARQUE PRESQUE BIEN FORMÉE N'EST PAS UNE MARQUE — sans quoi `from_str_radix` accepterait
        // un `+`, une longueur variable ou des majuscules, et deux écritures de la forme divergeraient.
        for presque in ["cold-union/", "cold-union/+123456789abcdef", "cold-union/0123456789ABCDEF", "cold-union/0123456789abcde", "cold-union/0123456789abcdef0"] {
            assert_eq!(
                crate::lire_espace_du_curseur(presque),
                crate::EspaceCurseur::SansLecteur,
                "marque mal formée « {presque} » : refusée, jamais interprétée « au mieux »"
            );
        }
        assert_eq!(
            crate::lire_espace_du_curseur("un-espace-que-ce-binaire-ne-connait-pas"),
            crate::EspaceCurseur::SansLecteur,
            "un espace sans lecteur : personne ne sait ce que ce nombre veut dire, donc personne ne le rejoue"
        );
        assert!(
            !crate::ESPACE_ID_COLD_VECTORISE.starts_with(crate::ESPACE_ID_COLD_UNION_PREFIXE),
            "INSTRUMENT : deux espaces qui se confondraient ne distingueraient rien"
        );
        // DEUX NUMÉROTATIONS DIFFÉRENTES NE PORTENT PAS LA MÊME MARQUE — sans quoi la comparaison du
        // handler serait vraie partout et ne trancherait rien.
        assert_ne!(
            crate::espace_oracle(1),
            crate::espace_oracle(2),
            "INSTRUMENT : la marque doit VARIER avec l'empreinte, sinon elle ne porte pas la numérotation"
        );
    }

    /// `P10.5-g` — ON N'INFÈRE JAMAIS L'ESPACE D'UN CURSEUR : LA RÈGLE D'ENTRÉE, CAUSE PAR CAUSE.
    ///
    /// CE QUE CE TÉMOIN FERME, ET QUE LE PRÉCÉDENT NE POUVAIT PAS FERMER. La règle vivait EN LIGNE dans
    /// le handler, donc chacun de ses cas exigeait un routeur, une base, une frontière froide posée et
    /// un environnement de processus pour être joué — et c'est ainsi que sa jambe « oracle » n'a JAMAIS
    /// été jouée AVEC frontière : elle rendait `cold_boundary.is_some()`, c'est-à-dire « il existe UNE
    /// fenêtre froide », d'où elle DÉDUISAIT « c'est la MÊME ». La règle est maintenant une valeur
    /// (`verdict_du_curseur`), et chaque cause s'éprouve seule.
    ///
    /// LES DEUX SENS SONT TENUS. Sans les jambes NÉGATIVES, un handler qui refuserait TOUT curseur
    /// passerait ce témoin — et casserait toute pagination, chaude comprise.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ks_la_regle_dentree_lit_lespace_du_curseur_et_ne_le_deduit_jamais() {
        use crate::{espace_oracle, verdict_du_curseur, VerdictCurseur, ESPACE_ID_COLD_VECTORISE};
        let b = 1_700_000_000i64;
        let froid = Some((b - 1, 42));
        let chaud = Some((b + 1, 42));

        // ---- JAMBES NÉGATIVES : ce qui doit RESTER servi. ------------------------------------------
        assert_eq!(
            verdict_du_curseur(None, None, true, Some(b)),
            VerdictCurseur::Servir,
            "TÉMOIN NÉGATIF EN ÉCHEC : une PREMIÈRE page n'a pas de curseur, il n'y a rien à trancher"
        );
        assert_eq!(
            verdict_du_curseur(chaud, None, false, Some(b)),
            VerdictCurseur::Servir,
            "TÉMOIN NÉGATIF EN ÉCHEC : au-dessus de la frontière un curseur nu porte l'`event.id` RÉEL, que \
             toutes les voies lisent de la même façon — le refuser casserait la pagination chaude"
        );
        assert_eq!(
            verdict_du_curseur(froid, None, false, None),
            VerdictCurseur::Servir,
            "TÉMOIN NÉGATIF EN ÉCHEC : sans frontière froide (tier éteint, ou fenêtre qui ne l'atteint pas) il n'y a \
             pas de ligne sans `id` stocké — le profil de production par défaut ne change PAS"
        );
        assert_eq!(
            verdict_du_curseur(froid, Some(ESPACE_ID_COLD_VECTORISE), true, Some(b)),
            VerdictCurseur::Servir,
            "TÉMOIN NÉGATIF EN ÉCHEC : la marque du browse colonnaire, quand c'est LUI qui sert la page, est servie"
        );
        assert_eq!(
            verdict_du_curseur(froid, Some(&espace_oracle(7)), false, Some(b)),
            VerdictCurseur::Servir,
            "TÉMOIN NÉGATIF EN ÉCHEC : la marque de l'oracle passe la règle d'ENTRÉE dès que son chemin est atteint — \
             l'égalité des NUMÉROTATIONS se juge sur l'empreinte mesurée par l'hydratation, pas ici"
        );

        // ---- LE CŒUR DU LOT : un curseur FROID qui ne dit pas dans quel espace il a été numéroté. ---
        assert_eq!(
            verdict_du_curseur(froid, None, true, Some(b)),
            VerdictCurseur::RefusFroidSansEspace,
            "sous la frontière AUCUNE ligne n'a d'`id` stocké : un curseur nu ne dit pas quelle voie a fabriqué le \
             sien, et les DEUX marquent désormais ce qu'elles émettent — il se refuse, sans consulter la routabilité"
        );
        assert_eq!(
            verdict_du_curseur(froid, None, false, Some(b)),
            VerdictCurseur::RefusFroidSansEspace,
            "LE MÊME VERDICT AVEC LA VOIE COLONNAIRE FERMÉE : c'est bien la POSITION et l'ABSENCE DE MARQUE qui \
             tranchent, jamais une voie supposée. La branche qui DÉDUISAIT rendait ici deux réponses opposées."
        );

        // ---- LES MARQUES SANS LECTEUR POUR CETTE PAGE. ---------------------------------------------
        assert_eq!(
            verdict_du_curseur(froid, Some(ESPACE_ID_COLD_VECTORISE), false, Some(b)),
            VerdictCurseur::RefusMarqueSansLecteur,
            "la marque du browse colonnaire alors qu'il ne sert PAS cette page : refus (le rejouer par l'oracle \
             rendrait une page qui commence ailleurs)"
        );
        assert_eq!(
            verdict_du_curseur(froid, Some(&espace_oracle(7)), true, None),
            VerdictCurseur::RefusMarqueSansLecteur,
            "la marque de l'oracle alors que son chemin n'est pas atteint : refus"
        );
        assert_eq!(
            verdict_du_curseur(froid, Some("cold-union"), true, Some(b)),
            VerdictCurseur::RefusMarqueSansLecteur,
            "LE COÛT ASSUMÉ, ÉCRIT : la marque NUE émise par la version précédente nomme un LECTEUR sans dire CE \
             QU'IL A NUMÉROTÉ — elle n'a plus de lecteur. Une fois, au déploiement, un parcours froid repart de la \
             première page ; c'est infiniment moins grave qu'une page qui commence ailleurs sans le dire."
        );
        assert_eq!(
            verdict_du_curseur(froid, Some("un-espace-que-ce-binaire-ne-connait-pas"), true, Some(b)),
            VerdictCurseur::RefusMarqueSansLecteur,
            "un espace dont aucune voie n'est le lecteur ne se rejoue pas « au cas où »"
        );
        // ET AU-DESSUS DE LA FRONTIÈRE AUSSI : la règle porte sur la MARQUE, pas sur la position, dès
        // qu'une marque est présente. Une marque incohérente avec sa position est jugée plus bas
        // (`cold_keyset_vectorized_page`), mais elle n'est jamais SERVIE par défaut ici.
        assert_eq!(
            verdict_du_curseur(chaud, Some(ESPACE_ID_COLD_VECTORISE), false, Some(b)),
            VerdictCurseur::RefusMarqueSansLecteur,
            "une marque dont la voie ne sert pas cette page est refusée où que pointe le curseur"
        );
    }

    /// `P10.5-c` — TOUT CHEMIN QUI AVOUE UNE PART FROIDE AVOUE AUSSI LA VOIE QUI A SERVI.
    ///
    /// LE DÉFAUT MESURÉ (2026-08-28). Le refus d'exactitude du tier froid
    /// (`cold_store::exactness::TruncatedAggregate::message`) envoie le lecteur à `stats.served_from` :
    /// « ce qui tranche l'exactitude est publié par la RÉPONSE ». Or ce refus n'est émis QUE par
    /// l'oracle d'union, et le chemin de l'oracle ne publiait PAS ce champ — il rendait sa réponse avant
    /// d'atteindre le seul site qui l'écrit. Le lecteur qui suivait le conseil (a) du message
    /// (« restreindre la fenêtre jusqu'à ce que la lecture froide tienne sous le plafond ») recevait donc
    /// sa réponse EXACTE par ce même chemin, et ne trouvait rien pour la distinguer d'un pré-agrégé
    /// APPROXIMATIF. Un message qui renvoie à un champ absent est une promesse fausse.
    ///
    /// LA PROPRIÉTÉ EST DÉRIVÉE, PAS ÉNUMÉRÉE : chaque site qui écrit l'aveu de part froide
    /// (`stats_cold(`) doit, avant de RENDRE, publier l'aveu de voie. Un troisième chemin d'union écrit
    /// demain ne peut pas oublier l'un des deux sans que ce témoin rougisse — c'est la même forme de
    /// garde que celle qui tient la sortie unique du keyset, et pour la même raison mesurée : ce sont
    /// les chemins ajoutés à côté qui oublient.
    ///
    /// L'INSTRUMENT SE VALIDE : les deux ancrages doivent être TROUVÉS, et le nombre de sites d'aveu
    /// doit être NON NUL — sans quoi ce test serait vert par vacuité.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn ks_tout_aveu_de_part_froide_saccompagne_de_laveu_de_voie() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("handlers").join("query.rs"),
        )
        .expect("le handler de requête est lisible");
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");

        // Les SITES D'AVEU DE PART FROIDE : les appels, pas la définition (qui porte le `fn`).
        let sites: Vec<usize> = code.match_indices("stats_cold(boundary, &meta)").map(|(i, _)| i).collect();
        assert!(
            sites.len() >= 2,
            "INSTRUMENT : au moins deux chemins d'union publient `stats.cold` (vu {}) — sinon ce témoin ne mesure rien",
            sites.len()
        );
        for i in &sites {
            // La FIN du chemin : la première sortie rencontrée après l'aveu.
            let reste = &code[*i..];
            let fin = ["keyset_reponse(", "Json(value).into_response()", "Json(v).into_response()"]
                .iter()
                .filter_map(|m| reste.find(m))
                .min()
                .unwrap_or_else(|| panic!("INSTRUMENT : aucun site de SORTIE après l'aveu de part froide à l'offset {i}"));
            let segment = &reste[..fin];
            assert!(
                segment.contains("apply_rollup_stats("),
                "un chemin publie `stats.cold` (offset {i}) puis REND sans publier `stats.served_from` — c'est \
                 exactement le champ auquel le refus d'exactitude renvoie le lecteur. Segment : {segment}"
            );
        }
    }

    /// `P10.5-g` — LA RÈGLE D'ENTRÉE N'EST PAS RECOPIÉE DANS LE HANDLER, ELLE Y EST LUE.
    ///
    /// MÊME PROPRIÉTÉ STRUCTURELLE QUE POUR LA PORTE, ET POUR LA MÊME RAISON MESURÉE : deux écritures
    /// d'une même décision divergent. Le handler doit APPELER la règle, une seule fois, et n'écrire
    /// nulle part la condition qu'elle porte.
    #[test]
    fn ks_la_regle_dentree_du_curseur_nest_ecrite_quune_fois() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("handlers").join("query.rs"),
        )
        .expect("le handler de requête est lisible");
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");

        let appels = code.matches("verdict_du_curseur(").count();
        assert_eq!(
            appels, 2,
            "la règle d'entrée doit être DÉFINIE une fois et APPELÉE une fois (2 occurrences) — vu {appels}"
        );
        // La ROUTABILITÉ D'UNE TRAVERSÉE — la déduction supprimée — ne doit plus être nommée nulle part
        // dans le démon. Une déduction qui dort est une déduction qu'un lot suivant rebranche.
        //
        // LE MOTIF EST ASSEMBLÉ À L'EXÉCUTION, ET C'EST UNE CORRECTION D'INSTRUMENT : écrit en toutes
        // lettres, il se trouvait LUI-MÊME dans ce fichier et rendait le témoin rouge par auto-appariement
        // (mesuré à la première exécution, 2026-08-28). Un motif qui se voit dans son propre miroir ne
        // mesure pas l'arbre.
        let disparu = format!("cold_keyset_{}", "traversee_routable");
        let temoin_present = format!("map_keyset_{}", "route"); // vivant, lui : l'instrument doit le TROUVER
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut restes: Vec<String> = Vec::new();
        let mut vus_du_temoin = 0usize;
        let mut pile = vec![racine.clone()];
        let mut fichiers_lus = 0usize;
        while let Some(d) = pile.pop() {
            for e in std::fs::read_dir(&d).expect("arbre du démon lisible").flatten() {
                let p = e.path();
                if p.is_dir() {
                    pile.push(p);
                } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                    fichiers_lus += 1;
                    let t = std::fs::read_to_string(&p).unwrap_or_default();
                    for l in t.lines() {
                        if l.trim_start().starts_with("//") {
                            continue;
                        }
                        if l.contains(disparu.as_str()) {
                            restes.push(format!("{}: {}", p.display(), l.trim()));
                        }
                        if l.contains(temoin_present.as_str()) {
                            vus_du_temoin += 1;
                        }
                    }
                }
            }
        }
        assert!(fichiers_lus > 50, "INSTRUMENT : la marche de l'arbre n'a lu que {fichiers_lus} fichiers — elle ne mesure rien");
        assert!(
            vus_du_temoin >= 2,
            "INSTRUMENT : le témoin POSITIF `{temoin_present}` doit être trouvé dans le code (vu {vus_du_temoin} fois) — \
             sinon ce test est vert par vacuité, le mode de panne des gardes de source"
        );
        assert!(
            restes.is_empty(),
            "la déduction d'espace par la routabilité de la traversée est SUPPRIMÉE, pas endormie — restes : {restes:?}"
        );
    }

    /// `P10.5-g` — LE REFUS ARRIVE JUSQU'AU CLIENT, PAR LE ROUTEUR RÉEL.
    ///
    /// Le témoin précédent juge la DÉCISION ; celui-ci juge ce que le produit RÉPOND. Sans lui, une
    /// règle d'entrée juste mais jamais appelée passerait — c'est exactement le défaut qu'on ferme :
    /// la règle existait, une clause plus haut la court-circuitait.
    ///
    /// LA CAUSE CHOISIE EST (c) — le curseur renvoyé AVEC un `offset` non nul — parce qu'elle ferme la
    /// porte QUEL QUE SOIT l'état du tier froid dans ce processus : le verdict ne dépend donc d'aucune
    /// variable d'environnement qu'un autre test pourrait tenir au même instant.
    ///
    /// LES DEUX SENS :
    ///   • le curseur MARQUÉ (marque connue, puis marque inconnue) -> 422 qui NOMME sa cause ;
    ///   • le MÊME curseur SANS marque -> servi. La règle porte sur la MARQUE, pas sur le fait qu'il y
    ///     ait un curseur ni sur l'`offset` — sans cette jambe, un handler qui refuserait TOUT curseur
    ///     passerait ce test.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ks_un_curseur_marque_est_refuse_quand_sa_voie_ne_sert_pas_la_page() {
        let (st, _db) = router_test_state("ks-espace-sans-lecteur");
        let addr = router_serve(st).await;
        let authz = viewer_authz();
        let entetes = [("Content-Type", "application/json")];
        let corps = |espace: Option<&str>| -> String {
            let curseur = match espace {
                Some(e) => format!("{{\"ts\":1,\"id\":2,\"espace\":\"{e}\"}}"),
                None => "{\"ts\":1,\"id\":2}".to_string(),
            };
            format!("{{\"soql\":\"search\",\"keyset\":true,\"limit\":10,\"offset\":100,\"cursor\":{curseur}}}")
        };

        // CONTRÔLE : la route est joignable et sert bien une page keyset. Sans lui, un 422 pourrait
        // venir de tout autre chose que de la règle qu'on éprouve.
        let (code_nu, corps_nu) =
            router_probe_envoi(addr, "POST", "/api/query", Some(&authz), &entetes, "{\"soql\":\"search\",\"keyset\":true,\"limit\":10}").await;
        assert_eq!(code_nu, 200, "CONTRÔLE EN ÉCHEC : la page 1 keyset doit être servie. Réponse : {corps_nu}");

        // ① MARQUE CONNUE, VOIE FERMÉE -> refus NOMMÉ.
        let (code_m, corps_m) =
            router_probe_envoi(addr, "POST", "/api/query", Some(&authz), &entetes, &corps(Some(crate::ESPACE_ID_COLD_VECTORISE))).await;
        assert_eq!(
            code_m, 422,
            "un curseur portant la marque du browse colonnaire, alors que cette voie ne sert PAS cette page, doit être REFUSÉ — \
             le servir par l'oracle rendrait une page qui commence ailleurs, en silence, en 200 OK. Réponse : {corps_m}"
        );
        assert!(
            corps_m.contains("cold_cursor_espace_sans_lecteur"),
            "le refus doit NOMMER sa cause de façon lisible par une machine, sinon le client ne peut rien en faire : {corps_m}"
        );

        // ② MARQUE SANS LECTEUR -> même refus. Un nombre dont plus personne ne connaît la numérotation
        //    ne se rejoue pas « au cas où ».
        let (code_i, corps_i) =
            router_probe_envoi(addr, "POST", "/api/query", Some(&authz), &entetes, &corps(Some("espace-que-ce-binaire-ne-connait-pas"))).await;
        assert_eq!(code_i, 422, "un espace d'identifiant inconnu n'a aucun lecteur : refus. Réponse : {corps_i}");

        // ③ TÉMOIN NÉGATIF — LE MÊME CURSEUR, SANS MARQUE : servi. Il vit dans l'espace d'`event.id`,
        //    que toutes les voies lisent de la même façon.
        let (code_nc, corps_nc) = router_probe_envoi(addr, "POST", "/api/query", Some(&authz), &entetes, &corps(None)).await;
        assert_eq!(
            code_nc, 200,
            "TÉMOIN NÉGATIF EN ÉCHEC : un curseur SANS espace d'identifiant doit rester servi — la règle porte sur la MARQUE, \
             pas sur la présence d'un curseur. Réponse : {corps_nc}"
        );
    }

    /// `P10.5-g` — LA PORTE DE LA VOIE COLONNAIRE N'EST ÉCRITE QU'UNE FOIS, ET LE REFUS LA PRÉCÈDE.
    ///
    /// CE QUE CE TÉMOIN TIENT, ET QU'AUCUN TEST DE COMPORTEMENT NE PEUT TENIR : la FORME du code qui
    /// rendait le défaut possible. Une règle d'entrée qui RECOPIE la condition de la porte est une
    /// deuxième écriture, et deux écritures d'une même condition divergent — c'est le mécanisme exact
    /// du défaut fermé ici. La propriété est donc structurelle : UNE seule dérivation de la porte
    /// (`voie_colonnaire_pour_cette_page`), et le refus posé AVANT le dispatch qui la consomme.
    ///
    /// L'INSTRUMENT SE VALIDE : chacun des trois ancrages doit être TROUVÉ. Un ancrage introuvable
    /// rendrait ce test vert par vacuité, ce qui est le mode de panne des gardes de source.
    #[test]
    fn ks_la_porte_de_la_voie_colonnaire_n_est_ecrite_qu_une_fois() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("handlers").join("query.rs"),
        )
        .expect("le handler de requête est lisible");
        // Les COMMENTAIRES sont retirés : celui de la porte CITE son propre nom, et une citation n'est
        // pas une décision.
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");

        let appels = code.matches("voie_colonnaire_pour_cette_page(").count();
        assert_eq!(
            appels, 2,
            "la porte doit être DÉFINIE une fois et APPELÉE une fois (2 occurrences : la signature et l'unique site d'appel) — \
             vu {appels}. Une deuxième dérivation de la porte est une deuxième écriture de la même condition, et c'est ce que \
             la règle d'entrée de la marque ne peut pas survivre."
        );
        let armed = code.matches("cold_vectorized_armed(").count();
        assert_eq!(
            armed, 1,
            "le gate `PLUME_COLD_VECTORIZED` n'est lu qu'à l'intérieur de la porte — vu {armed} lecture(s) dans le handler"
        );

        let i_refus = code.find("return refuse_curseur_sans_lecteur(").expect("INSTRUMENT : le refus doit être APPELÉ dans le handler");
        let i_dispatch = code.find("if let Some(rsoql) = voie_colonnaire").expect("INSTRUMENT : le dispatch doit CONSOMMER la porte");
        let i_decision = code.find("let voie_colonnaire: Option<String> =").expect("INSTRUMENT : la porte doit être DÉCIDÉE une fois");
        assert!(
            i_decision < i_refus && i_refus < i_dispatch,
            "l'ordre du code de `query()` est linéaire : la porte est décidée, PUIS la marque est jugée, PUIS seulement le \
             dispatch s'exécute. Vu décision={i_decision}, refus={i_refus}, dispatch={i_dispatch}"
        );
    }

    /// `P10.5-g` — UNE PAGE KEYSET N'A QU'UNE SORTIE, DONC LE RETRAIT DES COLONNES D'AIDE N'A QU'UN SITE.
    ///
    /// LE DÉFAUT MESURÉ (2026-08-28, PRÉEXISTANT). Les trois retours keyset du handler refaisaient à la
    /// main la même fin de travail, et l'un des trois — celui de la voie colonnaire — en oubliait une
    /// part : il ne retirait pas les colonnes ajoutées par `keyset_projection_augment`. `search
    /// source=web | table ts,message` rendait donc `["ts","message","id"]` sur les pages que la part
    /// CHAUDE remplit seule, puis `["ts","message"]` dès que le chaud s'épuise — la MÊME requête
    /// changeant de nombre de colonnes au milieu d'un parcours, contre le contrat écrit sur
    /// l'augmentation (« ni plus ni moins »).
    ///
    /// LA CORRECTION N'EST PAS UN APPEL DE PLUS, C'EST UNE SORTIE DE MOINS : `keyset_reponse`. Ce
    /// témoin tient CETTE forme-là — un quatrième chemin keyset écrit demain ne peut pas oublier un
    /// geste qui n'est plus à sa charge.
    #[test]
    fn ks_le_retrait_des_colonnes_daide_na_quun_site() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("handlers").join("query.rs"),
        )
        .expect("le handler de requête est lisible");
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");

        let trims = code.matches("keyset_trim_helper_cols(").count();
        assert_eq!(
            trims, 2,
            "le retrait des colonnes d'aide doit être DÉFINI une fois et APPELÉ une fois, depuis la sortie unique — vu {trims} \
             occurrence(s). Un site d'appel de plus, c'est un chemin qui peut en manquer un ; c'est exactement ce qui est arrivé."
        );
        // La sortie unique est bien la SEULE à porter le retrait, et elle sert les TROIS retours keyset.
        let sorties = code.matches("keyset_reponse(").count();
        assert!(
            sorties >= 4,
            "la sortie unique doit être DÉFINIE une fois et servir les TROIS retours keyset (voie colonnaire, oracle d'union, \
             chemin chaud) — vu {sorties} occurrence(s)"
        );
        let i_def = code.find("fn keyset_reponse(").expect("INSTRUMENT : la sortie unique doit exister");
        let i_trim = code.find("keyset_trim_helper_cols(&mut v, trim)").expect("INSTRUMENT : le retrait doit vivre DANS la sortie unique");
        assert!(i_def < i_trim, "le retrait vit dans le corps de la sortie unique (def={i_def}, retrait={i_trim})");
    }
