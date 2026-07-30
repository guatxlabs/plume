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
            crate::keyset_finalize(&mut v, lim);
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
        crate::keyset_finalize(&mut v, 10);
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
        crate::keyset_finalize(&mut v1, 10);
        assert_eq!(v1["has_more"], json!(true));
        let cur = (v1["next_cursor"]["ts"].as_i64().unwrap(), v1["next_cursor"]["id"].as_i64().unwrap());
        let mut v2 = ks_run_page(&c, &crate::page_sql(&base, crate::keyset_plan(Some(cur), 0), 10));
        assert_eq!(v2["rows"].as_array().unwrap().len(), 3, "reste 3 lignes");
        crate::keyset_finalize(&mut v2, 10);
        assert_eq!(v2["has_more"], json!(false), "3 < 10 -> dernière page");
        assert!(v2["next_cursor"].is_null(), "dernière page -> next_cursor null");
    }

    // (5) CONTRAT keyset_finalize isolé : has_more/next_cursor/limite + défense sur colonnes manquantes.
    #[test]
    fn keyset_finalize_contract() {
        // exactement lim lignes -> has_more + curseur = dernière ligne
        let mut full = json!({ "columns": ["ts", "host", "id"], "rows": [[9, "a", 1], [8, "b", 2], [7, "c", 3]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut full, 3);
        assert_eq!(full["has_more"], json!(true));
        assert_eq!(full["next_cursor"], json!({ "ts": 7, "id": 3 }));
        assert_eq!(full["limit"], json!(3));
        // moins que lim -> dernière page
        let mut part = json!({ "columns": ["ts", "id"], "rows": [[9, 1]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut part, 3);
        assert_eq!(part["has_more"], json!(false));
        assert!(part["next_cursor"].is_null());
        // troncature run_query_ex (max_rows atteint) < lim -> il RESTE des lignes -> has_more (curseur fourni)
        let mut trunc = json!({ "columns": ["ts", "id"], "rows": [[9, 1], [8, 2]], "stats": { "truncated": true } });
        crate::keyset_finalize(&mut trunc, 100);
        assert_eq!(trunc["has_more"], json!(true), "truncated -> il reste des lignes");
        assert_eq!(trunc["next_cursor"], json!({ "ts": 8, "id": 2 }));
        // DÉFENSIF : colonnes ts/id absentes (curseur inextractible) -> pas de has_more (arrêt, jamais boucle infinie)
        let mut noid = json!({ "columns": ["source", "message"], "rows": [["a", "x"], ["b", "y"], ["c", "z"]], "stats": { "truncated": false } });
        crate::keyset_finalize(&mut noid, 3);
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
