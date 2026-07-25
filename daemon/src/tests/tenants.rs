    // ============================================================================================
    // FONDATION MULTI-TENANT #2a-1 — TEST D'ISOLATION : deux db_path distincts NE PARTAGENT PAS l'état
    // process-global re-clé (R1 READ_POOL, R4 AUTOINDEX_BUF, R4 PARSERS). Preuve directe que la re-clé
    // par db_path borne l'état au-dessus du handle DB. En mono-tenant (un seul db_path) tout ce code
    // n'a qu'UNE clé -> comportement STRICTEMENT identique ; ici on exerce 2 clés pour prouver la garde.
    // ============================================================================================
    #[test]
    fn mt_isolation_read_pool_and_caches_keyed_by_db_path() {
        let a = mk_tmp_path("mt-a.db");
        let b = mk_tmp_path("mt-b.db");
        // deux bases RÉELLES avec un marqueur distinct -> prouve QUELLE base a servi la connexion.
        for (p, tag) in [(&a, "AAA"), (&b, "BBB")] {
            let c = Connection::open(p).unwrap();
            c.execute_batch(&format!("CREATE TABLE marker(v TEXT); INSERT INTO marker VALUES('{tag}');")).unwrap();
        }

        // ---- R1 READ_POOL ---- : une connexion rendue sous A ne doit JAMAIS être servie pour B
        // (bug LATENT avant re-clé : l'ancien Vec global rendait n'importe quelle connexion pour n'importe
        // quelle base). On remplit le pool de A puis un get(B) DOIT servir une connexion ouverte sur B.
        let ca = read_conn_get(&a).expect("open A");
        read_conn_put(&a, ca); // READ_POOL.by_path[A] = [conn ouverte sur A]
        let cb = read_conn_get(&b).expect("open B");
        let vb: String = cb.query_row("SELECT v FROM marker", [], |r| r.get(0)).unwrap();
        assert_eq!(vb, "BBB", "R1 : get(B) ne doit JAMAIS servir une connexion ouverte sur A");
        read_conn_put(&b, cb);
        let ca2 = read_conn_get(&a).expect("reopen A");
        let va: String = ca2.query_row("SELECT v FROM marker", [], |r| r.get(0)).unwrap();
        assert_eq!(va, "AAA", "R1 : le pool de A ne sert que des connexions ouvertes sur A");
        read_conn_put(&a, ca2);

        // ---- R4 AUTOINDEX_BUF ---- : un hit noté sous A ne doit PAS apparaître sous B.
        {
            let _g = AUTOINDEX_TEST_LOCK.lock();
            AUTOINDEX_ON.store(true, std::sync::atomic::Ordering::Relaxed);
            autoindex_buf().lock().clear();
            autoindex_note(&a, "iso_field");
            {
                let top = autoindex_buf().lock();
                assert!(top.get(a.as_str()).and_then(|m| m.get("iso_field")).is_some(),
                        "R4 : le hit noté sous A doit exister sous la clé A");
                assert!(top.get(b.as_str()).and_then(|m| m.get("iso_field")).is_none(),
                        "R4 : le hit noté sous A ne doit JAMAIS apparaître sous la clé B");
            }
            autoindex_buf().lock().clear();
            AUTOINDEX_ON.store(false, std::sync::atomic::Ordering::Relaxed);
        }

        // ---- R4 PARSERS ---- : un registre chargé sous A ne s'applique pas à une ingestion sous B.
        {
            { let mut w = parsers_cell().write();
                let re = regex::Regex::new(r"tok=(?P<iso>\w+)").unwrap();
                w.insert(a.clone(), vec![("*".to_string(), re)]);
            }
            let fa = parsers_apply(&a, "src", "tok=HELLO", None);
            let fb = parsers_apply(&b, "src", "tok=HELLO", None);
            assert!(fa.as_deref().map_or(false, |s| s.contains("HELLO")),
                    "R4 : les parseurs de A enrichissent une ingestion sous A");
            assert!(fb.is_none(),
                    "R4 : les parseurs de A ne s'appliquent JAMAIS à une ingestion sous B");
            { let mut w = parsers_cell().write(); w.remove(a.as_str()); }
        }

        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

