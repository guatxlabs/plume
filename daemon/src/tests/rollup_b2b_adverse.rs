// =====================================================================================
// B2b MERGE — TESTS ADVERSES (rollup ∪ raw-partiels, résultat prétendu EXACT & FRAIS).
// Oracle = `count by source,severity` sur `event` brut (scan complet = vérité). Le merge DOIT
// reproduire ce compte EXACTEMENT (au COMPTE près, pas au bucket près) pour être `approx:false`.
// Réutilise le harnais du fichier rollup.rs (même module via include!) : B2_ENV_LOCK, b2_map,
// test_db, rollup_events, try_rollup_route_at, soql_to_sql_x.
// =====================================================================================

    /// Sème `n_each` copies de chaque (source,severity) au `ts` donné (host peuplé, action absente =
    /// hors du group-by testé -> aucune divergence NULL/''). Ne roule PAS (l'appelant décide quand).
    fn b2adv_seed_at(conn: &Connection, ts: i64, n_each: usize, tag: &str) {
        let combos: &[(&str, i64)] = &[("web", 4), ("web", 2), ("sshd", 3), ("auditd", 3), ("firewall", 2)];
        for (src, sev) in combos {
            for i in 0..n_each {
                conn.execute(
                    "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,?2,?3,'h1','{}',?4)",
                    params![ts, src, sev, format!("{tag}-{src}-{sev}-{i}")],
                )
                .unwrap();
            }
        }
    }

    /// VECTEUR 1 — FRONTIÈRES EXACTES. Events posés PILE aux ts de frontière (H_lo, une frontière de
    /// bucket interne, body_hi=recent, et `to`). Chaque event doit être compté EXACTEMENT une fois
    /// (ni double-comptage tête∩corps / corps∩queue, ni trou). Fenêtre alignée bas, `to` sub-horaire
    /// touchant l'heure courante -> tête (aucune ici, from aligné) + corps + queue.
    #[test]
    fn b2b_adverse_v1_exact_boundary_events_counted_once() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        let recent = cur - 3600;
        // Events PILE aux frontières critiques :
        b2adv_seed_at(&conn, cur - 4 * 3600, 2, "at_from");      // = from (H_lo aligné) -> corps, bucket cur-4H
        b2adv_seed_at(&conn, cur - 3 * 3600, 2, "at_bktbound");  // frontière de bucket interne cur-3H -> corps
        b2adv_seed_at(&conn, recent - 1, 2, "at_body_hi_minus"); // dernier ts du dernier bucket DÉFINITIF -> corps
        b2adv_seed_at(&conn, recent, 2, "at_recent");            // PILE body_hi=recent -> DOIT être en QUEUE (raw), pas corps
        b2adv_seed_at(&conn, cur + 30, 2, "at_now");             // heure courante -> queue
        rollup_events(&conn);
        let soql = "search | stats count by source,severity";
        let from = cur - 4 * 3600;
        let to = cur + 60; // sub-horaire, touche l'heure courante
        let rr = try_rollup_route_at(soql, from, to, None, n, event_rollup_wm(&conn))
            .expect("corps définitif présent -> DOIT router");
        let got = b2_map(&conn, &rr.sql);
        let want = b2_map(&conn, &soql_to_sql_x(soql, from, to, None).unwrap());
        assert_eq!(got, want, "FRONTIÈRES: merge != raw exact\nmerge={got:?}\nraw={want:?}\nSQL={}", rr.sql);
        let tot_r: i64 = got.iter().map(|(_, x)| x).sum();
        let tot_w: i64 = want.iter().map(|(_, x)| x).sum();
        assert_eq!(tot_r, tot_w, "total events aux frontières conservé (compté 1x)");
        assert!(!rr.approx, "HOT -> approx:false");
    }

    /// VECTEUR 2 — WATERMARK `recent` : structure ET parité aux frontières recent / recent-1 / recent+3600.
    /// Le corps NE lit QUE `bucket < recent` (définitifs) ; la queue raw démarre PILE à recent. Aucun bucket
    /// >= recent lu par le corps (sinon double-comptage avec la queue), aucun bucket < recent zappé.
    #[test]
    fn b2b_adverse_v2_watermark_frontier_no_overlap_no_gap() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        let recent = cur - 3600;
        // events à recent-1 (dernier définitif), recent (1er volatile), recent+3600=cur (courant volatile).
        b2adv_seed_at(&conn, recent - 1, 3, "def_last");
        b2adv_seed_at(&conn, recent, 3, "vol_first");
        b2adv_seed_at(&conn, recent + 3600, 3, "cur_hour");
        rollup_events(&conn);
        let soql = "search | stats count by source,severity";
        let from = cur - 5 * 3600;
        let rr = try_rollup_route_at(soql, from, n, None, n, event_rollup_wm(&conn)).expect("DOIT router");
        // STRUCTURE : corps borné < recent ; queue raw depuis recent (pas recent±1).
        assert!(rr.sql.contains(&format!("bucket < {recent}")), "corps borné < recent : {}", rr.sql);
        assert!(rr.sql.contains(&format!("ts >= {recent}")), "queue raw démarre PILE à recent : {}", rr.sql);
        assert!(!rr.sql.contains(&format!("bucket < {}", recent + 3600)), "corps ne lit JAMAIS un bucket >= recent : {}", rr.sql);
        // PARITÉ à chaque borne autour du watermark.
        for &(f, t) in &[(from, recent - 1), (from, recent), (from, recent + 3600), (from, n)] {
            if let Some(r) = try_rollup_route_at(soql, f, t, None, n, event_rollup_wm(&conn)) {
                let got = b2_map(&conn, &r.sql);
                let want = b2_map(&conn, &soql_to_sql_x(soql, f, t, None).unwrap());
                assert_eq!(got, want, "WATERMARK parité ({f},{t})\nmerge={got:?}\nraw={want:?}\nSQL={}", r.sql);
            }
        }
    }

    /// VECTEUR 3 — LE PIÈGE. Un event ingéré APRÈS le tick de rollup dans un bucket que le merge considère
    /// DÉFINITIF (`bucket < recent`) est lu depuis le CORPS rollup (périmé) et n'est PAS rattrapé par la
    /// queue raw (qui ne couvre que `ts >= recent`). Le scan brut d'`event`, lui, le voit. => MERGE < RAW,
    /// alors que la route rend `approx:false, note:none` (prétendu EXACT & FRAIS).
    ///
    /// RÉALISME (non-disclosed) : le merge calcule `recent = plancher-heure(now_query) - 3600` mais NE
    /// consulte JAMAIS le watermark réel du job (`event_rollup_wm`, = recent du DERNIER tick). Juste après
    /// une frontière d'heure, `recent_query` a avancé d'une heure alors que le tick de finalisation du
    /// bucket cur-2H n'a pas encore tourné (cadence ~5 min) : ce bucket est « définitif » pour le merge mais
    /// pas encore finalisé côté job. Tout event à ingestion normale-mais-décalée (30-90 min) tombant dans ce
    /// bucket pendant cette fenêtre est SILENCIEUSEMENT sous-compté et présenté comme exact.
    #[test]
    fn b2b_adverse_v3_late_event_in_definitive_bucket_undercounts() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        let recent = cur - 3600;
        // État initial : events présents au moment du tick, sur buckets définitifs + volatils. Puis ROLLUP.
        b2adv_seed_at(&conn, cur - 3 * 3600 + 60, 2, "def_ontime"); // bucket cur-3H (définitif)
        b2adv_seed_at(&conn, cur - 2 * 3600 + 60, 2, "def2_ontime"); // bucket cur-2H (définitif)
        b2adv_seed_at(&conn, recent + 30, 2, "vol_ontime");          // heure préc. (volatile)
        b2adv_seed_at(&conn, cur + 30, 2, "cur_ontime");            // heure courante (volatile)
        rollup_events(&conn); // matérialise event_rollup + écrit event_rollup_wm = recent

        // === WATERMARK EN RETARD (réaliste) : le tick de FINALISATION du bucket cur-2H n'a PAS encore tourné.
        // On simule un job dont le watermark RÉEL est resté à cur-2*3600 alors que `recent_query` (dérivé du now
        // de la requête) a déjà sauté 1 h en avant (cadence tick ~5 min). Le bucket cur-2H est donc `< recent_query`
        // (que le merge NAÏF croyait DÉFINITIF) mais `>= wm` (réellement PAS encore finalisé côté job).
        let wm = cur - 2 * 3600;
        conn.execute("UPDATE meta SET value=?1 WHERE key='event_rollup_wm'", params![wm.to_string()]).unwrap();
        assert_eq!(event_rollup_wm(&conn), wm, "watermark simulé bien lu depuis meta");

        // === LATE : 5 events 'web'/sev4 ingérés APRÈS le tick, dans le bucket cur-2H (>= wm, < recent_query). ===
        // (cas réaliste : ts ~ il y a 65 min, arrivé maintenant ; le job les rattraperait au prochain tick.)
        let late_ts = cur - 2 * 3600 + 120;
        assert!(late_ts < recent, "bucket du late event < recent_query (le merge NAÏF le croyait définitif)");
        assert!(late_ts >= wm, "…mais >= wm RÉEL -> DOIT être rattrapé par la queue raw (jamais lu du rollup périmé)");
        for i in 0..5 {
            conn.execute(
                "INSERT INTO event(ts,source,severity,host,fields,dedup) VALUES(?1,'web',4,'h1','{}',?2)",
                params![late_ts, format!("LATE-{i}")],
            )
            .unwrap();
        }

        let soql = "search | stats count by source,severity";
        let from = cur - 4 * 3600;
        // FIX : la route lit le watermark RÉEL (event_rollup_wm) et borne le corps à `< wm` -> le bucket cur-2H
        // est servi par la QUEUE RAW (à jour, index-servie) et NON depuis le rollup périmé.
        let rr = try_rollup_route_at(soql, from, n, None, n, event_rollup_wm(&conn)).expect("DOIT router (corps définitif présent)");
        let got = b2_map(&conn, &rr.sql);                                    // ce que sert le merge
        let want = b2_map(&conn, &soql_to_sql_x(soql, from, n, None).unwrap()); // ORACLE brut

        let mget = |k: &str| got.iter().find(|(x, _)| x == k).map(|(_, c)| *c).unwrap_or(0);
        let mwant = |k: &str| want.iter().find(|(x, _)| x == k).map(|(_, c)| *c).unwrap_or(0);
        eprintln!(
            "[V3 FIX] web|4 -> merge={} raw={} (delta={}) ; approx={} note={:?}\nmerge={:?}\nraw={:?}",
            mget("web|4"), mwant("web|4"), mwant("web|4") - mget("web|4"), rr.approx, rr.note, got, want
        );
        // VERT : les 5 late events sont comptés (queue raw bornée au watermark) -> merge EXACT == oracle brut.
        assert_eq!(got, want, "MERGE == RAW exact (plus de sous-comptage des late events)\nmerge={got:?}\nraw={want:?}\nSQL={}", rr.sql);
        assert_eq!(mwant("web|4") - mget("web|4"), 0, "aucun late event omis (web|4 exact : {} == {})", mget("web|4"), mwant("web|4"));
        // HONNÊTE : HOT -> tout partiel est raw-servable -> `approx:false` est RÉELLEMENT exact (pas un mensonge).
        assert!(!rr.approx && rr.note.is_none(), "approx:false HONNÊTE (le compte est réellement exact)");
        // STRUCTURE : corps borné au watermark RÉEL (`< wm`), pas à recent_query ; queue raw démarre à `wm`.
        assert!(rr.sql.contains(&format!("bucket < {wm}")), "corps borné au watermark RÉEL (< wm) : {}", rr.sql);
        assert!(rr.sql.contains(&format!("ts >= {wm}")), "queue raw démarre au watermark RÉEL (>= wm) : {}", rr.sql);
        assert!(!rr.sql.contains(&format!("bucket < {recent}")), "le corps ne lit PLUS jusqu'à recent_query (périmé) : {}", rr.sql);
    }

    /// VECTEUR 4 — PARITÉ +env_id (non couvert ailleurs). Filtre env appliqué au corps rollup ET aux
    /// partiels raw ; parité exacte par environnement.
    #[test]
    fn b2b_adverse_v4_env_filter_parity() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        let n = now();
        let cur = (n / 3600) * 3600;
        // deux environnements, sur définitif + volatile.
        for (env, base) in [("prod", 0i64), ("staging", 0)] {
            for off in [3 * 3600 + 60, 30] {
                let combos: &[(&str, i64)] = &[("web", 4), ("sshd", 3)];
                for (src, sev) in combos {
                    for i in 0..(2 + base) {
                        conn.execute(
                            "INSERT INTO event(ts,source,severity,host,env_id,fields,dedup) VALUES(?1,?2,?3,'h1',?4,'{}',?5)",
                            params![cur - off + 1, src, sev, env, format!("{env}-{src}-{sev}-{off}-{i}")],
                        )
                        .unwrap();
                    }
                }
            }
        }
        rollup_events(&conn);
        let soql = "search | stats count by source,severity";
        let from = cur - 4 * 3600;
        for env in ["prod", "staging"] {
            let rr = try_rollup_route_at(soql, from, n, Some(env), n, event_rollup_wm(&conn)).expect("DOIT router");
            let got = b2_map(&conn, &rr.sql);
            let want = b2_map(&conn, &soql_to_sql_x(soql, from, n, Some(env)).unwrap());
            assert_eq!(got, want, "PARITÉ env={env}\nmerge={got:?}\nraw={want:?}\nSQL={}", rr.sql);
            assert!(rr.sql.contains(&format!("env_id='{env}'")), "filtre env poussé dans le SQL : {}", rr.sql);
        }
    }

    /// VECTEUR 5 — DÉCLINE quand aucun corps définitif (`!has_body`) -> None -> scan raw (exact). Fenêtres
    /// sub-horaire pure et entièrement dans les ~2h volatiles.
    #[test]
    fn b2b_adverse_v5_declines_when_no_definitive_body() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let soql = "search | stats count by source,severity";
        let now_ts = 1_000_000_000_i64;
        let cur = (now_ts / 3600) * 3600;
        let recent = cur - 3600;
        // (a) sub-horaire dans l'heure courante. (wm=MAX : le déclin vient de l'absence de bucket définitif, pas du wm.)
        assert!(try_rollup_route_at(soql, cur + 100, cur + 200, None, now_ts, i64::MAX).is_none(), "sub-horaire courant -> décline");
        // (b) entièrement dans les 2h volatiles [recent, now].
        assert!(try_rollup_route_at(soql, recent + 5, now_ts, None, now_ts, i64::MAX).is_none(), "fenêtre volatile pure -> décline");
        // (c) fenêtre sub-horaire dans l'heure préc. (aucun bucket complet définitif).
        assert!(try_rollup_route_at(soql, recent + 100, recent + 200, None, now_ts, i64::MAX).is_none(), "sub-horaire volatile -> décline");
    }

    /// VECTEUR 6 (COLD) — parité pour une fenêtre COLD alignée-heure (dashboards) : EXACT & FRAIS
    /// (approx:false) ; et RÉSIDU BORNÉ pour une tête deep-past sub-horaire (<B, `event` purgé) -> repli
    /// sur le corps rollup, approx:true, mais divergence <= 1 bucket (pas large).
    #[cfg(feature = "cold_tier")]
    #[test]
    fn b2b_adverse_v6_cold_aligned_exact_and_bounded_residual() {
        let _g = B2_ENV_LOCK.lock();
        std::env::remove_var("PLUME_ROLLUP_MULTIDIM");
        let conn = test_db();
        // crée cold_rollup (miroir) + event_rollup.
        let _ = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cold_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
               severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
               host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
               env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(bucket,source,severity,action,src_ip,host,env_id));",
        );
        let now_ts = 1_000_000_000_i64;
        let cur = (now_ts / 3600) * 3600;
        let recent = cur - 3600;
        let boundary = cur - 6 * 3600; // frontière hot/cold B (event purgé sous B)
        // corps COLD (< B) : peuplons cold_rollup directement (buckets alignés définitifs).
        for (src, sev, nn) in [("web", 4i64, 3i64), ("sshd", 3, 2)] {
            conn.execute(
                "INSERT INTO cold_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) \
                 VALUES(?1,?2,?3,'','','',?4,?1,'prod')",
                params![boundary - 3600, src, sev, nn],
            )
            .unwrap();
        }
        // corps HOT (>= B, < recent) + volatile : via event + rollup.
        b2adv_seed_at(&conn, cur - 3 * 3600 + 60, 2, "hot_def");
        b2adv_seed_at(&conn, cur + 30, 2, "cur");
        rollup_events(&conn);
        let soql = "search | stats count by source,severity";
        // (a) fenêtre COLD alignée-heure (from aligné sous B, to aligné) -> approx:false attendu.
        let ra = try_cold_rollup_route_at(soql, boundary - 2 * 3600, recent, None, boundary, now_ts, event_rollup_wm(&conn)).expect("cold aligné DOIT router");
        assert!(!ra.approx, "COLD aligné-heure -> EXACT (approx:false) : note={:?}", ra.note);
        // (b) tête deep-past SUB-HORAIRE (<B) -> repli corps -> approx:true (résidu honnête BORNÉ).
        let rb = try_cold_rollup_route_at(soql, boundary - 2 * 3600 + 123, recent, None, boundary, now_ts, event_rollup_wm(&conn)).expect("cold sub-horaire DOIT router");
        assert!(rb.approx, "tête deep-past sub-horaire (<B, event purgé) -> approx:true (résidu borné)");
        assert!(rb.note.is_some(), "résidu approx -> note explicite (jamais silencieux)");
    }
