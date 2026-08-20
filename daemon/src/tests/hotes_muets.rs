    // ================================================================================================
    // P3.2-a — UN HÔTE QUI SE TAIT DOIT PRODUIRE UN SIGNAL, ET LA PORTÉE D'UNE SONDE DOIT SE LIRE.
    //
    // LE DÉFAUT, EN UNE PHRASE. Vingt sondes d'events et une sonde de métriques rendent `MAX(ts)` SANS
    // filtre d'hôte : elles déclarent la source vivante tant qu'UNE machine du parc parle encore. Les
    // dix-neuf autres peuvent être mortes depuis des heures sans qu'aucun signal ne se lève.
    //
    // CE QUE CES TESTS ÉTABLISSENT, DANS CET ORDRE :
    //   1. `hotes_muets_un_seul_hote_parle_et_les_21_sondes_restent_vertes` — LA MUTATION. Sur un parc
    //      de 20 machines dont 19 se taisent depuis 2 h, les 21 sondes à portée « tous hôtes confondus »
    //      rendent TOUTES un statut non-muet, y compris celles qui suivent `pipeline_is_fresh` (lui aussi
    //      un agrégat sans hôte). Les 2 sondes à portée par-hôte, elles, crient. La sonde de FLOTTE compte
    //      19 muets sur 20.
    //   2. `hotes_muets_temoin_inverse_un_parc_qui_parle_ne_leve_rien` — LE TÉMOIN NÉGATIF. Sans lui, une
    //      sonde qui alerte TOUJOURS passerait pour une réussite.
    //   3. `hotes_muets_alerte_nomme_les_machines_et_declare_sa_portee` — ce que l'exploitant LIT.
    //   4. `hotes_muets_cardinalite_bornee_quelle_que_soit_la_taille_du_parc` — LA BORNE, éprouvée en
    //      MULTIPLIANT le parc par 25 : une alerte, au plus `PLAFOND_NOMS` noms, le reste COMPTÉ.
    //   5. `hotes_muets_portee_par_hote_suivrait_le_volume` — LE COÛT DE L'AUTRE VOIE, mesuré par le
    //      compteur de SQLite (déterministe) sous mutation du volume x4 : la variante par hôte d'une sonde
    //      d'event suit le volume, l'actuelle et celle de flotte non. C'est la raison chiffrée pour
    //      laquelle la portée des 21 sondes n'est PAS repassée par hôte.
    //   6. `hotes_muets_une_machine_de_plus_ouvre_un_episode_neuf` — le résidu (machine décommissionnée,
    //      jamais prunée de `host_rollup`) n'AVALE pas la mort de la suivante.
    //   7. `hotes_muets_lecture_impossible_ne_resout_rien` — une surface qui n'a pas pu observer ne se
    //      tait pas comme si elle avait observé le vide.
    //   8. `hotes_muets_portee_declaree_et_lisible_dans_le_panneau` — la portée est RENDUE (21 confondues,
    //      2 par-hôte) au lieu d'être devinée en lisant le SQL dérivé.
    //   9. `hotes_muets_prefixe_de_dedup_ne_collisionne_avec_aucun_capteur` — la famille d'épisodes ne
    //      peut pas marcher sur les clés `hb-<id>` des 23 capteurs.
    // ================================================================================================

    /// Peuple l'inventaire de flotte PAR LE VRAI CHEMIN : des lignes `metric` portant un hôte, puis le
    /// plancher de rattrapage noté à l'ingest, puis le tick de rollup. Passer par `host_rollup` en écriture
    /// directe aurait testé la sonde contre une table que la production ne remplit pas comme ça.
    /// `metric` plutôt qu'`event` : ça n'anime QUE la sonde `resources`, donc les 20 sondes d'events
    /// restent au statut « inconnu » et ne polluent pas le décompte d'alertes.
    fn hm_parc_metrique(conn: &Connection, vivants: &[(&str, i64)]) {
        let mut plancher = i64::MAX;
        for (hote, ts) in vivants {
            conn.execute(
                "INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,'cpu','{}',1.0,?2)",
                params![ts, hote],
            )
            .unwrap();
            plancher = plancher.min(*ts);
        }
        note_host_backfill_floor(conn, plancher);
        rollup_hosts(conn);
    }

    /// Un parc de `n` machines dont UNE SEULE parle encore : `srv000` fraîche, les autres muettes depuis
    /// `retard` secondes. C'est la forme exacte du défaut poursuivi.
    fn hm_parc_une_seule_voix(conn: &Connection, now_ts: i64, n: usize, retard: i64) {
        let noms: Vec<String> = (0..n).map(|i| format!("srv{i:03}")).collect();
        let vivants: Vec<(&str, i64)> = noms
            .iter()
            .enumerate()
            .map(|(i, h)| (h.as_str(), if i == 0 { now_ts - 60 } else { now_ts - retard }))
            .collect();
        hm_parc_metrique(conn, &vivants);
    }

    fn hm_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1)
    }

    /// Le coût d'UN énoncé, compté par SQLite lui-même (`SQLITE_STMTSTATUS_VM_STEP`) — déterministe, donc
    /// opposable là où un chronomètre ne le serait pas. Même instrument que `sondes_cout.rs`.
    fn hm_vm(conn: &Connection, sql: &str, bind: Option<&str>) -> i64 {
        let mut s = conn.prepare(sql).expect("énoncé valide");
        let _ = match bind {
            Some(b) => s.query_row(params![b], |r| r.get::<_, Option<i64>>(0)),
            None => s.query_row([], |r| r.get::<_, Option<i64>>(0)),
        };
        s.get_status(rusqlite::StatementStatus::VmStep) as i64
    }

    // ---------------------------------------------------------------------------------------------
    // (1) LA MUTATION — un parc dont une seule machine parle encore
    // ---------------------------------------------------------------------------------------------

    /// LA PREUVE PAR MUTATION. Parc de 20 machines, 19 muettes depuis 2 h, 1 qui parle. Les 21 sondes à
    /// portée « tous hôtes confondus » restent NON-MUETTES — c'est le défaut, mesuré et non allégué. Les
    /// 2 sondes par-hôte crient. La sonde de flotte, elle, compte 19 muets sur 20 : le signal existe.
    ///
    /// CE QUE CE TEST RÉFUTE AU PASSAGE. Le bandeau de `sondes.rs` a longtemps affirmé que les sondes
    /// suivant `pipeline_is_fresh` « ne présentent pas ce risque ». `pipeline_is_fresh` est un `MAX(ts)`
    /// sur event∪metric∪snapshot SANS filtre d'hôte : la machine encore vivante le rend vrai, donc ces
    /// sondes-là masquent AUSSI. Le test l'exige explicitement, sur les DEUX familles.
    #[test]
    fn hotes_muets_un_seul_hote_parle_et_les_21_sondes_restent_vertes() {
        let conn = test_db();
        let now_ts = now();
        // Chaque source d'event a une donnée FRAÎCHE venant de la SEULE machine encore vivante, et une
        // donnée VIEILLE venant d'une machine morte. C'est le parc réel d'un SOC dont le parc s'est tu.
        for (_, _, _, sonde, _) in COLLECTORS.iter() {
            match sonde {
                Sonde::EventFlux { sources } => {
                    for s in sources.iter() {
                        conn.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,'x',1,'srv000','m')", params![now_ts - 30, s]).unwrap();
                        conn.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,'x',1,'srv001','m')", params![now_ts - 7200, s]).unwrap();
                    }
                }
                Sonde::EventBattementSante { source } => {
                    conn.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,'health',0,'srv000','beat')", params![now_ts - 30, source]).unwrap();
                    conn.execute("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,'health',0,'srv001','beat')", params![now_ts - 7200, source]).unwrap();
                }
                Sonde::Instantane { kind } => {
                    conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,'h','{}','srv000')", params![now_ts - 30, kind]).unwrap();
                    conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,'h','{}','srv001')", params![now_ts - 7200, kind]).unwrap();
                }
                Sonde::MetriqueFlotteConfondue => {}
            }
        }
        hm_parc_une_seule_voix(&conn, now_ts, 20, 7200);

        let pipe = pipeline_is_fresh(&conn, now_ts);
        assert!(pipe, "précondition : le pipeline GLOBAL est frais — une seule machine suffit à le rendre vrai");
        let (mut confondues, mut par_hote_muettes) = (0usize, 0usize);
        for (id, _, interval, sonde, event_based) in COLLECTORS.iter() {
            let st = statut_capteur(
                sonde.derniere_collecte(&conn),
                *interval,
                *event_based,
                pipe,
                CYCLES_TOLERES_ALERTE,
                now_ts,
            );
            match sonde.portee() {
                Portee::FlotteConfondue => {
                    confondues += 1;
                    assert_ne!(
                        st,
                        StatutCapteur::Muet,
                        "sonde `{id}` (portée « tous hôtes confondus ») : 19 machines sur 20 sont muettes \
                         depuis 2 h et son verdict reste non-muet. C'EST le défaut P3.2-a, mesuré."
                    );
                }
                Portee::ParHote => {
                    assert_eq!(st, StatutCapteur::Muet, "sonde `{id}` (portée par-hôte) doit voir la machine la plus en retard");
                    par_hote_muettes += 1;
                }
            }
        }
        assert_eq!((confondues, par_hote_muettes), (21, 2), "décompte des portées, DÉRIVÉ du tableau et non recopié");

        // LE SIGNAL QUI MANQUAIT : rendu comme un COMPTE, pas comme une série par hôte.
        let f = flotte_muette(&conn, now_ts).expect("l'inventaire est lisible");
        assert_eq!((f.muets, f.attendus), (19, 20), "19 machines sur 20 se sont tues, et la sonde de flotte le DIT");
        assert!(f.pires.len() <= PLAFOND_NOMS, "les noms rendus sont bornés : {}", f.pires.len());
    }

    // ---------------------------------------------------------------------------------------------
    // (2) LE TÉMOIN INVERSE — sans lui, une sonde qui alerte toujours passerait pour une réussite
    // ---------------------------------------------------------------------------------------------

    /// TÉMOIN NÉGATIF. Le MÊME parc de 20 machines, mais toutes parlent : ZÉRO muet, ZÉRO alerte de la
    /// famille. Le test (1) ne prouve quelque chose que parce que celui-ci existe.
    #[test]
    fn hotes_muets_temoin_inverse_un_parc_qui_parle_ne_leve_rien() {
        let conn = test_db();
        let now_ts = now();
        let noms: Vec<String> = (0..20).map(|i| format!("srv{i:03}")).collect();
        let vivants: Vec<(&str, i64)> = noms.iter().map(|h| (h.as_str(), now_ts - 60)).collect();
        hm_parc_metrique(&conn, &vivants);

        let f = flotte_muette(&conn, now_ts).expect("l'inventaire est lisible");
        assert_eq!((f.muets, f.attendus), (0, 20), "parc entièrement vivant : aucun muet");
        assert!(f.cle_dedup().is_none(), "aucun muet -> aucun épisode à ouvrir");

        let db = Arc::new(Mutex::new(conn));
        check_heartbeats(&db);
        let conn = db.lock();
        assert_eq!(
            hm_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets'"),
            0,
            "TÉMOIN INVERSE : sur un parc qui parle, la sonde de flotte ne lève RIEN"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (3) CE QUE L'EXPLOITANT LIT
    // ---------------------------------------------------------------------------------------------

    /// L'ALERTE SE LÈVE, NOMME LES MACHINES, PORTE SON DÉNOMINATEUR ET DÉCLARE SA PORTÉE. « des hôtes
    /// sont muets » sans dire lesquels ni combien sur combien n'est pas actionnable.
    #[test]
    fn hotes_muets_alerte_nomme_les_machines_et_declare_sa_portee() {
        let conn = test_db();
        let now_ts = now();
        hm_parc_une_seule_voix(&conn, now_ts, 20, 7200);
        let db = Arc::new(Mutex::new(conn));

        check_heartbeats(&db);

        let conn = db.lock();
        assert_eq!(
            hm_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets'"),
            1,
            "19 machines muettes -> UNE alerte (avant : aucune, le silence du parc était invisible)"
        );
        let (titre, detail): (String, String) = conn
            .query_row(
                "SELECT title, detail FROM alert WHERE rule='heartbeat.flotte-hotes-muets'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(titre, "Hôtes muets : 19 sur 20", "le titre porte le COMPTE et son dénominateur (et aucun nom de machine : il remonte dans le bulletin de support)");
        assert!(detail.contains("portée : par-hôte"), "le détail DÉCLARE sa portée : {detail}");
        assert!(detail.contains("srv001"), "au moins une machine muette est NOMMÉE : {detail}");
        assert!(!detail.contains("srv000"), "la machine encore vivante n'est PAS accusée : {detail}");
        assert!(detail.contains("et 14 autre(s)"), "le reste est COMPTÉ, jamais tu : {detail}");
        // L'imputation : un INCONNU NOMMÉ, jamais une source prise au hasard (cette alerte parle d'hôtes).
        let sources: String = conn
            .query_row("SELECT sources FROM alert WHERE rule='heartbeat.flotte-hotes-muets'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sources, SOURCE_INDETERMINABLE, "une alerte d'HÔTES ne s'impute à aucun feed — et le dit");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) LA BORNE — le piège du chantier : la cardinalité
    // ---------------------------------------------------------------------------------------------

    /// LA CARDINALITÉ NE SUIT PAS LE PARC. Le parc est MULTIPLIÉ PAR 25 (20 -> 500 machines) : le nombre
    /// d'alertes, de noms rendus et de séries reste le MÊME. C'est l'invariant qui distingue « rendre un
    /// COMPTE » de « rendre une série par hôte » — cette dernière aurait produit 500 séries ici, et
    /// 21 x 500 = 10 500 si les 21 sondes confondues avaient été repassées par hôte.
    #[test]
    fn hotes_muets_cardinalite_bornee_quelle_que_soit_la_taille_du_parc() {
        let mesure = |n: usize| -> (usize, usize, i64, i64) {
            let conn = test_db();
            let now_ts = now();
            hm_parc_une_seule_voix(&conn, now_ts, n, 7200);
            let f = flotte_muette(&conn, now_ts).expect("inventaire lisible");
            let (muets, noms) = (f.muets, f.pires.len());
            // Ce que la sonde de flotte COÛTE, sur le même instrument déterministe que P3.7-a. Elle
            // tourne sous le VERROU D'ÉCRITURE : sa borne doit être dite, pas supposée.
            let cout = hm_vm(
                &conn,
                "SELECT COUNT(*) FROM (SELECT host, MAX(last_ts) FROM host_rollup WHERE host<>'' GROUP BY host ORDER BY host)",
                None,
            );
            let db = Arc::new(Mutex::new(conn));
            check_heartbeats(&db);
            let conn = db.lock();
            let alertes = hm_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets'");
            (muets, noms, alertes, cout)
        };
        let (m20, n20, a20, c20) = mesure(20);
        let (m500, n500, a500, c500) = mesure(500);
        assert_eq!((m20, m500), (19, 499), "le COMPTE, lui, suit le parc — c'est bien la mesure attendue");
        assert_eq!(
            (n20, n500),
            (PLAFOND_NOMS, PLAFOND_NOMS),
            "les NOMS rendus sont plafonnés : x25 sur le parc, 0 nom de plus"
        );
        assert_eq!((a20, a500), (1, 1), "PIRE CAS : une alerte, quel que soit le nombre de machines muettes");
        // CE QUE LA SONDE COÛTE, ET DE QUOI CE COÛT DÉPEND. MESURÉ le 2026-08-20 sur ce protocole :
        // 587 pas de machine virtuelle pour 20 machines, 14 027 pour 500 — soit une pente EXACTE de
        // 28 pas par machine et une constante de 27. Linéaire en la FLOTTE, et rien d'autre : le volume
        // d'events n'y entre pas (c'est ce que prouve `hotes_muets_portee_par_hote_suivrait_le_volume`,
        // où la même sonde ne bouge pas d'un pas sous un volume x4). PIRE CAS DIT : pour mille machines,
        // ~28 000 pas toutes les 20 s sous le verrou d'écriture — contre 16 pas pour une sonde d'event.
        // C'est le prix, borné et connu, du seul signal qui voie une machine se taire.
        // L'encadrement est à DEUX bornes : le plafond dit « pas plus que linéaire », le plancher dit
        // « la mesure bouge vraiment » — sans lui, un instrument bloqué passerait pour une réussite.
        assert!(
            c500 <= c20 * 30 && c500 >= c20 * 20,
            "COÛT DE LA SONDE DE FLOTTE : parc x25 -> coût x{:.2} ({c20} -> {c500} pas). Attendu : \
             LINÉAIRE en la flotte (donc x25 à la constante près), jamais quadratique, jamais figé.",
            c500 as f64 / c20.max(1) as f64
        );
    }

    /// CE QUE COÛTERAIT L'AUTRE VOIE, MESURÉ ET NON SUPPOSÉ. La variante PAR HÔTE d'une sonde d'event
    /// (`MIN` sur les `MAX(ts) GROUP BY host`) n'est servie par AUCUN index de `event` — aucun ne porte
    /// `host`. Son coût suit donc le VOLUME, c'est-à-dire le défaut fermé en P3.7-a, qu'il faudrait
    /// rouvrir vingt fois, sous le verrou d'écriture, toutes les 20 s. La sonde ACTUELLE et celle de
    /// FLOTTE, elles, ne bougent pas. Mutation : volume x4, compteur déterministe de SQLite.
    ///
    /// MESURÉ le 2026-08-20 sur ce protocole (base au schéma de `db/schema.sql` + chaîne de migrations,
    /// 20 machines, `ANALYZE` fait), en pas de machine virtuelle SQLite :
    ///   - sonde ACTUELLE (tous hôtes confondus)  : 16 -> 16          (x1,00 — saut en fin de plage d'index)
    ///   - variante PAR HÔTE de la MÊME sonde     : 26 366 -> 104 366 (x3,96 — le volume, exactement)
    ///   - sonde de FLOTTE (`host_rollup`)        : 587 -> 587        (x1,00 — bornée par la flotte)
    /// Le facteur 3,96 pour un volume x4 EST la définition d'un coût O(N) ; il est aussi le contrôle
    /// positif de l'instrument, que les deux témoins constants complètent par le contrôle négatif.
    #[test]
    fn hotes_muets_portee_par_hote_suivrait_le_volume() {
        const PAR_HOTE: &str =
            "SELECT MIN(l) FROM (SELECT host, MAX(ts) AS l FROM event WHERE source=?1 GROUP BY host)";
        let mesure = |n: i64| -> (i64, i64, i64) {
            let conn = test_db();
            let now_ts = now();
            let mut st = conn
                .prepare("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'ufw','firewall',1,?2,'m')")
                .unwrap();
            for i in 0..n {
                st.execute(params![now_ts - n + i, format!("srv{:03}", i % 20)]).unwrap();
            }
            drop(st);
            hm_parc_une_seule_voix(&conn, now_ts, 20, 7200);
            conn.execute_batch("ANALYZE").unwrap();
            let actuelle = Sonde::EventFlux { sources: &["ufw"] }.requete();
            (
                hm_vm(&conn, actuelle.sql(), Some("ufw")),
                hm_vm(&conn, PAR_HOTE, Some("ufw")),
                hm_vm(
                    &conn,
                    "SELECT COUNT(*) FROM (SELECT host, MAX(last_ts) FROM host_rollup WHERE host<>'' GROUP BY host ORDER BY host)",
                    None,
                ),
            )
        };
        let (act1, hote1, flotte1) = mesure(2_000);
        let (act4, hote4, flotte4) = mesure(8_000);

        assert!(
            hote4 >= hote1 * 7 / 2,
            "PORTÉE PAR HÔTE : volume x4 -> coût x{:.2} ({hote1} -> {hote4} pas de machine virtuelle). \
             Un `GROUP BY host` sur `event` n'a aucun index : le coût SUIT le volume. Multiplié par les \
             20 sondes d'events, sous le verrou d'écriture, toutes les 20 s — c'est P3.7-a rouvert.",
            hote4 as f64 / hote1.max(1) as f64
        );
        assert_eq!(act1, act4, "TÉMOIN : la sonde ACTUELLE (tous hôtes confondus) ne bouge pas sous x4 volume");
        assert_eq!(
            flotte1, flotte4,
            "TÉMOIN : la sonde de FLOTTE est bornée par la CARDINALITÉ DE LA FLOTTE (inchangée ici), \
             pas par le volume d'events — c'est ce qui rend la voie retenue tenable sous 2 Gio"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (5) LE RÉSIDU, ET CE QUI L'EMPÊCHE DE MASQUER LA SUITE
    // ---------------------------------------------------------------------------------------------

    /// UNE MACHINE DÉCOMMISSIONNÉE NE DOIT PAS AVALER LA MORT DE LA SUIVANTE. `host_rollup` n'est jamais
    /// prunée : la première machine muette le reste pour toujours. Si l'épisode était keyé sur la FAMILLE,
    /// l'alerte resterait ouverte et la mort de la deuxième machine ne réveillerait plus personne. Il est
    /// keyé sur l'EMPREINTE DE L'ENSEMBLE : l'ensemble change -> épisode neuf, l'ancien résolu.
    #[test]
    fn hotes_muets_une_machine_de_plus_ouvre_un_episode_neuf() {
        let conn = test_db();
        let now_ts = now();
        hm_parc_metrique(&conn, &[("srv000", now_ts - 60), ("srv001", now_ts - 60), ("srv002", now_ts - 7200)]);
        let db = Arc::new(Mutex::new(conn));
        check_heartbeats(&db);
        let premiere: String = db
            .lock()
            .query_row("SELECT dedup FROM alert WHERE rule='heartbeat.flotte-hotes-muets'", [], |r| r.get(0))
            .expect("un premier épisode est ouvert");

        // Une DEUXIÈME machine se tait ; la première reste muette (décommissionnée).
        {
            let conn = db.lock();
            conn.execute(
                "UPDATE host_rollup SET last_ts=?1 WHERE host='srv001'",
                params![now_ts - 7200],
            )
            .unwrap();
        }
        check_heartbeats(&db);

        let conn = db.lock();
        assert_eq!(
            hm_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets' AND status IN ('new','ack')"),
            1,
            "UN SEUL épisode ouvert à la fois — l'ancien est résolu quand l'ensemble change"
        );
        let ouverte: String = conn
            .query_row(
                "SELECT dedup FROM alert WHERE rule='heartbeat.flotte-hotes-muets' AND status IN ('new','ack')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(ouverte, premiere, "ENSEMBLE CHANGÉ -> ÉPISODE NEUF : la 2ᵉ machine morte réveille bien quelqu'un");
        assert_eq!(
            hm_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets'"),
            2,
            "l'épisode précédent est CONSERVÉ (résolu), pas effacé : l'historique reste lisible"
        );
    }

    /// UNE SURFACE QUI N'A PAS PU OBSERVER NE SE TAIT PAS COMME SI ELLE AVAIT OBSERVÉ LE VIDE. Inventaire
    /// illisible -> `None` -> aucune alerte levée ET aucune alerte résolue. Le contraire (résoudre) serait
    /// affirmer un parc sain qu'on n'a pas regardé — exactement la famille de défauts poursuivie ici.
    #[test]
    fn hotes_muets_lecture_impossible_ne_resout_rien() {
        let conn = test_db();
        let now_ts = now();
        hm_parc_une_seule_voix(&conn, now_ts, 20, 7200);
        let db = Arc::new(Mutex::new(conn));
        check_heartbeats(&db);
        assert_eq!(
            hm_compte(&db.lock(), "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets' AND status='new'"),
            1,
            "précondition : un épisode est ouvert"
        );

        {
            let conn = db.lock();
            conn.execute_batch("DROP TABLE host_rollup").unwrap();
            assert!(flotte_muette(&conn, now_ts).is_none(), "inventaire absent -> AUCUN verdict rendu");
        }
        check_heartbeats(&db);

        assert_eq!(
            hm_compte(&db.lock(), "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.flotte-hotes-muets' AND status='new'"),
            1,
            "lecture impossible -> l'épisode ouvert RESTE ouvert (le résoudre serait un « tout va bien » fabriqué)"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (6) LA PORTÉE EST DÉCLARÉE, ET LISIBLE
    // ---------------------------------------------------------------------------------------------

    /// LA PORTÉE EST RENDUE PAR LE PANNEAU, pas devinée en lisant le SQL dérivé. Éprouvé sur le vrai
    /// calcul (`compute_integrations`), pas sur le type seul : c'est la chaîne complète — type -> JSON —
    /// qui doit tenir, sinon un exploitant lit toujours un statut sans savoir ce qu'il couvre.
    #[test]
    fn hotes_muets_portee_declaree_et_lisible_dans_le_panneau() {
        let _tmpg = crate::tmp_possede::TmpPossede::neuf("hotesmuets");
        let p = _tmpg.sous("plume.db").chemin().to_string_lossy().to_string();
        let now_ts = now();
        {
            let w = open_db(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "fixture : la chaîne de migrations va au bout");
            hm_parc_une_seule_voix(&w, now_ts, 20, 7200);
        }
        let v = compute_integrations(&p);
        let cs = v["collectors"].as_array().expect("le panneau rend les capteurs");
        assert_eq!(cs.len(), COLLECTORS.len(), "tous les capteurs sont rendus");
        let confondues = cs.iter().filter(|c| c["portee"] == "tous hôtes confondus").count();
        let par_hote = cs.iter().filter(|c| c["portee"] == "par-hôte").count();
        assert_eq!(
            (confondues, par_hote),
            (21, 2),
            "CHAQUE capteur déclare sa portée : 21 « tous hôtes confondus » (la dette) et 2 par-hôte"
        );
        assert_eq!(v["flotte"]["muets"], 19, "le panneau porte le COMPTE d'hôtes muets — ce qu'aucune des 21 sondes ne peut dire");
        assert_eq!(v["flotte"]["attendus"], 20, "et son dénominateur");
        assert_eq!(v["flotte"]["seuil_s"], FLEET_STALE_S, "et le seuil, qui est celui du panneau Flotte — un seul auteur");
        let _ = std::fs::remove_file(&p);
    }

    /// GARDE — la famille d'épisodes de flotte ne peut pas marcher sur la clé `hb-<id>` d'un capteur.
    /// Un identifiant de capteur nommé `flotte-muets-…` ferait collision et un capteur redevenu actif
    /// résoudrait l'alerte de parc (ou l'inverse). Dérivé de `COLLECTORS`, jamais d'une liste tenue à part.
    #[test]
    fn hotes_muets_prefixe_de_dedup_ne_collisionne_avec_aucun_capteur() {
        for (id, _, _, _, _) in COLLECTORS.iter() {
            let cle = format!("hb-{id}");
            assert!(
                !cle.starts_with(DEDUP_FLOTTE_MUETTE),
                "le capteur `{id}` fabrique la clé `{cle}`, qui tombe dans la famille `{DEDUP_FLOTTE_MUETTE}*` \
                 de la sonde de flotte : les deux se résoudraient l'une l'autre"
            );
        }
    }
