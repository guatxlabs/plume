    // ================================================================================================
    // `P10.5-i` — UN PANNEAU DIT JUSQU'OÙ IL A PU VOIR, ET LE NOMBRE NE BOUGE PAS.
    //
    // CE QUI ÉTAIT CASSÉ. Un panneau de tableau de bord ne consulte jamais la bande froide : sa requête
    // est calculée sur la seule fenêtre que la rétention a laissée, puis rendue comme une courbe
    // ENTIÈRE. Le cas fondateur est écrit dans `rollups.rs` : « une console qui trace une courbe sur une
    // fenêtre plus ancienne rend aujourd'hui une courbe VIDE au lieu de dire que l'horizon s'arrête là ».
    //
    // CE QUI EST TENU ICI, ET CE QUI NE L'EST PAS. La voie engagée est (a) : DIRE, sans changer le
    // nombre. Ces témoins prouvent donc DEUX choses de nature opposée — que l'aveu paraît là où il doit
    // paraître, et qu'il ne paraît PAS là où il n'aurait rien à dire (l'anti-fatigue) — plus une
    // troisième, qui est la contrainte principale : que `columns` et `rows` sont IDENTIQUES À L'OCTET
    // avant et après. Ce qu'ils ne prouvent pas : que le nombre devienne juste. Il reste faux ; il le
    // dit. Les voies (b) et (c) restent ouvertes.
    //
    // POURQUOI L'AVEU DE PROVENANCE A TROIS ÉTATS, ET POURQUOI UN TÉMOIN LE GARDE. Le geste naïf —
    // estamper `served_from:"raw", approx:false` sur tous les chemins — AJOUTERAIT un mensonge sur onze
    // panneaux LIVRÉS dont le SQL lit `event_dim_rollup`, pré-agrégé plafonné en top-N (écart mesuré
    // jusqu'à x16,4). Le témoin `un_panneau_opaque_...` tient cette borne, et sa MUTATION rejoue
    // exactement le geste naïf pour montrer ce qu'il aurait publié.
    // ================================================================================================

    /// Sous ce nombre de panneaux SEMÉS réellement éprouvés, la dérivation est cassée et le témoin
    /// d'identité du nombre rendrait vert en ne mesurant presque rien. MESURÉ le 2026-08-28 sur une base
    /// fraîchement semée : bien au-delà (les familles de `seed_tenant_content`).
    const PA_PLANCHER_FAMILLES: usize = 7;

    /// Sous ce nombre de routes DÉRIVÉES de la table de routage, la garde de service ne prouve plus rien.
    /// MESURÉ le 2026-08-28 : 4 routes sous les deux préfixes, dont DEUX en `get` — les deux seules qu'une
    /// sonde `GET` puisse interroger, et les deux seules qui SERVENT une réponse de panneau
    /// (`/api/panels/{id}/data` et `/api/dashboard-snapshots/{token}`). Le plancher porte sur celles-là.
    const PA_PLANCHER_ROUTES: usize = 2;

    /// Une base NEUVE, semée exactement comme une installation fraîche — `seed_tenant_content` est le
    /// point unique que le démarrage du serveur et la création d'un tenant partagent. La POPULATION des
    /// panneaux éprouvés en est DÉRIVÉE : un panneau semé demain entre sans que personne l'inscrive.
    fn pa_base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("pa-{tag}"));
        let conn = open_db(path.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        crate::tenants::seed_tenant_content(&conn);
        (path, conn)
    }

    /// Une conf VIDE : la résolution retombe alors sur `setting` (que les témoins écrivent) puis sur les
    /// défauts du produit. Aucun test ici ne MUTE l'environnement du processus.
    fn pa_conf() -> HashMap<String, String> {
        HashMap::new()
    }

    /// Les couples (requête, is_soql) des panneaux SEMÉS, dédupliqués — la population des familles.
    fn pa_familles_semees(conn: &Connection) -> Vec<(String, bool)> {
        let mut stmt = conn.prepare("SELECT DISTINCT query, is_soql FROM panel ORDER BY query").unwrap();
        let v: Vec<(String, bool)> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))
            .unwrap()
            .flatten()
            .collect();
        assert!(
            v.len() >= PA_PLANCHER_FAMILLES,
            "INSTRUMENT MUET : {} famille(s) de panneaux semés lues, plancher {PA_PLANCHER_FAMILLES} — la \
             dérivation est cassée et le témoin d'identité mesurerait le vide.",
            v.len()
        );
        v
    }

    /// La requête du panneau de COURBE MÉTRIQUE semé — LA FAMILLE LA PLUS AMPUTÉE, et celle du constat
    /// fondateur. DÉRIVÉE (le seul panneau semé dont la requête nomme la table des métriques), jamais
    /// recopiée : reformuler le semis change le témoin du même geste.
    fn pa_requete_metrique(conn: &Connection) -> String {
        let mut v: Vec<String> = pa_familles_semees(conn)
            .into_iter()
            .filter(|(q, is_soql)| !*is_soql && q.contains("FROM metric"))
            .map(|(q, _)| q)
            .collect();
        v.sort();
        assert!(!v.is_empty(), "aucun panneau semé ne lit la table des métriques : le témoin le plus amputé n'existe plus");
        v.remove(0)
    }

    /// Le SQL COMPILÉ d'un panneau, lu par la porte de test du coffre (la production, elle, n'a aucun
    /// moyen de sortir ce texte).
    fn pa_sql(query: &str, is_soql: bool, from: i64, to: i64) -> String {
        panneau_avoue::compile_panneau_avoue(query, is_soql, from, to, None)
            .expect("le panneau semé compile")
            .sql_de_test()
            .to_string()
    }

    /// Pose une valeur de rétention par la table `setting` — la voie qui GAGNE sur l'env et la conf, donc
    /// la seule qui contrôle réellement la valeur sans muter l'environnement du processus.
    fn pa_poser_retention(conn: &Connection, cle: &str, jours: i64) {
        conn.execute(
            "INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)",
            params![cle, jours.to_string()],
        )
        .unwrap();
    }

    // ------------------------------------------------------------------------------------------------
    // (1) L'HORIZON : LE TÉMOIN POSITIF SUR LA FAMILLE LA PLUS AMPUTÉE, ET LES TROIS NÉGATIFS.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn l_horizon_dit_ce_qu_une_fenetre_n_a_pas_pu_voir_et_se_tait_quand_rien_ne_manque() {
        let (path, conn) = pa_base("horizon");
        let conf = pa_conf();
        let q = pa_requete_metrique(&conn);
        let now_s: i64 = 1_800_000_000; // horloge INJECTÉE : aucun témoin ici ne dépend de l'heure murale
        // LA CLÉ QUI COUPE `metric` EST `metric_raw_hours`, ET ELLE EST EN HEURES. C'est l'ordre de
        // suppression lui-même qui le dit (`DELETE FROM metric WHERE ts < now - metric_raw_hours*3600`,
        // `rollups.rs`) ; `metric_days`, lui, coupe le PRÉ-AGRÉGÉ `metric_rollup`. Écrire ici
        // `metric_days` — ce que faisait la première rédaction — validait la constante FAUSSE contre
        // elle-même : au défaut, l'aveu annonçait 90 jours de portée sur une table qui en garde DEUX,
        // c'est-à-dire un CERTIFICAT DE COMPLÉTUDE FAUX sur la famille du constat fondateur.
        pa_poser_retention(&conn, "metric_raw_hours", 720);
        pa_poser_retention(&conn, "alert_days", 90);
        drop(conn); // writer relâché -> le pool de LECTURE voit le WAL
        let sql = pa_sql(&q, false, 0, 0);
        let attendu = now_s - 720 * 3_600;

        // --- POSITIF : fenêtre BORNÉE et plus ancienne que l'horizon des métriques. ---
        let from_vieux = attendu - 30 * 86_400;
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, from_vieux, now_s);
        assert_eq!(cov["older_outside_window"], json!(true), "fenêtre sous l'horizon : l'aveu doit le dire — {cov}");
        assert_eq!(cov["horizon_ts"], json!(attendu), "l'horizon d'un panneau qui lit `metric` est `now - metric_raw_hours*3600` — {cov}");
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_RETENTION), "{cov}");
        assert_eq!(cov["searched_from"], json!(from_vieux), "la fenêtre RÉELLEMENT demandée est publiée — {cov}");
        assert_eq!(cov["calcule_a"], json!(now_s), "l'instant du calcul est publié — {cov}");

        // --- NÉGATIF nº1 : fenêtre bornée À L'INTÉRIEUR de l'horizon. L'aveu reste PRÉSENT. ---
        // Un aveu CONDITIONNEL serait indiscernable d'un aveu oublié — c'est le triple angle mort que
        // `search_cold_coverage` porte encore (elle rend `None` dans trois cas distincts).
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, attendu + 10 * 86_400, now_s);
        assert_eq!(cov["older_outside_window"], json!(false), "rien n'est resté dehors — {cov}");
        assert!(cov.get("horizon_ts").is_some(), "l'aveu est INCONDITIONNEL, même quand il n'annonce rien — {cov}");

        // --- NÉGATIF nº2, L'ANTI-FATIGUE : la fenêtre « Tout » (from=0). ---
        // Sans lui, douze panneaux sur douze porteraient le badge sur une base de trois jours où rien n'a
        // jamais été purgé, et le panneau réellement amputé serait celui qu'on ne verrait plus.
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, 0, now_s);
        assert_eq!(cov["older_outside_window"], json!(false), "« Tout » ne laisse rien dehors — {cov}");
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_FENETRE_NON_BORNEE), "{cov}");
        assert_eq!(cov["horizon_ts"], json!(attendu), "l'horizon EXISTE et il est publié même non borné — {cov}");

        // --- LA MARGE EST CELLE DU DÉPÔT, PAS UNE TOLÉRANCE INVENTÉE : `CACHE_BUCKET_S`, la granularité
        //     à laquelle le cache tient DÉJÀ deux fenêtres pour identiques. Trois fenêtres au ras de
        //     l'horizon ne déclenchent rien. ---
        for delta in [-1, 0, 1] {
            let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, attendu + delta, now_s);
            assert_eq!(
                cov["older_outside_window"],
                json!(false),
                "une fenêtre à {delta} s de l'horizon n'a rien laissé dehors (marge = CACHE_BUCKET_S) — {cov}"
            );
        }
        // … et la marge n'avale pas tout : un cran AU-DELÀ d'elle déclenche.
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, attendu - CACHE_BUCKET_S - 1, now_s);
        assert_eq!(cov["older_outside_window"], json!(true), "au-delà de la marge, l'aveu revient — {cov}");

        // --- NÉGATIF SUR L'INSTRUMENT : sans le tier froid, l'horizon est celui de la SEULE rétention.
        //     Le chemin froid est DOUBLEMENT gaté (compilation + exécution) : il est absent de la plupart
        //     des binaires, et une installation par défaut est déjà amputée par la rétention seule. ---
        #[cfg(feature = "cold_tier")]
        assert!(
            !crate::cold_store::cold_tier_runtime_on(&conf),
            "INSTRUMENT : ce témoin décrit le cas tier froid ÉTEINT ; il l'est sur cette conf"
        );
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, from_vieux, now_s);
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_RETENTION), "froid éteint -> l'horizon est la rétention — {cov}");

        // --- CAS RÉEL DE REFUS : les panneaux `banned_ip` ne relèvent d'AUCUNE clé de rétention. On ne
        //     fabrique pas un horizon : on dit qu'on ne sait pas. ---
        let sql_ban = pa_sql("SELECT source FROM banned_ip WHERE last_seen >= __FROM__", false, from_vieux, 0);
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql_ban, from_vieux, now_s);
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_PORTEE_NON_DERIVABLE), "{cov}");
        assert!(cov.get("horizon_ts").is_none(), "un horizon non dérivable n'est pas un horizon inventé — {cov}");
        assert!(
            cov.get("older_outside_window").is_none(),
            "sans horizon, aucun verdict sur ce qui est resté dehors — {cov}"
        );

        // --- UN NOM DE TABLE DANS UN LITTÉRAL N'EST PAS UNE LECTURE DE CETTE TABLE, ET LE CROIRE
        //     PRODUISAIT UN AVEU FAUX — pas un horizon « trop prudent ». Le SQL ci-dessous ne lit QUE
        //     `alert` (90 j) ; le mot `event` y est une valeur cherchée. Sans le retrait des littéraux,
        //     la famille `event` entrait, son horizon (30 j au défaut) étant le PLUS COURT il l'emportait,
        //     et une réponse COMPLÈTE sortait avec `older_outside_window: true` + « portée incomplète ».
        //     C'est exactement l'usure que le témoin anti-fatigue ci-dessus existe pour empêcher. ---
        let sql_litteral =
            pa_sql("SELECT ts AS bucket, count(*) FROM alert WHERE ts>=__FROM__ AND rule LIKE '%event%' GROUP BY 1", false, 0, 0);
        let from_60j = now_s - 60 * 86_400;
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql_litteral, from_60j, now_s);
        assert_eq!(
            cov["horizon_ts"],
            json!(now_s - 90 * 86_400),
            "l'horizon doit être celui d'`alert` (90 j) : le `event` du littéral n'est pas une table lue — {cov}"
        );
        assert_eq!(cov["older_outside_window"], json!(false), "60 j tiennent au-dessus de 90 j : rien n'est resté dehors — {cov}");
        // … ET L'INSTRUMENT EST VALIDÉ DANS L'AUTRE SENS : le MÊME mot, en position de TABLE, entre bien.
        let sql_vraie_table = pa_sql("SELECT ts FROM alert JOIN event ON 1=1 WHERE ts>=__FROM__", false, 0, 0);
        let cov = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql_vraie_table, from_60j, now_s);
        assert_eq!(
            cov["older_outside_window"],
            json!(true),
            "une VRAIE lecture d'`event` (30 j) ampute une fenêtre de 60 j : si ce témoin ne rougit pas, le \
             retrait des littéraux a emporté la dérivation entière — {cov}"
        );
    }

    /// LA TABLE DES FAMILLES NE PEUT PAS NOMMER UNE CLÉ QUI N'EXISTE PAS, NI SE TROMPER D'UNITÉ.
    ///
    /// DEUX DÉFAUTS FERMÉS EN AMONT, PAS RATTRAPÉS EN AVAL. (1) `retention_effective` rend **0** pour une
    /// clé inconnue de `RETENTION_FIELDS` : la boucle de l'horizon ferait alors `continue`, `haut`
    /// resterait `None`, et la réponse publierait `horizon_non_mesure` avec la notice « le pool de lecture
    /// n'a pas pu être pris » — une CAUSE FAUSSE, indiscernable du vrai défaut de pool. (2) La valeur
    /// rendue est un NOMBRE NU : 48 pour `metric_raw_hours` comme 90 pour `metric_days`. Multiplier par
    /// 86 400 une valeur en HEURES est exactement l'erreur qui annonçait 90 jours de portée sur une table
    /// qui en garde deux. La population est DÉRIVÉE des deux tables, jamais recopiée.
    #[test]
    fn chaque_famille_de_retention_nomme_une_cle_reelle_avec_sa_vraie_unite() {
        let connues: Vec<&str> = crate::RETENTION_FIELDS.iter().map(|(k, _, _, _, _)| *k).collect();
        assert!(connues.len() >= 5, "INSTRUMENT MUET : {} clé(s) de rétention lues", connues.len());
        assert!(
            panneau_avoue::FAMILLES_DE_RETENTION.len() >= 6,
            "INSTRUMENT MUET : {} famille(s) déclarées",
            panneau_avoue::FAMILLES_DE_RETENTION.len()
        );
        for (table, cle, unite) in panneau_avoue::FAMILLES_DE_RETENTION {
            assert!(
                connues.contains(cle),
                "la famille `{table}` nomme la clé `{cle}`, que `RETENTION_FIELDS` ne connaît pas : \
                 `retention_effective` rendrait 0 et la réponse publierait `horizon_non_mesure` avec la \
                 notice du POOL — une cause fausse. Clés réelles : {connues:?}"
            );
            // L'UNITÉ EST DÉRIVÉE DU SUFFIXE DE LA CLÉ, qui est la convention de `RETENTION_FIELDS` —
            // pas d'une liste écrite ici : une clé en heures ajoutée demain est jugée le jour même.
            let attendue = if cle.ends_with("_hours") { 3_600 } else { 86_400 };
            assert_eq!(
                *unite, attendue,
                "la famille `{table}` déclare l'unité {unite} s pour la clé `{cle}` : son suffixe dit \
                 {attendue} s. Une heure comptée pour un jour multiplie l'horizon annoncé par 24."
            );
        }
    }

    #[test]
    fn la_valeur_de_l_horizon_suit_son_levier_et_une_mesure_impossible_se_dit() {
        let (path, conn) = pa_base("levier");
        let conf = pa_conf();
        let q = pa_requete_metrique(&conn);
        let sql = pa_sql(&q, false, 0, 0);
        let now_s: i64 = 1_800_000_000;
        let from = now_s - 200 * 86_400;

        // --- MUTATION SUR LA VALEUR : sans elle, un horizon CODÉ EN DUR passerait tous les témoins
        //     précédents. On nomme LA valeur qui change — et c'est le levier qui coupe RÉELLEMENT la
        //     table des métriques (`metric_raw_hours`, en HEURES), pas celui qui coupe son pré-agrégé. ---
        pa_poser_retention(&conn, "metric_raw_hours", 720);
        drop(conn);
        let a = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, from, now_s);
        {
            let c = open_db(path.as_str()).unwrap();
            pa_poser_retention(&c, "metric_raw_hours", 24);
        }
        let b = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, from, now_s);
        assert_eq!(
            b["horizon_ts"].as_i64().unwrap() - a["horizon_ts"].as_i64().unwrap(),
            (720 - 24) * 3_600,
            "l'horizon doit bouger d'EXACTEMENT (720−24) HEURES : {a} -> {b}"
        );
        // … ET LE LEVIER VOISIN NE DOIT RIEN Y FAIRE : `metric_days` coupe `metric_rollup`, pas `metric`.
        // Sans cette moitié, une table de familles qui nommerait la mauvaise clé passerait la mutation
        // ci-dessus (elle bougerait aussi, mais pour la mauvaise raison).
        {
            let c = open_db(path.as_str()).unwrap();
            pa_poser_retention(&c, "metric_days", 3650);
        }
        let d = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql, from, now_s);
        assert_eq!(
            d["horizon_ts"], b["horizon_ts"],
            "`metric_days` a déplacé l'horizon d'un panneau qui lit `metric` : c'est la clé du PRÉ-AGRÉGÉ — {b} -> {d}"
        );
        // … et le pré-agrégé, lui, la SUIT.
        let sql_rollup = pa_sql("SELECT ts, avg FROM metric_rollup WHERE ts>=__FROM__", false, 0, 0);
        let r = panneau_avoue::horizon_du_sql(path.as_str(), &conf, &sql_rollup, from, now_s);
        assert_eq!(
            r["horizon_ts"],
            json!(now_s - 3650 * 86_400),
            "un panneau qui lit `metric_rollup` a un horizon DÉRIVABLE (`metric_days`) — le refuser était un \
             refus là où une mesure existe : {r}"
        );

        // --- MUTATION JUMELLE, SUR LE DÉFAUT : le pool de lecture indisponible. Un plancher calculé HORS
        //     BASE serait indiscernable d'un plancher mesuré ; l'aveu doit donc être SANS horizon. ---
        let cov = panneau_avoue::horizon_du_sql("/introuvable/aucune-base-ici.db", &conf, &sql, from, now_s);
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_HORIZON_NON_MESURE), "{cov}");
        assert!(cov.get("horizon_ts").is_none(), "un horizon NON MESURÉ n'est pas un horizon par défaut — {cov}");
        assert!(cov.get("older_outside_window").is_none(), "aucun verdict sans mesure — {cov}");
    }

    // ------------------------------------------------------------------------------------------------
    // (2) L'AVEU DE PROVENANCE — LE TÉMOIN QUI SAUVE ONZE PANNEAUX LIVRÉS.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn un_panneau_opaque_ne_se_declare_ni_brut_ni_exact_et_un_panneau_route_dit_son_rollup() {
        let (path, conn) = pa_base("provenance");
        let conf = pa_conf();
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'web','http',1,'h1','ok')",
            params![now()],
        )
        .unwrap();
        drop(conn);

        // --- NÉGATIF : le panneau semé « Top URLs » lit `event_dim_rollup`, PRÉ-AGRÉGÉ PLAFONNÉ. Sa
        //     réponse ne doit porter NI `served_from`, NI `approx`, NI `truncated` — on ne publie pas un
        //     aveu d'exactitude sur une provenance qu'on n'a pas dérivée. ---
        let q_dim = dim_panel_sql("web", "path", 20, false);
        let pc = panneau_avoue::compile_panneau_avoue(&q_dim, false, 0, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, 0).unwrap();
        let st = &v["stats"];
        assert_eq!(st["provenance_non_derivee"], json!(true), "provenance NON dérivée, et c'est dit — {st}");
        // `truncated` N'EST PAS dans cette liste, et la raison est MESURÉE : le moteur de requête le pose
        // déjà (plafond de LIGNES), sur toute réponse. Ce que le coffre ne doit pas faire, c'est y OR-er un
        // plafond top-N qu'il n'a pas chiffré — on le vérifie par ÉGALITÉ avec la réponse nue, plus bas.
        for champ in ["served_from", "approx", "topn_ecartes", "topn_servis", "topn_total"] {
            assert!(
                st.get(champ).is_none(),
                "`{champ}` ne doit PAS être publié sur un SQL opaque : une case absente est une case non \
                 mesurée, jamais un zéro rassurant — {st}"
            );
        }
        let nu = run_query(path.as_str(), &pa_sql(&q_dim, false, 0, 0)).unwrap();
        assert_eq!(
            st["truncated"], nu["stats"]["truncated"],
            "`truncated` doit rester EXACTEMENT ce que le moteur a posé : le coffre n'y ajoute aucun plafond \
             qu'il n'a pas chiffré — {st}"
        );
        let note = st["rollup_note"].as_str().unwrap_or("");
        assert!(
            note.contains("top-N") && note.contains("PLANCHER"),
            "la note doit dire qu'un plafond top-N existe et que le compte est un PLANCHER — « {note} »"
        );

        // --- LA MUTATION, ET C'EST ELLE QUI DONNE SON SENS AU TÉMOIN : rejouer le geste naïf
        //     (`apply_rollup_stats(&mut v, &None)`) sur CE chemin publierait « brut / exact », que la
        //     console rend « Données brutes (scan, non pré-agrégé) — exact » sur un top-20 d'un
        //     pré-agrégé tronqué. Le témoin ci-dessus doit rougir face à cette réponse-là. ---
        let mut mutant = v.clone();
        apply_rollup_stats(&mut mutant, &None);
        assert_eq!(mutant["stats"]["served_from"], json!("raw"), "le mutant publie bien l'aveu FAUX que ce geste évite");
        assert_eq!(mutant["stats"]["approx"], json!(false), "… et il le publie comme EXACT");
        assert!(
            v["stats"].get("served_from").is_none(),
            "la réponse RÉELLE ne porte pas cet aveu : c'est exactement la différence que ce témoin garde"
        );

        // --- POSITIF SYMÉTRIQUE : un panneau GXQL routé vers le pré-agrégé DOIT, lui, dire qu'il l'est.
        //     Sans ce couple, `provenance_non_derivee` serait indiscernable d'un aveu simplement absent. ---
        let pc = panneau_avoue::compile_panneau_avoue("search | stats count by source", true, 0, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, 0).unwrap();
        assert_eq!(v["stats"]["served_from"], json!("rollup"), "la route de pré-agrégat le DIT — {}", v["stats"]);
        assert_eq!(v["stats"]["approx"], json!(true), "… et elle dit qu'elle approxime — {}", v["stats"]);
        assert!(v["stats"].get("provenance_non_derivee").is_none(), "une provenance DÉRIVÉE ne se dit pas non dérivée");

        // --- ET LE COMPILATEUR BRUT, TROISIÈME ÉTAT : un GXQL non routable compile un scan des tables
        //     VIVES, où « brut / exact » est VRAI. ---
        let pc = panneau_avoue::compile_panneau_avoue("search source=web | table message", true, 0, 0, None).unwrap();
        let v = panneau_avoue::executer(path.as_str(), &conf, pc, 0).unwrap();
        assert_eq!(v["stats"]["served_from"], json!("raw"), "{}", v["stats"]);
        assert_eq!(v["stats"]["approx"], json!(false), "{}", v["stats"]);

        // --- ET DANS LES TROIS CAS, `coverage` EST LÀ. ---
        assert!(v["stats"]["coverage"].is_object(), "l'horizon est publié inconditionnellement — {}", v["stats"]);
    }

    // ------------------------------------------------------------------------------------------------
    // (3) LA CONTRAINTE PRINCIPALE : LE NOMBRE NE CHANGE PAS.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn le_nombre_servi_est_identique_a_l_octet_avant_et_apres_l_aveu() {
        let (path, conn) = pa_base("identite");
        let conf = pa_conf();
        // De quoi que les panneaux aient QUELQUE CHOSE à rendre : un témoin d'identité sur sept réponses
        // toutes vides ne distinguerait pas « inchangé » de « rien mesuré ».
        let n = now();
        for i in 0..40i64 {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) \
                 VALUES(?1,?2,'http',?3,?4,'m','10.0.0.7',?5)",
                params![n - i * 60, if i % 2 == 0 { "web" } else { "sshd" }, i % 5, format!("h{}", i % 3), format!("{{\"path\":\"/p{}\"}}", i % 4)],
            )
            .unwrap();
            conn.execute("INSERT INTO metric(ts,name,value,host) VALUES(?1,'cpu_pct',?2,'h1')", params![n - i * 60, i as f64]).unwrap();
        }
        rollup_events(&conn);
        let familles = pa_familles_semees(&conn);
        drop(conn);

        let mut avec_lignes = 0usize;
        let mut eprouvees = 0usize;
        for (q, is_soql) in &familles {
            let Ok(pc) = panneau_avoue::compile_panneau_avoue(q, *is_soql, 0, 0, None) else { continue };
            let sql = pc.sql_de_test().to_string();
            let Ok(avant) = run_query(path.as_str(), &sql) else { continue };
            let apres = panneau_avoue::executer(path.as_str(), &conf, pc, 0).expect("le même SQL, exécuté par le coffre");
            eprouvees += 1;
            // BYTE À BYTE, sur la forme SÉRIALISÉE : c'est ce qui distingue « dire » de « corriger ».
            assert_eq!(
                serde_json::to_string(&avant["columns"]).unwrap(),
                serde_json::to_string(&apres["columns"]).unwrap(),
                "les colonnes ont bougé sur `{q}`"
            );
            assert_eq!(
                serde_json::to_string(&avant["rows"]).unwrap(),
                serde_json::to_string(&apres["rows"]).unwrap(),
                "les lignes ont bougé sur `{q}`"
            );
            assert!(apres["stats"]["coverage"].is_object(), "et pourtant `stats` a gagné son aveu — `{q}`");
            if !apres["rows"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
                avec_lignes += 1;
            }
        }
        assert!(
            eprouvees >= PA_PLANCHER_FAMILLES,
            "INSTRUMENT MUET : {eprouvees} famille(s) réellement exécutées, plancher {PA_PLANCHER_FAMILLES}"
        );
        assert!(
            avec_lignes >= 3,
            "INSTRUMENT MUET : {avec_lignes} réponse(s) portaient réellement des lignes — une égalité entre \
             sept vides ne prouve pas que le nombre n'a pas bougé"
        );
    }

    /// LA RÉDUCTION DE TROIS SITES DE COMPILATION À DEUX BRANCHES EST UN DÉPLACEMENT PUR, ET C'EST
    /// PROUVÉ DANS L'ARBRE.
    ///
    /// CE QUE LE TÉMOIN D'IDENTITÉ CI-DESSUS NE PROUVE PAS. Il prend le SQL de la porte NEUVE et le
    /// compare à lui-même exécuté par le coffre : il établit qu'`executer` ne touche ni `columns` ni
    /// `rows`, RIEN sur l'égalité du SQL entre l'ancienne porte et la nouvelle. Cette moitié-là ne vivait
    /// que dans un script d'empreintes HORS ARBRE, et ce script ne couvrait que deux des trois branches
    /// fondues : la troisième — celle qui vivait EN LIGNE dans `capture_dashboard_data`, le bras
    /// « masques NON vides ET `is_soql=0` » — n'était tenue par rien.
    ///
    /// CE QUE CELUI-CI ÉTABLIT, ET IL SUFFIT POUR CETTE BRANCHE : pour `is_soql=0`, les DEUX portes du
    /// coffre — masquée et non masquée — produisent un SQL BYTE-IDENTIQUE. C'est exactement l'égalité qui
    /// autorise la réduction (le site d'origine appliquait la même substitution au même
    /// `apply_excl_placeholders`), et un futur geste qui déplacerait un `.trim()` ou changerait l'ordre
    /// des substitutions dans l'une des deux la fait rougir.
    #[test]
    fn les_deux_portes_du_coffre_compilent_le_meme_sql_brut_et_c_est_ce_qui_autorise_la_reduction() {
        let (path, conn) = pa_base("portes");
        let familles = pa_familles_semees(&conn);
        drop(conn);
        let _ = path;
        let masques = guatx_core::soql::FieldMaskSet::new();
        let mut brutes = 0usize;
        for (q, is_soql) in &familles {
            if *is_soql {
                continue; // GXQL : les deux portes empruntent des compilateurs DIFFÉRENTS, par conception
            }
            let nue = panneau_avoue::compile_panneau_avoue(q, false, 111, 222, None).map(|pc| pc.sql_de_test().to_string());
            let masquee =
                panneau_avoue::compile_panneau_avoue_masque(q, false, 111, 222, None, &masques).map(|pc| pc.sql_de_test().to_string());
            assert_eq!(nue, masquee, "les deux portes divergent sur le SQL brut de `{q}` : la réduction de trois sites à deux branches n'est plus un déplacement pur");
            brutes += 1;
        }
        assert!(brutes >= 3, "INSTRUMENT MUET : {brutes} panneau(x) SQL brut éprouvés — la population est vide");
        // … ET L'INSTRUMENT EST VALIDÉ : sur du GXQL, les deux portes NE sont PAS censées coïncider, et
        // une comparaison qui rendrait vrai partout ne prouverait rien.
        let g_nue = panneau_avoue::compile_panneau_avoue("search source=web | table message", true, 0, 0, None).map(|pc| pc.sql_de_test().to_string());
        let g_masquee = panneau_avoue::compile_panneau_avoue_masque("search source=web | table message", true, 0, 0, None, &masques)
            .map(|pc| pc.sql_de_test().to_string());
        assert!(g_nue.is_ok() && g_masquee.is_ok(), "instrument : les deux compilations GXQL doivent aboutir");
    }

    // ------------------------------------------------------------------------------------------------
    // (4) LA GARDE DÉRIVÉE DE LA TABLE : toute ligne du cache rendu porte son aveu.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn toute_ligne_du_cache_de_panneau_porte_son_aveu() {
        let (path, conn) = pa_base("cache");
        let n = now();
        for i in 0..10i64 {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'web','http',1,'h1','m')",
                params![n - i * 60],
            )
            .unwrap();
        }
        rollup_events(&conn);
        drop(conn);

        // LE CINQUIÈME POINT D'EXÉCUTION, par sa condition RÉELLE : un tick de pré-chauffage.
        let db = Arc::new(Mutex::new(open_db(path.as_str()).unwrap()));
        let sem = Arc::new(tokio::sync::Semaphore::new(4));
        cache_refresh_all_panels(&db, path.as_str(), &sem);

        let conn = db.lock();
        let mut stmt = conn.prepare("SELECT panel_id, payload FROM panel_cache").unwrap();
        let lignes: Vec<(i64, String)> = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .flatten()
            .collect();
        drop(stmt);
        assert!(
            !lignes.is_empty(),
            "INSTRUMENT MUET : le cache est VIDE après un tick de pré-chauffage — la garde rendrait vert en \
             ne regardant rien (le motif « deux moniteurs à vide 20 h » du dépôt)."
        );
        for (id, payload) in &lignes {
            let v: Value = serde_json::from_str(payload).unwrap_or_else(|e| panic!("payload du panneau {id} illisible : {e}"));
            assert!(
                v["stats"]["coverage"].is_object(),
                "la ligne du panneau {id} ne porte AUCUN aveu : servie plus tard, elle se relirait comme une \
                 réponse entière. Payload : {payload}"
            );
            assert!(v["stats"]["coverage"].get("reason").is_some(), "l'aveu du panneau {id} ne dit pas POURQUOI");
        }

        // TÉMOIN DE NON-DÉGÉNÉRESCENCE DU PLANCHER : il n'est pas décoratif. Sur la MÊME base, la table
        // vidée rend zéro ligne — exactement ce que le plancher refuse. Sans cette moitié, rien ne
        // prouverait que « la table n'est pas vide » est une CONDITION et non une constatation.
        let vides = panneau_avoue::cache_vider(&conn);
        assert!(vides >= 1, "le vidage a bien porté sur les lignes qu'on vient de lire");
        let restant: i64 = conn.query_row("SELECT COUNT(*) FROM panel_cache", [], |r| r.get(0)).unwrap();
        assert_eq!(restant, 0, "la table est vide : c'est l'état que le plancher `>= 1` interdit");
    }

    // ------------------------------------------------------------------------------------------------
    // (5) LA GARDE DÉRIVÉE DU ROUTEUR ET DE LA FORME DU CORPS.
    // ------------------------------------------------------------------------------------------------

    /// Les routes déclarées sous les deux préfixes qui SERVENT une réponse de panneau, lues à l'unique
    /// site de déclaration de la table de routage. Une route ajoutée demain sous l'un de ces préfixes
    /// entre sans que personne l'inscrive.
    ///
    /// LA MÉTHODE EST DÉRIVÉE AVEC LE CHEMIN, ET C'EST CE QUI DONNE UN SENS AU PLANCHER. La sonde n'émet
    /// que des `GET` ; deux des quatre routes des préfixes sont `post().delete()` et `delete()`, donc
    /// STRUCTURELLEMENT ignorées (405). Un plancher « moins de routes ignorées que de routes trouvées »
    /// tolérait alors 3 ignorées sur 4 : la surface de service d'un panneau pouvait n'être jugée par
    /// AUCUNE assertion pendant que la garde restait verte. En dérivant la méthode, la population devient
    /// celle que la sonde peut réellement interroger, et l'exigence peut être ZÉRO ignorée.
    fn pa_routes_get_de_panneau() -> Vec<String> {
        let src = texte_du_module_serveur();
        let mut out = Vec::new();
        for line in src.lines() {
            let code = line.split("//").next().unwrap_or("");
            let Some((_, rest)) = code.split_once(".route(\"") else { continue };
            let Some((path, apres)) = rest.split_once('"') else { continue };
            if !(path.starts_with("/api/panels/") || path.starts_with("/api/dashboard-snapshots/")) {
                continue;
            }
            if !apres.contains("get(") {
                continue; // route en écriture seule : la sonde n'a rien à y demander
            }
            out.push(path.to_string());
        }
        out.sort();
        out.dedup();
        out
    }

    /// LA RÈGLE PORTE SUR LA FORME DU CORPS, PAS SUR LA ROUTE : tout objet de la réponse qui porte un
    /// tableau `rows` — au premier niveau ou sous `data.panels[*]` — doit porter `stats.coverage` À CÔTÉ.
    /// Une mutation sans corps (les `StatusCode` nus de `panel_update`/`panel_delete`) sort donc d'elle-
    /// même, sans qu'on l'inscrive nulle part.
    fn pa_objets_a_juger(v: &Value) -> Vec<Value> {
        let mut out = Vec::new();
        if v.get("rows").map(|r| r.is_array()).unwrap_or(false) {
            out.push(v.clone());
        }
        if let Some(panels) = v.pointer("/data/panels").and_then(|p| p.as_array()) {
            for p in panels {
                if p.get("rows").map(|r| r.is_array()).unwrap_or(false) {
                    out.push(p.clone());
                }
            }
        }
        out
    }

    /// LA SONDE DE CE MODULE, ET POURQUOI ELLE N'EST PAS CELLE DU VOISIN. `router_probe_corps` borne sa
    /// lecture à 4 Kio : c'est ce qu'il faut pour CHERCHER un marqueur dans une réponse, et pas assez pour
    /// en PARSER une — la règle tenue ici porte sur la FORME du corps ENTIER (un objet qui porte `rows`
    /// doit porter `stats.coverage` à côté), et un corps coupé se lirait comme un JSON invalide, donc
    /// comme une route « ignorée ». La borne est relevée à 1 Mio ; elle reste une borne.
    async fn pa_probe_json(addr: std::net::SocketAddr, chemin: &str, authz: &str) -> (u16, Option<Value>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!(
            "GET {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: {authz}\r\nContent-Length: 0\r\n\r\n"
        );
        let fut = async {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            s.write_all(req.as_bytes()).await.ok()?;
            let mut brut: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            while brut.len() < 1_048_576 {
                match s.read(&mut buf).await.ok()? {
                    0 => break,
                    n => brut.extend_from_slice(&buf[..n]),
                }
            }
            let sep = brut.windows(4).position(|w| w == b"\r\n\r\n")?;
            let entetes = String::from_utf8_lossy(&brut[..sep]).to_ascii_lowercase();
            let code = entetes.split_whitespace().nth(1)?.parse::<u16>().ok()?;
            let corps = pa_decoder_corps(&brut[sep + 4..], entetes.contains("transfer-encoding: chunked"));
            Some((code, serde_json::from_slice::<Value>(&corps).ok()))
        };
        tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten().unwrap_or((0, None))
    }

    /// DÉCODAGE `chunked` MINIMAL, SUR DES OCTETS. Le serveur ne connaît pas la longueur d'une réponse
    /// JSON construite à la volée : il l'émet en morceaux préfixés de leur taille. La sonde voisine
    /// cherche un MARQUEUR, que ce cadrage ne gêne pas ; celle-ci PARSE, et un cadre laissé dans le
    /// corps se lirait comme « pas du JSON », donc comme une route ignorée — un vert par aveuglement.
    /// Le découpage se fait en OCTETS : une frontière de morceau peut tomber au milieu d'un caractère.
    fn pa_decoder_corps(corps: &[u8], chunked: bool) -> Vec<u8> {
        if !chunked {
            return corps.to_vec();
        }
        let mut out = Vec::new();
        let mut reste = corps;
        loop {
            let Some(nl) = reste.windows(2).position(|w| w == b"\r\n") else { break };
            let tete = String::from_utf8_lossy(&reste[..nl]).to_string();
            let Ok(n) = usize::from_str_radix(tete.split(';').next().unwrap_or("").trim(), 16) else { break };
            if n == 0 || reste.len() < nl + 2 + n {
                break;
            }
            out.extend_from_slice(&reste[nl + 2..nl + 2 + n]);
            reste = &reste[(nl + 2 + n + 2).min(reste.len())..];
        }
        out
    }

    #[tokio::test]
    async fn toute_reponse_de_panneau_servie_par_le_routeur_dit_sa_couverture() {
        let routes = pa_routes_get_de_panneau();
        assert!(
            routes.len() >= PA_PLANCHER_ROUTES,
            "INSTRUMENT MUET : {} route(s) GET de panneau dérivées, plancher {PA_PLANCHER_ROUTES} — la table \
             de routage n'est plus lue et le balayage sonderait le vide. Trouvées : {routes:?}",
            routes.len()
        );

        // `_garde` n'est pas inutilisé : c'est le POSSESSEUR du répertoire temporaire. Le relâcher
        // effacerait la base sous le routeur qu'on interroge.
        let (_garde, dbp) = {
            let p = crate::tmp_possede::TmpDb::neuf("pa-routeur");
            let conn = open_db(p.as_str()).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture routeur : migrations complètes");
            crate::tenants::seed_tenant_content(&conn);
            conn.execute("INSERT INTO user(name,hash,role) VALUES('vwr',?1,'viewer')", params![hash_pw("viewerpw12345").unwrap()])
                .unwrap();
            let n = now();
            for i in 0..20i64 {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,'web','http',1,'h1','m')",
                    params![n - i * 60],
                )
                .unwrap();
            }
            rollup_events(&conn);
            let s = p.as_str().to_string();
            (p, s)
        };

        // UN PANNEAU RÉEL et UN INSTANTANÉ RÉEL : la dérivation donne le CHEMIN d'une route, jamais la
        // valeur qu'il faut y mettre. Les deux valeurs sont prises dans la base, pas inventées.
        let (panel_id, token) = {
            let conn = open_db(&dbp).unwrap();
            let panel_id: i64 = conn
                .query_row("SELECT p.id FROM panel p JOIN dashboard d ON d.id=p.dashboard_id ORDER BY p.id LIMIT 1", [], |r| r.get(0))
                .unwrap();
            let did: i64 = conn.query_row("SELECT dashboard_id FROM panel WHERE id=?1", params![panel_id], |r| r.get(0)).unwrap();
            // LE SIXIÈME POINT D'EXÉCUTION, par sa condition RÉELLE : une capture d'instantané.
            let vide = guatx_core::soql::FieldMaskSet::new();
            let data = capture_dashboard_data(&dbp, &conn, &pa_conf(), did, "D", 0, 0, None, &vide, &PorteeLecture::Proprietaire);
            let token = gen_snapshot_token().expect("entropie /dev/urandom dispo en test");
            conn.execute(
                "INSERT INTO dashboard_snapshot(token,name,dashboard_id,data,created,created_by,role_at_capture) \
                 VALUES(?1,'D',?2,?3,?4,'root','admin')",
                params![token, did, serde_json::to_string(&data).unwrap(), now()],
            )
            .unwrap();
            (panel_id, token)
        };

        // LE PRÉ-CHAUFFAGE D'ABORD : sans lui, `panel_data` sert un corps `warming` TOUJOURS vide, et le
        // plancher « au moins un corps a porté des lignes » ne tiendrait que par l'instantané. Avec lui, le
        // routeur traverse aussi le chemin SWR (HIT + re-estampe) — la condition RÉELLE, pas un appel direct.
        {
            let db = Arc::new(Mutex::new(open_db(&dbp).unwrap()));
            let sem = Arc::new(tokio::sync::Semaphore::new(4));
            cache_refresh_all_panels(&db, &dbp, &sem);
        }
        // … PUIS LE PANNEAU SONDÉ EST POUSSÉ SUR LE CHEMIN **LIVE**, ET C'EST LA MOITIÉ QUI MANQUAIT.
        // La garde jumelle de la TABLE ne joue que le tick de fond : sa population réelle est « les lignes
        // écrites par UN écrivain sur cinq », pas « toute ligne du cache ». En déclarant un coût MESURÉ et
        // faible pour ce panneau et en vidant SA ligne, `panel_data` prend la branche LIVE — qui exécute
        // et RÉÉCRIT le cache elle-même. La relecture de `panel_cache` en fin de témoin juge donc une
        // ligne écrite par le CHEMIN DE SERVICE.
        {
            let conn = open_db(&dbp).unwrap();
            let (q, sq): (String, i64) =
                conn.query_row("SELECT query, is_soql FROM panel WHERE id=?1", params![panel_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            let fp = query_fingerprint(&q, sq != 0);
            record_panel_cost(&conn, panel_id, &fp, 1.0, now()); // coût CONNU et faible -> ni LOURD ni INCONNU
            panneau_avoue::cache_invalider_panneau(&conn, panel_id);
        }
        let mut st = ds_file_state(&dbp);
        st.user = Arc::new("root".to_string());
        st.pass_hash = Arc::new(hash_pw("rootpw1234567").unwrap());
        st.rl_auth_max = 1_000_000;
        st.rl_ip_max = 1_000_000;
        st.rl_global_max = 1_000_000;
        let addr = router_serve(st).await;
        let authz = viewer_authz();

        let mut ignorees = 0usize;
        let mut juges = 0usize;
        let mut avec_lignes_et_aveu = 0usize;
        let mut surfaces_jugees: Vec<String> = Vec::new();
        for gabarit in &routes {
            let chemin = gabarit.replace("{id}", &panel_id.to_string()).replace("{token}", &token);
            assert!(!chemin.contains('{'), "gabarit non résolu : {chemin} — la sonde interrogerait une URL littérale");
            let chemin = if chemin.ends_with("/data") { format!("{chemin}?from=0&to=0") } else { chemin };
            let (code, corps) = pa_probe_json(addr, &chemin, &authz).await;
            // 405 (route en écriture seule), 404, 403, corps non-JSON : rien n'est SERVI, rien à juger.
            let (Some(v), 200) = (corps, code) else {
                ignorees += 1;
                continue;
            };
            let objets = pa_objets_a_juger(&v);
            if objets.is_empty() {
                ignorees += 1;
                continue;
            }
            surfaces_jugees.push(gabarit.clone());
            for o in objets {
                juges += 1;
                assert!(
                    o["stats"]["coverage"].is_object(),
                    "`{chemin}` sert un corps qui porte des LIGNES et ne dit pas jusqu'où il a regardé : tout \
                     consommateur le lit comme une réponse entière. Corps : {v}"
                );
                if !o["rows"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
                    avec_lignes_et_aveu += 1;
                }
            }
        }
        // ZÉRO IGNORÉE, ET C'EST LA CORRECTION DU PLANCHER. La population est celle des routes que la
        // sonde peut interroger : une seule d'entre elles qui refuse, rend un corps illisible ou un corps
        // sans `rows`, et la garde ne juge plus la surface qu'elle prétend juger.
        assert_eq!(
            ignorees, 0,
            "INSTRUMENT MUET : {ignorees} route(s) GET ignorées sur {} ({surfaces_jugees:?} jugées) — une \
             surface de panneau n'a été jugée par AUCUNE assertion pendant que la garde restait verte",
            routes.len()
        );
        // … et l'identité des surfaces atteintes est VÉRIFIÉE, pas déduite d'un compte d'objets : un seul
        // corps d'instantané porte SEPT panneaux, donc `juges >= 2` était satisfait par une seule surface.
        assert_eq!(
            surfaces_jugees, routes,
            "les surfaces réellement jugées ne sont pas les surfaces dérivées : jugées={surfaces_jugees:?} / dérivées={routes:?}"
        );
        assert!(juges >= 2, "INSTRUMENT MUET : {juges} corps jugés");
        assert!(
            avec_lignes_et_aveu >= 1,
            "INSTRUMENT MUET : aucun corps n'a porté DES LIGNES avec son aveu. Une garde qui ne voit que des \
             tableaux vides rendrait vert sur un démon qui ne sert plus rien."
        );

        // LA TABLE DU CACHE, APRÈS UN PASSAGE PAR `panel_data` — et pas seulement après le pré-chauffage.
        // La garde jumelle (`toute_ligne_du_cache_de_panneau_porte_son_aveu`) ne joue QUE le tick de fond :
        // sa population réelle était « les lignes écrites par UN écrivain », pas « toute ligne du cache ».
        // Ici la route a été RÉELLEMENT servie (SWR : HIT + re-estampe, ou LIVE qui repeuple), donc les
        // lignes relues portent la trace de ce chemin-là.
        {
            let conn = open_db(&dbp).unwrap();
            let mut stmt = conn.prepare("SELECT panel_id, payload FROM panel_cache").unwrap();
            let lignes: Vec<(i64, String)> = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .flatten()
                .collect();
            drop(stmt);
            assert!(!lignes.is_empty(), "INSTRUMENT MUET : le cache est vide après un service par la route");
            assert!(
                lignes.iter().any(|(id, _)| *id == panel_id),
                "INSTRUMENT MUET : le panneau {panel_id} n'a PAS été réécrit par le chemin LIVE — la relecture \
                 ne juge alors que les lignes du pré-chauffage, c'est-à-dire un écrivain sur cinq"
            );
            for (id, payload) in &lignes {
                let v: Value = serde_json::from_str(payload).unwrap_or_else(|e| panic!("payload du panneau {id} illisible : {e}"));
                assert!(
                    v["stats"]["coverage"].is_object(),
                    "la ligne du panneau {id}, écrite par le chemin de SERVICE, ne porte AUCUN aveu — {payload}"
                );
            }
        }
    }

    // ------------------------------------------------------------------------------------------------
    // (6) SWR : LA FENÊTRE QUE LES LIGNES ONT VUE, ET LE PAYLOAD DU BINAIRE PRÉCÉDENT.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn la_re_estampe_ne_certifie_pas_une_fenetre_que_les_lignes_n_ont_pas_vue() {
        let (path, conn) = pa_base("swr");
        let conf = pa_conf();
        let q = pa_requete_metrique(&conn);
        pa_poser_retention(&conn, "metric_raw_hours", 720);
        drop(conn);
        let pc = panneau_avoue::compile_panneau_avoue(&q, false, 0, 0, None).unwrap();

        // Un payload ÉCRIT À T0 sur [T0−24 h, T0] : c'est cette fenêtre-là que ses lignes ont vue.
        let t0 = now() - 30 * 3600;
        let from_t0 = t0 - 86_400;
        let mut v = json!({ "columns": ["a"], "rows": [[1]], "stats": {} });
        v["stats"]["coverage"] = panneau_avoue::horizon_du_sql(path.as_str(), &conf, pc.sql_de_test(), from_t0, t0);
        let stocke = v["stats"]["coverage"]["horizon_ts"].as_i64().unwrap();

        // --- LE CAS DOMINANT EN PRODUCTION, ET IL ÉTAIT FAUX : SERVI TRENTE HEURES PLUS TARD, POLITIQUE
        //     INCHANGÉE. `horizon_ts` vaut `instant_du_calcul − rétention` : il AVANCE avec l'horloge.
        //     Comparer les deux INSTANTS faisait donc basculer en `horizon_perime` tout HIT servi ne
        //     serait-ce qu'une seconde après l'écriture — c'est-à-dire la quasi-totalité — et la phrase
        //     « l'horizon a BOUGÉ depuis » s'allumait alors que rien n'avait bougé sinon l'horloge. Ce
        //     qu'on compare est la DURÉE de conservation. ---
        let now_s = now();
        panneau_avoue::cache_reestamper(&mut v, path.as_str(), &conf, Some(&pc), t0, now_s);
        let cov = &v["stats"]["coverage"];
        assert_eq!(cov["searched_from"], json!(from_t0), "la fenêtre servie reste celle des LIGNES — {cov}");
        assert_eq!(cov["calcule_a"], json!(t0), "l'instant du calcul reste celui de l'écriture — {cov}");
        assert_ne!(
            cov["reason"],
            json!(panneau_avoue::RAISON_HORIZON_PERIME),
            "l'horloge a avancé de trente heures, la POLITIQUE n'a pas bougé : annoncer « l'horizon a bougé \
             depuis » sur ce HIT allume le signal en permanence, donc il n'informe plus de rien — {cov}"
        );
        assert_eq!(cov["horizon_ts"], json!(stocke), "l'horizon servi reste celui que les LIGNES ont affronté — {cov}");
        assert_eq!(v["rows"], json!([[1]]), "la re-estampe ne touche pas aux lignes");

        // --- ET QUAND LA POLITIQUE CHANGE VRAIMENT, LE SIGNAL PART. C'est ce que ce champ prétend
        //     annoncer, et c'est la seule chose qu'il doit annoncer. ---
        {
            let c = open_db(path.as_str()).unwrap();
            pa_poser_retention(&c, "metric_raw_hours", 24);
        }
        let mut vp = json!({ "columns": ["a"], "rows": [[1]], "stats": {} });
        vp["stats"]["coverage"] = json!({
            "searched_from": from_t0, "calcule_a": t0, "horizon_ts": stocke,
            "older_outside_window": false, "reason": panneau_avoue::RAISON_RETENTION, "notice": "",
        });
        panneau_avoue::cache_reestamper(&mut vp, path.as_str(), &conf, Some(&pc), t0, now_s);
        let cov = &vp["stats"]["coverage"];
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_HORIZON_PERIME), "la rétention est passée de 720 h à 24 h : ça, c'est un horizon qui a BOUGÉ — {cov}");
        assert_eq!(cov["searched_from"], json!(from_t0), "même périmé, on ne certifie pas une fenêtre que les lignes n'ont pas vue — {cov}");
        assert!(cov["horizon_ts"].as_i64().unwrap() > stocke, "l'horizon COURANT est publié — {cov}");

        // TÉMOIN INVERSE, SUR LE MÊME INSTANT : un correctif dégénéré « toujours périmé » le ferait
        // rougir tout autant, et il tient l'autre borne (« jamais périmé » est réfuté juste au-dessus).
        let mut w = json!({ "columns": ["a"], "rows": [[1]], "stats": {} });
        w["stats"]["coverage"] = panneau_avoue::horizon_du_sql(path.as_str(), &conf, pc.sql_de_test(), from_t0, now_s);
        panneau_avoue::cache_reestamper(&mut w, path.as_str(), &conf, Some(&pc), now_s, now_s);
        assert_ne!(
            w["stats"]["coverage"]["reason"],
            json!(panneau_avoue::RAISON_HORIZON_PERIME),
            "un horizon inchangé ne se déclare pas périmé — {}",
            w["stats"]["coverage"]
        );

        // --- UNE CHARGE UTILE QUI N'EST PAS UN OBJET NE FAIT PAS TOMBER LE HANDLER QUI SERT LE PANNEAU.
        //     `v["stats"]["coverage"] = …` PANIQUE sur un tableau ou un scalaire (`IndexMut` de
        //     serde_json ne tolère que `Object` et `Null`), et une ligne de `panel_cache` est un TEXTE que
        //     rien ne contraint — import, restauration partielle, écriture d'exploitant. ---
        for brut in ["[]", "3", "\"x\"", "null"] {
            let mut informe: Value = serde_json::from_str(brut).unwrap();
            panneau_avoue::cache_reestamper(&mut informe, path.as_str(), &conf, Some(&pc), t0, now_s);
        }

        // TÉMOIN JUMEAU : une ligne écrite par un BINAIRE ANTÉRIEUR ne porte aucun aveu. Elle ressort
        // « non dit » — jamais « brut / exact », qui serait une affirmation d'exactitude inventée.
        let mut ancien = json!({ "columns": ["a"], "rows": [[1]] });
        panneau_avoue::cache_reestamper(&mut ancien, path.as_str(), &conf, Some(&pc), t0, now_s);
        let cov = &ancien["stats"]["coverage"];
        assert_eq!(cov["reason"], json!(panneau_avoue::RAISON_PAYE_UTILE_ANTERIEURE), "{cov}");
        assert!(ancien["stats"].get("served_from").is_none(), "aucune provenance n'est inventée pour une vieille ligne");
    }

    // ------------------------------------------------------------------------------------------------
    // (7) LA POPULATION DES POINTS D'EXÉCUTION EST DÉRIVÉE, ET ELLE EST DE SIX.
    // ------------------------------------------------------------------------------------------------

    #[test]
    fn tous_les_points_d_execution_d_un_panneau_passent_par_le_coffre() {
        // DÉRIVÉE PAR PARCOURS DE `src/`, jamais énumérée : un septième point écrit demain entre dans le
        // compte sans que personne l'inscrive. Ce que ce témoin établit est une BORNE BASSE — il ne
        // prouve pas qu'aucun autre chemin n'existe (la couche 1 ne ferme pas cela, c'est écrit).
        let mut fichiers = Vec::new();
        crate::db_open::door_tests::rs_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut fichiers);
        let mut sites: Vec<String> = Vec::new();
        for f in &fichiers {
            if f.components().any(|c| c.as_os_str() == "tests") {
                continue; // les témoins ne sont pas des points d'exécution de production
            }
            let src = std::fs::read_to_string(f).unwrap();
            for (i, l) in src.lines().enumerate() {
                let code = l.split("//").next().unwrap_or("");
                if code.contains("panneau_avoue::executer(") {
                    sites.push(format!("{}:{}", f.file_name().unwrap().to_string_lossy(), i + 1));
                }
            }
        }
        assert!(
            sites.len() >= 6,
            "INSTRUMENT MUET ou RÉGRESSION : {} point(s) d'exécution passent par le coffre, attendu au moins \
             SIX (quatre dans le handler de panneau, un au pré-chauffage, un à la capture d'instantané). \
             Trouvés : {sites:?}",
            sites.len()
        );
        // … et la réciproque : plus aucun de ces fichiers ne doit exécuter un panneau HORS du coffre par
        // l'ancienne porte, qui n'existe plus. Un nom qui reviendrait serait une régression silencieuse.
        for f in &fichiers {
            if f.components().any(|c| c.as_os_str() == "tests") {
                continue; // même population que ci-dessus : la PRODUCTION, pas les témoins
            }
            let src = std::fs::read_to_string(f).unwrap();
            for (i, l) in src.lines().enumerate() {
                let code = l.split("//").next().unwrap_or("");
                assert!(
                    !code.contains("compile_panel_sql("),
                    "l'ancienne porte de compilation de panneau est revenue : {}:{}",
                    f.display(),
                    i + 1
                );
            }
        }
    }
