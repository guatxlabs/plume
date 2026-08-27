// QUERY-VERIFY — preuve que le CHEMIN DE REQUÊTE SOC ne PERD JAMAIS silencieusement d'événements.
// On compile la VRAIE SoQL via le choke-point du daemon (`crate::soql_to_sql_masked_x` -> store().schema =
// events()), puis on EXÉCUTE le SQL émis sur une base in-memory au schéma de prod (`test_db()`), en installant
// la même UDF `regexp` que la connexion de lecture du daemon (`crate::query_exec::install_query_udfs`) pour les
// requêtes `=~`. On vérifie l'ensemble de lignes RENDU contre un ensemble ATTENDU calculé à la main.
//
// Réutilise les helpers du module `tests` (mêmes includes) : `test_db()`, `ks_run_page()`, `ks_col()`.

    // `FieldMaskSet` est déjà `use`é par keyset.rs (même module `tests` via include!) -> on le qualifie complet.

    // Insère un event source=auditd avec message + severity + fields explicites.
    fn qv_ins(c: &Connection, ts: i64, sev: i64, msg: &str, fields: &str) {
        c.execute(
            "INSERT INTO event(ts,source,severity,message,fields,origin) VALUES(?1,'auditd',?2,?3,?4,'')",
            params![ts, sev, msg, fields],
        )
        .unwrap();
    }

    // Compile la SoQL (fenêtre from/to), l'exécute sur `c`, renvoie la LISTE ORDONNÉE des ts rendus.
    fn qv_ts(c: &Connection, soql: &str, from: i64, to: i64) -> Vec<i64> {
        let sql = crate::soql_to_sql_masked_x(soql, from, to, None, &guatx_core::soql::FieldMaskSet::new())
            .unwrap_or_else(|e| panic!("compile SoQL a échoué pour `{soql}` : {e}"));
        let v = ks_run_page(c, &sql);
        let ti = ks_col(&v, "ts");
        v["rows"].as_array().unwrap().iter().map(|r| r[ti].as_i64().unwrap()).collect()
    }

    // Idem mais renvoie juste le nombre de lignes.
    fn qv_count(c: &Connection, soql: &str, from: i64, to: i64) -> usize {
        qv_ts(c, soql, from, to).len()
    }

    // ---------------------------------------------------------------------------------------------
    // (1) BORNES TEMPORELLES INCLUSIVES — aucune perte de bord. `from`>0 -> `ts >= from` ; `to`>0 -> `ts <= to`.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_time_bounds_inclusive_no_edge_loss() {
        let c = test_db();
        for ts in [100, 200, 300, 400, 500] {
            qv_ins(&c, ts, 1, "x", "{}");
        }
        // Fenêtre [200,400] : les DEUX bornes doivent être RENDUES (inclusif), 100 et 500 exclus.
        let mut got = qv_ts(&c, "search source=auditd", 200, 400);
        got.sort();
        assert_eq!(got, vec![200, 300, 400], "bornes INCLUSIVES : 200 et 400 présents, 100/500 exclus");

        // Sans borne (0,0) -> les 5.
        let mut all = qv_ts(&c, "search source=auditd", 0, 0);
        all.sort();
        assert_eq!(all, vec![100, 200, 300, 400, 500], "from=0,to=0 -> aucune borne -> tout");

        // Borne basse seule (250,0) -> 300,400,500 (250 non présent en data ; 300 est >= 250).
        let mut lo = qv_ts(&c, "search source=auditd", 250, 0);
        lo.sort();
        assert_eq!(lo, vec![300, 400, 500], "from=250,to=0 -> ts >= 250, aucune borne haute");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) REGEX SUR message (`=~`) — l'UDF regexp FILTRE réellement (pas un pass-through).
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_regex_message() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c); // UDF `regexp` (comme la connexion de lecture du daemon)
        qv_ins(&c, 100, 1, "login failed", "{}");
        qv_ins(&c, 200, 1, "login ok", "{}");
        qv_ins(&c, 300, 1, "LOGIN FAILED", "{}"); // casse différente -> capté par (?i)
        qv_ins(&c, 400, 1, "sudo cmd", "{}");

        // (?i)^login failed$ -> matche EXACTEMENT "login failed" et "LOGIN FAILED" (2), pas "login ok"/"sudo cmd".
        let mut got = qv_ts(&c, r#"search source=auditd | where message =~ "(?i)^login failed$""#, 0, 0);
        got.sort();
        assert_eq!(got, vec![100, 300], "regex insensible à la casse -> exactement les 2 matches");

        // Motif non-correspondant -> 0 ligne : prouve que l'UDF FILTRE (sinon les 4 passeraient).
        let n = qv_count(&c, r#"search source=auditd | where message =~ "zzz""#, 0, 0);
        assert_eq!(n, 0, "motif sans correspondance -> 0 ligne (l'UDF filtre vraiment)");
    }

    // ---------------------------------------------------------------------------------------------
    // (3) FILTRE SUR CHAMP JSON — `user=alice` -> json_extract(fields,'$.user')='alice' ; regex idem.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_regex_json_field() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c);
        qv_ins(&c, 100, 1, "m", r#"{"user":"alice"}"#);
        qv_ins(&c, 200, 1, "m", r#"{"user":"bob"}"#);

        // Filtre d'égalité de base sur un champ JSON -> exactement 1 ligne (alice).
        let got = qv_ts(&c, "search source=auditd user=alice", 0, 0);
        assert_eq!(got, vec![100], "user=alice via json_extract -> exactement 1 ligne");

        // Même résultat via regex sur le champ JSON.
        let got_re = qv_ts(&c, r#"search source=auditd | where user =~ "^al""#, 0, 0);
        assert_eq!(got_re, vec![100], "user =~ ^al -> exactement 1 ligne (alice), bob exclu");
    }

    // ---------------------------------------------------------------------------------------------
    // (4) TERME LIBRE (LIKE) et le JOKER `*`. On DOCUMENTE le comportement RÉEL de `search *`.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_freetext_and_star() {
        let c = test_db();
        qv_ins(&c, 100, 1, "alpha one", "{}");
        qv_ins(&c, 200, 1, "beta two", "{}");

        // Terme libre -> message LIKE '%alpha%' -> 1 ligne.
        let got = qv_ts(&c, "search source=auditd alpha", 0, 0);
        assert_eq!(got, vec![100], "terme libre `alpha` -> LIKE %alpha% -> 1 ligne");

        // COMPORTEMENT RÉEL de `search *` : le compilateur intercepte `*` SEUL comme le JOKER SIEM « tous les
        // événements » (aucun filtre plein-texte) -> renvoie TOUTES les lignes, PAS 0. (Contredit l'hypothèse
        // « *` -> LIKE %*% -> 0 ligne » : ce n'est PAS un terme littéral.)
        let mut star = qv_ts(&c, "search *", 0, 0);
        star.sort();
        assert_eq!(star, vec![100, 200], "`search *` = JOKER match-all -> TOUTES les lignes (PAS 0, PAS littéral)");

        // Le SQL émis pour `search *` ne contient AUCUN filtre `message LIKE` (preuve que `*` n'est pas littéral).
        let star_sql = crate::soql_to_sql_masked_x("search *", 0, 0, None, &guatx_core::soql::FieldMaskSet::new()).unwrap();
        assert!(!star_sql.contains("LIKE '%*%'"), "`*` NE compile PAS en LIKE '%*%' : {star_sql}");
    }

    // ---------------------------------------------------------------------------------------------
    // (5) COMBO COMPLEXE — fenêtre temporelle + `where severity>=3` + regex + `sort -ts`.
    //     Croisé contre un ensemble attendu calculé à la main.
    // ---------------------------------------------------------------------------------------------
    #[test]
    fn qv_complex_combo() {
        let c = test_db();
        crate::query_exec::install_query_udfs(&c);
        //     ts   sev  message           dans le résultat ?
        qv_ins(&c, 100, 5, "alert boom", "{}");   // hors fenêtre (from=150)
        qv_ins(&c, 200, 2, "alert low", "{}");    // severity 2 < 3 -> exclu
        qv_ins(&c, 250, 4, "alert alpha", "{}");  // GARDÉ
        qv_ins(&c, 300, 4, "alert fire", "{}");   // GARDÉ
        qv_ins(&c, 400, 5, "noise", "{}");        // regex `alert` ne matche pas -> exclu
        qv_ins(&c, 500, 4, "alert storm", "{}");  // hors fenêtre (to=400)

        // Fenêtre [150,400] : {200,250,300,400}. severity>=3 : {250,300,400}. regex alert : {250,300}. -ts : [300,250].
        let got = qv_ts(
            &c,
            r#"search source=auditd | where severity>=3 | where message =~ "alert" | sort -ts"#,
            150,
            400,
        );
        assert_eq!(got, vec![300, 250], "combo fenêtre+severity+regex+sort -> exactement [300,250] (ordre DESC)");
    }

    // ---------------------------------------------------------------------------------------------
    // (6) GARDE DE BUDGET — ce qu'elle DOIT protéger, et ce qu'elle NE DOIT PAS coûter.
    //
    // L'ancienne garde SONDAIT un drapeau (`sleep(50 ms)` en boucle) et le chemin de requête la
    // JOIGNAIT avant de rendre sa réponse : toute lecture était donc arrondie au multiple de 50 ms
    // supérieur (mesuré sur la base de banc : SQL 0,76 ms -> 50,7 ms de `server_ms`). Les tests
    // ci-dessous épinglent, dans cet ordre : (a) la protection MORD toujours ET son attente SUIT le
    // budget, (b) elle ne coûte plus l'arrondi — sur les DEUX portes d'exécution, (c) aucune autre
    // porte ne peut apparaître. Un quatrième juge l'INSTRUMENT du banc lui-même (`P7.19-b`) : il
    // n'a rien à dire sur la garde de budget, il dit que la mesure est valide avant qu'on la croie.
    // ---------------------------------------------------------------------------------------------

    /// Un SELECT dont la durée est PARAMÉTRABLE, sans horloge ni dépendance à la machine : une CTE
    /// récursive qui compte jusqu'à `n`. `readonly()` vaut vrai (c'est un SELECT) -> passe la garde
    /// `stmt.readonly()` de `run_on_conn`.
    fn qb_slow_sql(n: i64) -> String {
        format!("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < {n}) SELECT count(*) FROM c")
    }

    // =============================================================================================
    // `P7.19-b` — L'INSTRUMENT DU BANC S'ÉTALONNE, ET IL DIT « JE N'AI PAS PU MESURER » AUTREMENT
    // QU'EN DISANT « LA PROPRIÉTÉ EST VIOLÉE ».
    //
    // CE QUI N'ALLAIT PAS, ET CE QUI ALLAIT. Le test (b) ci-dessous fabrique une requête témoin dont
    // la durée doit tomber DANS une fenêtre : trop rapide, la course « la requête finit avant que la
    // garde ne s'endorme » masque l'arrondi et le test passerait EN PRÉSENCE du défaut ; trop lente,
    // l'arrondi au tick se noie dans la mesure. Refuser de conclure hors de cette fenêtre est juste.
    // Mais la charge était une CONSTANTE (`n = 2 000`) et le refus une ASSERTION : sur une machine
    // plus rapide que celle de la mesure d'origine, la requête tombait SOUS le plancher et le banc
    // annonçait une régression du produit. CONSTATÉ le 2026-08-26 dans les journaux d'exécution :
    // deux mises à jour de dépendance sans rapport entre elles ont échoué sur ce seul test, sur ce
    // seul garde-fou. REPRODUIT ICI le 2026-08-27 en simulant une machine dix fois plus rapide (la
    // charge de départ ramenée à n=200) : la requête témoin coûte alors 0,053 ms, SOUS le plancher
    // de 0,2 ms — la condition exacte qui faisait rougir le banc. Avec l'étalonnage, le même banc
    // monte à n=11 321, mesure 2,04 ms, et conclut.
    //
    // CE QUI CHANGE : LA FENÊTRE NE BOUGE PAS, C'EST LA CHARGE QUI S'Y ADAPTE. `qb_etalonner` monte
    // (ou descend) `n` jusqu'à ce que la mesure entre dans la fenêtre, en visant proportionnellement
    // — le coût de la CTE est linéaire en `n` — donc l'instrument est valide PAR CONSTRUCTION sur une
    // machine lente comme sur une rapide. Le plancher n'est pas desserré : le desserrer ferait passer
    // le test sans qu'il prouve quoi que ce soit.
    //
    // ET SI L'ÉTALONNAGE ÉCHOUE MALGRÉ TOUT — butée de charge, `stats.elapsed_ms` absent, coût qui ne
    // suit plus la charge — le banc passe par `qb_refuser_de_conclure`, PAS par une assertion. Ce que
    // ça change, et c'est le point : le message porte la marque `QB_MARQUE_REFUS`, dit en toutes
    // lettres que ce n'est pas une violation de propriété, et rend la trace des paliers.
    //
    // OÙ VA CETTE MARQUE, MESURÉ — ET CE QUE LA PHRASE PRÉCÉDENTE AFFIRMAIT DE TROP. Le 2026-08-27,
    // `grep -rn "INSTRUMENT NON" .github/` rendait ZÉRO : la marque existait, le TRI n'existait
    // nulle part. Le texte d'ici disait pourtant « la CI trie sur cette marque et rend le code 2 »,
    // et citait en modèle `check_windows_collector_is_honest.py` — MESURÉ le même jour, `pwsh`
    // absent : il rend **1**, pas 2. Deux affirmations plus larges que la mesure, dans la même
    // phrase, sur un mécanisme POSÉ et NON ARMÉ.
    //
    // CE QUI EST ARMÉ MAINTENANT, ET SA BORNE. `.github/scripts/check_a_bench_refusal_is_a_distinct_
    // channel.py --trier <journal> <code-cargo>` est appelé APRÈS chaque `cargo test` de `ci.yml` :
    // marque présente -> **code 2**, aucune marque et cargo en échec -> le code de cargo, cargo vert
    // -> 0. La marque n'est pas recopiée là-bas : la garde la LIT dans `QB_MARQUE_REFUS`, ci-dessous,
    // et refuse de conclure si elle n'y est plus. CE QUE LE CODE 2 N'ACHÈTE PAS, ET C'EST DIT : le
    // job reste ROUGE dans les deux cas — délibérément, le vert reste interdit à un banc qui sait ne
    // pas avoir mesuré. Ce que le code 2 achète est un tri MÉCANIQUE (le code de sortie de l'étape,
    // et une annotation distincte) au lieu d'une lecture d'humain sur un `panic!` indiscernable.
    //
    // LE BALAYAGE DE LA FAMILLE, RENDU (l'ATTENDU de `P7.19-b` le demande : « chercher au passage les
    // autres tests dont une assertion porte sur un temps mesuré »). Fait le 2026-08-27.
    // POPULATION : les 19 sites de `daemon/src/tests/**` qui appellent `.elapsed()`, plus les
    // assertions citant `Duration::from_`.
    // CRITÈRE, ÉCRIT AVANT DE TRIER : est MEMBRE une assertion dont un côté est une durée d'horloge
    // MESURÉE sur cette machine et l'autre une CONSTANTE ABSOLUE — c'est-à-dire une assertion que la
    // seule LENTEUR de la machine peut faire rougir, en disant « la propriété est violée » là où la
    // vérité est « je n'ai pas pu mesurer ».
    // MEMBRES — TROIS, ET UN SEUL EST NON TRAITÉ :
    //   * `daemon/src/tests/cases.rs:1043` — `assert!(d < Duration::from_secs(2))` sur un tick
    //     `rollup_hosts`, sans étalonnage et sans canal de refus. C'EST LE MEMBRE NON TRAITÉ, et il
    //     est nommé plutôt que passé sous silence : le corriger demande soit une concordance (juger
    //     le tick RELATIVEMENT à un travail mesuré sur la même machine, comme `P6.9-b` l'a fait), soit
    //     le canal de refus rendu partageable hors de ce module. Aucun des deux n'est dans ce lot.
    //   * `daemon/src/tests/entrees_scriptees_bornees.rs` — `duree_ms < 10_000` pour une borne
    //     demandée à 1 s : membre par la forme, marge de 10×, et la borne qu'il juge est elle-même
    //     une durée d'horloge — il n'y a pas de mesure sans horloge à cet endroit.
    //   * `daemon/src/tests/vieillissement_serie.rs:621` — `mur0.elapsed() < 120 s` pour 200 ms de
    //     CPU de fil : membre par la forme, marge de 600×, et son message impute déjà la faute à
    //     l'INSTRUMENT (« ce n'est pas une machine lente, c'est un oracle qui n'avance pas »).
    // NON-MEMBRES, VÉRIFIÉS UN PAR UN — et deux des trois « voisins » qu'on m'avait désignés n'en
    // sont pas, ce qui est le résultat le plus utile du balayage :
    //   * `index_usage_observatoire.rs:224` — le `.elapsed()` n'alimente qu'un `println!` ; les deux
    //     assertions du test portent sur des COMPTES de plans lus, pas sur un temps ;
    //   * `attente_serie.rs:301` — l'assertion est une RELATION entre trois durées de la MÊME
    //     fenêtre (`verrou + permis <= mural + 1`) : la vitesse de la machine s'y annule ;
    //   * `rollup.rs:718/721` (`d_roll <= d_raw`), `attente_serie.rs:544/549` et
    //     `vieillissement_serie.rs:765/768` (rapports à un étalon mesuré dans la MÊME boucle, avec un
    //     garde-fou d'instrument `r > Duration::ZERO` qui refuse déjà de conclure) : des comparaisons
    //     entre deux mesures, pas des murs ;
    //   * `backup_streaming.rs:691/694` — les durées sont IMPRIMÉES ; les assertions portent sur des
    //     tailles et des comptes de lignes ;
    //   * `vieillissement_serie.rs:633` et `entrees_scriptees_bornees.rs:237` — bornes INFÉRIEURES
    //     posées après un sommeil injecté : structurellement insensibles à la charge (c'est déjà
    //     écrit dans l'ATTENDU de `P6.9-b`) ;
    //   * les quatre `.elapsed()` de CE fichier — ce sont le banc que ce lot ÉTALONNE et la PENTE de
    //     `P6.9-b` (une attente rapportée à une autre, aux deux budgets) : traités par ce lot même,
    //     et c'est de leur traitement que le critère ci-dessus est tiré.
    // CE QUE CE BALAYAGE NE DIT PAS : il porte sur les tests du démon. Les tests des trois autres
    // crates (`agent`, `collector-syslog`, `collector-mail`) n'ont pas été balayés.
    // =============================================================================================

    /// LE TICK DU SONDAGE DISPARU. C'est l'arrondi que (b) doit pouvoir voir ; toute la fenêtre de
    /// validité en est dérivée, aucun de ses bords n'est un chiffre rond choisi à la main.
    const QB_TICK_MS: f64 = 50.0;
    /// PLANCHER DE LA FENÊTRE — INCHANGÉ, et c'est délibéré. Sous cette durée, la requête peut finir
    /// avant que le fil de garde ne se soit endormi : l'arrondi ne serait pas visible ET LE DÉFAUT
    /// NON PLUS. Il vaut quatre fois le démarrage d'un fil (~50 µs), chiffre que la forme précédente
    /// portait déjà. CE QU'IL GARDE, MESURÉ LE 2026-08-27 : avec le sondage réintroduit et une charge
    /// tombée à n=200, le surcoût vaut 43 à 50 ms et le test rougit ; sous le plancher, la course
    /// « la requête finit avant que la garde ne s'endorme » le rendrait vert malgré le défaut.
    /// Desserrer ce plancher ferait donc passer le test sans qu'il prouve rien.
    const QB_PLANCHER_MS: f64 = 0.2;
    /// PLAFOND DE LA FENÊTRE. Au-delà, la durée SQL couvre le tick et l'arrondi ne s'en distingue
    /// plus. Posé à 90 % du tick.
    const QB_PLAFOND_MS: f64 = 0.9 * QB_TICK_MS;
    /// Nombre de tirs par palier. On prend le MINIMUM : il est insensible aux pics de charge, alors
    /// que l'arrondi au tick, lui, est DÉTERMINISTE — il ne peut pas être « chanceux ».
    const QB_TIRS: usize = 7;
    /// Paliers d'étalonnage. Le tir vise le milieu GÉOMÉTRIQUE de la fenêtre et le coût est linéaire
    /// en `n` : deux paliers suffisent en pratique, douze est le filet.
    const QB_PALIERS: usize = 12;
    /// Bornes de charge. EN BAS, c'est 1 — délibérément, et pas un plancher choisi à la main : ce
    /// qui décide de la validité est la FENÊTRE, pas la charge. Une machine si lente qu'une seule
    /// itération dépasse déjà le plafond ne peut pas porter cette mesure, et l'instrument doit le
    /// DIRE au lieu de s'arrêter sur une charge minimale qu'il aurait fallu justifier. En haut :
    /// au-delà, un palier coûterait plus que la fenêtre entière.
    const QB_N_MIN: i64 = 1;
    const QB_N_MAX: i64 = 200_000_000;
    /// Charge de DÉPART — la constante historique. Ce n'est plus une valeur figée, seulement le point
    /// d'entrée de la recherche ; sur cette machine l'étalonnage la corrige au premier palier.
    const QB_N_SEMENCE: i64 = 2_000;

    /// LA MARQUE DU REFUS DE CONCLURE — SOURCE UNIQUE. Elle est LUE ici par
    /// `.github/scripts/check_a_bench_refusal_is_a_distinct_channel.py`, qui la cherche dans ce
    /// fichier plutôt que de la recopier : la changer ici la change là-bas, et la faire disparaître
    /// fait REFUSER la garde au lieu de la rendre verte sur une marque qui n'existe plus.
    const QB_MARQUE_REFUS: &str = "[BANC] INSTRUMENT NON ÉTALONNÉ";

    /// LE CANAL DISTINCT (`P7.19-b`). « Je n'ai pas pu mesurer » ne sort JAMAIS par `assert!` : ni le
    /// même appel, ni le même texte, ni le même code de sortie côté CI (2, posé par le tri de
    /// `ci.yml`, là où une propriété violée laisse passer le code de cargo). La marque est en tête de
    /// message ET sur stderr, pour que le tri soit mécanique et non une lecture d'humain.
    fn qb_refuser_de_conclure(porte: &str, motif: &str, trace: &[String]) -> ! {
        let m = format!(
            "{QB_MARQUE_REFUS} — {porte} : je n'ai pas pu MESURER. Ce n'est PAS une \
             violation de la propriété gardée (le surcoût de la garde n'a pas été jugé) : c'est le \
             témoin qui n'a pas pu être amené dans sa fenêtre de validité [{QB_PLANCHER_MS} ; \
             {QB_PLAFOND_MS} ms]. {motif}\n  paliers d'étalonnage : {}",
            trace.join(" | ")
        );
        eprintln!("{m}");
        panic!("{m}");
    }

    /// L'ÉTALONNAGE. `mesure(n)` rend `(durée SQL minimale, surcoût minimal)` pour la charge `n` ;
    /// on fait varier `n` jusqu'à ce que la durée SQL entre dans la fenêtre, et on rend le surcoût
    /// mesuré AU PALIER RETENU (donc jugé sur une mesure dont la validité vient d'être établie).
    ///
    /// LA RECHERCHE EST PROPORTIONNELLE, pas dichotomique : la CTE récursive coûte linéairement en
    /// `n`, donc `n_suivant = n × (cible / mesuré)` atterrit du premier coup à la précision du bruit.
    /// Le facteur est borné à [0,05 ; 200] pour qu'une mesure aberrante (une préemption au premier
    /// tir) ne projette pas la charge hors des bornes en un pas.
    fn qb_etalonner(
        mesure: &dyn Fn(i64) -> Result<(f64, f64), String>,
    ) -> Result<(i64, f64, f64, Vec<String>), (String, Vec<String>)> {
        let cible = (QB_PLANCHER_MS * QB_PLAFOND_MS).sqrt();
        let mut n = QB_N_SEMENCE;
        let mut trace: Vec<String> = Vec::new();
        let mut vus: Vec<i64> = Vec::new();
        for _ in 0..QB_PALIERS {
            let (sql_ms, surcout_ms) = match mesure(n) {
                Ok(v) => v,
                Err(e) => return Err((format!("la mesure a échoué à n={n} : {e}"), trace)),
            };
            trace.push(format!("n={n} -> SQL {sql_ms:.3} ms"));
            if (QB_PLANCHER_MS..=QB_PLAFOND_MS).contains(&sql_ms) {
                return Ok((n, sql_ms, surcout_ms, trace));
            }
            vus.push(n);
            let facteur = (cible / sql_ms.max(1e-6)).clamp(0.05, 200.0);
            let suivant = ((n as f64) * facteur).round() as i64;
            let suivant = suivant.clamp(QB_N_MIN, QB_N_MAX);
            if suivant == n || vus.contains(&suivant) {
                return Err((
                    format!(
                        "la charge ne progresse plus (n={n} -> {suivant}, bornes [{QB_N_MIN} ; {QB_N_MAX}]) : \
                         soit la machine ne peut pas placer la requête dans la fenêtre, soit le coût de la \
                         CTE ne suit plus la charge"
                    ),
                    trace,
                ));
            }
            n = suivant;
        }
        Err((format!("{QB_PALIERS} palier(s) d'étalonnage sans converger"), trace))
    }

    /// `P7.19-b` — L'ÉTALONNAGE PLACE LE TÉMOIN DANS LA FENÊTRE SUR TOUTE MACHINE, ET IL DIT QUAND
    /// IL NE PEUT PAS. C'est le test de l'INSTRUMENT, pas de la garde de budget : il ne touche à
    /// aucune horloge. `qb_etalonner` reçoit ici un MODÈLE DE COÛT — la CTE récursive est linéaire en
    /// `n`, c'est la seule propriété dont la recherche proportionnelle a besoin — balayé sur SEPT
    /// ordres de grandeur de vitesse machine autour de celle mesurée ici (0,370 ms pour n=2 000 le
    /// 2026-08-27, soit 1,85e-4 ms par itération). Une machine mille fois plus rapide comme une
    /// machine mille fois plus lente doivent toutes deux atterrir DANS la fenêtre, sans que le
    /// plancher ne bouge d'un cheveu.
    ///
    /// LES DEUX TÉMOINS NÉGATIFS disent ce que l'étalonnage ne prétend pas : un coût qui ne dépend
    /// PAS de la charge (une CTE que l'optimiseur aurait effondrée, une horloge en panne) et une
    /// mesure qui échoue rendent tous deux une ERREUR — jamais un verdict, jamais une boucle sans
    /// fin. C'est cette erreur que `qb_refuser_de_conclure` transforme en « je n'ai pas pu mesurer ».
    #[test]
    fn qb_l_etalonnage_place_le_temoin_dans_la_fenetre_sur_toute_machine() {
        /// Coût par itération MESURÉ sur ce banc le 2026-08-27 : 0,370 ms pour n=2 000.
        const QB_COUT_ITERATION_MS: f64 = 1.85e-4;
        for exposant in -3..=3 {
            let k = QB_COUT_ITERATION_MS * 10f64.powi(exposant);
            let mesure = move |n: i64| -> Result<(f64, f64), String> { Ok((n as f64 * k, 0.0)) };
            let (n, sql, _, trace) = qb_etalonner(&mesure).unwrap_or_else(|(m, t)| {
                panic!("machine x10^{exposant} : l'étalonnage a renoncé ({m}) — paliers : {}", t.join(" | "))
            });
            assert!(
                (QB_PLANCHER_MS..=QB_PLAFOND_MS).contains(&sql),
                "machine x10^{exposant} : le témoin retenu (n={n}) coûte {sql:.4} ms, hors de la fenêtre                  [{QB_PLANCHER_MS} ; {QB_PLAFOND_MS}] — paliers : {}",
                trace.join(" | ")
            );
            // LA RECHERCHE EST PROPORTIONNELLE, PAS UN BALAYAGE : sur un coût exactement linéaire, le
            // premier tir atterrit et le second confirme. Plus de trois paliers voudrait dire que la
            // recherche tâtonne, et le filet de `QB_PALIERS` masquerait ce tâtonnement.
            assert!(
                trace.len() <= 3,
                "machine x10^{exposant} : {} paliers pour un coût LINÉAIRE — la visée n'est plus                  proportionnelle : {}",
                trace.len(),
                trace.join(" | ")
            );
        }
        // NÉGATIF (1) — un coût que la charge ne fait pas bouger ne peut pas être amené dans la
        // fenêtre. L'étalonnage doit RENDRE UNE ERREUR : ni boucler, ni prétendre avoir mesuré.
        let plat = |_n: i64| -> Result<(f64, f64), String> { Ok((QB_PLANCHER_MS / 10.0, 0.0)) };
        let (motif, trace) = qb_etalonner(&plat).expect_err(
            "un coût indépendant de la charge NE PEUT PAS entrer dans la fenêtre : l'étalonnage doit renoncer",
        );
        assert!(
            motif.contains("ne progresse plus") || motif.contains("sans converger"),
            "le renoncement doit DIRE pourquoi : {motif}"
        );
        assert!(!trace.is_empty(), "un renoncement rend la trace des paliers, sinon il n'est pas relisible");
        // NÉGATIF (2) — une mesure en échec se propage en erreur, pas en verdict.
        let casse = |_n: i64| -> Result<(f64, f64), String> { Err("stats.elapsed_ms absent".into()) };
        let (motif2, _) = qb_etalonner(&casse).expect_err("une mesure en échec ne peut pas rendre un verdict");
        assert!(motif2.contains("stats.elapsed_ms"), "le renoncement porte la cause rendue par la mesure : {motif2}");
    }

    /// LE PLAFOND DE SURCOÛT — DÉRIVÉ, pas choisi. Le défaut à attraper est l'arrondi au tick : il
    /// vaut au MINIMUM un demi-tick (une requête tirée au hasard dans un tick paie en moyenne un
    /// demi-tick, et le minimum sur `QB_TIRS` tirs d'une requête de durée quasi constante paie
    /// presque le tick entier). Le plafond est donc posé sous le DEMI-tick.
    const QB_SURCOUT_MAX_MS: f64 = QB_TICK_MS / 2.5;

    /// (a) LA PROTECTION MORD, ET SON ATTENTE SUIT LE BUDGET (`P6.9-b`).
    ///
    /// CE QUE LA PROTECTION EXISTE POUR EMPÊCHER : un scan fou qui monopolise un thread de lecture et
    /// un permit du sémaphore sans fin. Le levier de latence ne doit pas l'échanger contre des
    /// millisecondes.
    ///
    /// `P6.9-b` — LA MARGE, CHIFFRÉE, PUIS LA BORNE REMPLACÉE. La forme précédente assertait
    /// `attente < 10 s` sur un budget de 300 ms, et se disait « large » sans jamais avoir chiffré la
    /// marge qui la séparait d'une dégradation réelle. TROIS MESURES faites le 2026-08-27 sur ce banc
    /// (12 cœurs, binaire de test `debug`) disent enfin ce que cette borne gardait, et ce qu'elle ne
    /// gardait pas :
    ///
    ///   * NOMINAL — l'attente vaut le budget plus une latence d'interruption de **0,2 ms** au repos.
    ///     La borne mordait donc à 33 fois le nominal : elle ne risquait pas de rougir sous charge,
    ///     ce qui veut aussi dire qu'elle ne surveillait presque rien ;
    ///   * MUTATION « LA GARDE NE TIRE JAMAIS » — la requête témoin va au bout : **71 203 ms** mesurés.
    ///     C'est la seule dégradation que la borne à 10 s séparait du nominal, et l'assertion
    ///     `expect_err` la voit de toute façon avant elle ;
    ///   * MUTATION « DÉLAI FIXE » — la garde tire à 300 ms en ignorant le budget qu'on lui donne :
    ///     attentes mesurées **300,2 ms à 200 ms de budget et 300,2 ms à 800 ms**. LA BORNE ABSOLUE
    ///     RESTAIT VERTE. C'est la dégradation qu'elle ne séparait de rien, et c'est elle qui justifie
    ///     de remplacer la borne plutôt que de la resserrer.
    ///
    /// LA FORME NEUVE EST UNE CONCORDANCE, prise DANS LA MÊME EXÉCUTION : la même requête est lancée
    /// sous DEUX budgets dans un rapport de 4, en alternance, et on exige que la PENTE
    /// `(attente₂ − attente₁) / (budget₂ − budget₁)` vaille 1. La différence annule le coût fixe
    /// (démarrage du fil, préparation, latence d'interruption) et la pente est sans dimension : elle
    /// ne dépend plus de la vitesse de la machine. Sur la mutation « délai fixe », la pente vaut
    /// **0,000** et le test ROUGIT là où l'ancienne borne passait : la forme neuve n'est pas seulement
    /// plus stable, elle est PLUS SÉVÈRE.
    ///
    /// PENTE MESURÉE LE 2026-08-27, TROIS BANCS (la latence d'interruption entre parenthèses) :
    ///
    /// | banc                                        | pente            | latence d'interruption |
    /// |---------------------------------------------|------------------|------------------------|
    /// | au repos                                    | 1,000 (x3)       | 0,2 à 0,3 ms           |
    /// | 24 brûleurs sur 12 cœurs (machine à 2x)     | 1,002/0,999/1,001| 1,7 à 3,4 ms           |
    /// | 8 brûleurs épinglés sur le cœur du test     | 0,987 / 0,988    | 9,7 à 17,6 ms          |
    ///
    /// La latence d'interruption est donc multipliée par ~60 entre le repos et la charge la plus dure,
    /// et la pente bouge de 1,3 % : c'est exactement ce que la différence est censée annuler.
    ///
    /// CE QUI RESTE ABSOLU, ET CE QUE ÇA VAUT : `QB_FILET_MS`, à 9 600 ms — plus SERRÉ que les 10 s
    /// qu'il remplace, et sept fois sous les 71 203 ms d'une garde qui ne tire pas. Ce n'est pas une
    /// mesure, c'est un FILET : sans lui, une garde qui ne tirerait jamais ferait pendre la suite au
    /// lieu de parler. Le franchir ne dit pas « machine lente », il dit « la garde n'a pas tiré », et
    /// le test le DIT.
    #[test]
    fn budget_guard_interrupts_a_runaway_query() {
        /// Les deux budgets, dans un rapport de 4 EXACT. Le petit est celui de la forme précédente.
        const QB_BUDGET_1: u64 = 200;
        const QB_BUDGET_2: u64 = 800;
        /// Rondes alternées : chaque ronde mesure les deux bras l'un après l'autre, donc sous le même
        /// ordonnancement. La MÉDIANE réduit les rondes — sous préemption, une moyenne rapprocherait
        /// les deux bras et la pente deviendrait aveugle.
        const QB_RONDES: usize = 3;
        /// FILET, pas mesure (cf. le commentaire de doc). Il vaut 12 fois le plus gros budget, soit
        /// 9 600 ms : cinq cent fois au-dessus de la pire latence d'interruption mesurée (17,6 ms) et
        /// sept fois sous la durée NATURELLE de la requête témoin (71 203 ms), qui est ce qu'on mesure
        /// quand la garde ne tire pas. Il est PLUS SERRÉ que les 10 000 ms qu'il remplace.
        const QB_FILET_MS: f64 = 12.0 * QB_BUDGET_2 as f64;

        let c = test_db();
        // 400 millions d'itérations : MESURÉ le 2026-08-27 sans garde, 71 203 ms ; ~le budget avec.
        let sql = qb_slow_sql(400_000_000);
        let mut attentes: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
        for _ in 0..QB_RONDES {
            for (bras, budget) in [QB_BUDGET_1, QB_BUDGET_2].into_iter().enumerate() {
                let t0 = std::time::Instant::now();
                let r = crate::query_exec::run_on_conn(&c, ":memory:", &sql, budget, None);
                let attente = t0.elapsed().as_secs_f64() * 1000.0;
                let err = r.expect_err("une requête au-delà de son budget DOIT être interrompue, pas rendue");
                assert!(
                    err.contains("budget"),
                    "l'erreur doit NOMMER le budget (et non se confondre avec une annulation utilisateur) : {err}"
                );
                assert!(
                    attente < QB_FILET_MS,
                    "FILET (pas une borne de mesure) : la garde n'a pas tiré — {attente:.0} ms d'attente \
                     pour un budget de {budget} ms, soit la durée NATURELLE de la requête témoin"
                );
                attentes[bras].push(attente);
            }
        }
        let mediane = |v: &mut Vec<f64>| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let (a1, a2) = (mediane(&mut attentes[0]), mediane(&mut attentes[1]));
        let pente = (a2 - a1) / (QB_BUDGET_2 - QB_BUDGET_1) as f64;
        eprintln!(
            "[P6.9-b] attente médiane : {a1:.1} ms à {QB_BUDGET_1} ms de budget, {a2:.1} ms à {QB_BUDGET_2} ms \
             -> pente {pente:.3} (latence d'interruption : {:.1} et {:.1} ms)",
            a1 - QB_BUDGET_1 as f64,
            a2 - QB_BUDGET_2 as f64
        );
        /// TOLÉRANCE SUR LA PENTE, dérivée de la mesure du 2026-08-27 (le tableau des trois bancs est
        /// dans le commentaire de doc) : la pente vaut 1,000 au repos et 0,987 sous la charge la plus
        /// dure, soit un écart maximal OBSERVÉ de 1,3 %. La fenêtre est posée à [0,5 ; 2], soit
        /// trente-huit fois cet écart par le bas, pour absorber une préemption qui tomberait sur le
        /// seul bras long ; elle exclut toujours la pente 0,000 que rend une garde qui ignore son
        /// budget (mesurée par mutation), et la pente ≫ 1 d'une garde qui tire bien après l'échéance.
        const QB_PENTE_MIN: f64 = 0.5;
        const QB_PENTE_MAX: f64 = 2.0;
        assert!(
            (QB_PENTE_MIN..=QB_PENTE_MAX).contains(&pente),
            "L'ATTENTE NE SUIT PLUS LE BUDGET : {a1:.1} ms à {QB_BUDGET_1} ms et {a2:.1} ms à {QB_BUDGET_2} ms \
             donnent une pente de {pente:.3} au lieu de 1. Une pente proche de 0 = la garde tire à un délai \
             qui ne dépend pas du budget (ou ne tire pas) ; une pente ≫ 1 = elle tire bien après l'échéance."
        );
    }

    /// (b) LA GARDE NE QUANTIFIE PLUS LA LATENCE — sur les DEUX portes d'exécution bornées du daemon
    /// (`run_on_conn`, qui sert /api/query, et `read_with_watchdog`, qui sert alertes/cases/fraîcheur/
    /// /api/search). On mesure le SURCOÛT (mur total − durée SQL rapportée) et on prend le MINIMUM sur
    /// plusieurs tirs : le minimum est insensible aux pics de charge, alors que l'arrondi au tick, lui,
    /// est DÉTERMINISTE (il ne peut pas être « chanceux »). Avec le sondage `sleep(50 ms)`, ce minimum
    /// valait ~50 ms − durée SQL ; ici il doit rester sous le DEMI-tick.
    ///
    /// `P7.19-b` — LA CHARGE DU TÉMOIN EST ÉTALONNÉE À L'EXÉCUTION, jamais écrite en dur : voir le
    /// pavé au-dessus de `qb_etalonner`. Ce que le test juge est mesuré au palier retenu, donc sur une
    /// mesure dont la validité vient d'être établie sur CETTE machine.
    #[test]
    fn budget_guard_does_not_quantize_query_latency() {
        let c = test_db();

        // ---- porte 1 : `run_on_conn` (/api/query) ------------------------------------------------
        let mesure1 = |n: i64| -> Result<(f64, f64), String> {
            let sql = qb_slow_sql(n);
            let (mut min_sql, mut min_sur) = (f64::MAX, f64::MAX);
            for _ in 0..QB_TIRS {
                let t0 = std::time::Instant::now();
                let v = crate::query_exec::run_on_conn(&c, ":memory:", &sql, 60_000, None)?;
                let mur_ms = t0.elapsed().as_secs_f64() * 1000.0;
                let sql_ms = v["stats"]["elapsed_ms"].as_f64().ok_or("stats.elapsed_ms absent du résultat")?;
                min_sql = min_sql.min(sql_ms);
                min_sur = min_sur.min(mur_ms - sql_ms);
            }
            Ok((min_sql, min_sur))
        };
        let (n1, sql1, surcout1, trace1) = match qb_etalonner(&mesure1) {
            Ok(v) => v,
            Err((motif, trace)) => qb_refuser_de_conclure("run_on_conn", &motif, &trace),
        };
        eprintln!("[P7.19-b] run_on_conn : étalonné à n={n1} (SQL {sql1:.3} ms) — paliers : {}", trace1.join(" | "));
        assert!(
            surcout1 < QB_SURCOUT_MAX_MS,
            "run_on_conn : surcoût minimal {surcout1:.2} ms (charge étalonnée n={n1}, SQL {sql1:.3} ms) — \
             au-delà de {QB_SURCOUT_MAX_MS} ms la latence est arrondie au tick de {QB_TICK_MS} ms de la \
             garde : le sondage est revenu"
        );

        // ---- porte 2 : `read_with_watchdog` (alertes / cases / fraîcheur / /api/search) -----------
        // Elle prend une connexion DANS LE POOL du db_path ; on l'exerce sur une base fichier
        // temporaire pour que le pool puisse l'ouvrir.
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("budget-guard");
        let dir = _tmpg1.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let dbp = dir.join("q.db");
        let dbps = dbp.to_string_lossy().to_string();
        {
            let c2 = Connection::open(&dbp).unwrap();
            c2.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&c2), "fixture de test : la chaîne de migrations doit aller au bout");
        }
        let mesure2 = |n: i64| -> Result<(f64, f64), String> {
            let sql = qb_slow_sql(n);
            let (mut min_sql, mut min_sur) = (f64::MAX, f64::MAX);
            for _ in 0..QB_TIRS {
                let t0 = std::time::Instant::now();
                let sql_ms = crate::query_exec::read_with_watchdog(&dbps, -1.0f64, |conn| {
                    let t1 = std::time::Instant::now();
                    let _n: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
                    t1.elapsed().as_secs_f64() * 1000.0
                });
                if sql_ms < 0.0 {
                    return Err("read_with_watchdog n'a pas pu ouvrir la base de test".into());
                }
                min_sql = min_sql.min(sql_ms);
                min_sur = min_sur.min(t0.elapsed().as_secs_f64() * 1000.0 - sql_ms);
            }
            Ok((min_sql, min_sur))
        };
        let (n2, sql2, surcout2, trace2) = match qb_etalonner(&mesure2) {
            Ok(v) => v,
            Err((motif, trace)) => qb_refuser_de_conclure("read_with_watchdog", &motif, &trace),
        };
        eprintln!("[P7.19-b] read_with_watchdog : étalonné à n={n2} (SQL {sql2:.3} ms) — paliers : {}", trace2.join(" | "));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            surcout2 < QB_SURCOUT_MAX_MS,
            "read_with_watchdog : surcoût minimal {surcout2:.2} ms (charge étalonnée n={n2}, SQL {sql2:.3} ms) — \
             la latence des listes/panneaux est arrondie au tick de {QB_TICK_MS} ms de la garde"
        );
    }

    /// (c) AUCUNE AUTRE PORTE. Le défaut corrigé n'était pas « une ligne à changer » : c'était DEUX
    /// gardes de budget écrites à la main, chacune avec sa boucle de sondage, et rien n'empêchait une
    /// troisième d'apparaître. L'invariant DÉRIVÉ est : un `InterruptHandle` ne peut être armé que par
    /// les deux mécanismes sanctionnés — `budget_guard` (budget temps, attente à CONDITION) ou
    /// `cancel_register` (annulation utilisateur). Tout nouveau site qui prendrait un handle pour
    /// piloter son propre fil de garde fait rougir ce test, sans qu'il ait besoin d'être énuméré ici.
    #[test]
    fn budget_guard_is_the_only_way_to_arm_an_interrupt() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites: Vec<(String, String)> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    // `src/tests/` est du code de test : il a le droit d'exercer les primitives.
                    if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                        continue;
                    }
                    stack.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                let src = std::fs::read_to_string(&p).unwrap();
                for line in src.lines() {
                    if line.contains("get_interrupt_handle()") {
                        sites.push((p.strip_prefix(&root).unwrap().to_string_lossy().to_string(), line.trim().to_string()));
                    }
                }
            }
        }
        assert!(!sites.is_empty(), "invariant vide = invariant mort : aucun site d'armement trouvé, la sonde est cassée");
        for (file, line) in &sites {
            assert!(
                line.contains("budget_guard(") || line.contains("cancel_register("),
                "{file} arme un InterruptHandle hors des deux mécanismes sanctionnés \
                 (`budget_guard` = budget temps par attente à condition, `cancel_register` = annulation \
                 utilisateur). Une garde écrite à la main réintroduit le sondage et son arrondi : {line}"
            );
        }
        // Et le sondage lui-même ne doit plus exister dans l'exécuteur de lecture : c'est là que les
        // deux boucles vivaient, et c'est la forme (pas le site) qu'on interdit.
        let qe = std::fs::read_to_string(root.join("query_exec.rs")).unwrap();
        assert!(
            !qe.lines().any(|l| l.contains("thread::sleep") && !l.trim_start().starts_with("//")),
            "query_exec.rs ne doit plus attendre par SONDAGE : une garde de budget attend une CONDITION (condvar avec délai)"
        );
    }

    // ===================== P7.3-b/c — L'EXPORT AVOUE DANS LE FICHIER =====================
    // Le handler `export` n'avait AUCUN test. Ce qui est éprouvé ici, c'est la RÈGLE : ce que le
    // nom du fichier doit dire, pour toute combinaison (tronqué ?, ampleur connue ?).

    /// L'INVARIANT ANTI-OUBLI, dérivé sur la famille ENTIÈRE des cas plutôt qu'énuméré sur trois
    /// exemples choisis : la marque est présente SI ET SEULEMENT SI le résultat est tronqué. Aucun
    /// couple (tronqué, ampleur) ne peut produire un nom d'apparence complète.
    #[test]
    fn la_marque_de_troncature_est_presente_exactement_quand_le_resultat_est_tronque() {
        for tronque in [false, true] {
            for ecartes in [None, Some(-1), Some(0), Some(1), Some(42), Some(16_420)] {
                let m = marque_troncature(tronque, ecartes);
                assert_eq!(
                    !m.is_empty(), tronque,
                    "marque présente <=> tronqué (tronqué={tronque}, ecartes={ecartes:?}, marque={m:?})"
                );
                if tronque {
                    assert!(m.contains("TRONQUE"), "un nom tronqué doit se lire comme tel : {m:?}");
                }
            }
        }
    }

    /// L'AMPLEUR quand elle est connue — le NOMBRE lui-même est dans le nom, pas seulement un
    /// drapeau. C'est ce qui manquait au top-N, où une perte jusqu'à x16,42 tenait dans un booléen.
    #[test]
    fn la_marque_porte_le_nombre_de_lignes_manquantes_quand_il_est_mesure() {
        for n in [1_i64, 7, 4_242] {
            let m = marque_troncature(true, Some(n));
            assert!(m.contains(&n.to_string()), "l'ampleur mesurée ({n}) doit figurer dans le nom : {m:?}");
            assert!(!m.contains("inconnue"), "ampleur mesurée -> jamais « inconnue » : {m:?}");
        }
    }

    /// UNE AMPLEUR NON ÉTABLIE S'AVOUE — elle n'est pas repliée sur zéro. `None` (sonde sans base)
    /// et `Some(0)` (aucune ligne écartée COMPTÉE) valent tous deux « inconnue » ici : le plafond a
    /// mordu, donc annoncer « 0 ligne manquante » serait un chiffre faux, pas une absence de perte.
    #[test]
    fn une_ampleur_non_etablie_est_avouee_pas_supposee_nulle() {
        for ecartes in [None, Some(0), Some(-3)] {
            let m = marque_troncature(true, ecartes);
            assert!(m.contains("ampleur-inconnue"), "ampleur non établie ({ecartes:?}) -> aveu explicite : {m:?}");
            assert!(!m.contains("-0-"), "jamais « 0 ligne manquante » sur une ampleur non établie : {m:?}");
        }
    }
