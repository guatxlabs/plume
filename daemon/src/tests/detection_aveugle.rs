    // `P3.9-a` — UNE RÈGLE ABANDONNÉE À RÉPÉTITION LÈVE UNE ALERTE, ET UNE SEULE.
    //
    // CE QUE LA SUITE TIENT, DANS LES DEUX SENS, sur une base sur DISQUE (l'ordonnanceur évalue sur
    // une connexion de lecture ouverte par chemin) :
    //   ① N abandons consécutifs d'une règle -> UNE alerte de cécité (clé de déduplication stable), dont
    //     le titre nomme la règle, la CAUSE et le NOMBRE ; un abandon de plus ne la duplique pas ;
    //   ② N−1 abandons -> RIEN (le témoin inverse : une émission au premier abandon rougit ici) ;
    //   ③ une évaluation réussie après N -> l'alerte est RÉSOLUE, la clé libérée, le compte à zéro, et un
    //     épisode suivant s'ouvre à nouveau (une clé jamais libérée rougit ici) ;
    //   ④ deux règles en échec -> deux alertes, chacune à son nom ;
    //   ⑤ chaque cause rendue appartient à l'ensemble fermé, et le seuil est DÉRIVÉ de l'intervalle.
    // Les échecs sont DÉTERMINISTES : une table absente (erreur de requête), une cellule textuelle (non
    // numérique), une requête SOQL que le compilateur refuse — jamais une course contre un budget, sauf
    // dans le témoin qui vise précisément le chien de garde, et qui l'appelle avec SON budget.
    //
    // La GARDE DÉRIVÉE (`toute_replanification_sans_evaluation_passe_par_le_consignateur`) relit les
    // évaluateurs de règles du démon — toute fonction qui compte des abandons ET lit la table `rule` —
    // et exige que chacun consigne, ou soit nommé comme écart avec sa raison.
    use crate::detection_aveugle::{
        cle_dedup, consigner_abandon, evaluer_valeur_de_regle, seuil_d_abandons_consecutifs, AbandonDEvaluation,
        CAUSES_D_ABANDON, CAUSE_BUDGET_DEPASSE, CAUSE_COMPILATION_REFUSEE, CAUSE_ERREUR_REQUETE,
        CAUSE_EVALUATEUR_EN_PANNE, CAUSE_VALEUR_NON_NUMERIQUE, FAMILLE_ALERTE, HORIZON_DE_CECITE_S, PLANCHER_D_ABANDONS,
    };

    /// L'intervalle des témoins : dix minutes, l'intervalle de la règle livrée que l'incident a
    /// éteinte ; le seuil en est DÉRIVÉ (six), jamais recopié.
    const INTERVALLE_TEMOIN_S: i64 = 600;

    fn base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
        }
        (tmp, db, p)
    }

    /// Une règle SQL BRUT (pas de compilation) — son échec est celui de SA requête, déterministe.
    fn regle_brute(conn: &Connection, nom: &str, sql: &str) -> i64 {
        conn.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
             VALUES(?1,1,?2,0,'>',1000000,3,?3,3600)",
            params![nom, sql, INTERVALLE_TEMOIN_S],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Un tick où la règle est DUE : `last_run` est effacé (l'ordonnanceur ne re-évalue une règle
    /// qu'après son intervalle, et les témoins ne peuvent pas attendre dix minutes).
    fn tick(db: &Arc<Mutex<Connection>>, p: &str) -> Mesure<u32> {
        db.lock().execute("UPDATE rule SET last_run=NULL", []).unwrap();
        run_due_rules(db, p)
    }

    fn alertes_de_cecite(conn: &Connection, id: i64) -> Vec<(String, String, Option<String>)> {
        let mut st = conn
            .prepare("SELECT title, status, dedup FROM alert WHERE rule=?1 ORDER BY id")
            .unwrap();
        st.query_map(params![format!("{FAMILLE_ALERTE}.{id}")], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect()
    }

    fn abandons_consecutifs(conn: &Connection, id: i64) -> i64 {
        conn.query_row("SELECT abandons_consecutifs FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap()
    }

    /// ⑤ LE SEUIL EST DÉRIVÉ : le nombre d'intervalles dans l'horizon, arrondi vers le haut, jamais
    /// sous le plancher. Les valeurs attendues sont RECALCULÉES ici depuis les constantes, pas recopiées.
    #[test]
    fn le_seuil_est_derive_de_l_intervalle_et_plancher() {
        let attendu = |i: i64| -> u32 { u32::try_from((HORIZON_DE_CECITE_S + i - 1) / i).unwrap().max(PLANCHER_D_ABANDONS) };
        assert_eq!(seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S), attendu(INTERVALLE_TEMOIN_S));
        assert_eq!(seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S), 6, "dix minutes : six abandons = une heure aveugle");
        assert_eq!(seuil_d_abandons_consecutifs(1000), 4, "arrondi vers le HAUT (3,6 -> 4) : jamais moins d'une heure");
        assert_eq!(seuil_d_abandons_consecutifs(HORIZON_DE_CECITE_S), PLANCHER_D_ABANDONS, "une règle horaire : le plancher");
        assert_eq!(seuil_d_abandons_consecutifs(HORIZON_DE_CECITE_S * 4), PLANCHER_D_ABANDONS, "plus lent que l'horizon : le plancher, jamais 1");
        assert_eq!(seuil_d_abandons_consecutifs(0), seuil_d_abandons_consecutifs(1), "un intervalle nul compte comme une seconde");
        assert!(PLANCHER_D_ABANDONS >= 2, "un seuil de 1 ferait alerter au premier abandon — le témoin inverse n'aurait plus de sens");
    }

    /// ⑤ CHAQUE CAUSE RENDUE EST DANS L'ENSEMBLE FERMÉ, et chaque famille d'échec rend SA cause : table
    /// absente, cellule textuelle, aucune ligne, compilation refusée, fil en panique, et le chien de garde
    /// appelé avec un budget d'une milliseconde sur une requête qui en demande des milliers.
    #[test]
    fn chaque_famille_d_echec_rend_sa_cause_dans_l_ensemble_ferme() {
        let (_tmp, _db, p) = base_sur_disque("p39a-causes");
        let cas: Vec<(&str, Result<f64, AbandonDEvaluation>)> = vec![
            ("table absente", evaluer_valeur_de_regle(&p, "SELECT count(*) FROM table_absente_p39a", 5000)),
            ("cellule textuelle", evaluer_valeur_de_regle(&p, "SELECT 'abc'", 5000)),
            ("aucune ligne", evaluer_valeur_de_regle(&p, "SELECT 1 WHERE 0", 5000)),
            (
                "chien de garde",
                evaluer_valeur_de_regle(
                    &p,
                    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 200000000) SELECT count(*) FROM c",
                    1,
                ),
            ),
        ];
        let attendu = [CAUSE_ERREUR_REQUETE, CAUSE_VALEUR_NON_NUMERIQUE, CAUSE_VALEUR_NON_NUMERIQUE, CAUSE_BUDGET_DEPASSE];
        for ((quoi, r), cause) in cas.iter().zip(attendu) {
            let a = r.as_ref().expect_err(&format!("{quoi} : une évaluation qui devait être abandonnée a rendu une valeur"));
            assert_eq!(a.cause, cause, "{quoi} : {}", a.detail);
            assert!(CAUSES_D_ABANDON.contains(&a.cause), "{quoi} : cause hors de l'ensemble fermé");
            assert!(!a.detail.is_empty(), "{quoi} : le détail est vide");
        }
        assert_eq!(AbandonDEvaluation::compilation_refusee("x").cause, CAUSE_COMPILATION_REFUSEE);
        assert_eq!(AbandonDEvaluation::evaluateur_en_panne().cause, CAUSE_EVALUATEUR_EN_PANNE);
        // TÉMOIN INVERSE : une requête saine rend sa valeur, et un VRAI zéro est une valeur.
        assert_eq!(evaluer_valeur_de_regle(&p, "SELECT count(*) FROM rule", 5000), Ok(0.0));
        assert_eq!(evaluer_valeur_de_regle(&p, "SELECT 2.5", 5000), Ok(2.5));
    }

    /// ① ② ③ — LE CŒUR : N−1 abandons -> rien ; le N-ième -> une alerte qui nomme règle, cause et nombre ;
    /// un de plus -> toujours UNE (titre rafraîchi) ; une évaluation réussie -> résolue, clé libérée,
    /// compte à zéro ; et l'épisode suivant s'ouvre à nouveau.
    #[test]
    fn n_abandons_consecutifs_levent_une_alerte_une_seule_resolue_au_retour() {
        let (_tmp, db, p) = base_sur_disque("p39a-coeur");
        let id = regle_brute(&db.lock(), "p39a-fuite", "SELECT count(*) FROM table_absente_p39a");
        let seuil = seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S);

        // ② N−1 abandons : comptés, persistés, AUCUNE alerte.
        for k in 1..seuil {
            assert_eq!(tick(&db, &p), Mesure::Lue(1), "tick {k} : l'abandon reste compté pour le bilan du tick");
            let conn = db.lock();
            assert_eq!(abandons_consecutifs(&conn, id), i64::from(k), "le compte consécutif persiste en base");
            assert!(alertes_de_cecite(&conn, id).is_empty(), "tick {k} (< seuil {seuil}) : aucune alerte — le témoin inverse");
        }

        // ① le N-ième : UNE alerte, ouverte, à la clé stable de la règle, qui nomme règle, cause et nombre.
        assert_eq!(tick(&db, &p), Mesure::Lue(1));
        {
            let conn = db.lock();
            let a = alertes_de_cecite(&conn, id);
            assert_eq!(a.len(), 1, "exactement une alerte au seuil : {a:?}");
            let (titre, statut, dedup) = &a[0];
            assert_eq!(statut, "new");
            assert_eq!(dedup.as_deref(), Some(cle_dedup(id).as_str()), "la clé de déduplication est celle de la règle");
            assert!(titre.contains("détection aveugle"), "{titre}");
            assert!(titre.contains("p39a-fuite"), "le titre nomme la règle : {titre}");
            assert!(titre.contains(CAUSE_ERREUR_REQUETE), "le titre nomme la cause : {titre}");
            assert!(titre.contains(&format!("{seuil} évaluations")), "le titre porte le nombre : {titre}");
            let sev: i64 = conn.query_row("SELECT severity FROM alert WHERE dedup=?1", params![cle_dedup(id)], |r| r.get(0)).unwrap();
            assert_eq!(sev, 3, "l'alerte vaut la sévérité de la règle qu'elle éteint");
            let detail: String = conn.query_row("SELECT detail FROM alert WHERE dedup=?1", params![cle_dedup(id)], |r| r.get(0)).unwrap();
            assert!(detail.contains("table_absente_p39a"), "le détail porte l'erreur telle que la base l'a dite : {detail}");
            let sources: String = conn.query_row("SELECT sources FROM alert WHERE dedup=?1", params![cle_dedup(id)], |r| r.get(0)).unwrap();
            assert_eq!(sources, imputation_encoder(&[SOURCE_INDETERMINABLE.to_string()]), "imputée à l'inconnu NOMMÉ : une règle éteinte n'accuse aucun feed");
        }

        // ① un abandon de plus : toujours UNE alerte (dédupliquée), au nombre rafraîchi.
        assert_eq!(tick(&db, &p), Mesure::Lue(1));
        {
            let conn = db.lock();
            let a = alertes_de_cecite(&conn, id);
            assert_eq!(a.len(), 1, "un abandon de plus ne duplique pas l'alerte : {a:?}");
            assert!(a[0].0.contains(&format!("{} évaluations", seuil + 1)), "le nombre est rafraîchi : {}", a[0].0);
            let total: i64 = conn.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
            assert_eq!(total, 1, "aucune autre alerte n'a été fabriquée (ni tir de règle sur un 0.0 inventé)");
        }

        // ③ la règle évalue à nouveau : résolue, clé libérée, compte à zéro — et ce tick est un VRAI zéro.
        db.lock().execute("UPDATE rule SET query='SELECT count(*) FROM rule' WHERE id=?1", params![id]).unwrap();
        assert_eq!(tick(&db, &p), Mesure::Lue(0));
        {
            let conn = db.lock();
            let a = alertes_de_cecite(&conn, id);
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].1, "resolved", "l'alerte est résolue au retour : {a:?}");
            assert_eq!(a[0].2, None, "la clé est LIBÉRÉE (dedup NULL), comme un retour sous le seuil");
            assert_eq!(abandons_consecutifs(&conn, id), 0, "le compte est remis à zéro à la première réussite");
        }

        // ③ l'épisode suivant s'ouvre à nouveau : N abandons -> une SECONDE ligne, la première restant résolue.
        db.lock().execute("UPDATE rule SET query='SELECT count(*) FROM table_absente_p39a' WHERE id=?1", params![id]).unwrap();
        for _ in 0..seuil {
            tick(&db, &p);
        }
        {
            let conn = db.lock();
            let a = alertes_de_cecite(&conn, id);
            assert_eq!(a.len(), 2, "un nouvel épisode ouvre une nouvelle alerte : {a:?}");
            assert_eq!((a[0].1.as_str(), a[1].1.as_str()), ("resolved", "new"));
            assert_eq!(a[1].2.as_deref(), Some(cle_dedup(id).as_str()));
        }
    }

    /// ② LE COMPTE NE COMPTE QUE LE CONSÉCUTIF : N−1 abandons, une réussite, N−1 abandons -> rien. Une
    /// mise en œuvre qui compterait les abandons CUMULÉS rougit ici.
    #[test]
    fn une_reussite_entre_deux_series_remet_le_compte_a_zero() {
        let (_tmp, db, p) = base_sur_disque("p39a-consecutif");
        let id = regle_brute(&db.lock(), "p39a-intermittente", "SELECT count(*) FROM table_absente_p39a");
        let seuil = seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S);
        for _ in 1..seuil {
            tick(&db, &p);
        }
        db.lock().execute("UPDATE rule SET query='SELECT count(*) FROM rule' WHERE id=?1", params![id]).unwrap();
        tick(&db, &p);
        db.lock().execute("UPDATE rule SET query='SELECT count(*) FROM table_absente_p39a' WHERE id=?1", params![id]).unwrap();
        for _ in 1..seuil {
            tick(&db, &p);
        }
        let conn = db.lock();
        assert_eq!(abandons_consecutifs(&conn, id), i64::from(seuil - 1));
        assert!(alertes_de_cecite(&conn, id).is_empty(), "2×(N−1) abandons séparés par une réussite : aucune alerte");
    }

    /// ④ DEUX RÈGLES EN ÉCHEC, DEUX ALERTES — chacune à son nom et à SA cause (erreur de requête pour
    /// l'une, cellule non numérique pour l'autre) ; une règle SAINE à côté n'en lève aucune.
    #[test]
    fn deux_regles_en_echec_levent_deux_alertes_chacune_a_sa_cause() {
        let (_tmp, db, p) = base_sur_disque("p39a-deux");
        let (a, b, saine) = {
            let conn = db.lock();
            (
                regle_brute(&conn, "p39a-table-absente", "SELECT count(*) FROM table_absente_p39a"),
                regle_brute(&conn, "p39a-texte", "SELECT 'pas un nombre'"),
                regle_brute(&conn, "p39a-saine", "SELECT count(*) FROM rule"),
            )
        };
        let seuil = seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S);
        for _ in 0..seuil {
            assert_eq!(tick(&db, &p), Mesure::Lue(2), "deux abandons par tick, la saine est évaluée");
        }
        let conn = db.lock();
        let aa = alertes_de_cecite(&conn, a);
        let ab = alertes_de_cecite(&conn, b);
        assert_eq!((aa.len(), ab.len()), (1, 1), "une alerte par règle aveugle : {aa:?} / {ab:?}");
        assert!(aa[0].0.contains("p39a-table-absente") && aa[0].0.contains(CAUSE_ERREUR_REQUETE), "{}", aa[0].0);
        assert!(ab[0].0.contains("p39a-texte") && ab[0].0.contains(CAUSE_VALEUR_NON_NUMERIQUE), "{}", ab[0].0);
        assert!(alertes_de_cecite(&conn, saine).is_empty(), "la règle saine n'est pas aveugle");
        assert_eq!(abandons_consecutifs(&conn, saine), 0);
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(total, 2);
    }

    /// UNE RÈGLE SOQL QUE LE COMPILATEUR REFUSE : la cause est `compilation_refusee`, dans le titre.
    #[test]
    fn une_compilation_refusee_est_nommee_comme_telle() {
        let (_tmp, db, p) = base_sur_disque("p39a-compil");
        let id = {
            let conn = db.lock();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('p39a-mal-formee',1,'search | stats count by | where',1,'>',0,2,?1,3600)",
                params![INTERVALLE_TEMOIN_S],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        for _ in 0..seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S) {
            tick(&db, &p);
        }
        let conn = db.lock();
        let a = alertes_de_cecite(&conn, id);
        assert_eq!(a.len(), 1, "{a:?}");
        assert!(a[0].0.contains(CAUSE_COMPILATION_REFUSEE), "{}", a[0].0);
    }

    /// LE CONSIGNATEUR SEUL : sur une règle qui n'existe plus, rien n'est relu et rien n'est posé (une
    /// alerte sur un compte qu'on n'a pas lu serait inventée) ; sur une règle existante, le compte rendu
    /// est celui de la base et l'alerte n'est posée qu'au seuil.
    #[test]
    fn le_consignateur_ne_pose_rien_sur_une_regle_disparue() {
        let (_tmp, db, _p) = base_sur_disque("p39a-disparue");
        let conn = db.lock();
        let abandon = AbandonDEvaluation::compilation_refusee("x");
        assert_eq!(consigner_abandon(&conn, 424242, "fantôme", 2, now(), &abandon), None);
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
        let id = regle_brute(&conn, "p39a-presente", "SELECT 1");
        let c = consigner_abandon(&conn, id, "p39a-presente", 2, now(), &abandon).unwrap();
        assert_eq!((c.consecutifs, c.seuil, c.alerte_posee), (1, seuil_d_abandons_consecutifs(INTERVALLE_TEMOIN_S), false));
    }

    /// LA MIGRATION v116 EST ADDITIVE ET CONVERGENTE : une base dont la table `rule` a la forme v115
    /// (sans la colonne) reçoit la colonne à DEFAULT 0 ; la forme déclarée n'a aucun manque ; le rejeu
    /// est idempotent ; et le compte ÉCRIT survit à une réouverture (il est en base, pas en mémoire).
    #[test]
    fn la_migration_v116_est_additive_et_le_compte_survit_a_une_reouverture() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p39a-v116");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        {
            let conn = open_db(&p).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            // La forme v115 : la MÊME table, sans la colonne, estampillée 115 (DROP COLUMN : SQLite >= 3.35).
            conn.execute_batch(
                "INSERT INTO rule(name) VALUES('p39a-ancienne'); \
                 ALTER TABLE rule DROP COLUMN abandons_consecutifs; \
                 UPDATE meta SET value='115' WHERE key='schema_version';",
            )
            .unwrap();
            let colonnes: Vec<String> = conn
                .prepare("SELECT name FROM pragma_table_info('rule')").unwrap()
                .query_map([], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect();
            assert!(!colonnes.iter().any(|c| c == "abandons_consecutifs"), "témoin : la forme v115 n'a pas la colonne");

            assert!(migrate(&conn), "le rejeu depuis v115 va au bout");
            let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
            assert_eq!(v, CODE_SCHEMA_MAX.to_string());
            let n: i64 = conn.query_row("SELECT abandons_consecutifs FROM rule WHERE name='p39a-ancienne'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "la ligne existante reçoit le DEFAULT 0");
            assert!(migrate(&conn), "idempotent");
            conn.execute("UPDATE rule SET abandons_consecutifs=4 WHERE name='p39a-ancienne'", []).unwrap();
        }
        // Réouverture : le compte est en base.
        let conn = open_db(&p).unwrap();
        assert!(migrate(&conn));
        let n: i64 = conn.query_row("SELECT abandons_consecutifs FROM rule WHERE name='p39a-ancienne'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 4, "le compte consécutif survit à une réouverture du démon");
        // Base NEUVE (schema.sql) et base MIGRÉE convergent : aucun manque déclaré.
        let neuve = open_db(&tmp.sous("neuve.db").chemin().to_string_lossy()).unwrap();
        neuve.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&neuve));
        assert_eq!(schema_gaps(&neuve).unwrap(), Vec::<String>::new());
        assert_eq!(schema_gaps(&conn).unwrap(), Vec::<String>::new());
    }

    /// GARDE DÉRIVÉE — TOUT ÉVALUATEUR DE RÈGLES DU DÉMON CONSIGNE SES ABANDONS, OU EST NOMMÉ.
    ///
    /// La population n'est pas une liste : c'est toute fonction du démon (hors tests) qui COMPTE des
    /// abandons (`abandonnees += 1`) ET lit la table `rule` — la signature d'un évaluateur qui peut
    /// abandonner une règle. Chacune doit appeler `consigner_abandon`, sinon elle doit figurer parmi
    /// les ÉCARTS CONNUS, avec sa raison ; un écart qui n'en est plus un rougit aussi (la liste ne
    /// doit pas survivre à sa correction). L'instrument est validé dans les deux sens : il doit trouver
    /// au moins un évaluateur qui consigne ET les écarts nommés.
    #[test]
    fn toute_replanification_sans_evaluation_passe_par_le_consignateur() {
        // Les écarts connus : même famille d'abandon, hors du périmètre de `P3.9-a` — une règle avancée
        // ou de risque abandonnée à répétition n'a PAS d'alerte de cécité, et c'est écrit ici.
        const ECARTS_CONNUS: [(&str, &str); 2] = [
            ("run_advanced_rules", "règles avancées (fenêtre de suppression / throttle / per-result) : abandons comptés, non consignés"),
            ("run_risk_rules", "règles de risque (RBA) : abandons comptés, non consignés"),
        ];
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        fn marcher(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    if p.file_name().map_or(false, |n| n == "tests") { continue; }
                    marcher(&p, out);
                } else if p.extension().map_or(false, |x| x == "rs") && p.file_name().map_or(true, |n| n != "tests.rs") {
                    out.push(p);
                }
            }
        }
        marcher(&racine, &mut fichiers);
        assert!(fichiers.len() > 50, "l'instrument n'a lu que {} fichiers : la racine est fausse", fichiers.len());
        let tete = regex::Regex::new(r"^(?:pub(?:\(crate\))? )?(?:async )?fn (\w+)").unwrap();
        let lit_rule = regex::Regex::new(r"FROM rule\b").unwrap();
        let mut consignent = Vec::new();
        let mut muets = Vec::new();
        for f in &fichiers {
            let texte = std::fs::read_to_string(f).unwrap();
            let lignes: Vec<&str> = texte.lines().collect();
            let tetes: Vec<(usize, String)> =
                lignes.iter().enumerate().filter_map(|(i, l)| tete.captures(l).map(|c| (i, c[1].to_string()))).collect();
            for (k, (debut, nom)) in tetes.iter().enumerate() {
                let fin = tetes.get(k + 1).map_or(lignes.len(), |t| t.0);
                let corps = lignes[*debut..fin].join("\n");
                if !(corps.contains("abandonnees += 1") && lit_rule.is_match(&corps)) { continue; }
                let site = format!("{}::{nom}", f.strip_prefix(&racine).unwrap().display());
                if corps.contains("consigner_abandon(") { consignent.push(site) } else { muets.push((nom.clone(), site)) }
            }
        }
        // Le SITE d'abord (c'est lui qu'un lecteur doit corriger), le plancher de l'instrument ensuite.
        let non_excuses: Vec<&str> = muets.iter().filter(|(n, _)| !ECARTS_CONNUS.iter().any(|(e, _)| e == n)).map(|(_, s)| s.as_str()).collect();
        assert!(
            non_excuses.is_empty(),
            "évaluateur(s) de règles qui abandonnent SANS consigner (aucune alerte de cécité possible) : {non_excuses:?} — \
             appeler `detection_aveugle::consigner_abandon`, ou nommer l'écart avec sa raison"
        );
        assert!(!consignent.is_empty(), "l'instrument n'a trouvé AUCUN évaluateur qui consigne : il ne peut pas conclure");
        for (e, raison) in ECARTS_CONNUS {
            assert!(
                muets.iter().any(|(n, _)| n == e),
                "l'écart `{e}` ({raison}) n'est plus un écart, ou n'est plus un évaluateur : retirer la ligne (la liste ne survit pas à sa correction)"
            );
        }
    }
