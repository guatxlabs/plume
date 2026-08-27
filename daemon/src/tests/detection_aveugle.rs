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

    // ==============================================================================================
    // `P9.5-a` — UNE RÈGLE QU'AUCUN PRODUCTEUR LIVRÉ NE PEUT DÉCLENCHER N'EST PAS LIVRÉE ACTIVE.
    //
    // Le défaut est SILENCIEUX par construction : la règle s'évalue parfaitement et rend zéro, donc
    // l'ordonnanceur n'a AUCUN abandon à consigner et l'alerte de cécité ci-dessus ne peut pas se poser.
    // Le seul endroit où le mensonge se voit est la MATRICE ATT&CK, qui déclare une technique couverte
    // dès qu'une règle `enabled=1` la tague. Cette suite tient les trois maillons :
    //   ① l'instrument (la lecture des épinglages) est validé sur des témoins POSITIFS et NÉGATIFS,
    //     hors de toute base — un extracteur qui ne reconnaît plus rien rendrait « tout va bien » ;
    //   ② le verdict porte sur la base qu'une installation FRAÎCHE reçoit réellement (le semis est
    //     EXÉCUTÉ, pas relu : une garde qui lirait le texte de `seeds.rs` raterait tout ce que la
    //     migration ou un autre semeur ajoute), dans les DEUX sens — aucune active aveugle, et au
    //     moins une éteinte POUR CETTE RAISON, sans quoi la dérivation aurait pu être retirée en
    //     laissant le vert ;
    //   ③ la conséquence de sécurité, tenue à l'autre bout : la matrice ne doit annoncer COUVERTE
    //     aucune technique dont les seules règles qui la taguent sont éteintes faute de producteur.
    //
    // PORTÉE, DITE FRANCHEMENT : le VERROU au semis n'est posé que dans `seed_detection_rules`, là où le
    // défaut a été mesuré. Cette garde, elle, juge TOUTES les règles actives d'une base neuve : un autre
    // semeur qui introduirait le défaut la fait rougir, et la réponse sera d'étendre le verrou, jamais
    // d'excepter la règle.

    /// Une base NEUVE, semée exactement comme une installation fraîche (`seed_tenant_content` est le
    /// point unique que le démarrage du serveur et la création d'un tenant partagent).
    fn base_semee(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        crate::tenants::seed_tenant_content(&conn);
        (tmp, conn)
    }

    #[test]
    fn aucune_regle_semee_active_n_exige_une_source_sans_producteur_livre() {
        use crate::detection_aveugle::{producteur_livre, sources_exigees, sources_sans_producteur_livre, SourcesExigees};

        // ① L'INSTRUMENT AVANT LE VERDICT — ce qu'il DOIT lire, et ce qu'il ne DOIT PAS prendre pour un
        //    épinglage. Chaque ligne fausse ci-dessous a une conséquence : sur-lire accuse une règle
        //    saine, sous-lire blanchit une règle éteinte.
        let litterales = |q: &str| match sources_exigees(q) {
            SourcesExigees::Litterales(v) => v,
            autre => panic!("épinglages littéraux attendus pour `{q}`, obtenu {autre:?}"),
        };
        assert_eq!(litterales("search source=vault-audit operation=read | stats count"), vec!["vault-audit".to_string()]);
        assert_eq!(
            litterales("SELECT COUNT(*) FROM event WHERE source='crowdsec' AND category='health'"),
            vec!["crowdsec".to_string()],
            "le SQL brut épingle avec des guillemets : la lecture ne dépend pas de la langue de la requête"
        );
        assert_eq!(
            litterales(crate::ATTACKER_UNMITIGATED_RULE_SQL).len(),
            2,
            "les DEUX branches du UNION sont lues — sinon une disjonction serait jugée sur une seule moitié"
        );
        assert_eq!(
            litterales("search source=cloudflare action=blocked cf_source=firewallManaged | stats count"),
            vec!["cloudflare".to_string()],
            "`cf_source` est un CHAMP brut de Cloudflare, pas la source de l'événement"
        );
        assert_eq!(sources_exigees("search category=auth action=failure | stats count"), SourcesExigees::Aucune);
        assert_eq!(
            sources_exigees("search category=auth | stats count by source | sort -count"),
            SourcesExigees::Aucune,
            "grouper PAR source n'épingle aucune source"
        );
        assert_eq!(
            sources_exigees("search source!=web | stats count"),
            SourcesExigees::Aucune,
            "une exclusion n'exige rien : elle retire, elle ne demande pas"
        );
        assert_eq!(sources_exigees("search source=~sshd | stats count"), SourcesExigees::NonDecidable);
        assert_eq!(sources_exigees("search source=cloud* | stats count"), SourcesExigees::NonDecidable);
        assert_eq!(sources_exigees("SELECT 1 FROM event WHERE source IN ('a','b')"), SourcesExigees::NonDecidable);
        assert_eq!(
            sources_exigees("SELECT 1 FROM event WHERE message='source=vault-audit'"),
            SourcesExigees::Aucune,
            "un texte CITÉ n'est pas un épinglage — sinon une phrase recherchée fabriquerait un aveugle"
        );
        // Et l'oracle de production, dans les deux sens : AGRÉGER n'est pas PRODUIRE.
        assert!(producteur_livre("web") && producteur_livre("plume-auth") && producteur_livre("portscan"));
        assert!(
            !producteur_livre("vault-audit"),
            "`vault-audit` est ATTENDUE parce que le produit l'agrège ; aucun fichier livré ne l'émet — \
             confondre les deux est exactement le faux vert que cette clé ferme"
        );
        assert!(sources_sans_producteur_livre("search source=web | stats count").is_empty());
        assert_eq!(
            sources_sans_producteur_livre("search source=vault-audit | stats count"),
            vec!["vault-audit".to_string()]
        );

        // ② LE VERDICT, SUR LA BASE QU'UNE INSTALLATION FRAÎCHE REÇOIT.
        let (_tmp, conn) = base_semee("regle-sans-producteur");
        let lignes: Vec<(String, String, i64, String)> = {
            let mut stmt = conn
                .prepare("SELECT name, query, enabled, COALESCE(mitre,'') FROM rule ORDER BY id")
                .unwrap();
            let v = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .flatten()
                .collect();
            v
        };
        assert!(
            lignes.len() >= 40,
            "l'instrument n'a pas semé de base : {} règles lues (48 mesurées le 2026-08-27 ; le plancher laisse la place aux \
             ajouts légitimes, il n'épingle que « le semis a bien tourné »)",
            lignes.len()
        );
        let mut actives_aveugles: Vec<String> = Vec::new();
        let mut eteintes_faute_de_producteur: Vec<(String, String)> = Vec::new();
        let mut actives_nourrissables = 0usize;
        for (nom, q, actif, mitre) in &lignes {
            let manque = sources_sans_producteur_livre(q);
            if manque.is_empty() {
                if *actif == 1 && !matches!(sources_exigees(q), SourcesExigees::Aucune) {
                    actives_nourrissables += 1;
                }
            } else if *actif == 1 {
                actives_aveugles.push(format!("« {nom} » exige {}", manque.join(", ")));
            } else {
                eteintes_faute_de_producteur.push((nom.clone(), mitre.clone()));
            }
        }
        assert!(
            actives_aveugles.is_empty(),
            "règle(s) semée(s) ACTIVES qu'aucun producteur livré ne peut déclencher : {actives_aveugles:?}. \
             Elles ne tireront jamais ET feront compter leur technique comme couverte par la matrice ATT&CK. \
             Les semer éteintes (`actif_si_un_producteur_livre_existe`), ou livrer le producteur."
        );
        assert!(
            !eteintes_faute_de_producteur.is_empty(),
            "AUCUNE règle n'est éteinte faute de producteur : soit la dérivation ne voit plus rien, soit le \
             verrou du semis a été retiré — dans les deux cas ce vert ne prouve rien"
        );
        assert!(
            actives_nourrissables >= 10,
            "seulement {actives_nourrissables} règle(s) active(s) épinglent une source PRODUITE : la lecture \
             des épinglages ne reconnaît plus le corpus, elle rendrait vert sur n'importe quoi"
        );

        // ③ LA CONSÉQUENCE DE SÉCURITÉ : ce que la matrice ANNONCE couvert.
        let tags_actifs: Vec<String> = lignes.iter().filter(|(_, _, a, m)| *a == 1 && !m.is_empty()).map(|(_, _, _, m)| m.clone()).collect();
        let matrice = crate::handlers::alerts::build_attack_matrix(&tags_actifs, &[], &std::collections::HashMap::new());
        let mut couvertes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut non_couvertes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for tactique in matrice.get("tactics").and_then(|t| t.as_array()).into_iter().flatten() {
            for tech in tactique.get("techniques").and_then(|t| t.as_array()).into_iter().flatten() {
                let Some(tid) = tech.get("tid").and_then(|t| t.as_str()) else { continue };
                match tech.get("covered").and_then(|c| c.as_bool()) {
                    Some(true) => { couvertes.insert(tid.to_string()); }
                    Some(false) => { non_couvertes.insert(tid.to_string()); }
                    _ => {}
                }
            }
        }
        assert!(!couvertes.is_empty(), "la matrice n'annonce AUCUNE technique couverte : elle ne peut rien contredire");
        let mut angles_morts_rendus: Vec<String> = Vec::new();
        for (nom, mitre) in &eteintes_faute_de_producteur {
            for technique in crate::handlers::alerts::mitre_parents(mitre) {
                if tags_actifs.iter().any(|t| crate::handlers::alerts::mitre_parents(t).contains(&technique)) {
                    continue; // une AUTRE règle active la tient : la couverture est vraie
                }
                assert!(
                    !couvertes.contains(&technique),
                    "la matrice annonce `{technique}` COUVERTE alors que la seule règle qui la tague — « {nom} » — \
                     est éteinte faute de producteur : la couverture ne doit pas compter ce qui ne peut pas tirer"
                );
                // …et la technique ne DISPARAÎT pas non plus : un angle mort tu vaut un angle mort nié.
                assert!(
                    non_couvertes.contains(&technique),
                    "`{technique}` n'est ni couverte ni RENDUE comme angle mort par la matrice — une technique \
                     que plus rien ne surveille doit se VOIR, pas s'effacer"
                );
                angles_morts_rendus.push(format!("{technique} (« {nom} »)"));
            }
        }
        assert!(
            !angles_morts_rendus.is_empty(),
            "aucune technique ne bascule en angle mort : ce maillon ne prouve rien tant qu'il ne juge aucun cas réel"
        );
    }

    // ================================================================================================
    // `P9.5-a` (SUITE) — LE CAS QUE LA BASE NEUVE NE PEUT PAS VOIR : L'INSTALLATION DÉJÀ EN SERVICE.
    //
    // Le verrou du semis ne tourne QUE sur une base fraîche (`seed_detection_rules` court-circuite sur son
    // marqueur). Sur le parc réel la ligne a été posée ACTIVE par la migration, et le témoin ci-dessus —
    // qui part d'une base à blanc — ne pouvait rien en dire. Ces deux témoins jugent l'autre population.
    //
    // CE QUI EST TENU ICI, DANS LES DEUX SENS :
    //   ① sur une base remise dans l'état du parc (les règles que le semis avait éteintes faute de
    //     producteur sont RALLUMÉES, exactement ce que l'INSERT littéral de la migration laisse), la
    //     lecture NUE des règles activées annonce des techniques couvertes que la lecture HONNÊTE ne
    //     compte pas ;
    //   ② la matrice les rend dans le TROISIÈME ÉTAT — ni couvertes, ni confondues avec un angle mort —
    //     et elle NOMME LA RAISON, c'est-à-dire la ou les sources qui manquent ;
    //   ③ l'activation de personne n'est touchée : les lignes restent `enabled=1` après la lecture ;
    //   ④ et la lecture honnête n'est pas un « toujours non » : dès qu'UN événement de la source
    //     manquante existe sur cette base, la technique REDEVIENT couverte. C'est l'exploitant qui a
    //     branché son producteur, et il ne doit rien perdre.
    //
    // CE QUI A ÉTÉ RETIRÉ ICI, ET POURQUOI — LA JAMBE QUI NE JUGEAIT RIEN. Ce témoin a porté une
    // assertion « la matrice rend `t` comme angle mort », écrite `non_honnete.contains(t)`. Elle est une
    // TAUTOLOGIE : `build_attack_matrix` parcourt TOUT le catalogue et pose `covered = rc > 0` sur
    // chaque technique, donc l'ensemble des non-couvertes contient forcément toute technique à
    // `rule_count = 0`. MESURÉ PAR MUTATION : le corps de `lire_la_couverture_des_regles_activees`
    // remplacé par une lecture qui rend TOUT en attente — cette jambe restait VERTE. Elle ne pouvait
    // donc pas voir que la correction avait RETOURNÉ le défaut au lieu de le fermer : la règle affamée
    // retombait dans le seau de « personne n'a jamais écrit de règle ». Ce qui la remplace juge ce qui
    // SÉPARE les deux états — le compte de règles en attente et LA RAISON — et un vrai angle mort du
    // même catalogue sert de témoin NÉGATIF, sans quoi « la raison est rendue » se prouverait sur une
    // valeur que toute technique porterait.

    #[test]
    fn une_base_deja_deployee_ne_compte_pas_couverte_une_regle_qu_aucun_producteur_ne_nourrit() {
        use crate::detection_aveugle::{lire_la_couverture_des_regles_activees, sources_sans_producteur_livre};
        use crate::handlers::alerts::{build_attack_matrix, mitre_parents};

        let (_tmp, conn) = base_semee("regle-vivante-sans-producteur");

        // ① REMETTRE LA BASE DANS L'ÉTAT DU PARC. On ne recopie pas le littéral `1` de la migration : on
        //    reprend les règles que le VERROU a éteintes faute de producteur et on les rallume. C'est,
        //    par construction, l'écart EXACT entre le chemin de semis et le chemin de migration.
        let cibles: Vec<(i64, String, String, String)> = {
            let mut stmt = conn
                .prepare("SELECT id, name, COALESCE(mitre,''), query FROM rule WHERE enabled=0")
                .unwrap();
            let v: Vec<(i64, String, String, String)> = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
                })
                .unwrap()
                .flatten()
                .filter(|(_, _, m, q)| !m.is_empty() && !sources_sans_producteur_livre(q).is_empty())
                .collect();
            v
        };
        assert!(
            !cibles.is_empty(),
            "aucune règle semée éteinte faute de producteur ET taguée MITRE : ce témoin ne juge alors AUCUN \
             cas réel, et son vert ne prouverait rien"
        );
        for (id, _, _, _) in &cibles {
            conn.execute("UPDATE rule SET enabled=1 WHERE id=?1", rusqlite::params![id]).unwrap();
        }

        // ② LA LECTURE NUE (celle qui a survécu sur le parc) CONTRE LA LECTURE HONNÊTE.
        let tags_nus: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT COALESCE(mitre,'') FROM rule WHERE enabled=1 AND mitre IS NOT NULL AND mitre<>''")
                .unwrap();
            let v: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().flatten().collect();
            v
        };
        let lecture = lire_la_couverture_des_regles_activees(&conn);
        let tags_honnetes = lecture.tirent.clone();
        let couvertes = |tags: &[String]| -> std::collections::BTreeSet<String> {
            let mut s = std::collections::BTreeSet::new();
            for t in tags {
                for p in mitre_parents(t) {
                    s.insert(p);
                }
            }
            s
        };
        let nues = couvertes(&tags_nus);
        let honnetes = couvertes(&tags_honnetes);
        let fantomes: Vec<String> = nues.difference(&honnetes).cloned().collect();
        assert!(
            !fantomes.is_empty(),
            "la lecture honnête compte EXACTEMENT ce que la lecture nue comptait ({} technique(s)) alors que \
             {} règle(s) sans producteur viennent d'être rallumées : la dérivation ne retire plus rien, elle \
             rendrait vert sur une base déjà déployée",
            nues.len(),
            cibles.len()
        );

        // ③ CE QUE LA MATRICE ANNONCE, DES DEUX CÔTÉS — trois états relevés par technique : couverte,
        //    le compte de règles EN ATTENTE DE SOURCE, et la RAISON (les sources qui manquent).
        let lire = |tags: &[String],
                    attente: &[(String, Vec<String>)]|
         -> std::collections::BTreeMap<String, (bool, i64, Vec<String>)> {
            let m = build_attack_matrix(tags, attente, &std::collections::HashMap::new());
            let mut out = std::collections::BTreeMap::new();
            for tac in m.get("tactics").and_then(|t| t.as_array()).into_iter().flatten() {
                for tech in tac.get("techniques").and_then(|t| t.as_array()).into_iter().flatten() {
                    let Some(tid) = tech.get("tid").and_then(|t| t.as_str()) else { continue };
                    let couverte = tech.get("covered").and_then(|c| c.as_bool()).unwrap_or(false);
                    // `-1` quand la clé MANQUE : une matrice qui aurait cessé de publier le troisième
                    // état ne doit pas se lire comme « zéro règle en attente », qui est un vrai fait.
                    let en_attente = tech.get("rules_en_attente_de_source").and_then(|c| c.as_i64()).unwrap_or(-1);
                    let manquantes: Vec<String> = tech
                        .get("sources_manquantes")
                        .and_then(|c| c.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                        .unwrap_or_default();
                    out.insert(tid.to_string(), (couverte, en_attente, manquantes));
                }
            }
            out
        };
        let nu = lire(&tags_nus, &[]);
        let honnete = lire(&lecture.tirent, &lecture.en_attente_de_source);

        // TÉMOIN NÉGATIF, ET IL EST LE CŒUR DE CETTE JAMBE : un VRAI angle mort du même catalogue —
        // aucune règle ne le porte. Sans lui, « la raison est rendue » se prouverait sur une valeur que
        // TOUTE technique porte, et on aurait réécrit la tautologie sous un autre nom.
        let vrai_angle_mort = honnete
            .iter()
            .find(|(tid, (couverte, att, _))| !couverte && *att == 0 && !fantomes.contains(tid))
            .map(|(tid, v)| (tid.clone(), v.clone()))
            .expect("aucune technique du catalogue n'est un vrai angle mort : le témoin négatif manque");
        assert!(
            vrai_angle_mort.1 .2.is_empty(),
            "le témoin négatif `{}` — qu'AUCUNE règle ne porte — nomme pourtant des sources manquantes \
             {:?} : la raison serait posée sur tout le catalogue et ne distinguerait plus rien",
            vrai_angle_mort.0,
            vrai_angle_mort.1 .2
        );

        for t in &fantomes {
            let (couverte_nue, _, _) = nu.get(t).unwrap_or(&(false, -1, Vec::new())).clone();
            assert!(couverte_nue, "témoin positif : `{t}` doit être annoncée COUVERTE par la lecture nue");
            let (couverte, en_attente, manquantes) =
                honnete.get(t).cloned().unwrap_or((false, -1, Vec::new()));
            assert!(
                !couverte,
                "la matrice annonce encore `{t}` COUVERTE sur une base déjà déployée : c'est exactement la \
                 fausse couverture que le verrou de semis ne pouvait pas atteindre"
            );
            // LE DÉFAUT INTRODUIT PAR LA PREMIÈRE CORRECTION, ET C'EST LUI QUE CETTE LIGNE FERME : la
            // règle EXISTE et elle est ACTIVÉE. La rendre à `0` la ferait retomber dans le seau du
            // témoin négatif ci-dessus, celui de « personne n'a jamais écrit de règle ».
            assert!(
                en_attente >= 1,
                "`{t}` est rendue avec {en_attente} règle(s) en attente de source : elle est donc \
                 indistinguable de `{}`, que RIEN ne porte. Une règle activée que plus rien ne nourrit \
                 doit se COMPTER À PART, pas s'effacer — la console y annoncerait « aucune règle » et \
                 prescrirait d'en créer une seconde",
                vrai_angle_mort.0
            );
            // ET LA RAISON, PARCE QU'ELLE EST ACTIONNABLE : brancher ce producteur suffit. Elle était
            // CALCULÉE là où le filtre décide, puis jetée.
            let attendues: Vec<String> = cibles
                .iter()
                .filter(|(_, _, m, _)| mitre_parents(m).contains(t))
                .flat_map(|(_, _, _, q)| sources_sans_producteur_livre(q))
                .collect();
            assert!(
                !attendues.is_empty(),
                "instrument : aucune source manquante ne se dérive des règles qui portent `{t}` — cette \
                 jambe ne comparerait rien"
            );
            for src in &attendues {
                assert!(
                    manquantes.contains(src),
                    "`{t}` est comptée à part mais SANS SA RAISON : la matrice rend {manquantes:?} là où \
                     la règle épingle `{src}`. C'est le seul renseignement qui mène au geste utile — \
                     brancher le producteur — et l'attendu de `P9.5-a` le demande mot pour mot"
                );
            }
        }

        // ④ RIEN N'A ÉTÉ ÉTEINT. La volonté de l'exploitant n'est pas touchée : c'est la LECTURE qui a
        //    changé, pas la ligne. Une correction qui aurait flippé `enabled` rougirait ici.
        for (id, nom, _, _) in &cibles {
            let actif: i64 = conn
                .query_row("SELECT enabled FROM rule WHERE id=?1", rusqlite::params![id], |r| r.get(0))
                .unwrap();
            assert_eq!(actif, 1, "la règle « {nom} » a été ÉTEINTE par le chemin de lecture : rien ne doit l'être");
        }

        // ⑤ ET CE N'EST PAS UN « TOUJOURS NON » : la source manquante OBSERVÉE sur cette base rend la
        //    couverture. C'est le cas de l'exploitant qui a branché son producteur — la seule population
        //    qu'une extinction rétroactive aurait sacrifiée en silence.
        let (_, nom_cible, mitre_cible, q_cible) = cibles
            .iter()
            .find(|(_, _, m, _)| mitre_parents(m).iter().any(|p| fantomes.contains(p)))
            .expect("au moins une règle rallumée porte une des techniques fantômes");
        let source_manquante = sources_sans_producteur_livre(q_cible).into_iter().next().unwrap();
        conn.execute(
            "INSERT INTO event_rollup(bucket,source,n) VALUES(?1,?2,?3)",
            rusqlite::params![0i64, source_manquante, 1i64],
        )
        .unwrap();
        let lecture_apres = lire_la_couverture_des_regles_activees(&conn);
        let apres = couvertes(&lecture_apres.tirent);
        let rendu_apres = lire(&lecture_apres.tirent, &lecture_apres.en_attente_de_source);
        for p in mitre_parents(mitre_cible) {
            assert!(
                apres.contains(&p),
                "« {nom_cible} » épingle `{source_manquante}`, dont cette base porte désormais des \
                 événements : sa technique `{p}` doit REDEVENIR couverte. Sans ce sens-là, la dérivation \
                 punirait l'exploitant qui a branché son producteur"
            );
            // ET LE TROISIÈME ÉTAT SE RETIRE AVEC LA RAISON : une technique redevenue couverte ne peut
            // pas rester « en attente d'une source » qui est arrivée, ni continuer à la nommer.
            let (couverte, en_attente, manquantes) =
                rendu_apres.get(&p).cloned().unwrap_or((false, -1, Vec::new()));
            assert!(
                couverte && en_attente == 0 && !manquantes.contains(&source_manquante),
                "`{p}` est redevenue couverte mais la matrice la rend encore en attente de \
                 {manquantes:?} ({en_attente} règle(s)) : le troisième état survivrait à sa cause"
            );
        }
    }

    // ================================================================================================
    // `P9.5-a` (SUITE) — L'IMPORT SIGMA : LES DEUX CÔTÉS DE LA SOUSTRACTION SE COMPTENT PAREIL.
    //
    // LE DÉFAUT MESURÉ, ET IL A ÉTÉ INTRODUIT PAR LA PREMIÈRE CORRECTION. Le « avant » du delta de
    // couverture passait par le filtre neuf ; le jeu des techniques IMPORTÉES ne passait par rien ; et
    // l'« après » était l'union des deux. La différence était donc gonflée d'exactement l'ensemble que le
    // filtre venait de retirer du « avant » — dans le sens INVERSE de ce que son commentaire revendiquait.
    // Aucun test ne pouvait le voir : `sigma_bulk_coverage_delta` n'était appelé que sur des tags
    // fabriqués à la main, jamais à travers une base.
    //
    // TROIS SENS, PARCE QU'UN SEUL NE PROUVERAIT QUE L'INCAPACITÉ À COMPTER :
    //   ① un import qui tague la technique d'une règle affamée, et qui est lui-même affamé, ne ferme RIEN ;
    //   ② un import qui n'épingle aucune source ferme bien un angle mort — le témoin POSITIF ;
    //   ③ le MÊME import de ① ferme la technique dès que la base a REÇU la source qui manquait — la
    //     dérivation n'est pas un « toujours non », c'est un rapprochement.

    #[test]
    fn un_import_ne_ferme_pas_un_angle_mort_qu_aucun_producteur_ne_nourrit() {
        use crate::detection_aveugle::{lire_la_couverture_des_regles_activees, sources_sans_producteur_livre};
        use crate::handlers::alerts::mitre_parents;
        use crate::sigma::{delta_de_couverture_d_un_import, sigma_covered_parents, SigmaTranslation};

        let (_tmp, conn) = base_semee("import-sigma-sans-producteur");

        // LA BASE DU PARC : les règles que le semis a éteintes faute de producteur sont RALLUMÉES, ce que
        // l'INSERT littéral de la migration laisse sur une installation en service.
        let cibles: Vec<(i64, String, String)> = {
            let mut stmt = conn
                .prepare("SELECT id, COALESCE(mitre,''), query FROM rule WHERE enabled=0")
                .unwrap();
            let v: Vec<(i64, String, String)> = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
                .unwrap()
                .flatten()
                .filter(|(_, m, q)| !m.is_empty() && !sources_sans_producteur_livre(q).is_empty())
                .collect();
            v
        };
        assert!(!cibles.is_empty(), "aucune règle semée éteinte faute de producteur ET taguée : ce témoin ne juge rien");
        for (id, _, _) in &cibles {
            conn.execute("UPDATE rule SET enabled=1 WHERE id=?1", rusqlite::params![id]).unwrap();
        }
        let lecture = lire_la_couverture_des_regles_activees(&conn);
        let couvertes_avant = sigma_covered_parents(&lecture.tirent);
        let (_, mitre_cible, q_cible) = cibles
            .iter()
            .find(|(_, m, _)| mitre_parents(m).iter().any(|p| !couvertes_avant.contains(p)))
            .expect("au moins une règle rallumée porte une technique que la lecture honnête ne compte pas");
        let technique = mitre_parents(mitre_cible)
            .into_iter()
            .find(|p| !couvertes_avant.contains(p))
            .expect("technique cible");
        let source_manquante = sources_sans_producteur_livre(q_cible).into_iter().next().unwrap();

        // Une traduction Sigma se fabrique ici plutôt que de traduire un document : ce qui est jugé est le
        // rapprochement entre la requête TRADUITE et les producteurs, pas la traduction elle-même.
        let traduction = |nom: &str, mitre: &str, query: &str| SigmaTranslation {
            name: nom.to_string(),
            sigma_id: None,
            query: query.to_string(),
            severity: 3,
            mitre: mitre.to_string(),
            compliance: String::new(),
            interval_s: 300,
            window_s: 900,
            op: ">=".to_string(),
            threshold: 1.0,
            warnings: Vec::new(),
        };

        // ① L'IMPORT QUI NE FERME RIEN : même technique, même source absente.
        let affame = traduction(
            "import affamé",
            &technique,
            &format!("search source={source_manquante} | stats count"),
        );
        let plan_affame: Vec<(&SigmaTranslation, Option<i64>)> = vec![(&affame, None)];
        let d1 = delta_de_couverture_d_un_import(&conn, &plan_affame);
        assert!(
            !d1.nouvellement_couvertes.contains(&technique),
            "l'import annonce fermer `{technique}` alors que sa règle épingle `{source_manquante}`, \
             qu'aucun producteur ne fournit ici : le « avant » passait par le filtre et l'« après » pas, \
             donc la différence était gonflée d'exactement ce que le filtre venait de retirer"
        );
        assert_eq!(
            d1.apres, d1.avant,
            "l'import ne nourrit rien de neuf et pourtant la couverture monte de {} à {}",
            d1.avant, d1.apres
        );
        // ET CE QUI EST ÉCARTÉ N'EST PAS TU : la raison voyage, comme dans la matrice.
        let (_, _, manquantes) = d1
            .sans_producteur
            .iter()
            .find(|(nom, _, _)| nom == "import affamé")
            .expect("la règle écartée doit être RENDUE, pas effacée : sinon l'administrateur ne sait pas quoi brancher");
        assert!(
            manquantes.contains(&source_manquante),
            "la règle écartée est rendue sans sa raison : {manquantes:?} ne nomme pas `{source_manquante}`"
        );

        // ② TÉMOIN POSITIF — sans lui, le vert de ① ne prouverait que l'incapacité à compter quoi que ce
        //    soit. Une technique du catalogue que RIEN ne couvre, importée par une règle qui n'épingle
        //    aucune source : elle DOIT se fermer.
        let neuve = guatx_core::attack::CATALOG
            .iter()
            .map(|(tid, _)| tid.to_string())
            .find(|tid| !couvertes_avant.contains(tid) && *tid != technique)
            .expect("aucune technique non couverte au catalogue : le témoin positif manque");
        let nourrissable = traduction("import nourrissable", &neuve, "search category=auth action=failure | stats count");
        let plan_ok: Vec<(&SigmaTranslation, Option<i64>)> = vec![(&nourrissable, None)];
        let d2 = delta_de_couverture_d_un_import(&conn, &plan_ok);
        assert!(
            d2.nouvellement_couvertes.contains(&neuve) && d2.apres == d2.avant + 1,
            "l'import d'une règle que TOUT peut nourrir n'est pas compté comme fermant `{neuve}` \
             ({} -> {}, {:?}) : la dérivation refuserait tout, et ne mesurerait rien",
            d2.avant,
            d2.apres,
            d2.nouvellement_couvertes
        );
        assert!(d2.sans_producteur.is_empty(), "une règle sans épinglage est écartée : {:?}", d2.sans_producteur);

        // ③ ET LE SENS INVERSE : la base REÇOIT la source qui manquait. Le même import ferme alors la
        //    technique — l'exploitant qui branche son producteur ne doit rien perdre.
        conn.execute(
            "INSERT INTO event_rollup(bucket,source,n) VALUES(?1,?2,?3)",
            rusqlite::params![0i64, source_manquante, 1i64],
        )
        .unwrap();
        let d3 = delta_de_couverture_d_un_import(&conn, &plan_affame);
        assert!(
            d3.sans_producteur.is_empty(),
            "`{source_manquante}` est désormais observée sur cette base et l'import reste écarté : {:?}",
            d3.sans_producteur
        );
        // La technique est REDEVENUE couverte par la règle vivante elle-même : l'import ne « ferme » donc
        // plus rien de neuf, et c'est le compte AVANT qui a monté. C'est le fait qui compte ici.
        assert!(
            d3.avant > d1.avant,
            "la couverture AVANT n'a pas bougé ({} -> {}) alors que la source manquante est arrivée",
            d1.avant,
            d3.avant
        );
    }

    // ------------------------------------------------------------------------------------------------
    // LE POINT UNIQUE EST-IL VRAIMENT UNIQUE ? La fausse couverture a survécu à sa correction PARCE QUE
    // deux surfaces lisaient les règles activées chacune de son côté. Cette garde relit le démon et refuse
    // qu'une troisième apparaisse — et refuse aussi le retour de la forme EXACTE qui portait le défaut.
    //
    // CE QU'ELLE NE TIENT PAS, ET C'EST DIT : elle lie le FICHIER, pas l'argument. Un fichier qui appellerait
    // le point unique ET relirait la table à côté passerait. Ce qu'elle ferme, c'est le chemin par lequel le
    // défaut est réellement revenu : une surface de couverture qui ne connaît pas la dérivation du tout.
    #[test]
    fn aucune_surface_de_couverture_ne_lit_les_regles_actives_directement() {
        /// Les fonctions qui transforment des tags MITRE en VERDICT de couverture. Une surface qui en
        /// appelle une doit connaître le point unique.
        const VERDICTS_DE_COUVERTURE: [&str; 2] = ["build_attack_matrix(", "sigma_bulk_coverage_delta("];
        /// La forme EXACTE que les deux lectures nues portaient. Elle ne doit plus exister hors des tests.
        const LECTURE_NUE: &str = "SELECT mitre FROM rule WHERE enabled=1";

        fn balaye(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let nom = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                if p.is_dir() {
                    if nom != "tests" {
                        balaye(&p, out);
                    }
                } else if nom.ends_with(".rs") && nom != "tests.rs" {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        out.push((p.display().to_string(), t));
                    }
                }
            }
        }
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        balaye(&racine, &mut fichiers);
        assert!(
            fichiers.len() > 50,
            "le balayage n'a lu que {} fichier(s) : l'instrument ne voit plus le démon, il rendrait vert sur \
             n'importe quoi",
            fichiers.len()
        );

        // ① TÉMOIN POSITIF — des surfaces de couverture EXISTENT, sinon cette garde ne juge rien.
        let surfaces: Vec<&(String, String)> = fichiers
            .iter()
            .filter(|(_, t)| VERDICTS_DE_COUVERTURE.iter().any(|f| t.contains(f)))
            .collect();
        assert!(
            surfaces.len() >= 2,
            "seulement {} surface(s) de couverture trouvée(s) : le repérage ne reconnaît plus le corpus",
            surfaces.len()
        );

        // ② LE VERDICT — chacune passe par la dérivation. LES PORTES ADMISES NE SONT PLUS ÉNUMÉRÉES :
        //    elles sont DÉRIVÉES de `detection_aveugle.rs` — les fonctions qui lisent l'énoncé unique des
        //    règles activées (`ENONCE_TAGS_ACTIFS`), plus, par fermeture, celles de ce module qui les
        //    appellent (leurs projections). Un nom recopié ici aurait rougi le jour où la lecture s'est
        //    enrichie du troisième état, et on l'aurait « corrigé » en élargissant la garde.
        fn portes_de_couverture(module: &str) -> Vec<String> {
            // Un corps de fonction de premier niveau : de sa ligne `fn …` jusqu'à l'accolade seule en
            // colonne 0. C'est la forme que rustfmt tient sur tout ce dépôt, et elle exclut les
            // déclarations (`const`, `struct`) qui vivent ENTRE deux fonctions — sans quoi l'énoncé
            // lui-même serait attribué à la fonction qui le précède.
            let mut corps: Vec<(String, String)> = Vec::new();
            let lignes: Vec<&str> = module.lines().collect();
            let mut i = 0;
            while i < lignes.len() {
                let l = lignes[i];
                let reste = l.strip_prefix("pub(crate) ").or_else(|| l.strip_prefix("pub ")).unwrap_or(l);
                if let Some(apres) = reste.strip_prefix("fn ") {
                    let nom: String = apres.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    let mut j = i + 1;
                    let mut txt = String::new();
                    while j < lignes.len() && lignes[j] != "}" {
                        txt.push_str(lignes[j]);
                        txt.push('\n');
                        j += 1;
                    }
                    if !nom.is_empty() {
                        corps.push((nom, txt));
                    }
                    i = j + 1;
                    continue;
                }
                i += 1;
            }
            let mut admises: Vec<String> = corps
                .iter()
                .filter(|(_, t)| t.contains("ENONCE_TAGS_ACTIFS"))
                .map(|(n, _)| n.clone())
                .collect();
            // FERMETURE : une projection de la lecture est une porte, elle aussi.
            loop {
                let avant = admises.len();
                for (n, t) in &corps {
                    if !admises.contains(n) && admises.iter().any(|a| t.contains(&format!("{a}("))) {
                        admises.push(n.clone());
                    }
                }
                if admises.len() == avant {
                    break;
                }
            }
            admises
        }

        // L'INSTRUMENT AVANT LE VERDICT, sur un corpus FABRIQUÉ dont la réponse est connue : la lecture,
        // sa projection, et deux formes qui ne doivent PAS entrer — une fonction qui n'y touche pas, et
        // l'énoncé lui-même, qui vit ENTRE deux fonctions.
        const CORPUS_TEMOIN: &str = "pub(crate) const ENONCE_TAGS_ACTIFS: &str = \"SELECT …\";\n\
             pub(crate) fn ailleurs(x: u8) -> u8 {\n    x + 1\n}\n\
             pub(crate) fn la_lecture(c: &Connection) -> Vec<String> {\n    c.prepare(ENONCE_TAGS_ACTIFS);\n    Vec::new()\n}\n\
             pub(crate) fn la_projection(c: &Connection) -> usize {\n    la_lecture(c).len()\n}\n";
        let temoin = portes_de_couverture(CORPUS_TEMOIN);
        assert!(
            temoin.contains(&"la_lecture".to_string()) && temoin.contains(&"la_projection".to_string()),
            "instrument : la dérivation ne retrouve pas la lecture et sa projection sur un corpus fabriqué \
             ({temoin:?}) — elle rendrait vert en ne voyant aucune porte"
        );
        assert!(
            !temoin.contains(&"ailleurs".to_string()),
            "instrument : la dérivation admet une fonction qui ne lit pas l'énoncé ({temoin:?}) — l'énoncé \
             posé ENTRE deux fonctions est attribué à la mauvaise, et toute surface passerait"
        );

        let module = std::fs::read_to_string(racine.join("detection_aveugle.rs"))
            .expect("`detection_aveugle.rs` illisible : la dérivation des portes n'a pas de source");
        let portes = portes_de_couverture(&module);
        assert!(
            !portes.is_empty(),
            "AUCUNE porte de couverture dérivée de `detection_aveugle.rs` : la lecture de l'énoncé unique a \
             changé de forme et la garde ne la reconnaît plus — elle rendrait vert sur n'importe quelle surface"
        );
        let ignorantes: Vec<&str> = surfaces
            .iter()
            .filter(|(_, t)| !portes.iter().any(|p| t.contains(&format!("{p}("))))
            .map(|(f, _)| f.as_str())
            .collect();
        assert!(
            ignorantes.is_empty(),
            "surface(s) de couverture qui n'appellent AUCUNE des portes dérivées {portes:?} : {ignorantes:?}. \
             Une technique y serait annoncée couverte par une règle qu'aucun producteur ne nourrit — le défaut \
             de `P9.5-a`, revenu par la porte qui l'avait laissé passer."
        );

        // ③ ET LA FORME NUE NE REVIENT PAS.
        let nues: Vec<&str> = fichiers
            .iter()
            .filter(|(_, t)| t.contains(LECTURE_NUE))
            .map(|(f, _)| f.as_str())
            .collect();
        assert!(
            nues.is_empty(),
            "lecture NUE des règles activées retrouvée dans {nues:?} : `{LECTURE_NUE}` compte une règle \
             activée comme une règle surveillante. Passer par l'une des portes dérivées {portes:?}."
        );
    }
