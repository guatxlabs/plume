// =====================================================================================
// `P10.20-b` (hors handlers/ : `sigma.rs`, lecture de la règle EXISTANTE par un import Sigma) — UNE LECTURE RATÉE
// N'EST PAS « AUCUNE RÈGLE DE CE NOM ».
//
// LE DÉFAUT, LU SUR d8239ceb. `sigma_find_existing` rendait `Option` : `if let Ok(..)` à l'étage `sigma_id`, `.ok()` à
// l'étage nom. Une lecture ratée valait `None`, donc la disposition `Insert` (`sigma_import_disposition`). `rule.name`
// n'a pas de contrainte d'unicité (db/schema.sql) : l'INSERT passait, et l'import (unitaire, en masse, CLI) doublait
// une détection native (managed=0), un overlay géré (managed=1) ou une règle déjà importée — le contrat écrit au-dessus
// de `sigma_import_disposition` (« n'est JAMAIS écrasée/dupliquée ») ne tenait que si la lecture aboutissait. Une
// erreur à l'étage `sigma_id` retombait de plus sur le nom.
//
// LA VOIE D'ÉCHEC FABRIQUÉE : un autorisateur SQLite qui refuse la lecture d'UNE colonne de `rule` (`sigma_id` seul,
// ou `name` seul — l'autre étage reste lisible), ou de toutes ; et la table `rule` renommée (« no such table »).
//
// ATTENDU, ET TENU ICI : trois issues (`Ok(Some)`, `Ok(None)` absence établie, `Err`) ; une erreur à l'étage
// `sigma_id` ne bascule pas sur le nom ; l'import unitaire et l'import en masse (dry_run compris) refusent en 503 nommé
// (`CAUSE_IMPORT_SIGMA_NON_LU`, `CAUSE_IMPORT_SIGMA_EN_MASSE_NON_LU`) AVANT la transaction — rien d'écrit, aucune
// trace, rien du moteur au corps, la règle native du même nom intacte et seule ; le pas du CLI rend `Err(message)`
// sans écrire. Absence établie = Insert, re-import managed=2 = Update, native = protégée : comme avant.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (même chemin : toute erreur autre
// que « aucune ligne ») ; la sortie du binaire `plume sigma-import` (code 1, message sur stderr) n'est pas jouée en
// sous-processus — seul le pas extrait `sigma_cli_appliquer_une` l'est ; la ligne de journal (`eprintln!`) n'est pas
// capturée ; les écritures du CLI gardent leur `.expect` d'avant (une écriture refusée panique toujours) et le CLI
// n'ouvre pas de transaction (les règles déjà écrites avant l'arrêt restent) ; le mode multi-tenant n'est pas joué.
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par variable d'environnement sous cfg!(test), puis retirées du source) :
//  * « p5_id_ok » (étage `sigma_id` : `.ok()` rétabli, l'erreur retombe sur le nom) : (a), (c), (d), (e) ;
//  * « p5_nom_ok » (étage nom : `.ok()` rétabli) : (a), (b), (d), (e) ;
//  * « p5_import_non_cable » (import unitaire : l'erreur vaut absence) : (b), (c) ;
//  * « p5_masse_non_cable » (import en masse : l'erreur vaut absence) : (d) ;
//  * « p5_cli_non_cable » (pas du CLI : l'erreur vaut absence) : (e).
// =====================================================================================
mod sigma_import_lecture_ratee_refuse {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Refuse la lecture de `rule.<colonne>` (ou de toute colonne de `rule` si `None`) sur cette connexion.
    fn p5_refuser_la_lecture(conn: &Connection, colonne: Option<&'static str>) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "rule" && colonne.map_or(true, |c| c == column_name) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn p5_lever(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn p5_doc(titre: &str, id: Option<&str>) -> Value {
        let mut d = json!({ "title": titre, "logsource": { "service": "sshd" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" }, "level": "medium" });
        if let Some(i) = id {
            d["id"] = json!(i);
        }
        d
    }

    fn p5_traduire(titre: &str, id: Option<&str>) -> SigmaTranslation {
        sigma_translate(&p5_doc(titre, id)).expect("fixture : doc Sigma traduisible")
    }

    fn p5_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn p5_natif(conn: &Connection, nom: &str) {
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES(?1,1,'search p5natif | stats count',1,0)", params![nom])
            .expect("fixture : règle native");
    }

    fn p5_rien_du_moteur(b: &str) {
        for motif in ["prohibited", "not authorized", "no such table", "rule.", "sigma_id"] {
            assert!(!b.contains(motif), "rien du moteur au corps (`{motif}` dans {b})");
        }
    }

    async fn p5_corps(r: Response) -> (StatusCode, Value) {
        let code = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let s = String::from_utf8_lossy(&b).into_owned();
        p5_rien_du_moteur(&s);
        (code, serde_json::from_str(&s).unwrap_or(Value::String(s)))
    }

    /// (a) LA FONCTION : trois issues ; une lecture ratée à l'étage `sigma_id` rend `Err` même quand le NOM désigne une
    /// règle lisible (pas de bascule) ; étage nom refusé, toutes colonnes refusées, table renommée -> `Err`.
    #[test]
    fn p5_sigma_find_existing_rend_trois_issues_sans_bascule_sur_le_nom() {
        let conn = test_db();
        p5_natif(&conn, "P5 Natif");
        let sans_id = p5_traduire("P5 Natif", None);
        let avec_id = p5_traduire("P5 Natif", Some("p5-uuid-a"));
        let absente = p5_traduire("P5 Absente", Some("p5-uuid-absent"));

        assert_eq!(sigma_find_existing(&conn, &absente).expect("lisible").map(|(_, m)| m), None, "absence établie : Ok(None)");
        assert_eq!(sigma_find_existing(&conn, &sans_id).expect("lisible").map(|(_, m)| m), Some(0), "trouvée par nom : Ok(Some(managed=0))");
        assert_eq!(sigma_find_existing(&conn, &avec_id).expect("lisible").map(|(_, m)| m), Some(0), "id inconnu, nom connu : repli nom d'avant");

        p5_refuser_la_lecture(&conn, Some("sigma_id"));
        let r = sigma_find_existing(&conn, &avec_id);
        p5_lever(&conn);
        assert!(r.is_err(), "étage sigma_id illisible : Err, jamais la règle trouvée par le nom ({r:?})");

        for (colonne, quoi) in [(Some("name"), "étage nom illisible"), (None, "table illisible")] {
            p5_refuser_la_lecture(&conn, colonne);
            let r = sigma_find_existing(&conn, &sans_id);
            let r_absente = sigma_find_existing(&conn, &absente);
            p5_lever(&conn);
            assert!(r.is_err(), "{quoi} : Err ({r:?})");
            assert!(r_absente.is_err(), "{quoi} : Err aussi quand aucune règle n'existe — l'absence n'est pas établie ({r_absente:?})");
        }

        conn.execute_batch("ALTER TABLE rule RENAME TO p5_regles_a_l_ecart;").expect("fixture : renommage");
        let r = sigma_find_existing(&conn, &sans_id);
        conn.execute_batch("ALTER TABLE p5_regles_a_l_ecart RENAME TO rule;").expect("fixture : remise");
        assert!(r.is_err(), "table renommée : Err ({r:?})");
        assert_eq!(sigma_find_existing(&conn, &sans_id).expect("remise : lisible").map(|(_, m)| m), Some(0), "remise : trouvée de nouveau");
    }

    /// (b) IMPORT UNITAIRE, étage nom ou table illisible : 503 nommé, aucune transaction ouverte, aucune trace, la règle
    /// native du même nom intacte et SEULE. Levé : native protégée (skip), absente insérée, re-import = Update.
    #[tokio::test]
    async fn p5_import_unitaire_lecture_ratee_rend_503_et_ne_double_pas_la_native() {
        let (st, _p) = sp_state("p5-import");
        let adm = sp_au("adm", "admin");
        p5_natif(&st.db.lock(), "P5 Natif");
        let importer = |titre: &str| sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [p5_doc(titre, None)] })));

        for (colonne, quoi) in [(Some("name"), "étage nom illisible"), (None, "table illisible")] {
            p5_refuser_la_lecture(&st.db.lock(), colonne);
            let r = importer("P5 Natif").await;
            let autocommit = st.db.lock().is_autocommit();
            p5_lever(&st.db.lock());
            let (code, corps) = p5_corps(r).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : 503, jamais l'insertion d'un doublon ({corps})");
            assert_eq!(corps["error"], json!(CAUSE_IMPORT_SIGMA_NON_LU), "{quoi} : cause nommée");
            assert!(autocommit, "{quoi} : aucune transaction ouverte");
            let c = st.db.lock();
            assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Natif'"), 1, "{quoi} : la native reste SEULE");
            assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Natif' AND managed=0 AND query='search p5natif | stats count'"), 1, "{quoi} : native intacte");
            assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM ledger WHERE kind='config.sigma.import'"), 0, "{quoi} : aucune trace");
        }

        let (code, corps) = p5_corps(importer("P5 Natif").await).await;
        assert_eq!(code, StatusCode::OK, "levé : 200 ({corps})");
        assert_eq!(corps["imported"].as_array().map(Vec::len), Some(0), "levé : la native est protégée, rien d'importé ({corps})");
        assert_eq!(p5_compte(&st.db.lock(), "SELECT COUNT(*) FROM rule WHERE name='P5 Natif'"), 1, "levé : native seule");

        for passe in ["insert", "update"] {
            let (code, corps) = p5_corps(importer("P5 Neuve").await).await;
            assert_eq!(code, StatusCode::OK, "absence établie, {passe} : 200 ({corps})");
            assert_eq!(p5_compte(&st.db.lock(), "SELECT COUNT(*) FROM rule WHERE name='P5 Neuve' AND managed=2"), 1, "{passe} : une seule règle managed=2");
        }
    }

    /// (c) IMPORT UNITAIRE, étage `sigma_id` SEUL illisible (le nom reste lisible) : 503 nommé, pas de bascule sur le nom
    /// (le titre a dérivé, aucune règle de ce nom : la bascule insérerait un doublon de la règle importée). Levé : Update.
    #[tokio::test]
    async fn p5_import_unitaire_etage_sigma_id_illisible_ne_bascule_pas_sur_le_nom() {
        let (st, _p) = sp_state("p5-import-id");
        let adm = sp_au("adm", "admin");
        st.db.lock().execute("INSERT INTO rule(name,enabled,query,is_soql,managed,sigma_id) VALUES('P5 Ancien',1,'search p5 | stats count',1,2,'p5-uuid-c')", [])
            .expect("fixture : règle importée");
        let importer = || sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [p5_doc("P5 Nouveau", Some("p5-uuid-c"))] })));

        p5_refuser_la_lecture(&st.db.lock(), Some("sigma_id"));
        let r = importer().await;
        p5_lever(&st.db.lock());
        let (code, corps) = p5_corps(r).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "étage sigma_id illisible : 503 ({corps})");
        assert_eq!(corps["error"], json!(CAUSE_IMPORT_SIGMA_NON_LU), "cause nommée");
        {
            let c = st.db.lock();
            assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE sigma_id='p5-uuid-c'"), 1, "aucun doublon de la règle importée");
            assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Nouveau'"), 0, "rien d'inséré sous le titre dérivé");
        }

        let (code, corps) = p5_corps(importer().await).await;
        assert_eq!(code, StatusCode::OK, "levé : 200 ({corps})");
        let c = st.db.lock();
        assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE sigma_id='p5-uuid-c' AND name='P5 Nouveau' AND managed=2"), 1, "levé : Update de la même règle");
        assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE sigma_id='p5-uuid-c'"), 1, "levé : toujours une seule");
    }

    /// (d) IMPORT EN MASSE (enable:true, puis dry_run) : étage nom, table, étage `sigma_id` illisibles -> 503 nommé,
    /// rien d'écrit, aucune trace ; levé : native protégée, absente insérée une fois.
    #[tokio::test]
    async fn p5_import_en_masse_lecture_ratee_rend_503_dry_run_compris() {
        let (st, _p) = sp_state("p5-masse");
        let adm = sp_au("adm", "admin");
        p5_natif(&st.db.lock(), "P5 Natif");
        st.db.lock().execute("INSERT INTO rule(name,enabled,query,is_soql,managed,sigma_id) VALUES('P5 Ancien',0,'search p5 | stats count',1,2,'p5-uuid-d')", [])
            .expect("fixture : règle importée");
        let en_masse = |docs: Vec<Value>, dry: bool| sigma_import_bulk(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": docs, "enable": true, "dry_run": dry })));

        for (colonne, docs, quoi) in [
            (Some("name"), vec![p5_doc("P5 Natif", None)], "étage nom illisible"),
            (None, vec![p5_doc("P5 Natif", None)], "table illisible"),
            (Some("sigma_id"), vec![p5_doc("P5 Nouveau", Some("p5-uuid-d"))], "étage sigma_id illisible"),
        ] {
            for dry in [false, true] {
                p5_refuser_la_lecture(&st.db.lock(), colonne);
                let r = en_masse(docs.clone(), dry).await;
                let autocommit = st.db.lock().is_autocommit();
                p5_lever(&st.db.lock());
                let (code, corps) = p5_corps(r).await;
                assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{quoi} (dry_run={dry}) : 503 ({corps})");
                assert_eq!(corps["error"], json!(CAUSE_IMPORT_SIGMA_EN_MASSE_NON_LU), "{quoi} (dry_run={dry}) : cause nommée");
                assert!(autocommit, "{quoi} (dry_run={dry}) : aucune transaction ouverte");
                let c = st.db.lock();
                assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Natif'"), 1, "{quoi} : native seule");
                assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Nouveau' OR sigma_id='p5-uuid-d' AND name<>'P5 Ancien'"), 0, "{quoi} : rien d'inséré");
                assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM ledger WHERE kind='config.sigma.import-bulk'"), 0, "{quoi} : aucune trace");
            }
        }

        let (code, corps) = p5_corps(en_masse(vec![p5_doc("P5 Natif", None), p5_doc("P5 Neuve", None)], false).await).await;
        assert_eq!(code, StatusCode::OK, "levé : 200 ({corps})");
        assert_eq!((corps["imported"].clone(), corps["updated"].clone()), (json!(1), json!(0)), "levé : une insertion, native protégée ({corps})");
        let c = st.db.lock();
        assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Natif'"), 1, "levé : native seule");
        assert_eq!(p5_compte(&c, "SELECT COUNT(*) FROM rule WHERE name='P5 Neuve' AND managed=2 AND enabled=1"), 1, "levé : neuve insérée activée");
    }

    /// (e) LE PAS DU CLI : étage nom ou `sigma_id` illisible -> `Err(message)` qui nomme la règle, rien d'écrit, native
    /// intacte ; levé : native protégée, absente écrite, re-import écrit sans doublon.
    #[test]
    fn p5_pas_du_cli_lecture_ratee_rend_err_sans_ecrire() {
        let conn = test_db();
        p5_natif(&conn, "P5 Natif");
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed,sigma_id) VALUES('P5 Ancien',1,'search p5 | stats count',1,2,'p5-uuid-e')", [])
            .expect("fixture : règle importée");

        for (colonne, t, quoi) in [
            (Some("name"), p5_traduire("P5 Natif", None), "étage nom illisible"),
            (Some("sigma_id"), p5_traduire("P5 Nouveau", Some("p5-uuid-e")), "étage sigma_id illisible"),
        ] {
            p5_refuser_la_lecture(&conn, colonne);
            let r = sigma_cli_appliquer_une(&conn, &t);
            p5_lever(&conn);
            match r {
                Err(m) => assert!(m.contains(&t.name) && m.contains("NON LUE"), "{quoi} : message nommé ({m})"),
                Ok(issue) => panic!("{quoi} : Err attendu, rendu {issue:?}"),
            }
            assert_eq!(p5_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='P5 Natif' AND managed=0"), 1, "{quoi} : native seule");
            assert_eq!(p5_compte(&conn, "SELECT COUNT(*) FROM rule"), 2, "{quoi} : rien d'écrit");
        }

        assert_eq!(sigma_cli_appliquer_une(&conn, &p5_traduire("P5 Natif", None)), Ok(SigmaCliIssue::Protegee(0)), "levé : native protégée");
        assert_eq!(sigma_cli_appliquer_une(&conn, &p5_traduire("P5 Nouveau", Some("p5-uuid-e"))), Ok(SigmaCliIssue::Ecrite), "levé : Update par sigma_id");
        assert_eq!(p5_compte(&conn, "SELECT COUNT(*) FROM rule WHERE sigma_id='p5-uuid-e' AND name='P5 Nouveau'"), 1, "levé : même règle renommée");
        for passe in ["insert", "update"] {
            assert_eq!(sigma_cli_appliquer_une(&conn, &p5_traduire("P5 Neuve", None)), Ok(SigmaCliIssue::Ecrite), "{passe} : écrite");
            assert_eq!(p5_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='P5 Neuve' AND managed=2"), 1, "{passe} : une seule");
        }
    }
}
