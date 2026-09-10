    // ============================================================================================
    // P3.10-a — UN CSV DE TÉLÉMÉTRIE ENTRE PAR LA PORTE EXISTANTE : l'étape `csv` du parseur déclaratif
    // (2026-09-10). Une ligne = un enregistrement, colonnes DÉCLARÉES, en-tête reconnue et comptée, découpe
    // conforme (guillemets, `""`, séparateur quoté), bornes du langage, spec invalide ignorée, exemple livré.
    // ============================================================================================

    fn dparser_csv(conn: &Connection, dpath: &str, source: &str, spec: &str) {
        conn.execute(
            "INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,?2,?3,1,0,1,0)",
            params![format!("csv-{source}"), source, spec],
        ).unwrap();
        dparsers_reload(conn, dpath);
    }

    #[test]
    fn p3_10a_un_csv_de_telemetrie_entre_par_le_parseur_declaratif_et_ses_colonnes_sont_promues() {
        let conn = test_db();
        let dpath = ":memory:csv-porte";
        dparser_csv(&conn, dpath, "csvtel", r#"{"name":"csv","source":"csvtel","extract":[{"csv":{"columns":["ts","src","dst","action"]}}],"map":{"category":"firewall","src_ip":"$src","dst_ip":"$dst","action":"$action"}}"#);
        let (fields, cat, _) = dparsers_apply(dpath, "csvtel", "1700000000,203.0.113.9,198.51.100.2,deny", None);
        assert_eq!(cat.as_deref(), Some("firewall"));
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.9"); assert_eq!(fv["dst_ip"], "198.51.100.2"); assert_eq!(fv["action"], "deny");
        // Par la porte réelle : un événement par ligne, la ligne brute dans `message`, et la colonne src_ip PROMUE.
        ingest_events_batch(&conn, dpath, &[json!({"ts":1,"source":"csvtel","category":"","message":"1700000001,203.0.113.10,198.51.100.2,allow","dedup":"c1"})], 1, None, None).unwrap();
        let (src_ip, cat): (Option<String>, String) = conn.query_row("SELECT src_ip, category FROM event WHERE source='csvtel'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(src_ip.as_deref(), Some("203.0.113.10"), "la cellule `src` est devenue la colonne d'entité");
        assert_eq!(cat, "firewall");
    }

    #[test]
    fn p3_10a_la_ligne_d_en_tete_n_est_pas_un_enregistrement_et_elle_est_comptee() {
        let conn = test_db();
        let dpath = ":memory:csv-entete";
        dparser_csv(&conn, dpath, "csvent", r#"{"name":"csv","source":"csvent","extract":[{"csv":{"columns":["ts","src","action"]}}],"map":{"src_ip":"$src","fields":{"quand":"$ts"}}}"#);
        let avant = crate::metrics::INGEST_EN_TETES_CSV_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
        let (fields, _, _) = dparsers_apply(dpath, "csvent", "ts,src,action", None);
        assert!(fields.as_deref().map(|f| !f.contains("src_ip") && !f.contains("quand")).unwrap_or(true), "l'en-tête ne pose AUCUNE capture : {fields:?}");
        assert_eq!(crate::metrics::INGEST_EN_TETES_CSV_TOTAL.load(std::sync::atomic::Ordering::Relaxed) - avant, 1, "l'en-tête est comptée");
        // Un enregistrement dont une cellule vaut par hasard le nom d'une colonne n'est PAS une en-tête : toutes doivent coïncider.
        let (fields, _, _) = dparsers_apply(dpath, "csvent", "1700000000,src,deny", None);
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["quand"], "1700000000");
        assert_eq!(fv["src_ip"], "src", "une cellule qui vaut un nom de colonne reste une cellule");
    }

    #[test]
    fn p3_10a_guillemets_et_separateurs_inclus_sont_decoupes_conformement() {
        use crate::parsers::decouper_une_ligne_csv;
        assert_eq!(decouper_une_ligne_csv(r#""a, b",x,"dit ""x""",y"#, b','), vec!["a, b", "x", "dit \"x\"", "y"]);
        assert_eq!(decouper_une_ligne_csv("1;2;;4\r\n", b';'), vec!["1", "2", "", "4"], "séparateur déclaré, cellule vide, fin de ligne ôtée");
        assert_eq!(decouper_une_ligne_csv(r#""non refermé,reste"#, b','), vec!["non refermé,reste"], "un guillemet non refermé prend le reste de la ligne, sans erreur");
        assert_eq!(decouper_une_ligne_csv("é,ü,\"ç,c\"", b','), vec!["é", "ü", "ç,c"], "l'UTF-8 traverse la découpe");
        // À travers le parseur, avec un séparateur point-virgule.
        let conn = test_db();
        let dpath = ":memory:csv-guillemets";
        dparser_csv(&conn, dpath, "csvq", r#"{"name":"csv","source":"csvq","extract":[{"csv":{"delimiter":";","columns":["user","msg"]}}],"map":{"fields":{"user":"$user","note":"$msg"}}}"#);
        let (fields, _, _) = dparsers_apply(dpath, "csvq", r#"alice;"a; b ""c"""#, None);
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["user"], "alice"); assert_eq!(fv["note"], "a; b \"c\"");
    }

    #[test]
    fn p3_10a_colonne_manquante_sans_ecriture_et_ligne_trop_large_bornee() {
        let conn = test_db();
        let dpath = ":memory:csv-bornes";
        dparser_csv(&conn, dpath, "csvb", r#"{"name":"csv","source":"csvb","extract":[{"csv":{"columns":["a","b","c","d"]}}],"map":{"fields":{"a":"$a","b":"$b","c":"$c","d":"$d"}}}"#);
        let (fields, _, _) = dparsers_apply(dpath, "csvb", "1,2", None);
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!((fv["a"].as_str(), fv["b"].as_str()), (Some("1"), Some("2")));
        assert!(fv.get("c").is_none() && fv.get("d").is_none(), "colonnes manquantes : aucune écriture, jamais un champ vide");
        let large = (0..40).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let (fields, _, _) = dparsers_apply(dpath, "csvb", &large, None);
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["d"], "3", "les cellules surnuméraires sont ignorées, les quatre déclarées sont posées");
        assert_eq!(fv.as_object().unwrap().len(), 4);
    }

    #[test]
    fn p3_10a_une_spec_csv_invalide_est_ignoree_sans_crash() {
        let conn = test_db();
        let dir = mk_overlay_dir("dpar-csv-bad");
        write_overlay(&dir, "parsers", "vide.json", r#"{"name":"cbad-vide","source":"x","extract":[{"csv":{"columns":[]}}],"map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "delim.json", r#"{"name":"cbad-delim","source":"x","extract":[{"csv":{"delimiter":"ab","columns":["a"]}}],"map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "nom.json", r#"{"name":"cbad-nom","source":"x","extract":[{"csv":{"columns":["bad-name"]}}],"map":{"category":"web"}}"#);
        write_overlay(&dir, "parsers", "double.json", r#"{"name":"cbad-double","source":"x","extract":[{"csv":{"columns":["a","a"]}}],"map":{"category":"web"}}"#);
        let trente_trois: Vec<String> = (0..33).map(|i| format!("\"c{i}\"")).collect();
        write_overlay(&dir, "parsers", "trop.json", &format!(r#"{{"name":"cbad-trop","source":"x","extract":[{{"csv":{{"columns":[{}]}}}}],"map":{{"category":"web"}}}}"#, trente_trois.join(",")));
        write_overlay(&dir, "parsers", "bon.json", r#"{"name":"cgood","source":"x","extract":[{"csv":{"columns":["a","b"]}}],"map":{"fields":{"a":"$a"}}}"#);
        load_overlays_dir(&conn, &dir);
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM dparser WHERE name LIKE 'cbad-%'", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "les cinq specs invalides sont skippées (validé-ou-ignoré)");
        let good: i64 = conn.query_row("SELECT COUNT(*) FROM dparser WHERE name='cgood'", [], |r| r.get(0)).unwrap();
        assert_eq!(good, 1, "la spec valide est chargée");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn p3_10a_l_exemple_csv_livre_charge_et_mappe() {
        let conn = test_db();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config.d");
        load_overlays_dir(&conn, &root);
        let (source, managed): (String, i64) = conn.query_row("SELECT source, managed FROM dparser WHERE name='export CSV firewall → CIM'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((source.as_str(), managed), ("csv-firewall", 1));
        let dpath = ":memory:csv-livre";
        dparsers_reload(&conn, dpath);
        let (fields, cat, sev) = dparsers_apply(dpath, "csv-firewall", "1700000000,203.0.113.7,198.51.100.2,22,tcp,deny", None);
        assert_eq!((cat.as_deref(), sev), (Some("firewall"), Some(2)));
        let fv: Value = serde_json::from_str(fields.as_deref().unwrap()).unwrap();
        assert_eq!(fv["src_ip"], "203.0.113.7"); assert_eq!(fv["dst_ip"], "198.51.100.2"); assert_eq!(fv["action"], "deny");
        assert_eq!(fv["dst_port"], "22"); assert_eq!(fv["proto"], "tcp");
    }
