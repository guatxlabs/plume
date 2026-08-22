    // `P4.1-r` — UNE BRANCHE D'ÉCHEC MUETTE HORS DU CRATE DE L'AGENT : ce que les sites fermés RENDENT
    // quand la source manque, et ce qu'ils rendent quand elle est là.
    //
    // CE QUE LA GARDE STATIQUE NE PROUVE PAS, ET QUE CETTE SUITE TIENT. La garde
    // (`.github/scripts/check_coverage_loss_is_never_silent.py`) prouve une FORME : la branche d'échec
    // compte ou propage. Elle ne distingue pas un compte VRAI d'un compte inventé, ni un aveu rendu d'un
    // aveu PERMANENT. Chaque propriété est donc exercée DANS LES DEUX SENS sur un temporaire possédé :
    //   ① la source MANQUE (dossier absent, dossier refusé, fichier invalide, table absente) -> l'aveu,
    //     avec sa cause dans l'ensemble fermé de `S32`, et RIEN de supprimé ni d'inventé ;
    //   ② la même source SAINE -> la valeur lue, un VRAI zéro d'abandons, aucun aveu.
    // Un correctif dégénéré — « avoue toujours », « ne lit plus jamais », « rend `Lue(0)` sur un échec »
    // — échoue à l'un des deux témoins. C'est le témoin INVERSE qui rend le positif opposable.
    //
    // L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU : la famille « dossier refusé » n'est comptée que si la
    // privation de droits MORD réellement sur la machine qui exécute la suite (sous un compte
    // privilégié elle ne mord pas) ; le plancher `MIN_FAMILLES` refuse de conclure si trop peu de
    // familles ont été réellement exercées.
    use crate::bilan_de_tick::{self, BilanDuPlanificateur};
    use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ABSENTE, CAUSE_SOURCE_REFUSEE};
    use crate::overlays_adossement::{est_json, lister, RefusDePrune};

    /// Sous ce nombre de familles de trou RÉELLEMENT exercées, c'est l'instrument qui est cassé.
    const MIN_FAMILLES_ADOSSEMENT: usize = 3;

    /// Une privation de droits qui ne mord pas (compte privilégié) ne prouve rien : la famille n'est
    /// alors PAS comptée, plutôt que déclarée couverte sans avoir été vue.
    #[cfg(unix)]
    fn priver_de_lecture(dir: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::read_dir(dir).is_err()
    }
    #[cfg(unix)]
    fn rendre_la_lecture(dir: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }

    /// ① Un dossier ABSENT est un listing VIDE (les sous-dossiers de `config.d` sont optionnels) ;
    /// ② un dossier SAIN rend ses fichiers, filtrés et triés ; ③ un dossier REFUSÉ est `Illisible` avec
    /// la cause `source_refusee` — jamais une liste vide.
    #[test]
    fn un_listing_refuse_n_est_pas_un_listing_vide() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-listing");
        let racine = tmp.racine().chemin().to_path_buf();
        let mut familles = 0usize;

        // ① absent -> Lue(vide) : une valeur, pas une panne.
        assert_eq!(lister(&racine.join("absent"), est_json), Mesure::Lue(Vec::new()), "dossier absent = listing vide, c'est un fait");
        familles += 1;

        // ② sain -> les `.json`, triés, et rien d'autre.
        let d = racine.join("rules");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("b.json"), b"{}").unwrap();
        std::fs::write(d.join("a.json"), b"{}").unwrap();
        std::fs::write(d.join("note.txt"), b"x").unwrap();
        let lu = lister(&d, est_json);
        assert_eq!(lu, Mesure::Lue(vec![d.join("a.json"), d.join("b.json")]), "un dossier sain rend ses fichiers, triés : {lu:?}");
        familles += 1;

        // ③ refusé -> Illisible{source_refusee}, si la privation mord.
        #[cfg(unix)]
        {
        if priver_de_lecture(&d) {
            let refuse = lister(&d, est_json);
            rendre_la_lecture(&d);
            match refuse {
                Mesure::Illisible { cause, detail } => {
                    assert_eq!(cause, CAUSE_SOURCE_REFUSEE, "la cause est celle de l'ensemble fermé : {detail}");
                    assert!(detail.contains("rules"), "le détail nomme le dossier : {detail}");
                }
                Mesure::Lue(v) => panic!("un dossier refusé a rendu une liste ({} entrée(s)) — c'est le défaut que cette clé ferme", v.len()),
            }
            familles += 1;
        } else {
            rendre_la_lecture(&d);
        }
        }
        assert!(familles >= 2, "instrument : {familles} famille(s) exercée(s)");
    }

    /// L'ÉLAGAGE (`prune_orphan_overlays`) sur un adossement qu'on ne sait pas lire REFUSE et ne supprime
    /// RIEN — dossier refusé, fichier illisible, JSON invalide, fichier sans `name` — et le refus nomme le
    /// fichier. Témoin inverse : le même `config.d` réparé élague l'orphelin et garde l'adossé. Avant,
    /// chacun de ces cas élaguait TOUTES les règles livrées, sans erreur.
    #[test]
    fn l_elagage_refuse_sur_un_adossement_illisible_et_ne_supprime_rien() {
        let conn = test_db();
        conn.execute("INSERT INTO rule(name,managed) VALUES('ov-kept',1)", []).unwrap();
        conn.execute("INSERT INTO rule(name,managed) VALUES('ov-orphan',1)", []).unwrap();
        let regles_managed = || conn.query_row("SELECT COUNT(*) FROM rule WHERE managed=1", [], |r| r.get::<_, i64>(0)).unwrap();
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-prune");
        let root = tmp.racine().chemin().to_path_buf();
        let rules = root.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        let kept = rules.join("kept.json");
        std::fs::write(&kept, br#"{"name":"ov-kept","query":"search | stats count","is_soql":true}"#).unwrap();
        let mut familles = 0usize;

        let refus_sans_suppression = |r: Result<crate::PruneCounts, RefusDePrune>, quoi: &str| -> String {
            match r {
                Err(RefusDePrune::Adossement { cause, detail }) => {
                    assert_eq!(regles_managed(), 2, "{quoi} : RIEN ne doit être supprimé sur un refus");
                    format!("{cause} {detail}")
                }
                Err(RefusDePrune::Base(e)) => panic!("{quoi} : refusé pour la mauvaise raison (base) : {e}"),
                Ok(c) => panic!("{quoi} : l'élagage a eu lieu ({c:?}) sur un adossement illisible — c'est le défaut que cette clé ferme"),
            }
        };

        // JSON invalide à côté du fichier sain : refus, forme_inconnue, le fichier nommé.
        let bad = rules.join("bad.json");
        std::fs::write(&bad, b"{ pas du json").unwrap();
        let m = refus_sans_suppression(crate::prune_orphan_overlays(&conn, &root), "JSON invalide");
        assert!(m.starts_with(CAUSE_FORME_INCONNUE) && m.contains("bad.json"), "cause et fichier nommés : {m}");
        familles += 1;

        // Fichier sans `name` : on ne sait pas quelle ligne il adosse -> refus.
        std::fs::write(&bad, br#"{"query":"search | stats count"}"#).unwrap();
        let m = refus_sans_suppression(crate::prune_orphan_overlays(&conn, &root), "sans name");
        assert!(m.contains("name") && m.contains("bad.json"), "le refus dit ce qui manque : {m}");
        familles += 1;

        // Fichier présent mais REFUSÉ en lecture (si la privation mord).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&bad).is_err() {
                let m = refus_sans_suppression(crate::prune_orphan_overlays(&conn, &root), "fichier refusé");
                assert!(m.starts_with(CAUSE_SOURCE_REFUSEE) && m.contains("bad.json"), "cause E/S et fichier nommés : {m}");
                familles += 1;
            }
            let _ = std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644));
        }
        std::fs::remove_file(&bad).unwrap();

        // Dossier `rules/` REFUSÉ (si la privation mord) : c'est le cas qui supprimait tout.
        #[cfg(unix)]
        {
        if priver_de_lecture(&rules) {
            let r = crate::prune_orphan_overlays(&conn, &root);
            rendre_la_lecture(&rules);
            let m = refus_sans_suppression(r, "dossier refusé");
            assert!(m.starts_with(CAUSE_SOURCE_REFUSEE), "cause `source_refusee` : {m}");
            familles += 1;
        } else {
            rendre_la_lecture(&rules);
        }
        }

        // TÉMOIN INVERSE : le même `config.d`, sain -> l'orphelin est élagué, l'adossé conservé. Sans lui,
        // un élagage qui REFUSERAIT TOUJOURS passerait tout ce qui précède.
        let c = crate::prune_orphan_overlays(&conn, &root).expect("adossement sain : l'élagage a lieu");
        assert_eq!(c.rule, 1, "seul l'orphelin est élagué : {c:?}");
        assert_eq!(regles_managed(), 1, "l'adossé reste");
        familles += 1;

        assert!(
            familles >= MIN_FAMILLES_ADOSSEMENT,
            "seulement {familles} famille(s) réellement exercée(s) (plancher {MIN_FAMILLES_ADOSSEMENT}) : l'instrument ne peut pas conclure"
        );
    }

    /// LE CHARGEMENT dit ce qu'il ignore : un fichier invalide à côté d'un fichier sain -> `charges=1`,
    /// bilan `Lue(1)` ; un dossier refusé -> bilan `Illisible`, rien de chargé ; le tout PUBLIÉ pour la
    /// surface. Témoin inverse : un `config.d` sain rend `Lue(0)`.
    #[test]
    fn un_chargement_dit_ce_qu_il_ignore_et_le_publie() {
        let conn = test_db();
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-chargement");
        let root = tmp.racine().chemin().to_path_buf();
        let rules = root.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("ok.json"), br#"{"name":"p41r-ok","query":"search | stats count","is_soql":true,"enabled":false}"#).unwrap();

        // ② sain d'abord : un VRAI zéro.
        let total = crate::load_overlays_dir(&conn, &root);
        assert_eq!(total.charges, 1, "la règle saine est chargée");
        assert_eq!(total.mesure(), Mesure::Lue(0), "rien d'ignoré : un vrai zéro");
        assert_eq!(bilan_de_tick::dernier(crate::overlays_adossement::PASSE_OVERLAYS), Some(Mesure::Lue(0)), "le bilan est publié");

        // ① un fichier invalide de plus : compté, nommé dans le journal, et la règle saine toujours chargée.
        std::fs::write(rules.join("bad.json"), b"{ pas du json").unwrap();
        let total = crate::load_overlays_dir(&conn, &root);
        assert_eq!(total.charges, 1);
        assert_eq!(total.mesure(), Mesure::Lue(1), "UN fichier ignoré, compté");

        // ① dossier refusé (si la privation mord) : rien de chargé, et l'aveu domine le compte.
        #[cfg(unix)]
        {
        if priver_de_lecture(&rules) {
            let total = crate::load_overlays_dir(&conn, &root);
            rendre_la_lecture(&rules);
            assert_eq!(total.charges, 0, "rien ne peut être chargé d'un dossier refusé");
            match total.mesure() {
                Mesure::Illisible { cause, .. } => assert_eq!(cause, CAUSE_SOURCE_REFUSEE),
                Mesure::Lue(n) => panic!("un dossier refusé a rendu un compte ({n}) au lieu d'un aveu"),
            }
            assert!(matches!(bilan_de_tick::dernier(crate::overlays_adossement::PASSE_OVERLAYS), Some(Mesure::Illisible { .. })), "l'aveu est publié");
        } else {
            rendre_la_lecture(&rules);
        }
        }
    }

    /// UN TICK QUI NE PEUT PAS LIRE SES RÈGLES EST AVEUGLE, ET LE DIT : `run_due_rules` rend `Illisible`
    /// (cause `forme_inconnue` : la table manque) ; une règle due dont la requête ne compile pas est
    /// COMPTÉE (`Lue(1)`) et son `last_run` avance ; une règle saine est évaluée et le bilan est un VRAI
    /// zéro. Avant : `return` muet dans les trois cas, et la santé « détection » restait verte.
    #[test]
    fn un_tick_qui_ne_peut_pas_lire_ses_regles_est_aveugle_et_le_dit() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-tick");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('p41r-saine',1,'search | stats count',1,'>',1000000,2,300,3600)",
                [],
            ).unwrap();
        }
        // ② saine : évaluée, aucun abandon.
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(0), "une règle saine due n'est pas un abandon");

        // ① une règle due dont la requête ne compile pas : comptée, et re-planifiée (last_run avance).
        {
            let conn = db.lock();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('p41r-cassee',1,'search | stats count by | where',1,'>',0,2,300,3600)",
                [],
            ).unwrap();
        }
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(1), "UNE règle due abandonnée, comptée");
        {
            let conn = db.lock();
            let lr: Option<i64> = conn.query_row("SELECT last_run FROM rule WHERE name='p41r-cassee'", [], |r| r.get(0)).unwrap();
            assert!(lr.is_some(), "la règle abandonnée est re-planifiée, comme avant");
        }
        // ② re-tick immédiat : plus rien n'est dû -> vrai zéro (et non un compte qui grimpe à vide).
        assert_eq!(run_due_rules(&db, &p), Mesure::Lue(0));

        // ① la table manque : le tick est AVEUGLE, et ce n'est pas un `Lue(0)`.
        db.lock().execute_batch("DROP TABLE rule").unwrap();
        match run_due_rules(&db, &p) {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(cause, CAUSE_FORME_INCONNUE, "une table absente est une forme que la base ne présente pas : {detail}");
                assert!(detail.contains("règles"), "l'aveu nomme la famille : {detail}");
            }
            Mesure::Lue(n) => panic!("sans table `rule`, le tick a rendu Lue({n}) : un tick aveugle qui se dit calme"),
        }
    }

    /// LE PLANIFICATEUR ABSORBE ET LA SURFACE DIT : la somme des abandons reste un compte ; UNE famille
    /// aveugle rend le tout `Illisible` (un compte partiel serait plus petit que la réalité) ; et l'état
    /// de surface dérivé est vert/inchangé sur `Lue(0)`, JAUNE sur des abandons, ROUGE sur un tick aveugle,
    /// inchangé avant le premier tick. Puis la publication par boucle, relue par `combiner`.
    #[test]
    fn le_bilan_du_planificateur_absorbe_et_la_surface_le_dit() {
        let mut b = BilanDuPlanificateur::default();
        assert_eq!(b.mesure(), Mesure::Lue(0), "un planificateur neuf n'a rien abandonné : vrai zéro");
        b.absorber(Mesure::Lue(2));
        b.absorber(Mesure::Lue(3));
        assert_eq!(b.mesure(), Mesure::Lue(5), "les abandons s'additionnent");
        b.absorber(Mesure::Illisible { cause: CAUSE_SOURCE_ABSENTE, detail: "corrélations : x".into() });
        b.absorber(Mesure::Lue(1));
        match b.mesure() {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(cause, CAUSE_SOURCE_ABSENTE, "la première cause est conservée");
                assert!(detail.contains("corrélations") && detail.contains("6"), "le détail nomme la famille aveugle ET les abandons comptés par ailleurs : {detail}");
            }
            Mesure::Lue(n) => panic!("une famille aveugle a été absorbée dans un compte ({n})"),
        }
        let mut p = BilanDuPlanificateur::default();
        p.panique("t1");
        assert!(matches!(p.mesure(), Mesure::Illisible { .. }), "un tick qui a paniqué n'est pas un tick calme");

        // L'état de surface, dérivé — les quatre cas.
        let vert = ("green", "actif".to_string());
        assert_eq!(bilan_de_tick::etat_de_surface(vert.0, vert.1.clone(), None), ("green", "actif".into()), "avant le premier tick : inchangé");
        assert_eq!(bilan_de_tick::etat_de_surface(vert.0, vert.1.clone(), Some(&Mesure::Lue(0))), ("green", "actif".into()), "zéro abandon : inchangé");
        let (e, d) = bilan_de_tick::etat_de_surface(vert.0, vert.1.clone(), Some(&Mesure::Lue(3)));
        assert_eq!(e, "yellow");
        assert!(d.contains("3") && d.contains("ABANDONN"), "le détail porte le compte : {d}");
        let (e, d) = bilan_de_tick::etat_de_surface(vert.0, vert.1.clone(), Some(&Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: "règles : no such table".into() }));
        assert_eq!(e, "red", "un tick aveugle est ROUGE, pas un tick calme");
        assert!(d.contains("AVEUGLE") && d.contains("no such table"), "le détail porte la cause : {d}");
        // Le pire l'emporte : un tick déjà rouge (bloqué) ne redevient pas jaune pour 3 abandons.
        assert_eq!(bilan_de_tick::etat_de_surface("red", "bloqué".into(), Some(&Mesure::Lue(3))).0, "red");

        // Publication et relecture, sur une clé PROPRE à ce test (les clés des boucles réelles sont lues
        // par d'autres tests de santé, en parallèle).
        const CLE: &str = "p41r-test";
        assert_eq!(bilan_de_tick::combiner(&[CLE]), None, "avant toute publication : pas de bilan, pas un zéro inventé");
        bilan_de_tick::publier(CLE, Mesure::Lue(4));
        assert_eq!(bilan_de_tick::combiner(&[CLE]), Some(Mesure::Lue(4)));
        bilan_de_tick::publier(CLE, Mesure::Illisible { cause: CAUSE_SOURCE_ABSENTE, detail: "x".into() });
        assert!(matches!(bilan_de_tick::combiner(&[CLE, "p41r-jamais-publiee"]), Some(Mesure::Illisible { .. })), "une boucle aveugle rend le combiné aveugle ; une boucle jamais publiée n'y pèse rien");
        let mut objet = serde_json::Map::new();
        bilan_de_tick::poser_bilan(&mut objet, "abandons", bilan_de_tick::combiner(&[CLE]).as_ref());
        assert_eq!(objet["abandons_verdict"], "illisible");
        assert!(objet.get("abandons").is_none(), "aucun nombre à lire quand le bilan est illisible");
        let mut vide = serde_json::Map::new();
        bilan_de_tick::poser_bilan(&mut vide, "abandons", None);
        assert!(vide.is_empty(), "sans bilan, RIEN n'est posé : l'absence se lit « pas encore de tick »");
    }

    /// UN PASSAGE SUR LE SPOOL rend son bilan : spool absent -> `Illisible{source_absente}` (la voie
    /// fichier est morte pour ce passage) ; un fichier INDÉCODABLE -> compté ET mis en quarantaine
    /// (avant : SUPPRIMÉ, les événements d'un cycle de collecte disparaissaient) ; un fichier sain ->
    /// ingéré, vrai zéro.
    #[test]
    fn un_fichier_de_spool_indecodable_part_en_quarantaine_et_compte() {
        let (st, spool) = ing_state_with_spool();
        // ① spool absent.
        let absent = spool.join("absent");
        match ingest_once(&st.tenants, absent.to_str().unwrap()) {
            Mesure::Illisible { cause, .. } => assert_eq!(cause, CAUSE_SOURCE_ABSENTE),
            Mesure::Lue(n) => panic!("un spool absent a rendu Lue({n})"),
        }
        // ② sain : ingéré, retiré, zéro abandon.
        let ok = spool.join(format!("ingest-{}-1.json", now()));
        std::fs::write(&ok, json!({ "kind": "events", "ts": now(), "data": { "events": [ { "source": "p41r", "message": "m" } ] } }).to_string()).unwrap();
        assert_eq!(ingest_once(&st.tenants, &st.spool), Mesure::Lue(0), "un fichier sain n'est pas un abandon");
        assert!(!ok.exists(), "ingéré -> retiré du spool");
        // ① indécodable : compté, conservé en quarantaine, jamais supprimé.
        let bad = spool.join(format!("ingest-{}-2.json", now()));
        std::fs::write(&bad, b"{ pas du json").unwrap();
        assert_eq!(ingest_once(&st.tenants, &st.spool), Mesure::Lue(1), "UN fichier abandonné, compté");
        assert!(!bad.exists(), "retiré de la file (il ne serait jamais ingéré)");
        assert!(spool.join("quarantine").join(bad.file_name().unwrap()).exists(), "mais CONSERVÉ en quarantaine, pas supprimé");
        // ② un passage de plus : plus rien -> vrai zéro, pas un compte qui se souvient.
        assert_eq!(ingest_once(&st.tenants, &st.spool), Mesure::Lue(0));
    }

    /// LE BALAYAGE DES TEMPORAIRES rend ce qu'il n'a pas su lire : répertoire absent -> `repertoire_lisible
    /// = false` et RIEN d'effacé ; répertoire sain -> le compte des effacés et un vrai zéro d'illisibles.
    #[test]
    fn un_balayage_dit_ce_qu_il_n_a_pas_su_lire() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-balayage");
        let absent = tmp.racine().chemin().join("absent");
        let b = crate::backup::sweep_orphan_temps(&absent, std::time::Duration::ZERO);
        assert!(!b.repertoire_lisible && b.effaces == 0, "un répertoire absent : rien balayé, et c'est dit : {b:?}");
        assert!(b.phrase("x").contains("ILLISIBLE"), "la phrase du journal le dit aussi");
        let sain = crate::backup::sweep_orphan_temps(tmp.racine().chemin(), std::time::Duration::ZERO);
        assert_eq!(sain, crate::backup::Balayage::default(), "un répertoire sain et vide : vrai zéro partout, rien à dire");
        assert!(sain.phrase("x").is_empty(), "rien à dire -> phrase vide");
    }

    /// L'INVENTAIRE DU TIER FROID compte ce qu'il ne sait pas lire et se dit MINORANT, au lieu de se
    /// présenter complet. Témoin inverse : une arborescence saine n'avoue rien.
    #[test]
    fn un_inventaire_froid_partiel_se_dit_minorant() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p41r-froid");
        let racine = tmp.racine().chemin().to_path_buf();
        let env = racine.join("prod");
        std::fs::create_dir_all(&env).unwrap();
        std::fs::write(env.join("2026-01-01-0001.parquet"), b"x").unwrap();
        let sain = crate::cold_banniere::inventaire(&racine, 10_000);
        assert_eq!((sain.fichiers, sain.illisibles), (1, 0), "arborescence saine : compté, rien d'illisible");
        assert!(!sain.phrase().contains("MINORANT"));
        #[cfg(unix)]
        {
        if priver_de_lecture(&env) {
            let partiel = crate::cold_banniere::inventaire(&racine, 10_000);
            rendre_la_lecture(&env);
            assert_eq!(partiel.illisibles, 1, "le sous-répertoire refusé est COMPTÉ");
            assert!(partiel.phrase().contains("MINORANTS"), "et l'inventaire se dit minorant : {}", partiel.phrase());
        } else {
            rendre_la_lecture(&env);
        }
        }
    }
