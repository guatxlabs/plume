// =====================================================================================
// `P10.20-b` (reprise de la tranche des instantanés et de la tranche entretien) — CE QUE LA VÉRIFICATION DE LA VAGUE
// PRÉCÉDENTE A TROUVÉ NON TENU, ET QUI L'EST ICI.
//
//  (a) `dernier_instantane_par_hote` (`ingest/store.rs`) POURSUIT son parcours après une ligne illisible. La fixture
//      d'avant plaçait la ligne illisible en DERNIER : un `break` au premier `Err` restait vert. Ici les lignes
//      illisibles sont EN TÊTE (la plus fraîche) et AU MILIEU, des lignes lisibles derrière chacune.
//  (b) Les lignes de journal `[panel]` et `[suppressions]` disaient « N ligne(s) illisible(s) » sur
//      `FinDeParcours::erreurs()`, qui compte une interruption de `step()` pour UNE erreur et coupe un reste de taille
//      inconnue (`query_exec.rs`, doc de `erreurs`) : elles disent désormais « N erreur(s) de parcours, pas un nombre
//      de lignes », et la fin non commencée a sa propre phrase. Lignes jugées ENTIÈRES, par capture du stderr.
//  (c) `lire_le_jalon_d_analyse_complete` (`maintenance.rs`) : `lignes.parse().unwrap_or(0)` lisait un jalon
//      `<version>@<illisible>` comme une passe prise sur zéro ligne. Trois issues : taille mesurée, absente (jalon
//      ancien, base vide à dessein), illisible (passe refaite et DITE, jalon réécrit lisible : pas de boucle).
//  (d) `panel` (`handlers/overview.rs`) ne pose plus de cause sous `error` dans un deux cents (jambe B de
//      `check_a_refusal_is_not_rendered_as_an_absence.py`) : rien de lu = cinq cent trois nommé (`err_json`, témoin
//      dans `instantanes_non_lus_se_disent.rs`) ; lecture interrompue = deux cents, `hosts_etat`, `n_hosts` nul, SANS
//      clé `error`, y compris quand aucune ligne n'a été rendue.
//
// MUTANTS JOUÉS (commutateurs de mutation, retirés avant le commit), chacun vu ROUGE sur son témoin : AW3_ROW_BREAK, AW3_PANEL_200,
// AW3_PANEL_ERROR, AW3_PANEL_JOURNAL, AW3_FW_JOURNAL, AW3_JALON_ZERO, AW3_JALON_NEGATIF, AW3_JALON_REFAIT_PAS,
// AW3_JALON_MUET, AW3_JALON_VERSION ; puis AW3_CAUSE_LAST (garder la DERNIÈRE cause), resté vert tant que les deux
// lignes illisibles l'étaient sur la même colonne (même texte du moteur), rouge depuis que `srv-z` l'est sur `data`.
// =====================================================================================
mod parcours_des_instantanes_et_jalon_d_analyse_dits {
    use super::*;
    use crate::handlers::admin_ui::suppressions_get;
    use crate::handlers::overview::panel;
    use crate::maintenance::{
        analyze_full_background, la_passe_d_analyse_complete_est_a_refaire, lire_le_jalon_d_analyse_complete,
        CompteRenduDEntretien, TailleDuJalon,
    };
    use std::sync::Arc;

    const AW3_ENFANT: &str = "PLUME_TEST_AW3_ENFANT_JOURNAL";
    const AW3_PHASE: &str = "AW3-PHASE:";
    /// Le texte du moteur pour la PREMIÈRE ligne illisible (cellule BLOB lue en `TEXT`, troisième colonne).
    const AW3_CAUSE_BLOB: &str = "Invalid column type Blob at index: 2, name: COALESCE(s.hash,'')";
    /// Le texte de la DEUXIÈME (cellule BLOB lue en `TEXT`, quatrième colonne) : distinct du premier, sans quoi
    /// l'assertion « la première cause est gardée » serait vacante.
    const AW3_CAUSE_BLOB_DEUXIEME: &str = "Invalid column type Blob at index: 3, name: COALESCE(s.data,'')";
    const AW3_CAUSE_TABLE: &str = "no such table: snapshot";
    const AW3_PANEL_INTERROMPU: &str = "[panel] WARN instantanés \"firewall\" par machine : lecture interrompue (2 erreur(s) \
         de parcours, pas un nombre de lignes) — servi avec hosts_etat et n_hosts nul : ";
    const AW3_FW_INTERROMPU: &str = "[suppressions] WARN état du pare-feu par machine : lecture interrompue (2 erreur(s) de \
         parcours, pas un nombre de lignes) — servi avec firewall_etat et firewall_n_hosts nul : ";
    const AW3_PANEL_NON_COMMENCE: &str =
        "[panel] WARN instantanés \"firewall\" par machine : lecture non commencée, rien n'est lu — servi 503 : ";
    const AW3_FW_NON_COMMENCE: &str = "[suppressions] WARN état du pare-feu par machine : lecture non commencée, rien n'est \
         lu — servi avec firewall_etat et firewall_n_hosts nul : ";

    async fn aw3_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    /// Parc de trois machines lisibles, plus DEUX lignes illisibles : `srv-y` EN TÊTE (la plus fraîche, rendue la
    /// première) et `srv-z` AU MILIEU (entre `srv-a` et `srv-b`). Ordre rendu : y (illisible), a, z (illisible), b, c.
    /// Les deux illisibles le sont sur des COLONNES DIFFÉRENTES (`hash` pour `srv-y`, `data` pour `srv-z`) : le moteur
    /// rend deux textes distincts, et « la première cause est gardée » peut rougir (garder la dernière la change).
    fn aw3_parc_illisible_en_tete_et_au_milieu(conn: &Connection, kind: &str) {
        for (ts, h, illisible) in [(1005, "srv-y", Some("hash")), (1000, "srv-a", None), (995, "srv-z", Some("data")), (990, "srv-b", None), (980, "srv-c", None)] {
            let hash = format!("h-{}", &h[4..]);
            match illisible {
                None => conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}',?4)", params![ts, kind, hash, h]),
                Some("hash") => conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,X'00ff','{}',?3)", params![ts, kind, h]),
                Some(_) => conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,X'00ff',?4)", params![ts, kind, hash, h]),
            }
            .expect("fixture du parc");
        }
    }

    fn aw3_hotes(liste: &[Value]) -> Vec<String> {
        liste.iter().map(|h| h["host"].as_str().unwrap_or("?").to_string()).collect()
    }

    // ---------------------------------------------------------------------------------------------
    // (a) le parcours poursuit après une ligne illisible
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn aw3_par_hote_poursuit_apres_une_ligne_illisible_en_tete_et_au_milieu() {
        use crate::query_exec::FinDeParcours;
        let conn = test_db();
        aw3_parc_illisible_en_tete_et_au_milieu(&conn, "firewall");
        let lu = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
        let hotes: Vec<_> = lu.iter().map(|r| r.0.clone().unwrap_or_default()).collect();
        assert_eq!(hotes, ["srv-a", "srv-b", "srv-c"], "chaque ligne lisible DERRIÈRE une illisible est rendue");
        match &lu.fin {
            FinDeParcours::Interrompu { erreurs, cause } => {
                assert_eq!(*erreurs, 2, "deux lignes illisibles, deux erreurs : ni arrêt à la première, ni zéro");
                // Que les deux causes LUES diffèrent est jugé sur le moteur : `journal_des_instantanes_echappe_le_chemin.rs`.
                assert_eq!(cause, AW3_CAUSE_BLOB, "la PREMIÈRE cause est gardée, pas la dernière ({AW3_CAUSE_BLOB_DEUXIEME})");
            }
            autre => panic!("fin attendue Interrompu, pas {:?}", autre.etat()),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // (d) panel : deux cents sans `error` sur une lecture interrompue, avec ou sans ligne rendue
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn aw3_le_panneau_partiel_garde_son_deux_cents_sans_cle_error() {
        let (st, _tmp) = sp_state("aw3-panel-partiel");
        aw3_parc_illisible_en_tete_et_au_milieu(&st.db.lock(), "firewall");
        let (statut, corps) = aw3_corps(panel(State(st.clone()), Extension(sp_au("lectrice", "viewer")), Path("firewall".to_string())).await).await;
        assert_eq!(statut, 200, "{corps}");
        let cles: std::collections::BTreeSet<&str> = corps.as_object().expect("objet").keys().map(String::as_str).collect();
        assert_eq!(
            cles,
            ["data", "hash", "host", "hosts", "hosts_etat", "kind", "n_hosts", "ts"].into_iter().collect(),
            "ensemble exact des clés, sans `error` : {corps}"
        );
        assert_eq!(corps["hosts_etat"], json!("interrompu"), "{corps}");
        assert_eq!(corps["n_hosts"], Value::Null, "dénominateur non établi : {corps}");
        assert_eq!((corps["host"].clone(), corps["ts"].clone(), corps["hash"].clone()), (json!("srv-a"), json!(1000), json!("h-a")), "{corps}");
        assert_eq!(aw3_hotes(corps["hosts"].as_array().expect("hosts")), ["srv-a", "srv-b", "srv-c"], "{corps}");
    }

    #[tokio::test]
    async fn aw3_le_panneau_interrompu_sans_aucune_ligne_lue_garde_son_deux_cents() {
        let (st, _tmp) = sp_state("aw3-panel-sans-ligne");
        st.db
            .lock()
            .execute_batch("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'controls',X'00ff','{}','srv-y');")
            .expect("fixture");
        let (statut, corps) = aw3_corps(panel(State(st.clone()), Extension(sp_au("lectrice", "viewer")), Path("controls".to_string())).await).await;
        assert_eq!(
            (statut, corps),
            (200, json!({ "kind": "controls", "data": null, "hosts": [], "n_hosts": null, "hosts_etat": "interrompu" })),
            "une ligne lue illisible n'est ni « aucune donnée » (n_hosts 0) ni un refus : la fin est nommée"
        );
    }

    #[tokio::test]
    async fn aw3_les_suppressions_poursuivent_apres_une_ligne_illisible() {
        let (st, _tmp) = sp_state("aw3-suppressions");
        aw3_parc_illisible_en_tete_et_au_milieu(&st.db.lock(), "firewall");
        let (statut, corps) = aw3_corps(suppressions_get(State(st.clone()), Extension(sp_au("adm", "admin"))).await).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps["firewall"]["host"], json!("srv-a"), "la plus fraîche LISIBLE, derrière l'illisible de tête : {corps}");
        assert_eq!(aw3_hotes(corps["firewall_hosts"].as_array().expect("firewall_hosts")), ["srv-a", "srv-b", "srv-c"], "{corps}");
        assert_eq!(
            (corps["firewall_n_hosts"].clone(), corps["firewall_incomplets"].clone(), corps["firewall_etat"].clone()),
            (Value::Null, json!(true), json!("interrompu")),
            "{corps}"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (b) les lignes de journal disent des erreurs de parcours, jamais un nombre de lignes
    // ---------------------------------------------------------------------------------------------

    /// Deux phases dans un SOUS-PROCESSUS dont le stderr est lu : `illisible` (deux lignes illisibles, en tête et au
    /// milieu : deux erreurs) puis `retiree` (table renommée : fin non commencée). Lignes comparées ENTIÈRES.
    #[test]
    fn aw3_le_journal_dit_des_erreurs_de_parcours_jamais_des_lignes() {
        if std::env::var(AW3_ENFANT).is_ok() {
            let exec = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("exécuteur de test");
            exec.block_on(async {
                let (st, _tmp) = sp_state("aw3-journal");
                aw3_parc_illisible_en_tete_et_au_milieu(&st.db.lock(), "firewall");
                let adm = sp_au("adm", "admin");
                for (phase, geste) in [("illisible", ""), ("retiree", "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;")] {
                    if !geste.is_empty() {
                        st.db.lock().execute_batch(geste).expect("geste de phase");
                    }
                    eprintln!("{AW3_PHASE}{phase}");
                    let p = panel(State(st.clone()), Extension(sp_au("lectrice", "viewer")), Path("firewall".to_string())).await;
                    let s = suppressions_get(State(st.clone()), Extension(adm.clone())).await;
                    println!("AW3-ROUTES-{phase}:{}:{}", p.status().as_u16(), s.status().as_u16());
                }
                eprintln!("{AW3_PHASE}fin");
            });
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::parcours_des_instantanes_et_jalon_d_analyse_dits::aw3_le_journal_dit_des_erreurs_de_parcours_jamais_des_lignes",
            ])
            .env(AW3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("AW3-ROUTES-illisible:200:200"), "contrôle : {stdout}");
        assert!(stdout.contains("AW3-ROUTES-retiree:503:200"), "contrôle : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AW3_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AW3_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[panel] WARN") || l.starts_with("[suppressions] WARN état du pare-feu")).map(str::to_string).collect()
        };
        assert_eq!(
            phase("illisible"),
            vec![format!("{AW3_PANEL_INTERROMPU}{AW3_CAUSE_BLOB}"), format!("{AW3_FW_INTERROMPU}{AW3_CAUSE_BLOB}")],
            "lignes ENTIÈRES, une par route : {stderr}"
        );
        assert_eq!(
            phase("retiree"),
            vec![format!("{AW3_PANEL_NON_COMMENCE}{AW3_CAUSE_TABLE}"), format!("{AW3_FW_NON_COMMENCE}{AW3_CAUSE_TABLE}")],
            "lignes ENTIÈRES, une par route : {stderr}"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (c) le jalon d'analyse en trois issues
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn aw3_le_jalon_se_lit_en_trois_issues() {
        assert_eq!(lire_le_jalon_d_analyse_complete("119@500"), ("119", TailleDuJalon::Mesuree(500)));
        assert_eq!(lire_le_jalon_d_analyse_complete("119@0"), ("119", TailleDuJalon::Mesuree(0)), "zéro mesuré est une taille");
        assert_eq!(lire_le_jalon_d_analyse_complete("119"), ("119", TailleDuJalon::Absente), "jalon ancien : taille absente");
        assert_eq!(lire_le_jalon_d_analyse_complete("119@abc"), ("119", TailleDuJalon::Illisible));
        assert_eq!(lire_le_jalon_d_analyse_complete("119@365.0"), ("119", TailleDuJalon::Illisible), "non entier : illisible, jamais arrondi");
        assert_eq!(lire_le_jalon_d_analyse_complete("119@"), ("119", TailleDuJalon::Illisible));
        assert_eq!(lire_le_jalon_d_analyse_complete("119@-5"), ("119", TailleDuJalon::Illisible), "une taille négative n'est pas une mesure");
        assert!(la_passe_d_analyse_complete_est_a_refaire(Some("119@abc"), "119", 0), "illisible : refaite, même sur une table vide");
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119"), "119", 999), "absente : base vide à dessein, inchangé");
        assert!(!la_passe_d_analyse_complete_est_a_refaire(Some("119@0"), "119", 999), "mesurée à zéro : sous le seuil, rien");
    }

    fn aw3_base_d_analyse(jalon: impl FnOnce(&str) -> String) -> (Arc<parking_lot::Mutex<Connection>>, String, i64) {
        let db = Arc::new(parking_lot::Mutex::new(test_db()));
        let (v, n) = {
            let c = db.lock();
            let v: String = c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("version");
            let n: i64 = c.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).expect("taille");
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('analyze_full_done', ?1)", params![jalon(&v)]).expect("jalon posé");
            (v, n)
        };
        assert!(n < crate::maintenance::SEUIL_DE_LIGNES_DE_REARMEMENT_DE_L_ANALYSE, "contrôle : une passe « à zéro » ne serait pas refaite ici");
        (db, v, n)
    }

    fn aw3_jalon(db: &Arc<parking_lot::Mutex<Connection>>) -> String {
        db.lock().query_row("SELECT value FROM meta WHERE key='analyze_full_done'", [], |r| r.get(0)).expect("jalon")
    }

    #[test]
    fn aw3_un_jalon_a_taille_illisible_est_dit_puis_refait_une_fois() {
        let (db, v, n) = aw3_base_d_analyse(|v| format!("{v}@abc"));
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            CompteRenduDEntretien {
                lignes: vec![
                    format!("[analyze] jalon analyze_full_done de la version {v} : taille illisible (ni un entier positif ni absente) — la taille de la passe précédente n'est pas établie, ANALYZE complet refait et jalon réécrit"),
                    format!("[analyze] ANALYZE complet terminé (tâche de fond, jalon {v}@{n}) -> stats exactes pour les index composés"),
                ],
                lectures_non_faites: 0,
                ecritures_refusees: 0,
            }
        );
        assert_eq!(aw3_jalon(&db), format!("{v}@{n}"), "le jalon réécrit est lisible");
        assert_eq!(
            analyze_full_background(&db),
            CompteRenduDEntretien { lignes: vec![], lectures_non_faites: 0, ecritures_refusees: 0 },
            "réparé : pas de boucle"
        );
    }

    #[test]
    fn aw3_un_jalon_illisible_d_une_autre_version_est_refait_sans_la_ligne_de_taille() {
        let (db, v, n) = aw3_base_d_analyse(|_| "version-ancienne@abc".to_string());
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            CompteRenduDEntretien {
                lignes: vec![format!("[analyze] ANALYZE complet terminé (tâche de fond, jalon {v}@{n}) -> stats exactes pour les index composés")],
                lectures_non_faites: 0,
                ecritures_refusees: 0,
            },
            "un bump de version refait la passe ; la taille d'un jalon d'une autre version n'est pas en cause"
        );
        assert_eq!(aw3_jalon(&db), format!("{v}@{n}"));
    }
}
