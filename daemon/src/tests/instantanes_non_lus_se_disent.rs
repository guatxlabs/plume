// =====================================================================================
// `P10.20-b` — TRANCHE DES INSTANTANÉS : UNE LECTURE QUI N'A PAS ABOUTI N'EST NI « AUCUNE LIGNE » NI « UNE
// MACHINE DE MOINS ».
//
// LES TROIS LECTURES DE `ingest/store.rs` ET CE QU'ELLES SERVAIENT.
//   * `SnapshotSeries::dernier_hash` (`.ok()`) — appelée par l'ingestion du spool : une empreinte non lue
//     se lisait « série vide » et l'instantané était inscrit comme un état neuf EN SILENCE.
//   * `dernier_instantane_de` (`.ok()`) — appelée par `GET /api/snapshot/{genre}/{machine}` : une lecture
//     ratée servait le QUATRE CENT QUATRE nu, que la console lit comme « aucun instantané de cette machine ».
//   * `dernier_instantane_par_hote` (`else { return Vec::new() }` + `rows.flatten()`) — appelée par
//     `GET /api/panel/{kind}` et `suppressions_get` : une préparation refusée se servait « aucune donnée »,
//     une ligne illisible retirait une machine du parc et du dénominateur `n_hosts`.
//
// LES DEUX VOIES JOUÉES. La CELLULE ILLISIBLE (un `BLOB` dans `snapshot.hash`, colonne lue en `TEXT`) fait
// échouer le mappeur d'UNE ligne, la requête restant saine ; la TABLE RETIRÉE fait échouer la préparation.
// Chaque témoin porte aussi son contrôle positif (lecture saine) et l'absence vraie, jugée à part.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE sur son témoin :
//   AV6_HASH_OK (dernier_hash rend Ok(None) sur une lecture ratée), AV6_HASH_MUET (l'ingestion ne dit rien),
//   AV6_DE_OK (dernier_instantane_de rend Ok(None) sur une lecture ratée), AV6_DE_404 (la route sert 404),
//   AV6_PH_PREP_VIDE (préparation refusée rendue Complet), AV6_PH_FLATTEN (ligne illisible sautée sans fin
//   Interrompu), AV6_PH_SANS_BORNE (la boucle ne s'arrête plus à `max`), AV6_PANEL_SANS_AVEU (le panneau ne
//   juge pas la fin), AV6_PANEL_N_HOSTS (le dénominateur partiel reste servi), AV6_FW_ETAT (`suppressions_get`
//   ne sert pas la fin), AV6_FW_N_HOSTS (le dénominateur partiel du pare-feu reste servi).
// CORRECTION (la vérification a relevé que les trois routes jetaient l'erreur du moteur sans trace) : chaque route écrit
// au journal la classe ou le texte que son corps ne porte pas — mutants AV6C_SNAP_MUET, AV6C_PANEL_MUET, AV6C_FW_MUET,
// chacun vu ROUGE sur `inl_les_trois_routes_journalisent_la_lecture_ratee`.
// =====================================================================================
mod instantanes_non_lus_se_disent {
    use super::*;
    use crate::handlers::admin_ui::suppressions_get;
    use crate::handlers::overview::{panel, snapshot_par_genre_et_machine};

    const INL_ENFANT: &str = "PLUME_TEST_INL_ENFANT";
    const INL_PHASE: &str = "INL-PHASE:";
    const LIGNE_EMPREINTE_NON_LUE: &str = "[ingest] WARN instantané du spool : la dernière empreinte de sa série n'a pas été lue \
         (forme_inconnue) — l'instantané est inscrit comme un état neuf, pas comme un battement";
    const CAUSE_MACHINE: &str = "INSTANTANÉ NON LU : la base n'a pas rendu le dernier instantané de cette machine — rien \
         n'est établi sur son état, et ce n'est pas l'absence d'un instantané";
    // `P10.20-b` (reprise) — INVERSÉ : la cause n'est plus posée sous `error` dans un deux cents ; c'est celle du cinq cent
    // trois que `panel` sert quand rien n'a été lu.
    const CAUSE_PARC: &str = "INSTANTANÉS DU PARC NON LUS : la base n'a pas rendu le dernier instantané des machines de ce \
         genre — rien n'est établi sur le parc, et ce n'est pas l'absence d'instantané";

    async fn inl_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    fn inl_ecrire(st: &AppState, sql: &str) {
        let conn = st.db.lock();
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn inl_viewer() -> AuthUser {
        sp_au("lectrice", "viewer")
    }

    /// Un 503 d'`err_json` : exactement `error` (la cause attendue) et `id` (identifiant de corrélation).
    fn inl_juger_le_503(statut: u16, corps: &Value, cause: &str) {
        assert_eq!(statut, 503, "lecture ratée = 503, ni 404 ni 200 : {corps}");
        let cles: std::collections::BTreeSet<&str> = corps.as_object().expect("corps objet").keys().map(String::as_str).collect();
        assert_eq!(cles, ["error", "id"].into_iter().collect(), "ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "la cause nommée, à l'octet : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "identifiant de corrélation : {corps}");
    }

    // ---------------------------------------------------------------------------------------------
    // (1) `dernier_hash` — trois issues, et l'ingestion DIT l'empreinte non lue.
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn inl_dernier_hash_rend_trois_issues() {
        let conn = test_db();
        let vide = crate::ingest::store::SnapshotSeries::new("firewall", Some("srv-a"));
        assert_eq!(vide.dernier_hash(&conn).expect("série vide : lue"), None, "aucune ligne = Ok(None)");
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(100,'firewall','h-lue','{}','srv-a')", []).unwrap();
        assert_eq!(vide.dernier_hash(&conn).expect("série lisible"), Some("h-lue".to_string()), "empreinte lue");
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(100,'firewall',X'00ff','{}','srv-b')", []).unwrap();
        let illisible = crate::ingest::store::SnapshotSeries::new("firewall", Some("srv-b"));
        assert!(illisible.dernier_hash(&conn).is_err(), "cellule illisible = Err, jamais Ok(None)");
    }

    /// L'INGESTION, PAR LE VRAI CHEMIN (`ingest_once` sur un spool), DANS UN SOUS-PROCESSUS DONT LE STDERR EST LU.
    /// Phase `illisible` : la dernière ligne de la série porte une empreinte BLOB -> la ligne de journal ENTIÈRE,
    /// une fois, et l'instantané est inscrit (deux lignes). Phase `lisible` : même envoi sur une empreinte lisible
    /// identique -> battement, AUCUNE ligne (l'aveu n'est pas inconditionnel).
    #[test]
    fn inl_l_ingestion_dit_l_empreinte_non_lue_et_inscrit() {
        if std::env::var(INL_ENFANT).is_ok() {
            for (phase, empreinte_stockee) in [("illisible", "X'00ff'"), ("lisible", "'h-meme'")] {
                eprintln!("{INL_PHASE}{phase}");
                let (st, spool) = ing_state_with_spool();
                let t = now() - 100;
                inl_ecrire(
                    &st,
                    &format!("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES({},'firewall',{empreinte_stockee},'{{}}','web01');", t - 300),
                );
                let env = json!({ "ts": t, "host": "web01", "kind": "firewall", "hash": "h-meme", "data": { "ruleset_sha256": "h-meme" } });
                let fichier = depose_spool(&spool, "web01", 0, &env.to_string());
                ingest_once(&st.tenants, &st.spool);
                let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap();
                println!("INL-BILAN-{phase}:{n}:{}", fichier.exists());
            }
            eprintln!("{INL_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::instantanes_non_lus_se_disent::inl_l_ingestion_dit_l_empreinte_non_lue_et_inscrit",
            ])
            .env(INL_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("INL-BILAN-illisible:2:false"), "empreinte non lue : inscrit comme état neuf, fichier consommé : {stdout}");
        assert!(stdout.contains("INL-BILAN-lisible:1:false"), "empreinte lue identique : battement, fichier consommé : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{INL_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(INL_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[ingest] WARN instantané")).map(str::to_string).collect()
        };
        assert_eq!(phase("illisible"), vec![LIGNE_EMPREINTE_NON_LUE.to_string()], "la ligne ENTIÈRE, une fois : {stderr}");
        assert_eq!(phase("lisible"), Vec::<String>::new(), "aucun aveu sur une lecture saine : {stderr}");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) `dernier_instantane_de` et `GET /api/snapshot/{genre}/{machine}`.
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn inl_dernier_instantane_de_rend_trois_issues() {
        let conn = test_db();
        assert_eq!(crate::ingest::store::dernier_instantane_de(&conn, "controls", "srv-7").expect("lue"), None, "absence = Ok(None)");
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(500,'controls','h7','{\"failed\":0}','srv-7')", []).unwrap();
        assert_eq!(
            crate::ingest::store::dernier_instantane_de(&conn, "controls", "srv-7").expect("lue"),
            Some((500, "h7".to_string(), "{\"failed\":0}".to_string()))
        );
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(500,'controls',X'00ff','{}','srv-9')", []).unwrap();
        assert!(crate::ingest::store::dernier_instantane_de(&conn, "controls", "srv-9").is_err(), "cellule illisible = Err");
    }

    #[tokio::test]
    async fn inl_la_route_d_un_instantane_sert_503_sur_lecture_ratee_et_404_sur_absence() {
        let (st, _tmp) = sp_state("inl-snapshot");
        inl_ecrire(
            &st,
            "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(500,'controls','h7','{\"failed\":0}','srv-7'); \
             INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(500,'firewall',X'00ff','{}','srv-9');",
        );
        let lire = |kind: &str, host: &str| {
            snapshot_par_genre_et_machine(State(st.clone()), Extension(inl_viewer()), Path((kind.to_string(), host.to_string())))
        };
        let (statut, lu) = inl_corps(lire("controls", "srv-7").await).await;
        assert_eq!(statut, 200, "contrôle positif : {lu}");
        assert_eq!(lu, json!({ "kind": "controls", "host": "srv-7", "ts": 500, "hash": "h7", "data": { "failed": 0 } }));
        let (statut, illisible) = inl_corps(lire("firewall", "srv-9").await).await;
        inl_juger_le_503(statut, &illisible, CAUSE_MACHINE);
        let (statut, absent) = inl_corps(lire("firewall", "srv-7").await).await;
        assert_eq!((statut, absent), (404, json!({ "_texte": "" })), "absence établie : 404 nu, inchangé");
        inl_ecrire(&st, "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;");
        let (statut, retiree) = inl_corps(lire("controls", "srv-7").await).await;
        inl_juger_le_503(statut, &retiree, CAUSE_MACHINE);
    }

    // ---------------------------------------------------------------------------------------------
    // (3) `dernier_instantane_par_hote` — la fin du parcours rendue avec les lignes.
    // ---------------------------------------------------------------------------------------------

    fn inl_parc(conn: &Connection, kind: &str, illisible: bool) {
        for (i, h) in ["srv-a", "srv-b", "srv-c"].iter().enumerate() {
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}',?4)",
                params![1000 - i as i64 * 10, kind, format!("h-{h}"), h],
            )
            .unwrap();
        }
        if illisible {
            // La PLUS VIEILLE ligne (rendue en dernier, `ORDER BY ts DESC`) : la borne `max` peut s'arrêter avant.
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,?1,X'00ff','{}','srv-z')",
                params![kind],
            )
            .unwrap();
        }
    }

    #[test]
    fn inl_par_hote_rend_sa_fin() {
        use crate::query_exec::FinDeParcours;
        let conn = test_db();
        inl_parc(&conn, "firewall", false);
        let sain = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
        assert_eq!(sain.len(), 3, "contrôle positif : trois machines");
        assert!(matches!(sain.fin, FinDeParcours::Complet), "lecture saine = Complet");
        let vide = crate::ingest::store::dernier_instantane_par_hote(&conn, "jamais-vu", 500);
        assert!(vide.is_empty() && matches!(vide.fin, FinDeParcours::Complet), "absence vraie = vide ET Complet");

        inl_parc(&conn, "controls", true);
        let partiel = crate::ingest::store::dernier_instantane_par_hote(&conn, "controls", 500);
        let hotes: Vec<_> = partiel.iter().map(|r| r.0.clone().unwrap_or_default()).collect();
        assert_eq!(hotes, ["srv-a", "srv-b", "srv-c"], "les lignes lues restent rendues, la plus fraîche d'abord");
        assert!(matches!(partiel.fin, FinDeParcours::Interrompu { erreurs: 1, .. }), "une ligne illisible = Interrompu, une erreur");
        assert_eq!(partiel.fin.etat(), Some("interrompu"));

        let borne = crate::ingest::store::dernier_instantane_par_hote(&conn, "controls", 2);
        assert_eq!(borne.len(), 2, "la borne coupe la liste");
        assert!(matches!(borne.fin, FinDeParcours::Complet), "un plafond atteint n'est pas une lecture ratée");

        conn.execute_batch("ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;").unwrap();
        let retiree = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
        assert!(retiree.is_empty(), "rien n'a été lu");
        assert_eq!(retiree.fin.etat(), Some("non_commence"), "préparation refusée = non_commence, jamais Complet");
    }

    #[tokio::test]
    async fn inl_le_panneau_dit_sa_ventilation_non_lue() {
        let (st, _tmp) = sp_state("inl-panel");
        {
            let conn = st.db.lock();
            inl_parc(&conn, "firewall", false);
            inl_parc(&conn, "controls", true);
        }
        let lire = |kind: &str| panel(State(st.clone()), Extension(inl_viewer()), Path(kind.to_string()));
        let (statut, sain) = inl_corps(lire("firewall").await).await;
        assert_eq!(statut, 200, "contrôle positif : {sain}");
        let cles: std::collections::BTreeSet<&str> = sain.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(cles, ["data", "hash", "host", "hosts", "kind", "n_hosts", "ts"].into_iter().collect(), "chemin nominal inchangé : {sain}");
        assert_eq!(sain["n_hosts"], json!(3));

        // `P10.20-b` (reprise) — INVERSÉ : la lecture partielle garde son deux cents SANS clé `error` (la jambe B de
        // check_a_refusal_is_not_rendered_as_an_absence.py) ; la fin est nommée par `hosts_etat`.
        let (statut, partiel) = inl_corps(lire("controls").await).await;
        assert_eq!(statut, 200, "{partiel}");
        assert!(partiel.get("error").is_none(), "aucune cause dans un corps de succès : {partiel}");
        assert_eq!(partiel["hosts_etat"], json!("interrompu"), "{partiel}");
        assert_eq!(partiel["n_hosts"], Value::Null, "dénominateur non établi = null, jamais 3 : {partiel}");
        assert_eq!(partiel["host"], json!("srv-a"), "{partiel}");
        assert_eq!(partiel["hosts"].as_array().map(|a| a.len()), Some(3), "les machines lues restent listées : {partiel}");

        let (statut, absent) = inl_corps(lire("jamais-vu").await).await;
        assert_eq!(statut, 200);
        assert_eq!(absent, json!({ "kind": "jamais-vu", "data": null, "hosts": [], "n_hosts": 0 }), "absence vraie inchangée");

        inl_ecrire(&st, "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;");
        // `P10.20-b` (reprise) — INVERSÉ : rien de lu = cinq cent trois nommé (`err_json`), plus un deux cents à `error`.
        let (statut, retiree) = inl_corps(lire("firewall").await).await;
        inl_juger_le_503(statut, &retiree, CAUSE_PARC);
    }

    #[tokio::test]
    async fn inl_les_suppressions_disent_la_fin_du_pare_feu() {
        let (st, _tmp) = sp_state("inl-suppressions");
        let adm = sp_au("adm", "admin");
        {
            let conn = st.db.lock();
            inl_parc(&conn, "firewall", false);
        }
        let (statut, sain) = inl_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
        assert_eq!(statut, 200);
        assert_eq!(
            (sain["firewall_n_hosts"].clone(), sain["firewall_incomplets"].clone(), sain["firewall_etat"].clone()),
            (json!(3), json!(false), Value::Null),
            "contrôle positif : {sain}"
        );
        inl_ecrire(&st, "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,'firewall',X'00ff','{}','srv-z');");
        let (_, partiel) = inl_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
        assert_eq!(
            (partiel["firewall_n_hosts"].clone(), partiel["firewall_incomplets"].clone(), partiel["firewall_etat"].clone()),
            (Value::Null, json!(true), json!("interrompu")),
            "ligne illisible : {partiel}"
        );
        assert_eq!(partiel["firewall_hosts"].as_array().map(|a| a.len()), Some(3), "{partiel}");
        inl_ecrire(&st, "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;");
        let (statut, retiree) = inl_corps(suppressions_get(State(st.clone()), Extension(adm)).await).await;
        assert_eq!(statut, 200, "le corps reste servi : {retiree}");
        assert_eq!(
            (retiree["firewall"].clone(), retiree["firewall_n_hosts"].clone(), retiree["firewall_incomplets"].clone(), retiree["firewall_etat"].clone()),
            (Value::Null, Value::Null, json!(true), json!("non_commence")),
            "table retirée : {retiree}"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // (4) LE JOURNAL DE L'EXPLOITANT : chaque route dit au journal ce que son corps ne porte pas.
    // ---------------------------------------------------------------------------------------------

    const INL_ENFANT_ROUTES: &str = "PLUME_TEST_INL_ENFANT_ROUTES";
    const PREFIXES_DU_JOURNAL: [&str; 3] = ["[snapshot] WARN", "[panel] WARN", "[suppressions] WARN état du pare-feu"];

    /// Trois phases dans un SOUS-PROCESSUS dont le stderr est lu : `saine` (aucune ligne), `illisible` (une cellule BLOB :
    /// trois lignes, une par route, avec la classe ou la fin), `retiree` (table renommée : trois lignes, fin `non_commence`).
    #[test]
    fn inl_les_trois_routes_journalisent_la_lecture_ratee() {
        if std::env::var(INL_ENFANT_ROUTES).is_ok() {
            let exec = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("exécuteur de test");
            exec.block_on(async {
                let (st, _tmp) = sp_state("inl-journal");
                {
                    let conn = st.db.lock();
                    inl_parc(&conn, "firewall", false);
                }
                let adm = sp_au("adm", "admin");
                for (phase, geste) in [
                    ("saine", ""),
                    ("illisible", "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,'firewall',X'00ff','{}','srv-z');"),
                    ("retiree", "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;"),
                ] {
                    if !geste.is_empty() {
                        inl_ecrire(&st, geste);
                    }
                    eprintln!("{INL_PHASE}{phase}");
                    let machine = if phase == "saine" { "srv-a" } else { "srv-z" };
                    let r = snapshot_par_genre_et_machine(
                        State(st.clone()),
                        Extension(inl_viewer()),
                        Path(("firewall".to_string(), machine.to_string())),
                    )
                    .await;
                    let (statut_p, p) = inl_corps(panel(State(st.clone()), Extension(inl_viewer()), Path("firewall".to_string())).await).await;
                    let s = suppressions_get(State(st.clone()), Extension(adm.clone())).await;
                    println!("INL-ROUTES-{phase}:{}:{statut_p}/{}:{}", r.status().as_u16(), p["hosts_etat"], s.status().as_u16());
                }
                eprintln!("{INL_PHASE}fin");
            });
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::instantanes_non_lus_se_disent::inl_les_trois_routes_journalisent_la_lecture_ratee",
            ])
            .env(INL_ENFANT_ROUTES, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("INL-ROUTES-saine:200:200/null:200"), "contrôle : lecture saine : {stdout}");
        assert!(stdout.contains("INL-ROUTES-illisible:503:200/\"interrompu\":200"), "contrôle : cellule illisible : {stdout}");
        assert!(stdout.contains("INL-ROUTES-retiree:503:503/null:200"), "contrôle : table retirée (panel en 503) : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{INL_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(INL_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| PREFIXES_DU_JOURNAL.iter().any(|p| l.starts_with(p))).map(str::to_string).collect()
        };
        assert_eq!(phase("saine"), Vec::<String>::new(), "aucune ligne sur une lecture saine : {stderr}");
        // Chaque ligne : son début exact (classe ou fin nommée), puis un texte du moteur NON VIDE après « : ».
        let juger = |nom: &str, attendus: [&str; 3]| {
            let lignes = phase(nom);
            assert_eq!(lignes.len(), 3, "phase {nom} : une ligne par route, ni plus ni moins : {lignes:?}");
            for (ligne, debut) in lignes.iter().zip(attendus) {
                let reste = ligne.strip_prefix(debut).unwrap_or_else(|| panic!("phase {nom} : « {ligne} » ne commence pas par « {debut} »"));
                assert!(!reste.trim().is_empty(), "phase {nom} : le texte du moteur manque : « {ligne} »");
            }
        };
        juger(
            "illisible",
            [
                "[snapshot] WARN dernier instantané \"firewall\" de la machine \"srv-z\" NON lu (forme_inconnue) — servi 503 : ",
                // `P10.20-b` (reprise) — INVERSÉ : le compte est celui des erreurs du parcours, jamais « N ligne(s) illisible(s) ».
                "[panel] WARN instantanés \"firewall\" par machine : lecture interrompue (1 erreur(s) de parcours, pas un nombre de lignes) — servi avec hosts_etat et n_hosts nul : ",
                "[suppressions] WARN état du pare-feu par machine : lecture interrompue (1 erreur(s) de parcours, pas un nombre de lignes) — servi avec firewall_etat et firewall_n_hosts nul : ",
            ],
        );
        juger(
            "retiree",
            [
                "[snapshot] WARN dernier instantané \"firewall\" de la machine \"srv-z\" NON lu (forme_inconnue) — servi 503 : ",
                "[panel] WARN instantanés \"firewall\" par machine : lecture non commencée, rien n'est lu — servi 503 : ",
                "[suppressions] WARN état du pare-feu par machine : lecture non commencée, rien n'est lu — servi avec firewall_etat et firewall_n_hosts nul : ",
            ],
        );
    }
}
