// =====================================================================================
// `P10.32-o` — UNE LIGNE DE CACHE ILLISIBLE EST REMPLACÉE ET DITE ; UNE LIGNE NON LUE EST DITE AUTREMENT, AU JOURNAL COMME
// AU CORPS SERVI.
//
// LE DÉFAUT, RELEVÉ PAR LE VÉRIFICATEUR SUR f09e1b95 : la branche `LectureDeCache::Illisible` de
// `dashboards::joindre_l_echec_a_la_charge_valide` n'avait aucun témoin (mutant « Illisible traité comme NonLue » vert :
// la ligne n'était jamais remplacée et la route servait `warming` sans fin) ; `serve_swr` écrivait « ligne de cache NON
// LUE » aussi pour une ligne lue mais non décodable, et aucun témoin ne capturait cette ligne (mutant « MISS servi sans
// ligne » vert) ; une lecture refusée servait la raison `mesure_en_cours` (« la mesure est en cours »), fausse.
//
// LE CORRECTIF : `IssueDeLaChargeValide::Illisible` (cause portée) ; à la demande, `memoriser_l_echec_du_rafraichissement`
// la remplace par le corps d'échec et le dit (« ligne de cache ILLISIBLE (lue, non décodable) : … — remplacée par le
// corps d'échec ») ; au pré-chauffage, rien d'écrit, phrase ILLISIBLE propre ; `serve_swr` a deux lignes distinctes
// (ILLISIBLE, NON LUE) ; sur NON LUE, le corps `warming` porte la raison `cache_non_lu` et sa notice.
//
// CE QUE CE TÉMOIN JUGE, dans UN sous-processus (compte de PRODUCTION par processus, journal capturé), sur une ligne de
// cache dont la charge utile est un BLOB (`r.get::<String>` -> `InvalidColumnType`, issue `Illisible`) :
//  (1) par la ROUTE `panel_data` : corps `warming`, raison `mesure_en_cours` ; ligne `[panel] WARN ligne de cache
//      ILLISIBLE …` ENTIÈRE ; le rafraîchissement armé (panneau en panne) REMPLACE la ligne par le corps d'échec, et le dit
//      (ligne ILLISIBLE puis « corps d'échec servi ») ;
//  (2) la même route sert alors le corps d'échec (raison `calcul_echoue`, `error`, aucun `warming`) : la chauffe finit ;
//  (3) au pré-chauffage, sur une ligne BLOB reposée : ligne `[cache] WARN … ligne de cache ILLISIBLE …`, rien d'écrit ;
//  (4) lecture REFUSÉE par l'autorisateur : par la route, corps `warming` de raison `cache_non_lu` et sa notice (texte du
//      témoin), mêmes clés de couverture que (1) ; ligne `[panel] WARN ligne de cache NON LUE …` ENTIÈRE ;
//  compte : rangs 1 à 7 portés par les causes (les relectures du témoin comptent aussi).
// MUTANTS JOUÉS (variable de mutation sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// `LCI_JOINDRE_ILLISIBLE_NONLUE` (M26 du vérificateur), `LCI_SWR_ILLISIBLE_MUET` (M29), `LCI_SWR_ILLISIBLE_PHRASE_NONLUE`
// (la phrase NON LUE pour une ligne illisible), `LCI_MEMO_ILLISIBLE_MUET`, `LCI_PRECH_ILLISIBLE_PHRASE`,
// `LCI_NONLUE_RAISON_MESURE` (lecture refusée servie `mesure_en_cours`), `LCI_ILLISIBLE_RAISON_NONLUE`.
// CE QUE CE TÉMOIN NE TIENT PAS : une lecture refusée qui persiste reste servie `warming` (raison `cache_non_lu`) à chaque
// interrogation, et la console garde son texte « chargement (mesure en cours) » jusqu'à sa borne de chauffe
// (web/dashboards.js, `prochaineRelanceDeLaChauffe`) ; la notice du démon s'affiche sous le corps sans ligne.
// =====================================================================================
mod ligne_de_cache_illisible_remplacee_et_non_lue_dite {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const LCI_ILLISIBLE: &str = "Invalid column type Blob at index: 0, name: payload";
    const LCI_REFUS: &str = "access to panel_cache.payload is prohibited [code étendu 23]";
    const LCI_NOTICE_NON_LUE: &str = "la ligne de cache de ce panneau n'a pas pu être lue (lecture refusée par la base) : \
         aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS une absence ; le détail \
         est au journal de l'exploitant.";

    fn lci_poser_un_blob(st: &AppState, id: i64, rk: &str, fp: &str, calcule: i64) {
        st.db
            .lock()
            .execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                params![id, rk, fp, calcule],
            )
            .unwrap();
    }

    fn lci_issue(st: &AppState, id: i64, rk: &str, fp: &str) -> String {
        match panneau_avoue::cache_lire_dit(&st.db.lock(), id, rk, fp) {
            panneau_avoue::LectureDeCache::Lue(p, _) => format!("Lue:{p}"),
            panneau_avoue::LectureDeCache::Absente => "Absente".into(),
            panneau_avoue::LectureDeCache::Illisible(_) => "Illisible".into(),
            panneau_avoue::LectureDeCache::NonLue(_) => "NonLue".into(),
        }
    }

    #[tokio::test]
    async fn lci_ligne_illisible_remplacee_et_dite_ligne_non_lue_dite_autrement() {
        const ENFANT: &str = "LCI_ENFANT_LIGNE_DE_CACHE_ILLISIBLE";
        if std::env::var(ENFANT).is_ok() {
            let _env = VERROU_ENV_PROCESSUS.read(); // panel_data, panel_serve_cfg_de et le pré-chauffage lisent load_config()
            let (st, dbp, gxql, panne, sain) = t3c_state("lci-illisible");
            let au = t3c_admin();
            let from = t3c_from();
            let (rk, fp, ttl) = t3c_cle(&st, panne, from);
            assert!(ttl > 0, "prémisse : le cache des panneaux est actif");
            let calcule = now() - ttl - 5;
            st.db.lock().execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id IN (?1,?2)", params![gxql, sain]).unwrap();
            lci_poser_un_blob(&st, panne, &rk, &fp, calcule);
            let avant = lci_issue(&st, panne, &rk, &fp);
            let compte0 = panneau_avoue::lectures_de_cache_refusees();
            eprintln!("LCI-DEBUT-1");
            let (code1, corps1) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
            t3c_attendre_la_tache(&st).await;
            let apres1 = lci_issue(&st, panne, &rk, &fp);
            let (code2, corps2) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
            t3c_attendre_la_tache(&st).await;
            eprintln!("LCI-FIN-1");
            lci_poser_un_blob(&st, panne, &rk, &fp, calcule);
            eprintln!("LCI-DEBUT-3");
            crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
            eprintln!("LCI-FIN-3");
            let apres3 = lci_issue(&st, panne, &rk, &fp);
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            eprintln!("LCI-DEBUT-4");
            let (code4, corps4) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
            t3c_attendre_la_tache(&st).await;
            eprintln!("LCI-FIN-4");
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let compte_fin = panneau_avoue::lectures_de_cache_refusees();
            println!("LCI-ID:{panne}");
            println!("LCI-AVANT:{avant}");
            println!("LCI-ROUTE1:{code1}|{corps1}");
            println!("LCI-APRES1:{apres1}");
            println!("LCI-ROUTE2:{code2}|{corps2}");
            println!("LCI-APRES3:{apres3}");
            println!("LCI-ROUTE4:{code4}|{corps4}");
            println!("LCI-COMPTES:{compte0}|{compte_fin}");
            ff_rm(&dbp);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ligne_de_cache_illisible_remplacee_et_non_lue_dite::lci_ligne_illisible_remplacee_et_dite_ligne_non_lue_dite_autrement",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lire = |cle: &str| stdout.split_once(cle).map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        let route = |cle: &str| -> (String, Value) {
            let brut = lire(cle);
            let (code, corps) = brut.split_once('|').unwrap_or_else(|| panic!("contrôle : {cle} : {stdout}"));
            (code.to_string(), serde_json::from_str(corps).unwrap_or_else(|_| panic!("contrôle : corps JSON {cle} : {brut}")))
        };
        let fenetre = |debut: &str, fin: &str| -> String {
            stderr
                .split_once(debut)
                .and_then(|(_, r)| r.split_once(fin))
                .map(|(c, _)| c.to_string())
                .unwrap_or_else(|| panic!("contrôle : fenêtre {debut} : {stderr}"))
        };
        let id = lire("LCI-ID:");
        assert!(!id.is_empty(), "contrôle : panneau nommé : {stdout}");
        assert_eq!(lire("LCI-AVANT:"), "Illisible", "fixture : la ligne BLOB se lit Illisible : {stdout}");

        // (1) MISS servi, raison `mesure_en_cours` (un rafraîchissement est armé, qui remplacera la ligne).
        let (code1, corps1) = route("LCI-ROUTE1:");
        assert_eq!(code1, "200", "route (1) : {corps1}");
        assert_eq!(corps1["warming"], json!(true), "(1) servi comme un MISS : {corps1}");
        assert_eq!(corps1["rows"], json!([]), "(1) aucune ligne : {corps1}");
        assert_eq!(corps1["stats"]["coverage"]["reason"], json!("mesure_en_cours"), "(1) ligne illisible : mesure en cours : {corps1}");
        // La ligne a été REMPLACÉE par le corps d'échec.
        let apres1 = lire("LCI-APRES1:");
        let charge = apres1.strip_prefix("Lue:").unwrap_or_else(|| panic!("(1) la ligne illisible est remplacée : {apres1}"));
        let charge: Value = serde_json::from_str(charge).unwrap_or_else(|_| panic!("(1) corps d'échec JSON : {apres1}"));
        assert!(charge["error"].is_string(), "(1) corps d'échec écrit : {charge}");
        assert_eq!(charge["stats"]["coverage"]["reason"], json!("calcul_echoue"), "(1) corps d'échec écrit : {charge}");
        // (2) la chauffe finit : la route sert le corps d'échec.
        let (code2, corps2) = route("LCI-ROUTE2:");
        assert_eq!(code2, "200", "route (2) : {corps2}");
        assert!(corps2.get("warming").is_none(), "(2) plus de chauffe : {corps2}");
        assert!(corps2["error"].is_string(), "(2) la cause est servie : {corps2}");
        assert_eq!(corps2["stats"]["coverage"]["reason"], json!("calcul_echoue"), "(2) : {corps2}");

        let f1 = fenetre("LCI-DEBUT-1", "LCI-FIN-1");
        assert!(!f1.contains("NON LUE"), "(1) aucune phrase NON LUE pour une ligne lue : {f1}");
        let illisibles: Vec<&str> = f1.lines().filter(|l| l.contains("ILLISIBLE")).collect();
        assert_eq!(illisibles.len(), 2, "(1) deux lignes ILLISIBLE (route, rafraîchissement) : {f1}");
        let swr = format!(
            "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id} : {LCI_ILLISIBLE} (lecture de cache \
             ratée n° 2 depuis le démarrage) — servie comme un MISS (corps `warming`, rafraîchissement armé si le panneau \
             compile, qui la remplacera)"
        );
        assert_eq!(illisibles[0], swr, "(1) ligne de la route, entière");
        let tete = format!("[panel] WARN rafraîchissement du panneau {id} en échec (");
        let memo_fin = format!(
            ") — /api/panels/{{id}}/data, tenant 'default' — ligne de cache ILLISIBLE (lue, non décodable) : {LCI_ILLISIBLE} \
             (lecture de cache ratée n° 3 depuis le démarrage) — remplacée par le corps d'échec"
        );
        assert!(illisibles[1].starts_with(&tete) && illisibles[1].ends_with(&memo_fin), "(1) rafraîchissement : {}", illisibles[1]);
        let servis: Vec<&str> = f1.lines().filter(|l| l.starts_with(&tete) && l.contains("corps d'échec servi")).collect();
        assert_eq!(servis.len(), 1, "(1) le corps d'échec est écrit une fois : {f1}");

        // (3) pré-chauffage : phrase ILLISIBLE propre, rien d'écrit.
        let f3 = fenetre("LCI-DEBUT-3", "LCI-FIN-3");
        let pre: Vec<&str> = f3.lines().filter(|l| l.starts_with("[cache] WARN")).collect();
        assert_eq!(pre.len(), 1, "(3) une ligne de pré-chauffage : {f3}");
        let pre_debut = format!("[cache] WARN pré-chauffage du panneau {id} en échec (");
        let pre_fin = format!(
            ") — ligne de cache ILLISIBLE (lue, non décodable) : {LCI_ILLISIBLE} (lecture de cache ratée n° 4 depuis le \
             démarrage) — rien d'écrit, le chemin à la demande la remplacera"
        );
        assert!(pre[0].starts_with(&pre_debut) && pre[0].ends_with(&pre_fin), "(3) pré-chauffage : {}", pre[0]);
        assert_eq!(lire("LCI-APRES3:"), "Illisible", "(3) le pré-chauffage n'écrit rien : {stdout}");

        // (4) lecture refusée : raison `cache_non_lu` et sa notice, mêmes clés de couverture que (1).
        let (code4, corps4) = route("LCI-ROUTE4:");
        assert_eq!(code4, "200", "route (4) : {corps4}");
        assert_eq!(corps4["warming"], json!(true), "(4) servi comme un MISS : {corps4}");
        assert_eq!(corps4["rows"], json!([]), "(4) aucune ligne : {corps4}");
        assert_eq!(corps4["stats"]["coverage"]["reason"], json!("cache_non_lu"), "(4) lecture refusée : pas une mesure en cours : {corps4}");
        assert_eq!(corps4["stats"]["coverage"]["notice"], json!(LCI_NOTICE_NON_LUE), "(4) notice : {corps4}");
        let cles = |v: &Value| -> Vec<String> {
            let mut c: Vec<String> = v["stats"]["coverage"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
            c.sort();
            c
        };
        assert_eq!(cles(&corps4), cles(&corps1), "(4) mêmes clés de couverture que la chauffe : {corps4}");
        let f4 = fenetre("LCI-DEBUT-4", "LCI-FIN-4");
        assert!(!f4.contains("ILLISIBLE"), "(4) aucune phrase ILLISIBLE pour une lecture refusée : {f4}");
        let non_lue = format!(
            "[panel] WARN ligne de cache NON LUE, panneau #{id} : {LCI_REFUS} (lecture de cache ratée n° 6 depuis le \
             démarrage) — servie comme un MISS (corps `warming`, rafraîchissement armé si le panneau compile)"
        );
        let route4: Vec<&str> = f4.lines().filter(|l| l.starts_with("[panel] WARN ligne de cache")).collect();
        assert_eq!(route4, vec![non_lue.as_str()], "(4) ligne de la route, entière : {f4}");
        // Rangs : 1 la fixture (`lci_issue`), 2 la route, 3 le rafraîchissement, 4 le pré-chauffage, 5 la relecture après lui,
        // 6 la route sous refus, 7 son rafraîchissement armé.
        assert_eq!(lire("LCI-COMPTES:"), "1|7", "compte de production : une lecture ratée par lecture : {stdout}");
    }
}
