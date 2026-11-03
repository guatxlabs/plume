// =====================================================================================
// `P10.32-o` (vague BG, correction après vérification) — LA NOTICE D'UNE CHARGE UTILE ILLISIBLE EST LA SIENNE, ET UNE
// CHARGE TEXTE QUI N'EST PAS DU JSON NE MASQUE PLUS LE REFUS DU COMPILATEUR.
//
// MESURÉ PAR LE VÉRIFICATEUR SUR 072d265d :
//  * `panneau_avoue::coverage_synthetique` : un mutant qui élargit la branche `RAISON_LIGNE_DE_CACHE_NON_LUE` à
//    `RAISON_PAYE_UTILE_ILLISIBLE` restait vert (seule la sonde du vérificateur rougissait) : un corps 200
//    `paye_utile_illisible` annonçait « lecture refusée par la base ». Aucun témoin n'épinglait la notice de la charge
//    illisible, que la vague BG a placée en dernier recours de la chaîne ;
//  * `handlers/dashboards.rs::serve_swr`, bras HIT `Err(_)` : une charge TEXTE non JSON d'un panneau qui ne compile plus
//    servait un 200 `paye_utile_illisible` à chaque interrogation, n'armait rien et masquait le 400 du compilateur (sonde
//    « code=200 rien_en_vol=true … reason paye_utile_illisible », deux fois ; « code=400 » après retrait de la ligne).
//    Même défaut que la ligne BLOB corrigée par la vague BG, sur l'autre forme d'une charge illisible.
//
// LE CORRECTIF : le bras HIT `Err(_)` rend `bad_req(refus du compilateur)` quand le panneau ne compile pas (la ligne reste
// telle quelle, comme pour la ligne BLOB) ; la notice n'a pas changé, elle est désormais épinglée.
//
// CE QUE CES TÉMOINS JUGENT, par le HANDLER RÉEL `panel_data` (coût inconnu -> `serve_swr`) sur une base de test :
//  (A) `coverage_synthetique(paye_utile_illisible)` : raison et notice EXACTES (texte écrit ici, pas emprunté) ;
//  (B) panneau sain, charge texte non JSON fraîche : 200, clés exactes, sans `warming`, raison et notice exactes ;
//  (C) panneau sain, ligne BLOB (illisible) : 200, raison et notice exactes (l'autre forme, l'autre bras de `serve_swr`) ;
//  (D) panneau refusé par le compilateur, charge texte non JSON, fraîche puis périmée, deux interrogations chacune : 400,
//      corps EXACT `{error: refus du compilateur}`, la ligne reste telle quelle (aucune assertion « rien n'est armé » : sans
//      panneau compilé, `enqueue_panel_refresh` ne peut rien armer, l'assertion serait vraie par construction).
// MUTANTS JOUÉS (variable de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// BG4C_NOTICE_NONLUE_ELARGIE (le mutant du vérificateur : `paye_utile_illisible` prend la notice de `cache_non_lu`),
// BG4C_TEXTE_ILLISIBLE_MASQUE_LE_REFUS (l'ancien bras HIT : le 200 synthétique servi malgré le refus du compilateur).
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucune ligne de journal n'est écrite pour la charge texte non JSON (ni avant, ni
// après) ; une charge texte non JSON FRAÎCHE d'un panneau qui compile n'arme toujours rien avant l'expiration du TTL.
// =====================================================================================
mod charge_utile_illisible_dite_et_refus_du_compilateur_sur_un_texte_non_json {
    use super::*;

    /// La notice, écrite ici : un témoin qui lirait la production ne verrait pas qu'elle change.
    const BG4C_NOTICE_ILLISIBLE: &str = "la charge utile mise en cache n'a pas pu être relue : le corps servi est synthétique. Ce corps \
         vide n'établit PAS une absence.";
    const BG4C_TEXTE: &str = "pas du json";

    fn bg4c_poser_texte(st: &AppState, id: i64, rk: &str, fp: &str, calcule_a: i64) {
        st.db
            .lock()
            .execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)",
                params![id, rk, fp, calcule_a, BG4C_TEXTE],
            )
            .expect("fixture : charge texte non JSON");
    }

    fn bg4c_issue(st: &AppState, id: i64, rk: &str, fp: &str) -> String {
        match panneau_avoue::cache_lire_dit(&st.db.lock(), id, rk, fp) {
            panneau_avoue::LectureDeCache::Lue(p, _) => format!("Lue:{p}"),
            panneau_avoue::LectureDeCache::Absente => "Absente".into(),
            panneau_avoue::LectureDeCache::Illisible(_) => "Illisible".into(),
            panneau_avoue::LectureDeCache::NonLue(_) => "NonLue".into(),
        }
    }

    fn bg4c_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    #[test]
    fn bg4c_notice_de_la_charge_illisible_est_la_sienne() {
        let n = now();
        let cov = panneau_avoue::coverage_synthetique(panneau_avoue::RAISON_PAYE_UTILE_ILLISIBLE, n - 86_400, n, None);
        assert_eq!(cov["reason"], json!("paye_utile_illisible"), "(A) raison : {cov}");
        assert_eq!(cov["notice"], json!(BG4C_NOTICE_ILLISIBLE), "(A) notice exacte, jamais celle de `cache_non_lu` : {cov}");
    }

    #[tokio::test]
    async fn bg4c_charge_illisible_d_un_panneau_sain_dit_sa_notice() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, _dbp, _gxql, _panne, sain) = t3c_state("bg4c-sain");
        let au = t3c_admin();
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, sain, from);
        assert!(ttl > 0, "précondition : le cache des panneaux est actif");

        // (B) charge texte non JSON, fraîche : bras HIT `Err(_)`.
        bg4c_poser_texte(&st, sain, &rk, &fp, now() - 5);
        assert_eq!(bg4c_issue(&st, sain, &rk, &fp), format!("Lue:{BG4C_TEXTE}"), "fixture (B)");
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), t3c_q(from)).await).await;
        assert_eq!(code, 200, "(B) : {corps}");
        assert_eq!(bg4c_cles(&corps), vec!["columns", "rows", "stats"], "(B) forme exacte, sans `warming` : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("paye_utile_illisible"), "(B) : {corps}");
        assert_eq!(corps["stats"]["coverage"]["notice"], json!(BG4C_NOTICE_ILLISIBLE), "(B) notice exacte : {corps}");

        // (C) ligne BLOB : bras ILLISIBLE de l'absence.
        st.db
            .lock()
            .execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                params![sain, rk, fp, now() - 5],
            )
            .expect("fixture : ligne BLOB");
        assert_eq!(bg4c_issue(&st, sain, &rk, &fp), "Illisible", "fixture (C)");
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), t3c_q(from)).await).await;
        t3c_attendre_la_tache(&st).await;
        assert_eq!(code, 200, "(C) : {corps}");
        assert_eq!(bg4c_cles(&corps), vec!["columns", "rows", "stats"], "(C) forme exacte, sans `warming` : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("paye_utile_illisible"), "(C) : {corps}");
        assert_eq!(corps["stats"]["coverage"]["notice"], json!(BG4C_NOTICE_ILLISIBLE), "(C) notice exacte : {corps}");
    }

    #[tokio::test]
    async fn bg4c_texte_non_json_d_un_panneau_refuse_rend_le_refus_du_compilateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, _dbp, gxql, _panne, _sain) = t3c_state("bg4c-gxql");
        let au = t3c_admin();
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, gxql, from);
        assert!(ttl > 0, "précondition : le cache des panneaux est actif");
        let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None)
            .err()
            .unwrap_or_else(|| panic!("précondition (D) : le GXQL est refusé"));
        for (age, calcule_a) in [("fraîche", now() - 5), ("périmée", now() - ttl - 100_000)] {
            bg4c_poser_texte(&st, gxql, &rk, &fp, calcule_a);
            for passage in 1..=2 {
                let r = panel_data(State(st.clone()), Extension(au.clone()), Path(gxql), t3c_q(from)).await;
                let (code, corps) = t3c_json(r).await;
                assert_eq!(code, 400, "(D) {age} passage {passage} : le refus du compilateur, pas un corps synthétique : {corps}");
                assert_eq!(corps, json!({ "error": refus }), "(D) {age} passage {passage} : corps exact, celui du chemin live : {corps}");
                assert_eq!(bg4c_issue(&st, gxql, &rk, &fp), format!("Lue:{BG4C_TEXTE}"), "(D) {age} passage {passage} : la ligne reste telle quelle");
            }
        }
    }
}
