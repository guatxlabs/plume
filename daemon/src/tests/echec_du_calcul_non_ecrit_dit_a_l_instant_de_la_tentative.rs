// =====================================================================================
// `P10.32-o` (vague BH, correction) — L'ÉCHEC D'UN CALCUL DONT L'ÉCRITURE EST REFUSÉE EST NOTÉ À L'INSTANT DE LA
// TENTATIVE, ET DIT COMME UN ÉCHEC.
//
// MESURÉ PAR LE VÉRIFICATEUR SUR 006a0ff5 (sonde `verif_bh3_sonde`, non commitée) :
//  (A) charge valide périmée, calcul en échec, jonction de l'échec refusée par la base : le refus était noté par
//      `cache_ecrire_dit(conn, id, range_key, q_fp, calcule_a, …)` (dashboards.rs `joindre_l_echec_a_la_charge_valide`),
//      donc à l'ÂGE de la charge (« calcule_a=1793659306 avant=1793659866 note=Some(1793659306) arme2=true arme3=true ») :
//      un refus déjà plus vieux que la durée du cache, un calcul réarmé à CHAQUE interrogation, et une charge servie sous
//      `rafraichissement_en_echec = {cause: « le résultat du dernier calcul n'a pas pu être écrit… », echoue_a: calcule_a}`
//      — instant faux, et un « résultat » pour un calcul qui a échoué ;
//  (B) aucune charge valide, calcul en échec, écriture du corps d'échec refusée : le 503 servi était `cache_non_ecrit`
//      (« le résultat du dernier calcul »), la cause de l'échec n'était qu'au journal (« c2=503 reason2=cache_non_ecrit »).
//
// LE CORRECTIF : le registre des refus note, avec l'instant, CE QUE l'écriture refusée portait
// (`panneau_avoue::RefusDEcritureDeCache { refusee_a, echec_du_calcul }`). Les deux écritures d'un échec
// (`joindre_l_echec_a_la_charge_valide`, `memoriser_l_echec_du_rafraichissement`) passent par
// `panneau_avoue::cache_ecrire_l_echec_dit(…, calcule_a, tente_a, …, phrase servie)` : la ligne garde son âge, le refus est
// noté à `tente_a`. `serve_swr` sert alors, sur une charge valide, l'aveu `CAUSE_ECHEC_DU_CALCUL_NON_ECRIT_AU_CACHE` +
// phrase de la classe ; sans charge valide, le 503 `CAUSE_ECHEC_DU_PANNEAU_NON_ECRIT` + phrase, raison `calcul_echoue`.
// Le refus d'écrire un RÉSULTAT garde ses textes (`cache_non_ecrit`) : jugés par `ecriture_du_cache_refusee_dite_et_reessai_borne`.
//
// CE QUE CES TÉMOINS JUGENT :
//  (1) `joindre_l_echec_a_la_charge_valide` : ACCEPTÉE, la ligne réécrite garde son âge et porte l'échec à l'instant de la
//      tentative, aucun refus noté ; REFUSÉE, refus noté à l'instant de la tentative, comme un échec (phrase de la
//      classe) ; contre-épreuve : un résultat refusé est noté sans échec ;
//  (2) par le HANDLER RÉEL `panel_data`, panneau en panne du moteur, charge valide périmée : le refus noté par la tâche
//      (instant >= la requête, comme un échec), puis, tentative ANTIDATÉE dans la durée du cache, l'aveu exact (cause
//      d'échec + phrase, instant de la tentative et non du service), AUCUN calcul réarmé tant que le refus est récent ;
//  (3) par le handler, panneau en panne jamais mis en cache : le 503 (forme exacte, cause d'échec + phrase, raison
//      `calcul_echoue` et sa notice ; ce panneau ne nomme aucune table à rétention, son horizon est donc sans
//      `horizon_ts` : le corps entier, horizon compris, est jugé sur un panneau qui lit `event` par
//      `echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier`), réessai borné, puis l'écriture rendue possible efface
//      le refus et le corps d'échec est servi.
// MUTANTS JOUÉS (variable de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `BH3C_NOTE_A_L_AGE`,
// `BH3C_ECHEC_NOTE_COMME_RESULTAT`, `BH3C_HIT_AVEU_DE_RESULTAT`, `BH3C_503_DE_RESULTAT`, `BH3C_503_RAISON_NON_ECRIT`,
// `BH3C_CORPS_PAR_L_ECRITURE_DE_RESULTAT` ; vague BI : l'aveu servi à l'instant du service (D29), la ligne rajeunie par
// l'écriture d'un échec (P5), la jonction qui passe l'instant de la tentative comme âge (D46).
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne de journal du 503 (« échec du dernier calcul NON ÉCRIT au cache ») est
// relue par `echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier`, pas ici ; le pré-chauffage partage
// `joindre_l_echec_a_la_charge_valide` (jugée en (1)) sans témoin propre.
// =====================================================================================
mod echec_du_calcul_non_ecrit_dit_a_l_instant_de_la_tentative {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    // Écrites ici : un témoin qui lirait la constante de production ne verrait pas qu'elle change.
    const BH3C_CAUSE_503: &str = "CALCUL DU PANNEAU EN ÉCHEC, ÉCHEC NON ÉCRIT : le dernier calcul de ce panneau a échoué et la base a refusé d'écrire cet échec dans le cache — ce n'est PAS une mesure en cours. RIEN n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Cause du calcul : ";
    const BH3C_CAUSE_AVEU: &str = "le dernier calcul a échoué et cet échec n'a pas pu être écrit dans le cache (écriture refusée par la base) : la charge servie est la précédente. Cause du calcul : ";
    const BH3C_NOTICE_CALCUL_ECHOUE: &str = "le calcul de ce panneau a échoué (cause dans `error`) : aucune ligne n'a été calculée. Ce corps vide n'établit PAS une absence ; une nouvelle tentative suit l'expiration du cache.";

    fn bh3c_moteur() -> &'static str {
        crate::handlers::query::REQUETE_REJETEE_PAR_LE_MOTEUR
    }

    fn bh3c_charge() -> String {
        json!({ "columns": ["a"], "rows": [[42]] }).to_string()
    }

    /// Refuse les INSERT de `panel_cache` (si `cache`) et toujours ceux de `panel_cost` (le panneau reste au coût
    /// inconnu, donc en SWR).
    fn bh3c_refuser(conn: &Connection, cache: bool) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } if cache => Authorization::Deny,
            AuthAction::Insert { table_name: "panel_cost" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bh3c_refus(st: &AppState, id: i64, rk: &str, fp: &str) -> Option<panneau_avoue::RefusDEcritureDeCache> {
        panneau_avoue::refus_d_ecriture_de_cache(&st.db.lock(), id, rk, fp)
    }

    async fn bh3c_demander(st: &AppState, id: i64, from: i64) -> Response {
        panel_data(State(st.clone()), Extension(t3c_admin()), Path(id), t3c_q(from)).await
    }

    /// Note, par le coffre lui-même, le refus d'écrire l'échec du moteur à `instant` (autorisateur posé).
    fn bh3c_noter_un_echec_refuse(st: &AppState, id: i64, rk: &str, fp: &str, instant: i64) {
        let r = panneau_avoue::cache_ecrire_l_echec_dit(&st.db.lock(), id, rk, fp, instant, instant, "{}", bh3c_moteur());
        assert!(r.is_err(), "fixture : l'écriture qui note le refus est bien refusée");
    }

    fn bh3c_le_503(code: u16, v: &Value, quoi: &str) {
        let mut cles: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(code, 503, "{quoi} : refus nommé : {v}");
        assert_eq!(cles, vec!["columns", "error", "id", "rows", "stats"], "{quoi} : forme exacte, sans `warming` : {v}");
        assert_eq!(v["error"], json!(format!("{BH3C_CAUSE_503}{}", bh3c_moteur())), "{quoi} : l'échec et sa cause : {v}");
        assert!(v["id"].as_str().is_some_and(|s| !s.is_empty()), "{quoi} : identifiant de corrélation : {v}");
        assert_eq!((v["columns"].clone(), v["rows"].clone()), (json!([]), json!([])), "{quoi} : aucune ligne : {v}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("calcul_echoue"), "{quoi} : raison d'un échec : {v}");
        assert_eq!(v["stats"]["coverage"]["notice"], json!(BH3C_NOTICE_CALCUL_ECHOUE), "{quoi} : notice : {v}");
    }

    // ---------------------------------------------------------------------------------
    // (1) LA JONCTION REFUSÉE EST NOTÉE À L'INSTANT DE LA TENTATIVE, COMME UN ÉCHEC.
    // ---------------------------------------------------------------------------------
    #[test]
    fn bh3c_jonction_refusee_notee_a_la_tentative_comme_un_echec() {
        let (st, dbp, _g, _panne, sain) = t3c_state("bh3c-jonction");
        let from = t3c_from();
        let (rk, fp, _) = t3c_cle(&st, sain, from);
        let tente = now();
        let age = tente - 10_000;
        let phrase = "bh3c phrase servie de la classe";
        let echec = crate::handlers::dashboards::EchecMisEnCache::de_la_requete(crate::query_exec::EchecDeRequete::Produit(phrase.to_string()));
        {
            let conn = st.db.lock();
            panneau_avoue::cache_ecrire(&conn, sain, &rk, &fp, age, &bh3c_charge());
            // (vague BI) LA LIGNE GARDE SON ÂGE, jugée là où elle peut changer : la jonction ACCEPTÉE réécrit la ligne par
            // `cache_ecrire_l_echec_dit` ; un âge rajeuni (instant de la tentative écrit comme `computed_at`) se lirait ici.
            // L'assertion d'avant portait sur la jonction refusée, où l'autorisateur interdit tout INSERT : vraie par
            // construction, retirée.
            let issue = crate::handlers::dashboards::joindre_l_echec_a_la_charge_valide(&conn, sain, &rk, &fp, tente - 1, &echec);
            assert!(matches!(issue, crate::handlers::dashboards::IssueDeLaChargeValide::Jointe), "contrôle : jonction acceptée");
            let (payload, calcule_a) = panneau_avoue::cache_lire(&conn, sain, &rk, &fp).expect("la charge jointe est écrite");
            assert_eq!(calcule_a, age, "jonction acceptée : la ligne garde son âge, pas l'instant de la tentative : {payload}");
            let v: Value = serde_json::from_str(&payload).expect("charge JSON");
            assert_eq!(
                (v["rows"].clone(), v["stats"]["rafraichissement_en_echec"].clone()),
                (json!([[42]]), json!({ "cause": phrase, "echoue_a": tente - 1 })),
                "jonction acceptée : lignes intactes, échec joint à l'instant de la tentative : {payload}"
            );
            assert_eq!(panneau_avoue::refus_d_ecriture_de_cache(&conn, sain, &rk, &fp), None, "jonction acceptée : aucun refus noté");
            bh3c_refuser(&conn, true);
            let issue = crate::handlers::dashboards::joindre_l_echec_a_la_charge_valide(&conn, sain, &rk, &fp, tente, &echec);
            assert!(matches!(issue, crate::handlers::dashboards::IssueDeLaChargeValide::NonJointe(_)), "contrôle : jonction refusée");
        }
        assert_eq!(
            bh3c_refus(&st, sain, &rk, &fp),
            Some(panneau_avoue::RefusDEcritureDeCache { refusee_a: tente, echec_du_calcul: Some(phrase.to_string()) }),
            "refus noté à l'instant de la TENTATIVE (pas à l'âge {age}), comme l'échec d'un calcul"
        );
        // Contre-épreuve : un résultat refusé est noté sans échec.
        assert!(panneau_avoue::cache_ecrire_dit(&st.db.lock(), sain, &rk, &fp, tente + 1, "{}").is_err(), "contrôle : refusée");
        assert_eq!(
            bh3c_refus(&st, sain, &rk, &fp),
            Some(panneau_avoue::RefusDEcritureDeCache { refusee_a: tente + 1, echec_du_calcul: None }),
            "un résultat refusé n'est pas un échec"
        );
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (2) CHARGE VALIDE PÉRIMÉE, CALCUL EN ÉCHEC, JONCTION REFUSÉE — PAR LE HANDLER.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3c_charge_perimee_calcul_en_echec_jonction_refusee_aveu_exact_et_reessai_borne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("bh3c-hit");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, panne, from);
        assert!(ttl > 0, "précondition : le cache des panneaux est actif");
        panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, now() - ttl - 50, &bh3c_charge());
        bh3c_refuser(&st.db.lock(), true);

        let avant = now();
        let r = bh3c_demander(&st, panne, from).await;
        assert!(!t3c_rien_en_vol(&st), "(1) périmée, aucun refus connu : un calcul est armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "(1) : {v}");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3c_refus(&st, panne, &rk, &fp).expect("(1) le refus de joindre l'échec est noté");
        assert!(refus.refusee_a >= avant, "(1) noté à la tentative, pas à l'âge de la charge : {} < {avant}", refus.refusee_a);
        assert_eq!(refus.echec_du_calcul.as_deref(), Some(bh3c_moteur()), "(1) noté comme l'échec du calcul");

        // (vague BI) LA TENTATIVE EST ANTIDATÉE, encore dans la durée du cache : l'instant de la tentative et celui du
        // service DIFFÈRENT, et l'aveu doit porter le premier. Sans cela, tentative et service tombaient dans la même
        // seconde et un aveu à l'instant du service passait.
        assert!(ttl >= 10, "précondition : une durée du cache qui laisse antidater la tentative ({ttl})");
        let tentative = now() - ttl / 2;
        bh3c_noter_un_echec_refuse(&st, panne, &rk, &fp, tentative);
        for passage in 2..=3 {
            let r = bh3c_demander(&st, panne, from).await;
            assert!(t3c_rien_en_vol(&st), "({passage}) refus récent : aucun calcul réarmé avant l'expiration du cache");
            let (code, v) = t3c_json(r).await;
            assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "({passage}) la charge précédente reste servie : {v}");
            assert_eq!(
                v["stats"]["rafraichissement_en_echec"],
                json!({ "cause": format!("{BH3C_CAUSE_AVEU}{}", bh3c_moteur()), "echoue_a": tentative }),
                "({passage}) aveu exact : l'échec, sa cause, l'instant de la tentative (antidatée), pas celui du service : {v}"
            );
        }
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (3) AUCUNE CHARGE, CALCUL EN ÉCHEC, CORPS D'ÉCHEC REFUSÉ — PAR LE HANDLER.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3c_miss_calcul_en_echec_corps_refuse_503_de_l_echec_puis_corps_servi() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp, _g, panne, _s) = t3c_state("bh3c-miss");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, panne, from);
        bh3c_refuser(&st.db.lock(), true);

        let avant = now();
        let r = bh3c_demander(&st, panne, from).await;
        assert!(!t3c_rien_en_vol(&st), "(1) jamais mesuré : un calcul est armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["warming"].clone()), (200, json!(true)), "(1) rien n'est encore su : {v}");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3c_refus(&st, panne, &rk, &fp).expect("(1) le refus d'écrire le corps d'échec est noté");
        assert!(refus.refusee_a >= avant, "(1) instant de la tentative : {} < {avant}", refus.refusee_a);
        assert_eq!(refus.echec_du_calcul.as_deref(), Some(bh3c_moteur()), "(1) noté comme l'échec du calcul");

        let r = bh3c_demander(&st, panne, from).await;
        assert!(t3c_rien_en_vol(&st), "(2) refus récent : aucun calcul armé");
        let (code, v) = t3c_json(r).await;
        bh3c_le_503(code, &v, "(2)");

        bh3c_noter_un_echec_refuse(&st, panne, &rk, &fp, now() - ttl - 5);
        let r = bh3c_demander(&st, panne, from).await;
        assert!(!t3c_rien_en_vol(&st), "(3) durée du cache écoulée depuis le refus : un calcul est réarmé");
        let (code, v) = t3c_json(r).await;
        bh3c_le_503(code, &v, "(3)");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3c_refus(&st, panne, &rk, &fp).expect("(3) le calcul réarmé échoue, son écriture est refusée, noté");
        assert!(refus.refusee_a > now() - ttl, "(3) re-noté récent : le réessai est de nouveau borné ({})", refus.refusee_a);

        bh3c_noter_un_echec_refuse(&st, panne, &rk, &fp, now() - ttl - 5);
        bh3c_refuser(&st.db.lock(), false);
        let r = bh3c_demander(&st, panne, from).await;
        assert!(!t3c_rien_en_vol(&st), "(4) calcul armé");
        let (code, v) = t3c_json(r).await;
        bh3c_le_503(code, &v, "(4)");
        t3c_attendre_la_tache(&st).await;
        assert_eq!(bh3c_refus(&st, panne, &rk, &fp), None, "(4) le corps d'échec écrit efface le refus");
        let r = bh3c_demander(&st, panne, from).await;
        assert!(t3c_rien_en_vol(&st), "(5) corps d'échec frais : rien d'armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["error"].clone()), (200, json!(bh3c_moteur())), "(5) le corps d'échec écrit est servi : {v}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("calcul_echoue"), "(5) : {v}");
        ff_rm(&dbp);
    }
}
