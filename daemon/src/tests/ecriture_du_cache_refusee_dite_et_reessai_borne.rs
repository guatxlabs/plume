// =====================================================================================
// `P10.32-o` (vague BH) — UNE ÉCRITURE DU CACHE REFUSÉE N'EST PLUS UNE CHAUFFE SANS FIN NI SANS UN MOT, ET UNE CHARGE
// PÉRIMÉE D'UN PANNEAU QUI NE COMPILE PLUS LE DIT.
// `P10.29-l` (vague BH) — chaque ligne de journal neuve nomme le tenant de l'appelant, échappé ; la boucle de
// pré-chauffage elle-même passe le tenant.
//
// MESURÉ PAR LE VÉRIFICATEUR SUR LA VAGUE BG (sonde par `panel_data`, autorisateur qui refuse les INSERT de
// `panel_cache` et `panel_cost`) : trois interrogations « code=200 warming=true reason=mesure_en_cours arme=true
// ligne_ecrite=false » — `consigner_l_issue_du_rafraichissement` passait le succès à `panneau_avoue::cache_ecrire`, dont le
// `let _ = cache_ecrire_dit(…)` jetait le refus : la ligne restait absente, le MISS servait une chauffe et réarmait à
// chaque interrogation un calcul qui réussissait. Même `let _` au pré-chauffage (`rollups::cache_refresh_all_panels`) et
// au chemin live (`panel_data`). Lu aussi : une charge VALIDE périmée d'un panneau qui ne compile plus était servie
// indéfiniment, sans rafraîchissement ni journal (`cache_reestamper` avec `pc` à `None`, rien d'armé).
//
// LE CORRECTIF :
//  * `panneau_avoue::cache_ecrire_dit` NOTE l'issue de chaque écriture (base de la connexion, panneau, plage, empreinte ->
//    instant du dernier refus ; un succès l'efface ; registre borné, le plus ancien retiré) ; `cache_ecrire` n'est plus
//    qu'une forme des témoins. Les trois sites de production lisent `cache_ecrire_dit` et disent son refus avec le tenant ;
//  * `serve_swr` lit le refus sous le même verrou que la ligne : sans charge servable (absence, ligne illisible, texte
//    non JSON, corps d'échec, `stats` qui n'est pas un objet), un 503 nommé (`CAUSE_RESULTAT_DU_PANNEAU_NON_ECRIT`, raison
//    `cache_non_ecrit` et sa notice), jugé après la ligne NON LUE et après le refus du compilateur ; une charge servable
//    est servie avec `stats.rafraichissement_en_echec` (cause fixe, instant du refus) ; le nouveau calcul n'est armé
//    qu'une fois la durée du cache écoulée depuis le refus ;
//  * une charge PÉRIMÉE d'un panneau qui ne compile plus : servable -> servie, le refus du compilateur joint sous
//    `stats.rafraichissement_en_echec` (il l'emporte sur l'aveu d'écriture), ligne `[panel]` ; corps d'échec -> le 400 du
//    compilateur, ligne `[panel]` ; fraîche -> servie telle quelle ;
//  * `spawn_panel_refresh_loop` est joué sans sommeil sous les témoins (`DELAI_AVANT_LE_PREMIER_PRECHAUFFAGE`).
//
// CE QUE CES TÉMOINS JUGENT, par le HANDLER RÉEL `panel_data` (coût inconnu -> `serve_swr`) :
//  (1) MISS, écriture refusée : la chauffe une fois (rien n'est encore su), le refus noté après le calcul ; puis le 503
//      (forme exacte, cause, raison, notice ; le panneau du témoin ne nomme aucune table à rétention, donc pas
//      d'`horizon_ts` : le corps entier, horizon compris, est jugé sur un panneau qui lit `event` par
//      `echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier`), rien d'armé ; refus antidaté hors de la durée du
//      cache -> le 503 et UN calcul armé, refus re-noté récent ;
//      écriture rendue possible -> le refus est effacé, les lignes servies sans aveu ;
//  (2) charge servable périmée, écriture refusée : servie sans aveu puis avec l'aveu exact (cause, instant du refus),
//      rien d'armé, puis armé une fois le refus antidaté ;
//  (3) chaque classe sans charge servable (corps d'échec, texte non JSON, `stats` non objet, ligne BLOB) + refus -> 503 ;
//  (4) priorités : ligne NON LUE + refus -> le 503 `cache_non_lu` ; panneau refusé par le compilateur + refus -> le 400 ;
//  (5) charge d'un panneau qui ne compile plus : fraîche sans aveu, périmée avec le refus du compilateur (instant du
//      service), périmée + refus d'écriture -> le refus du compilateur l'emporte ; corps d'échec périmé -> 400, ligne
//      laissée ; corps d'échec frais -> servi tel quel ;
//  (6) la borne du registre : jugée sur le type de production (`RefusDEcritureDeCache`) par
//      `prechauffage_lit_le_registre_des_refus_et_borne_sur_le_type_de_production` (vague BI, correction) ;
//  (7) en sous-processus, MODE 1, DEUX tenants réels : chaque ligne neuve ENTIÈRE (résultat non écrit après un
//      rafraîchissement, 503 armé et non armé, live, charge périmée non compilable, corps d'échec périmé non compilable,
//      pré-chauffage joué par `spawn_panel_refresh_loop` elle-même), aucune autre.
// MUTANTS JOUÉS (variable de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : voir la liste du
// rapport du lot (`BH3_*`), un par branche, garde, borne et ligne de journal neuves.
// CE QUE CES TÉMOINS NE TIENNENT PAS : une ligne NON LUE dont l'écriture est aussi refusée réarme un calcul à chaque
// interrogation (le 503 `cache_non_lu` le dit : « un rafraîchissement est armé si le panneau compile ») ; le
// pré-chauffage saute un panneau qui ne compile pas sans ligne de journal (une par tick serait du bruit ; le refus est dit
// à la demande) ; le registre des refus est un état de processus, perdu au redémarrage (le panneau repart en chauffe une
// fois, puis le refus est re-noté).
// =====================================================================================
mod ecriture_du_cache_refusee_dite_et_reessai_borne {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// La cause du 503, écrite ici : un témoin qui lirait la constante de production ne verrait pas qu'elle change.
    const BH3_CAUSE: &str = "RÉSULTAT DU PANNEAU NON ÉCRIT : la base a refusé d'écrire dans le cache le résultat du dernier calcul de ce panneau — ce n'est PAS une mesure en cours. RIEN n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Si le refus persiste, la base est pleine ou en lecture seule.";
    const BH3_NOTICE: &str = "la base a refusé d'écrire dans le cache le résultat du dernier calcul de ce panneau : aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS une absence ; un nouveau calcul est armé au plus une fois par durée du cache, le détail est au journal de l'exploitant.";
    const BH3_CAUSE_ECRITURE: &str =
        "le résultat du dernier calcul n'a pas pu être écrit dans le cache (écriture refusée par la base) : la charge servie est la précédente";
    const BH3_ENFANT: &str = "BH3_ENFANT_JOURNAL_DES_ECRITURES_REFUSEES";
    const BH3_ATTENDU: &str = "BH3-ATTENDU:";
    const BH3_ALPHA: &str = "bh3-alpha";
    const BH3_BETA: &str = "bh3-beta";

    fn bh3_charge() -> String {
        json!({ "columns": ["a"], "rows": [[42]] }).to_string()
    }

    /// Refuse les INSERT de `panel_cache` (`cache`) et de `panel_cost` (`cout` : le panneau reste au coût inconnu, donc
    /// en SWR) ; tout le reste passe.
    fn bh3_refuser(conn: &Connection, cache: bool, cout: bool) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } if cache => Authorization::Deny,
            AuthAction::Insert { table_name: "panel_cost" } if cout => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Note un refus d'écriture à `instant` par le coffre lui-même (autorisateur posé : l'écriture est refusée).
    fn bh3_noter_un_refus(conn: &Connection, id: i64, rk: &str, fp: &str, instant: i64) {
        let r = panneau_avoue::cache_ecrire_dit(conn, id, rk, fp, instant, "{}");
        assert!(r.is_err(), "fixture : l'écriture qui note le refus est bien refusée");
    }

    fn bh3_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    fn bh3_refus(st: &AppState, id: i64, rk: &str, fp: &str) -> Option<i64> {
        panneau_avoue::ecriture_de_cache_refusee(&st.db.lock(), id, rk, fp)
    }

    async fn bh3_demander(st: &AppState, id: i64, from: i64) -> Response {
        panel_data(State(st.clone()), Extension(t3c_admin()), Path(id), t3c_q(from)).await
    }

    /// Le 503 d'une ligne sans charge servable dont l'écriture a été refusée : forme, cause, raison et notice (l'horizon
    /// est jugé par `echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier`).
    fn bh3_le_503(code: u16, v: &Value, quoi: &str) {
        assert_eq!(code, 503, "{quoi} : refus nommé : {v}");
        assert_eq!(bh3_cles(v), vec!["columns", "error", "id", "rows", "stats"], "{quoi} : forme exacte, sans `warming` : {v}");
        assert_eq!(v["error"], json!(BH3_CAUSE), "{quoi} : cause exacte : {v}");
        assert!(v["id"].as_str().is_some_and(|s| !s.is_empty()), "{quoi} : identifiant de corrélation : {v}");
        assert_eq!((v["columns"].clone(), v["rows"].clone()), (json!([]), json!([])), "{quoi} : aucune ligne : {v}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("cache_non_ecrit"), "{quoi} : raison : {v}");
        assert_eq!(v["stats"]["coverage"]["notice"], json!(BH3_NOTICE), "{quoi} : notice exacte : {v}");
    }

    // ---------------------------------------------------------------------------------
    // (1) MISS, ÉCRITURE REFUSÉE.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3_miss_ecriture_refusee_refus_nomme_reessai_borne_puis_succes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, dbp, _gxql, _panne, sain) = t3c_state("bh3-miss");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, sain, from);
        assert!(ttl > 0, "précondition : le cache des panneaux est actif");
        bh3_refuser(&st.db.lock(), true, true);

        let avant = now();
        let r = bh3_demander(&st, sain, from).await;
        assert!(!t3c_rien_en_vol(&st), "(1) jamais mesuré, aucun refus connu : un calcul est armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["warming"].clone()), (200, json!(true)), "(1) rien n'est encore su : la chauffe d'une absence : {v}");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3_refus(&st, sain, &rk, &fp).expect("(1) le refus d'écrire le résultat calculé est noté");
        assert!(refus >= avant, "(1) l'instant du refus est celui de la tentative : {refus} < {avant}");
        assert!(panneau_avoue::cache_lire(&st.db.lock(), sain, &rk, &fp).is_none(), "(1) contrôle, vrai par construction (l'autorisateur refuse tout INSERT de panel_cache) : rien d'écrit ; le juge est le refus noté");

        let r = bh3_demander(&st, sain, from).await;
        assert!(t3c_rien_en_vol(&st), "(2) refus récent : aucun calcul armé avant l'expiration du cache");
        let (code, v) = t3c_json(r).await;
        bh3_le_503(code, &v, "(2)");

        bh3_noter_un_refus(&st.db.lock(), sain, &rk, &fp, now() - ttl - 5);
        let r = bh3_demander(&st, sain, from).await;
        assert!(!t3c_rien_en_vol(&st), "(3) la durée du cache écoulée depuis le refus réarme un calcul");
        let (code, v) = t3c_json(r).await;
        bh3_le_503(code, &v, "(3)");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3_refus(&st, sain, &rk, &fp).expect("(3) le calcul réarmé est refusé à son tour, et noté");
        assert!(refus > now() - ttl, "(3) le refus re-noté est récent : le réessai est de nouveau borné ({refus})");

        bh3_noter_un_refus(&st.db.lock(), sain, &rk, &fp, now() - ttl - 5);
        bh3_refuser(&st.db.lock(), false, true);
        let r = bh3_demander(&st, sain, from).await;
        assert!(!t3c_rien_en_vol(&st), "(4) calcul armé");
        let (code, v) = t3c_json(r).await;
        bh3_le_503(code, &v, "(4)");
        t3c_attendre_la_tache(&st).await;
        assert_eq!(bh3_refus(&st, sain, &rk, &fp), None, "(4) l'écriture réussie efface le refus");
        let (code, v) = t3c_json(bh3_demander(&st, sain, from).await).await;
        assert_eq!(code, 200, "(4) : {v}");
        assert_eq!(v["rows"], json!([[1]]), "(4) les lignes calculées sont servies : {v}");
        assert!(v["stats"].get("rafraichissement_en_echec").is_none(), "(4) aucun aveu : {v}");
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (2) CHARGE SERVABLE PÉRIMÉE, ÉCRITURE REFUSÉE.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3_charge_servable_perimee_dit_l_ecriture_refusee_et_borne_le_reessai() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp, _gxql, _panne, sain) = t3c_state("bh3-hit");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, sain, from);
        panneau_avoue::cache_ecrire(&st.db.lock(), sain, &rk, &fp, now() - ttl - 50, &bh3_charge());
        bh3_refuser(&st.db.lock(), true, true);

        let r = bh3_demander(&st, sain, from).await;
        assert!(!t3c_rien_en_vol(&st), "(1) périmée, aucun refus connu : un calcul est armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "(1) : {v}");
        assert!(v["stats"].get("rafraichissement_en_echec").is_none(), "(1) aucun aveu avant le refus : {v}");
        t3c_attendre_la_tache(&st).await;
        let refus = bh3_refus(&st, sain, &rk, &fp).expect("(1) refus noté");

        let r = bh3_demander(&st, sain, from).await;
        assert!(t3c_rien_en_vol(&st), "(2) refus récent : aucun calcul armé");
        let (code, v) = t3c_json(r).await;
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "(2) la charge précédente reste servie : {v}");
        assert_eq!(
            v["stats"]["rafraichissement_en_echec"],
            json!({ "cause": BH3_CAUSE_ECRITURE, "echoue_a": refus }),
            "(2) aveu exact : cause fixe, instant du refus : {v}"
        );

        let antidate = now() - ttl - 5;
        bh3_noter_un_refus(&st.db.lock(), sain, &rk, &fp, antidate);
        let r = bh3_demander(&st, sain, from).await;
        assert!(!t3c_rien_en_vol(&st), "(3) la durée écoulée depuis le refus réarme un calcul");
        let (_, v) = t3c_json(r).await;
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["echoue_a"], json!(antidate), "(3) instant du refus servi : {v}");
        t3c_attendre_la_tache(&st).await;
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (3) CHAQUE CLASSE SANS CHARGE SERVABLE.
    // ---------------------------------------------------------------------------------
    async fn bh3_classe_sans_charge_servable(tag: &str, payload_sql: &str, payload: Option<String>) {
        let (st, dbp, _gxql, _panne, sain) = t3c_state(tag);
        let from = t3c_from();
        let (rk, fp, _ttl) = t3c_cle(&st, sain, from);
        st.db
            .lock()
            .execute(
                &format!("INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,{payload_sql})"),
                params![sain, rk, fp, now() - 5, payload],
            )
            .expect("fixture : ligne de cache");
        bh3_refuser(&st.db.lock(), true, true);
        bh3_noter_un_refus(&st.db.lock(), sain, &rk, &fp, now());
        let (code, v) = t3c_json(bh3_demander(&st, sain, from).await).await;
        bh3_le_503(code, &v, tag);
        ff_rm(&dbp);
    }

    #[tokio::test]
    async fn bh3_sans_charge_servable_et_ecriture_refusee_le_503_pour_chaque_classe() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let n = now();
        let mut echec = panneau_avoue::corps_d_echec("bh3 cause servie", n - 86_400, n);
        echec[crate::handlers::dashboards::MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!("moteur");
        bh3_classe_sans_charge_servable("bh3-classe-echec", "?5", Some(echec.to_string())).await;
        bh3_classe_sans_charge_servable("bh3-classe-texte", "?5", Some("pas du json".to_string())).await;
        bh3_classe_sans_charge_servable("bh3-classe-stats", "?5", Some(json!({ "columns": ["a"], "rows": [[1]], "stats": 5 }).to_string())).await;
        bh3_classe_sans_charge_servable("bh3-classe-blob", "COALESCE(?5, X'00FF')", None).await;
    }

    // ---------------------------------------------------------------------------------
    // (4) PRIORITÉS : LIGNE NON LUE, REFUS DU COMPILATEUR.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3_la_ligne_non_lue_et_le_refus_du_compilateur_passent_avant_l_ecriture_refusee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp, gxql, _panne, sain) = t3c_state("bh3-priorites");
        let from = t3c_from();
        let (rk, fp, _) = t3c_cle(&st, sain, from);
        panneau_avoue::cache_ecrire(&st.db.lock(), sain, &rk, &fp, now() - 5, &bh3_charge());
        bh3_refuser(&st.db.lock(), true, true);
        bh3_noter_un_refus(&st.db.lock(), sain, &rk, &fp, now());
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
            AuthAction::Insert { table_name: "panel_cache" } | AuthAction::Insert { table_name: "panel_cost" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (code, v) = t3c_json(bh3_demander(&st, sain, from).await).await;
        assert_eq!(code, 503, "NON LUE : {v}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("cache_non_lu"), "NON LUE : la ligne non lue l'emporte : {v}");
        assert!(v["error"].as_str().is_some_and(|e| e.starts_with("LIGNE DE CACHE NON LUE :")), "NON LUE : sa cause : {v}");
        t3c_attendre_la_tache(&st).await;

        bh3_refuser(&st.db.lock(), true, true); // la lecture est rendue : seule l'écriture reste refusée
        let (rkg, fpg, _) = t3c_cle(&st, gxql, from);
        bh3_noter_un_refus(&st.db.lock(), gxql, &rkg, &fpg, now());
        let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None).err().unwrap_or_else(|| panic!("précondition : GXQL refusé"));
        let (code, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        assert_eq!((code, v), (400, json!({ "error": refus })), "compilateur : le 400 l'emporte sur l'écriture refusée");
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (5) CHARGE D'UN PANNEAU QUI NE COMPILE PLUS.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bh3_charge_perimee_d_un_panneau_qui_ne_compile_plus_le_dit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp, gxql, _panne, _sain) = t3c_state("bh3-non-compilable");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, gxql, from);
        let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None).err().unwrap_or_else(|| panic!("précondition : GXQL refusé"));
        let poser = |calcule_a: i64, payload: &str| panneau_avoue::cache_ecrire(&st.db.lock(), gxql, &rk, &fp, calcule_a, payload);

        poser(now() - 5, &bh3_charge());
        let (code, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "fraîche : servie : {v}");
        assert!(v["stats"].get("rafraichissement_en_echec").is_none(), "fraîche : servie telle quelle, sans aveu : {v}");

        poser(now() - ttl - 50, &bh3_charge());
        let avant = now();
        let (code, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        let apres = now();
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "périmée : la charge reste servie : {v}");
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["cause"], json!(refus), "périmée : le refus du compilateur est joint : {v}");
        let echoue_a = v["stats"]["rafraichissement_en_echec"]["echoue_a"].as_i64().expect("périmée : instant");
        assert!((avant..=apres).contains(&echoue_a), "périmée : instant du service : {echoue_a} hors [{avant}, {apres}]");

        bh3_refuser(&st.db.lock(), true, true);
        bh3_noter_un_refus(&st.db.lock(), gxql, &rk, &fp, now());
        let (_, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["cause"], json!(refus), "périmée + écriture refusée : le compilateur l'emporte : {v}");
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);

        let n = now();
        let mut echec = panneau_avoue::corps_d_echec("bh3 cause servie", n - 86_400, n);
        echec[crate::handlers::dashboards::MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!("moteur");
        poser(now() - ttl - 50, &echec.to_string());
        let (code, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        assert_eq!((code, v), (400, json!({ "error": refus })), "corps d'échec périmé : le refus du compilateur");
        let laissee = panneau_avoue::cache_lire(&st.db.lock(), gxql, &rk, &fp).map(|(p, _)| p);
        assert_eq!(laissee, Some(echec.to_string()), "corps d'échec périmé : la ligne reste telle quelle");

        poser(now() - 5, &echec.to_string());
        let (code, v) = t3c_json(bh3_demander(&st, gxql, from).await).await;
        assert_eq!((code, v["error"].clone()), (200, json!("bh3 cause servie")), "corps d'échec frais : servi tel quel : {v}");
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (7) LES LIGNES DE JOURNAL, MODE 1, DEUX TENANTS, ET LA BOUCLE DE PRÉ-CHAUFFAGE.
    // ---------------------------------------------------------------------------------
    struct Bh3Panneaux {
        sain: i64,
        live: i64,
        gxql_charge: i64,
        gxql_echec: i64,
        boucle: i64,
    }

    fn bh3_semer(handle: &Arc<Mutex<Connection>>, rk: &str, ttl: i64) -> Bh3Panneaux {
        let conn = handle.lock();
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux semés hors du pré-chauffage");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('bh3','root','shared')", []).expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        let mut ids = Vec::new();
        for (q, soql) in [(T3C_SQL_SAIN, 0), (T3C_SQL_SAIN, 0), (T3C_GXQL_REFUSE, 1), (T3C_GXQL_REFUSE, 1), (T3C_SQL_SAIN, 0)] {
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'bh3',?2,?3,'table')", params![did, q, soql])
                .expect("fixture : panneau");
            ids.push(conn.last_insert_rowid());
        }
        let p = Bh3Panneaux { sain: ids[0], live: ids[1], gxql_charge: ids[2], gxql_echec: ids[3], boucle: ids[4] };
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id=?1", params![p.boucle]).expect("fixture : la boucle attend");
        let fpg = query_fingerprint(T3C_GXQL_REFUSE, true);
        let n = now();
        let mut echec = panneau_avoue::corps_d_echec("bh3 cause servie", n - 86_400, n);
        echec[crate::handlers::dashboards::MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!("moteur");
        panneau_avoue::cache_ecrire(&conn, p.gxql_charge, rk, &fpg, n - ttl - 50, &bh3_charge());
        panneau_avoue::cache_ecrire(&conn, p.gxql_echec, rk, &fpg, n - ttl - 50, &echec.to_string());
        p
    }

    #[tokio::test]
    async fn bh3_lignes_de_journal_des_ecritures_refusees_et_des_panneaux_non_compilables_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et cache_refresh_all_panels lisent load_config()
        if std::env::var(BH3_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            for t in [BH3_ALPHA, BH3_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bh3")), Json(json!({ "id": t, "name": t })))
                    .await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
            }
            let from = now() - 86_400;
            let rk = env_range_key(None, &cache_range_key(from, 0, now()));
            let fp = query_fingerprint(T3C_SQL_SAIN, false);
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            let mut attendus: Vec<String> = Vec::new();
            let mut boucles = Vec::new();
            for t in [BH3_ALPHA, BH3_BETA] {
                let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
                let ttl = ttl_global; // les panneaux du témoin n'ont pas de TTL propre
                let p = bh3_semer(&handle, &rk, ttl);
                let au = au_tadmin("adm", t);
                let demander = |id: i64| panel_data(State(st.clone()), Extension(au.clone()), Path(id), t3c_q(from));
                bh3_refuser(&handle.lock(), true, true);
                let refus_du_moteur = panneau_avoue::cache_ecrire_dit(&handle.lock(), -1, "bh3-sonde", "bh3-sonde", now(), "{}")
                    .expect_err("contrôle : l'autorisateur refuse l'écriture");
                let resultat_non_ecrit = format!(
                    "[panel] WARN rafraîchissement du panneau {} réussi, résultat NON ÉCRIT au cache ({refus_du_moteur}) — /api/panels/{{id}}/data, tenant \"{t}\" — la charge précédente reste servie avec l'aveu, sinon un refus nommé (503) ; nouveau calcul au plus une fois par durée du cache",
                    p.sain
                );
                let le_503 = |cid: &str, refusee_a: i64, geste: &str| {
                    format!(
                        "[{cid}] [panel] WARN résultat du dernier calcul NON ÉCRIT au cache (refus à {refusee_a}), panneau #{}, tenant \"{t}\" — aucune charge servable en cache : refus nommé servi en 503 (sans `warming`), {geste}",
                        p.sain
                    )
                };
                // MISS : chauffe, calcul, résultat non écrit.
                let (code, _) = t3c_json(demander(p.sain).await).await;
                assert_eq!(code, 200, "contrôle {t} : chauffe");
                t3c_attendre_la_tache(&st).await;
                attendus.push(resultat_non_ecrit.clone());
                // 503 non armé.
                let refusee_a = panneau_avoue::ecriture_de_cache_refusee(&handle.lock(), p.sain, &rk, &fp).expect("contrôle : refus noté");
                let (code, v) = t3c_json(demander(p.sain).await).await;
                assert_eq!(code, 503, "contrôle {t} : 503 : {v}");
                attendus.push(le_503(v["id"].as_str().unwrap_or_default(), refusee_a, "aucun calcul armé avant l'expiration du cache"));
                // 503 armé, puis résultat non écrit.
                bh3_noter_un_refus(&handle.lock(), p.sain, &rk, &fp, now() - ttl - 5);
                let refusee_a = panneau_avoue::ecriture_de_cache_refusee(&handle.lock(), p.sain, &rk, &fp).expect("contrôle : refus antidaté");
                let (code, v) = t3c_json(demander(p.sain).await).await;
                assert_eq!(code, 503, "contrôle {t} : 503 armé : {v}");
                attendus.push(le_503(v["id"].as_str().unwrap_or_default(), refusee_a, "nouveau calcul armé"));
                t3c_attendre_la_tache(&st).await;
                attendus.push(resultat_non_ecrit);
                // Live : panneau au coût connu et faible, écriture du cache seule refusée.
                bh3_refuser(&handle.lock(), true, false);
                record_panel_cost(&handle.lock(), p.live, &fp, 0.5, now());
                let (code, v) = t3c_json(demander(p.live).await).await;
                assert_eq!((code, v["rows"].clone()), (200, json!([[1]])), "contrôle {t} : live servi : {v}");
                attendus.push(format!("[panel] WARN panneau #{}, tenant \"{t}\" : résultat servi en direct NON ÉCRIT au cache ({refus_du_moteur})", p.live));
                // Charge périmée et corps d'échec périmé d'un panneau qui ne compile plus.
                let (code, _) = t3c_json(demander(p.gxql_charge).await).await;
                assert_eq!(code, 200, "contrôle {t} : charge périmée servie");
                attendus.push(format!(
                    "[panel] WARN panneau #{}, tenant \"{t}\" : charge utile périmée servie, le panneau ne compile plus — refus du compilateur joint au corps (`stats.rafraichissement_en_echec`), aucun calcul armé",
                    p.gxql_charge
                ));
                let (code, _) = t3c_json(demander(p.gxql_echec).await).await;
                assert_eq!(code, 400, "contrôle {t} : corps d'échec périmé -> 400");
                attendus.push(format!(
                    "[panel] WARN panneau #{}, tenant \"{t}\" : corps d'échec périmé en cache, le panneau ne compile plus — le refus du compilateur est servi (400), la ligne reste telle quelle",
                    p.gxql_echec
                ));
                // La boucle : seul son panneau est pré-chauffé, son écriture est refusée.
                {
                    let conn = handle.lock();
                    conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux hors du pré-chauffage");
                    conn.execute("UPDATE panel SET panel_cache_ttl_s=NULL WHERE id=?1", params![p.boucle]).expect("fixture : panneau de la boucle");
                }
                bh3_refuser(&handle.lock(), true, true);
                attendus.push(format!("[cache] WARN pré-chauffage du panneau {} réussi, tenant \"{t}\" — résultat NON ÉCRIT au cache ({refus_du_moteur})", p.boucle));
                boucles.push((handle, p.boucle));
            }
            let rk_du_prechauffage = cache_range_key(now() - 86_400, 0, now());
            crate::server::boucles_de_fond::spawn_panel_refresh_loop(st.tenants.clone(), st.refresh_sem.clone(), 86_400);
            for (handle, id) in &boucles {
                let mut vu = false;
                for _ in 0..20_000 {
                    if panneau_avoue::ecriture_de_cache_refusee(&handle.lock(), *id, &rk_du_prechauffage, &fp).is_some() {
                        vu = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                assert!(vu, "contrôle : la boucle a pré-chauffé le panneau {id}");
            }
            for l in &attendus {
                println!("{BH3_ATTENDU}{l}");
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ecriture_du_cache_refusee_dite_et_reessai_borne::bh3_lignes_de_journal_des_ecritures_refusees_et_des_panneaux_non_compilables_deux_tenants",
            ])
            .env(BH3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // La marque peut suivre, sur la même ligne, ce que le banc de test écrit sans retour à la ligne (« test … ») : on lit
        // après elle, où qu'elle soit.
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BH3_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> =
            stderr.lines().filter(|l| l.contains("NON ÉCRIT au cache") || l.contains("ne compile plus")).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert!(!attendus.is_empty(), "contrôle : l'enfant a rendu ses lignes attendues : {stdout}");
        assert_eq!(vus, attendus, "chaque ligne ENTIÈRE, tenant échappé, aucune autre :\n{stderr}");
    }
}
